"""
Threatray function attribution as an external Kesakode provider for Malcat.

Port of the "Attribute Functions" feature of Threatray's IDA plugin
(https://github.com/threatray/plugin-ida). It asks the Threatray platform which
malware family / library every function of the *currently opened file* belongs
to and shows the answer in Malcat's Kesakode view.

Requirements / caveats
----------------------
* The file must already have been analysed by Threatray: only its SHA256 is
  sent, the sample itself is *never* uploaded. A file Threatray doesn't know
  gives a "submit it for analysis first" error.
* Unlike Malcat's own Kesakode, only functions are attributed (no strings or
  constant sets).
* Threatray reports function addresses relative to the image base it saw
  when it analysed the sample. They are mapped onto Malcat's functions through
  the offset to that image base (same approach as the IDA plugin). A hit is only
  attached to a function whose *start* is exactly the reported address.
"""
import re
from concurrent.futures import ThreadPoolExecutor

import malcat
from intelligence.base import OnlineChecker
from kesakode import KesakodeExternalResult
from malcat import Detection, KesakodeMatch

# --- Threatray vocabulary (see threatray_ida/domain) -------------------------
VERDICT_BENIGN = "benign"
VERDICT_UNKNOWN = "unknown"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

CATEGORY_MALWARE = "malware"
CATEGORIES_LIBRARY = ("library", "runtime")

_SEVERITY = {  # for ordering hits: worst first
    VERDICT_MALICIOUS: 3,
    VERDICT_SUSPICIOUS: 2,
    VERDICT_BENIGN: 1,
}

# a Threatray realm is a DNS label; never let it smuggle anything else into the
# hostname we send the API key to
_REALM_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class ThreatrayError(Exception):
    """A user-presentable error (bad configuration, API error, ...)."""


# --- HTTP --------------------------------------------------------------------
def _api_base(realm):
    return f"https://api-{realm}.analysis.threatray.com/v1"


def _site_base(realm):
    return f"https://{realm}.analysis.threatray.com"


def _get_json(session, url, not_found_message, params=None):
    """GET *url* and return the decoded json, raising ThreatrayError for anything unusual."""
    try:
        resp = session.get(url, params=params)
    except Exception as e:  # requests.RequestException, SSLError, ...
        raise ThreatrayError(
            f"Failed to query the Threatray API ({type(e).__name__}). "
            "Check your realm, network and the 'Verify SSL certificates' option."
        ) from e
    if resp.status_code == 401:
        raise ThreatrayError("Threatray API key is invalid. Please update it in the preferences.")
    if resp.status_code == 404:
        raise ThreatrayError(not_found_message)
    if not resp.ok:
        raise ThreatrayError(f"Threatray API returned HTTP {resp.status_code}.")
    try:
        return resp.json()
    except ValueError as e:
        raise ThreatrayError("Threatray API returned invalid json.") from e


def fetch_image_base(session, realm, sha256):
    """Image base Threatray used for this file. 400 means 'no PE header', in which case the IDA plugin uses 0."""
    url = f"{_api_base(realm)}/files/{sha256}/pe-header"
    try:
        resp = session.get(url)
    except Exception as e:
        raise ThreatrayError(
            f"Failed to query the Threatray API ({type(e).__name__}). "
            "Check your realm, network and the 'Verify SSL certificates' option."
        ) from e
    if resp.status_code == 400:
        return 0
    if resp.status_code == 401:
        raise ThreatrayError("Threatray API key is invalid. Please update it in the preferences.")
    if resp.status_code == 404:
        raise ThreatrayError(_not_analysed(sha256))
    if not resp.ok:
        raise ThreatrayError(f"Threatray API returned HTTP {resp.status_code}.")
    try:
        return int(resp.json()["image_base"])
    except (ValueError, KeyError, TypeError) as e:
        raise ThreatrayError("Threatray API returned an unexpected pe-header response.") from e


def fetch_code_detections(session, realm, sha256):
    url = f"{_api_base(realm)}/functions/code-detections"
    data = _get_json(session, url, _not_analysed(sha256), params={"hash": sha256})
    if not isinstance(data, dict) or not isinstance(data.get("functions"), list):
        raise ThreatrayError("Threatray API returned an unexpected code-detections response.")
    return data["functions"]


def _not_analysed(sha256):
    return f"No entity found with the hash {sha256} in Threatray. Please submit the file for analysis first."


# --- mapping Threatray -> Malcat -----------------------------------------------
def detection_name(detection):
    """Name of one code detection. Same rule as CodeDetection.get_name() in the IDA plugin."""
    family = detection.get("family")
    if family and family.get("category") != CATEGORY_MALWARE:
        return family.get("name") or ""
    signature = detection.get("code_signature")
    if signature:
        return signature.get("name") or ""
    return ""


def detection_category(detection):
    family = detection.get("family")
    return (family or {}).get("category") or ""


def hit_level(verdict, category):
    """Malcat Detection.Level for a named detection, or None if it can't be expressed (e.g. unknown)."""
    if verdict == VERDICT_MALICIOUS:
        return Detection.Level.MALWARE
    if verdict == VERDICT_SUSPICIOUS:
        return Detection.Level.SUSPICIOUS
    if verdict == VERDICT_BENIGN:
        return Detection.Level.LIBRARY if category in CATEGORIES_LIBRARY else Detection.Level.CLEAN
    return None


def _function_at(analysis, mode, address, tr_image_base):
    """The Malcat function whose *start* is the Threatray *address* under interpretation *mode*, or None."""
    try:
        if mode == "offset":    # Threatray offset (address - its image base) re-based on Malcat's image base
            ea = analysis.v2a(analysis.imagebase + (address - tr_image_base))
        elif mode == "va":      # raw Threatray address used as a Malcat virtual address
            ea = analysis.v2a(address)
        else:                   # "rva": raw Threatray address used as a Malcat RVA
            ea = analysis.r2a(address)
        if ea is None:
            return None
        fn = analysis.fns.find(ea)
    except Exception:
        return None
    return fn if fn is not None and fn.start == ea else None


def resolve_functions(analysis, addresses, tr_image_base, dotnet):
    """
    Map Threatray addresses onto Malcat functions (exact function starts only).
    Returns (mode, [Function or None for each address]).

    Native code: always "offset" (same as the IDA plugin).
    .NET: the IDA plugin uses Threatray's raw address and I can't verify which Malcat address space that
    corresponds to. So pick, *once for the whole file*, the interpretation (raw address as VA, as RVA, or as
    offset) that lands the most records on function starts; ties go to the IDA-equivalent one (raw VA).
    """
    modes = ("va", "rva", "offset") if dotnet else ("offset",)
    best = None
    for mode in modes:
        resolved = [_function_at(analysis, mode, a, tr_image_base) for a in addresses]
        count = sum(1 for r in resolved if r is not None)
        if best is None or count > best[2]:
            best = (mode, resolved, count)
    return best[0], best[1]


def build_hits(function):
    """
    Turn one Threatray function record into a list of (Hit, detection_dict) tuples.

    * unknown                       -> nothing
    * benign without any signature  -> one anonymous CLEAN hit
    * otherwise                     -> one hit per *named* detection that has a verdict we can express
    """
    fn_verdict = function.get("verdict")
    detections = function.get("code_detections") or []
    if fn_verdict == VERDICT_UNKNOWN:
        return []
    signed = [d for d in detections if d.get("code_signature")]
    if fn_verdict == VERDICT_BENIGN and not signed:
        return [(KesakodeMatch.Hit(name="", level=Detection.Level.CLEAN, score=100.0, symbol=""), None)]
    hits = []
    seen = set()
    for d in signed:
        name = detection_name(d)
        level = hit_level(d.get("verdict") or fn_verdict, detection_category(d))
        if not name or level is None or (level, name) in seen:
            continue
        seen.add((level, name))
        score = max(0.0, min(100.0, float(d.get("score") or 0.0) * 100.0))
        hits.append((KesakodeMatch.Hit(name=name, level=level, score=score, symbol=""), d))
    return hits


def compute_verdict(per_function):
    """
    Global verdict {family: 0-100}, set explicitly instead of letting Malcat infer it from the hits.

    For every malware family: the share of the file's *malware-attributed* functions that belong to it,
    weighted by Threatray's per-function score (100 = every such function matches the family with score 1.0).
    Only MALWARE-level hits count, and only functions with at least one such hit are in the denominator:
    library / clean / benign / unknown / merely suspicious functions don't dilute the percentages.
    Families are not exclusive (shared code), so the values don't sum to 100.
    """
    malicious_functions = 0
    weight = {}
    for merged in per_function.values():
        families = {name: hit.score for (level, name), (hit, _) in merged.items()
                    if level == Detection.Level.MALWARE and name}
        if not families:
            continue
        malicious_functions += 1
        for name, score in families.items():
            weight[name] = weight.get(name, 0.0) + score / 100.0
    if not malicious_functions:
        return {}
    shares = {name: min(100.0, round(100.0 * w / malicious_functions, 2)) for name, w in weight.items()}
    return dict(sorted(shares.items(), key=lambda kv: (-kv[1], kv[0])))


def reference_url(realm, detection):
    ref = detection.get("reference_function")
    if not ref or not ref.get("analysis_id"):
        return ""
    return (f"{_site_base(realm)}/analyses/{ref['analysis_id']}"
            f"#{ref.get('pid')}-{ref.get('base')}-{ref.get('code_region')}")


def format_intelligence(realm, name, infos):
    """Text for Malcat's threat description panel (wiki syntax) for one detection name."""
    d = infos["detection"]
    family = d.get("family") or {}
    signature = d.get("code_signature") or {}
    lines = [
        f"[color1]{name}[/color1]",
        "[color1]" + "-" * max(6, len(name)) + "[/color1]",
        f"Verdict: {d.get('verdict') or infos['function_verdict']}",
    ]
    if family.get("category"):
        lines.append(f"Category: {family['category']}")
    if family.get("name") and family.get("name") != name:
        lines.append(f"Family: {family['name']}")
    if signature.get("scope"):
        lines.append(f"Signature scope: {signature['scope']}")
    lines.append(f"Functions in this file: {infos['count']}")
    lines.append(f"Best match: similarity {d.get('similarity')}, confidence {d.get('confidence')}, "
                 f"score {float(d.get('score') or 0):.2f}")
    url = reference_url(realm, d)
    if url:
        lines.append(f"Reference analysis: {url}")
    return "\n".join(lines)


# --- the provider --------------------------------------------------------------
class Threatray(OnlineChecker):
    """
    Function attribution using the Threatray platform (port of the 'Attribute Functions' feature of Threatray's IDA plugin).
    """

    name = "Threatray"
    kesakode_menu_name = "Threatray function attribution"

    options = {
        "realm": ("", "Threatray realm, i.e. the xxx in https://xxx.analysis.threatray.com"),
        "key": ("", "Threatray API key (see https://docs.threatray.com/reference/authentication)"),
        "timeout": (60, "HTTP timeout in seconds"),
    }

    # filled by kesakode() for introspection / tests
    stats = None

    def _config(self):
        realm = str(self.options.get("realm") or "").strip().lower()
        key = str(self.options.get("key") or "").strip()
        if not realm:
            raise ThreatrayError("No Threatray realm given, please configure it in the preferences.")
        if not _REALM_RE.match(realm):
            raise ThreatrayError(f"Invalid Threatray realm: {realm!r}")
        if not key:
            raise ThreatrayError("No Threatray API key given, please configure it in the preferences.")
        return realm, key

    def _session(self, key):
        session = self.preconfigured_session()
        session.headers.update({"Authorization": f"apikey {key}", "Accept": "application/json"})
        return session

    def kesakode(self, analysis, fuzzy_matching=False):
        realm, key = self._config()
        sha256 = analysis.entropy.sha256.lower()

        # both calls are independent (as in the IDA plugin), run them concurrently
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_functions = pool.submit(fetch_code_detections, self._session(key), realm, sha256)
            f_base = pool.submit(fetch_image_base, self._session(key), realm, sha256)
            functions = f_functions.result()
            tr_image_base = f_base.result()

        dotnet = analysis.architecture in (malcat.Architecture.DOTNET, malcat.Architecture.DOTNET_STRICT)

        # records that actually carry something to show: (address, record, hits)
        attributable = []
        for f in functions:
            try:
                address = int(f["address"])
            except (KeyError, TypeError, ValueError):
                continue
            hits = build_hits(f)
            if hits:
                attributable.append((address, f, hits))

        mode, resolved = resolve_functions(analysis, [a for a, _, _ in attributable], tr_image_base, dotnet)

        # Malcat function start -> {(level, name): (Hit, detection)}; a start can only be reported once
        per_function = {}
        fn_objects = {}
        function_verdict = {}
        unmatched = 0
        for (address, f, hits), fn in zip(attributable, resolved):
            if fn is None:
                unmatched += 1
                continue
            fn_objects[fn.start] = fn
            function_verdict[fn.start] = f.get("verdict")
            merged = per_function.setdefault(fn.start, {})
            for hit, detection in hits:
                merged.setdefault((hit.level, hit.name), (hit, detection))

        if attributable and not per_function:
            # a whole-file mapping failure must not look like "Threatray knows nothing about this file"
            raise ThreatrayError(
                f"Threatray attributed {len(attributable)} functions but none of them lands on the start of a "
                f"Malcat function (Threatray image base {tr_image_base:#x}, Malcat image base "
                f"{analysis.imagebase:#x}). The open file probably differs from the one Threatray analysed "
                "(e.g. unpacked/dumped vs original), or function recovery differs too much."
            )

        # most prevalent names first (same ordering as the IDA plugin), then best score
        prevalence = {}
        for merged in per_function.values():
            for (_, name) in merged:
                if name:
                    prevalence[name] = prevalence.get(name, 0) + 1

        result = KesakodeExternalResult()
        infos = {}
        for start in sorted(per_function):
            ordered = sorted(
                per_function[start].values(),
                key=lambda hd: (-prevalence.get(hd[0].name, 0), -hd[0].score, hd[0].name),
            )
            result[fn_objects[start]] = [h for h, _ in ordered]
            for hit, detection in ordered:
                if not hit.name or detection is None:
                    continue
                info = infos.setdefault(
                    hit.name, {"detection": detection, "count": 0, "function_verdict": function_verdict[start]})
                info["count"] += 1
                if float(detection.get("score") or 0) > float(info["detection"].get("score") or 0):
                    info["detection"] = detection

        # NB: KesakodeExternalResult.set_intelligence() is buggy in this Malcat version, set the attributes directly
        for name, info in infos.items():
            result.intelligence[name] = format_intelligence(realm, name, info)
        # explicit global verdict (see compute_verdict) rather than Malcat's own inference from the hits
        result.set_verdict(compute_verdict(per_function))

        self.stats = {"functions_reported": len(functions), "functions_matched": len(per_function),
                      "functions_unmatched": unmatched, "names": len(infos), "image_base": tr_image_base,
                      "address_mode": mode}
        return result
