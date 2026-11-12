# Malcat Plugins

A collection of my plugins for [Malcat](https://malcat.fr).

## Plugins

### Threatray (`.malcat/intelligence/Threatray.py`)

Kesakode provider that attributes functions of the opened file to malware families or libraries using the [Threatray](https://threatray.com) platform. Only the file's SHA256 is sent; the sample is never uploaded, so it must already be known to Threatray. Only functions are attributed (no strings or constants).

**Requirements:** a Threatray account and a valid API key. Before using the plugin, set the Realm and the API key in Malcat's settings.

## Installation

Plugins are placed in the matching subfolder of Malcat's data directory. The path inside this repo's `.malcat` folder mirrors that layout (e.g. `.malcat/intelligence/Threatray.py`).

Copy the plugin you want to one of:

- `<user data dir>/<subfolder>/` (recommended, survives Malcat updates; `~/.malcat/` on Linux)
- `<malcat install>/data/<subfolder>/`

To install all plugins at once, copy the whole `.malcat` folder into your home directory (or merge it with your existing `~/.malcat`).

Then re-analyse the file (Ctrl+R) or restart Malcat.

## License

See [LICENSE](LICENSE).
