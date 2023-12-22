<h1 align="center">
Equinox
</h1>
<p align="center">By <a href="https://github.com/m1stadev">m1sta</a>.

<p align="center">
  <a href="https://github.com/m1stadev/equinox/blob/master/LICENSE">
    <image src="https://img.shields.io/github/license/m1stadev/equinox">
  </a>
  <a href="https://github.com/m1stadev/equinox/stargazers">
    <image src="https://img.shields.io/github/stars/m1stadev/equinox">
  </a>
    <br>
</p>

<p align="center">
A Python CLI tool for downgrading i(Pad)OS devices.
</p>

## Usage
```
Usage: equinox [OPTIONS] IPSW LATEST_IPSW

  A Python CLI tool for downgrading i(Pad)OS devices.

Options:
  --ecid INTEGER
  -v, --verbose
  --version                    Show the version and exit.
  -t, --shsh-blob FILENAME     SHSH blob for target restore.  [required]
  -u, --update                 Keep user data during restore (not recommended if downgrading).
  -o, --ota-manifest FILENAME  OTA build manifest for latest IPSW.
  --help                       Show this message and exit.
```
## Notes
- Equinox only supports 64-bit devices.
- You can only restore using a signed 15.x or below IPSW as latest.
    - More info on that <a href="https://gist.github.com/Cryptiiiic/b82133ac290070939189e1377dc3ac85">here</a>.
- In place of an actual IPSW file in the `IPSW` or `LATEST_IPSW` arguments, you can pass a URL to an IPSW instead.
  - This is not recommended for the `IPSW` argument, as `remotezip`'ing the RootFS dmg will take quite a while...
- Ensure that whatever version you are restoring to is compatible with the SEP version in the latest IPSW.
    - You can find a spreadsheet that will show you what iOS versions are compatible with the latest SEP version <a href="https://docs.google.com/spreadsheets/d/1Mb1UNm6g3yvdQD67M413GYSaJ4uoNhLgpkc7YKi3LBs">here</a>.

## Requirements
- Python 3.8 or higher
- Valid SHSH blobs

## Installation
- ~~Install from [PyPI](https://pypi.org/project/equinox/):~~
    - ~~```python3 -m pip install equinox```~~
- Local installation:
    - `./install.sh`
    - Requires [Poetry](https://python-poetry.org)

## TODO
- Add PwnDFU functionality
- Add library for automatically finding IPSW

## Support

For any questions/issues you have, [open an issue](https://github.com/m1stadev/equinox/issues).
