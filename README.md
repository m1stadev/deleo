<h1 align="center">
deleo
</h1>
<p align="center">By <a href="https://github.com/m1stadev">m1sta</a>.

<p align="center">
  <a href="https://github.com/m1stadev/deleo/blob/master/LICENSE">
    <image src="https://img.shields.io/github/license/m1stadev/deleo">
  </a>
  <a href="https://github.com/m1stadev/deleo">
    <image src="https://tokei.rs/b1/github/m1stadev/deleo?category=code&lang=python&style=flat">
  </a>
  <a href="https://github.com/m1stadev/deleo/stargazers">
    <image src="https://img.shields.io/github/stars/m1stadev/deleo">
  </a>
    <br>
</p>

<p align="center">
A Python CLI tool for downgrading i(Pad)OS devices.
</p>

## Usage
```
Usage: deleo [OPTIONS] IPSW LATEST_IPSW

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
## Requirements
- Python 3.8 or higher
- Valid SHSH blobs
- A Linux or macOS system
  - Windows support will be coming in the future
- `usbmuxd` on Linux systems

## Notes
- deleo only supports 64-bit devices.
- In most cases, you can only restore using a signed 15.x or below IPSW as latest.
    - More info on that <a href="https://gist.github.com/Cryptiiiic/b82133ac290070939189e1377dc3ac85">here</a>.
- In place of an actual IPSW file in the `IPSW` or `LATEST_IPSW` arguments, you can pass a URL to an IPSW instead.
  - This is not recommended for the `IPSW` argument, as downloading the RootFS dmg directly from the ZIP will take quite a while...
- Ensure that whatever version you are restoring to is compatible with the SEP version in the latest IPSW.
    - You can find a spreadsheet that will show you what iOS versions are compatible with the latest SEP version <a href="https://docs.google.com/spreadsheets/d/1Mb1UNm6g3yvdQD67M413GYSaJ4uoNhLgpkc7YKi3LBs">here</a>.
- On Linux systems that utilize `udev`, you may need to install proper `udev` rules to have proper access to connected *OS devices
  - Typically, you only need to install `libirecovery` from your distribution's package manager.
  - Alternatively, you can download a rules file provided <a href="https://gist.github.com/m1stadev/c0c9313c37a2ed42ceb71903a5102677">here<a/>, and place it in `/etc/udev/rules.d`
  - Once the rules file is installed, reboot to ensure that the rules file is detected properly. 



## Installation
- Install from [PyPI](https://pypi.org/project/deleo/):
    - ```python3 -m pip install deleo```
- Local installation:
    - `./install.sh`
    - Requires [Poetry](https://python-poetry.org)

## Support

For any questions/issues you have, [open an issue](https://github.com/m1stadev/deleo/issues).
