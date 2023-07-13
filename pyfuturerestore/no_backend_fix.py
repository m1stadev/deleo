import os
import stat
import os.path

import click
from pymobiledevice3 import irecv
import usb
from pathlib import Path

# borrowed from https://github.com/Merculous/iBoot-Compile/blob/master/Odder.py
def doPatches(filepath, stockString, patchString, stringLine):
    # Bad patcher by Matty (@mosk_i)
    #print("Patching {}\nat line {}".format(filepath, stringLine))
    if os.path.exists(filepath):
        with open(filepath, "rt") as f:
            data = f.readlines()
            if patchString in data[stringLine]:
                click.echo("Already fixed")
                return 0
            if stockString in data[stringLine]:
                data[stringLine] = str(patchString)
                f.close()
                g = open(filepath, "wt")
                g.writelines(data)
                g.close()
                # changing file permissions
                os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
                         stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
                return 0
            else:
                #print("Didn't find {}\nin\n{}\nat line\n{}\nMoving on to next patch...".format(
                    #stockString, filepath, stringLine))
                return -1
    else:
        #print("Couldn't find file at {}\nMoving on to next patch...".format(filepath))
        return -1

# from m1stadev's Inferius
def _get_backend():  # Attempt to find a libusb 1.0 library to use as pyusb's backend, exit if one isn't found.
    directories = (
        '/usr/local/lib',
        '/opt/procursus/lib',
        '/usr/lib',
        '/opt/homebrew/lib' # this works on my M2 Mac, tell me to add more if libusb is in a different path on your computer
    )  # Common library directories to search

    libusb1 = None
    for libdir in directories:
        for file in Path(libdir).glob('libusb-1.0.0.*'):
            if not file.is_file() or (file.suffix not in ('.so', '.dylib')):
                continue

            libusb1 = file
            break

        else:
            continue

        break

    if libusb1 is None:
        click.secho('libusb not installed, run "brew install libusb" to install libusb first', fg='red')
        return -1

    return str(libusb1)


def fix():
    click.echo('Fixing pymobiledevice3 (No backend available)')
    pymobiledevice3_irecv_path = os.path.abspath(irecv.__file__)
    libusb_path = _get_backend()
    if libusb_path == -1:
        return -1
    if doPatches(pymobiledevice3_irecv_path, '', 'from usb.backend.libusb1 import get_backend\n', 8) == -1:
        click.secho('Fixing failed')
        return -1
    if doPatches(pymobiledevice3_irecv_path, '            for device in find(find_all=True):\n', f'            for device in find(find_all=True, backend=get_backend(find_library=lambda _: "{libusb_path}")):\n', 263) == -1:
        click.secho('Fixing failed')
        return -1
    return 0
