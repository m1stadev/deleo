import logging
import plistlib
import traceback
from typing import BinaryIO
from zipfile import ZipFile

import click
from pymobiledevice3.cli.restore import Command
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior
from remotezip import RemoteZip

from pyfuturerestore import PyFuturerestore, __version__

logger = logging.getLogger('pymobiledevice3')


# TODO: Add rest of arguments
@click.command(cls=Command)
@click.version_option(message=f'PyFutureRestore {__version__}')
@click.option(
    '-t',
    '--shsh-blob',
    'shsh_blob',
    type=click.File('rb'),
    help='SHSH blob for target restore.',
    required=True,
)
@click.option(
    '-u',
    '--update',
    'update_install',
    is_flag=True,
    help='Keep user data during restore.',
)
@click.argument('ipsw')
def main(device, shsh_blob: BinaryIO, ipsw: str, update_install: bool):
    '''A Python CLI tool for downgrading *OS devices.'''

    if shsh_blob:
        shsh = plistlib.load(shsh_blob)

    if ipsw.startswith('http://') or ipsw.startswith('https://'):
        ipsw = RemoteZip(ipsw)
    else:
        ipsw = ZipFile(ipsw)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)

    behavior = Behavior.Update if update_install else Behavior.Erase

    try:
#        Restore(ipsw, device, shsh=shsh, behavior=behavior).update()
        pass
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


if __name__ == '__main__':
    main()
