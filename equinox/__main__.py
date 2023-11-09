import logging
import plistlib
import traceback
from typing import BinaryIO
from zipfile import ZipFile

import click
import coloredlogs
from pymobiledevice3.cli.restore import Command
from pymobiledevice3.irecv import IRecv
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior
from remotezip import RemoteZip

from equinox.restore import Restore
from equinox import __version__

coloredlogs.install(level=logging.INFO)

logging.getLogger('quic').disabled = True
logging.getLogger('asyncio').disabled = True
logging.getLogger('zeroconf').disabled = True
logging.getLogger('parso.cache').disabled = True
logging.getLogger('parso.cache.pickle').disabled = True
logging.getLogger('parso.python.diff').disabled = True
logging.getLogger('humanfriendly.prompts').disabled = True
logging.getLogger('blib2to3.pgen2.driver').disabled = True
logging.getLogger('urllib3.connectionpool').disabled = True

logger = logging.getLogger(__name__)


# TODO: Add rest of arguments
@click.command(cls=Command)
@click.version_option(message=f'Equinox {__version__}')
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
    help='Keep user data during restore (not recommended if downgrading).',
)
@click.argument('ipsw')
@click.argument('latest_ipsw')
def main(
    device, shsh_blob: BinaryIO, ipsw: str, latest_ipsw: str, update_install: bool
):
    """A Python CLI tool for downgrading i(Pad)OS devices."""

    if shsh_blob:
        shsh = plistlib.load(shsh_blob)

    if ipsw.startswith('http://') or ipsw.startswith('https://'):
        ipsw = RemoteZip(ipsw)
    else:
        ipsw = ZipFile(ipsw)

    if latest_ipsw.startswith('http://') or latest_ipsw.startswith('https://'):
        latest_ipsw = RemoteZip(latest_ipsw)
    else:
        latest_ipsw = ZipFile(latest_ipsw)

    lockdown = None
    irecv = None
    if isinstance(device, LockdownClient):
        lockdown = device
    elif isinstance(device, IRecv):
        irecv = device
    device = Device(lockdown=lockdown, irecv=irecv)

    behavior = Behavior.Update if update_install else Behavior.Erase

    try:
        Restore(ipsw, latest_ipsw, device, shsh, behavior).update()
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


if __name__ == '__main__':
    main()
