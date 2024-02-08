import logging
import os
import plistlib
import traceback
from typing import BinaryIO, Optional
from zipfile import ZipFile

import click
import coloredlogs
from pymobiledevice3 import usbmux
from pymobiledevice3.cli.cli_common import set_verbosity
from pymobiledevice3.exceptions import ConnectionFailedError, IncorrectModeError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import Behavior
from remotezip import RemoteZip

from equinox import __version__
from equinox.irecv import IRecv
from equinox.restore import Restore

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


class Command(click.Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params[:0] = [
            click.Option(('device', '--ecid'), type=click.INT, callback=self.device),
            click.Option(
                ('verbosity', '-v', '--verbose'),
                count=True,
                callback=set_verbosity,
                expose_value=False,
            ),
        ]

    @staticmethod
    def device(ctx, param, value):
        if '_PYMOBILEDEVICE3_COMPLETE' in os.environ:
            # prevent lockdown connection establishment when in autocomplete mode
            return

        ecid = value
        logger.debug('searching among connected devices via lockdownd')
        for device in usbmux.list_devices():
            try:
                lockdown = create_using_usbmux(
                    serial=device.serial, connection_type='USB'
                )
            except (ConnectionFailedError, IncorrectModeError):
                continue
            if (ecid is None) or (lockdown.ecid == value):
                logger.debug('found device')
                return lockdown
            else:
                continue
        logger.debug('waiting for device to be available in Recovery mode')
        return IRecv(ecid=ecid)


# TODO: Add rest of arguments
@click.command(cls=Command)
@click.version_option(message=f'Equinox {__version__}')
@click.option(
    '-s',
    '--shsh-blob',
    'shsh_blob',
    type=click.File('rb'),
    help='SHSH blob for target restore.',
    required=True,
)
@click.option(
    '-n',
    '--set-nonce',
    'set_nonce',
    is_flag=True,
    help='Set nonce before restoring (device must be in pwned DFU mode).',
)
@click.option(
    '-u',
    '--update',
    'update_install',
    is_flag=True,
    help='Keep user data during restore (not recommended if downgrading).',
)
@click.option(
    '-o',
    '--ota-manifest',
    'ota_manifest',
    type=click.File('rb'),
    help='OTA build manifest for latest IPSW.',
)
@click.argument('ipsw')
@click.argument('latest_ipsw')
def main(
    device,
    shsh_blob: BinaryIO,
    ota_manifest: Optional[BinaryIO],
    ipsw: str,
    latest_ipsw: str,
    update_install: bool,
    set_nonce: bool,
):
    """A Python CLI tool for downgrading i(Pad)OS devices."""

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

    if update_install:
        behavior = Behavior.Update
        if 'updateInstall' not in shsh.keys():
            raise click.BadParameter(
                f'Provided SHSH blob does not support update install: {shsh_blob.name}'
            )
        shsh = shsh['updateInstall']
    else:
        behavior = Behavior.Erase

    if ota_manifest:
        manifest_data = ota_manifest.read()
    else:
        manifest_data = None

    try:
        Restore(
            ipsw, latest_ipsw, device, shsh, behavior, ota_manifest=manifest_data
        ).update(set_nonce=set_nonce)
    except Exception:
        # click may "swallow" several exception types so we try to catch them all here
        traceback.print_exc()
        raise


if __name__ == '__main__':
    main()
