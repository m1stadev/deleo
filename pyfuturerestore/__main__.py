import logging
from time import sleep
from typing import BinaryIO
from zipfile import ZipFile

import click
import sys
from pyfuturerestore import PyFuturerestore, __version__

logger = logging.getLogger('pymobiledevice3')


# TODO: Add rest of arguments
@click.command()
@click.version_option(message=f'PyFutureRestore {__version__}')
@click.option(
    '-v',
    '--verbose',
    'verbose',
    is_flag=True,
    help='Increase verbosity.',
)
@click.option(
    '-t',
    '--shsh-blob',
    'shsh_blob',
    type=click.File('rb'),
    help='SHSH blob for target restore.',
    required=True,
)
@click.argument('IPSW', type=ZipFile())  # TODO: check if this even works?
def main(
    verbose: bool,
    shsh_blob: BinaryIO,
    ipsw: ZipFile,
):
    '''A Python CLI tool for downgrading *OS devices.'''

    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        sys.tracebacklimit = 0

    click.echo("CLI isn't done yet")


# TODO: Clean this up later
'''    client = PyFuturerestore(
        ipsw,
        logger,
        setnonce=isinstance(args.set_nonce, blank),
        serial=args.serial,
        custom_gen=args.set_nonce[0] if not isinstance(args.set_nonce, blank) else None,
        ignore_nonce_matching=args.ignore_nonce_matching,
        noibss=args.no_ibss,
        skip_blob=args.skip_blob,
        pwndfu=args.use_pwndfu,
        custom_usb_backend=args.usb_backend[0] if args.usb_backend else None,
        no_cache=args.no_cache,
        verbose=args.debug,
    )
    client.init()
    logger.info('pyfuturerestore init done')
    retassure(client.irecv.is_image4_supported, '32-bit device is not supported')
    if args.exit_recovery:
        client.exit_recovery()
        logger.info('Done')
        return
    client.load_ap_ticket(args.apticket[0])

    if args.latest_sep:
        client.load_latest_sep()
    else:
        retassure(
            os.path.isfile(args.sep[0]), f'SEP firmware not found at {args.sep[0]}'
        )
        retassure(
            os.path.isfile(args.sep_manifest[0]),
            f'SEP BuildManifest not found at {args.sep_manifest[0]}',
        )
        with open(args.sep[0], 'rb') as sep, open(args.sep_manifest[0], 'rb') as sepbm:
            client.load_sep(sep.read(), sepbm.read())
    if args.no_baseband:
        logger.warning(
            'User specified is not to flash a baseband. This can make the restore fail if the device needs a baseband!'
        )
        i = 10
        while i:
            print('Continuing restore in ', end='')
            print(i, end='\r')
            i -= 1
            sleep(1)
        print('')
    else:
        if args.latest_baseband:
            client.load_latest_baseband()
        else:
            retassure(
                os.path.isfile(args.baseband[0]),
                f'Baseband firmware not found at {args.baseband[0]}',
            )
            retassure(
                os.path.isfile(args.baseband_manifest[0]),
                f'Baseband BuildManifest not found at {args.baseband_manifest[0]}',
            )
            with open(args.baseband[0], 'rb') as bb, open(
                args.baseband_manifest[0], 'rb'
            ) as bbbm:
                client.load_baseband(bb.read(), bbbm.read())

    if args.rdsk:
        client.load_ramdisk(args.rdsk[0])
    if args.rkrn:
        client.load_rkrn(args.rkrn[0])
    if args.boot_args:
        client.set_bootargs(args.boot_args[0])
    if client.irecv.is_image4_supported:
        client.download_latest_fw_components()

    try:
        client.do_restore()
        logger.info('Done: restoring succeeded!')
    except m1n1Exception as e:
        logger.error('Exception raised during restore:')
        logger.error(e)
        logger.error('Done: restoring failed!')
'''

if __name__ == '__main__':
    main()
