import binascii
import logging
import os
import plistlib
import struct
import sys
import typing
import zipfile
from io import BytesIO
from pathlib import Path
from time import sleep
from typing import Mapping, Optional
from zipfile import ZipFile

import pyimg4
import requests
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.exceptions import NoSuchBuildIdentityError
from ipsw_parser.ipsw import IPSW
from m1n1Exception import retassure, reterror
from pyipatcher.ipatcher import IPatcher
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    IncorrectModeError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.irecv import IRecv, Mode
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.restore import asr, fdr, tss
from pymobiledevice3.restore.asr import ASRClient
from pymobiledevice3.restore.base_restore import (
    RESTORE_VARIANT_ERASE_INSTALL,
    RESTORE_VARIANT_MACOS_RECOVERY_OS,
    RESTORE_VARIANT_UPGRADE_INSTALL,
    BaseRestore,
)
from pymobiledevice3.restore.consts import PROGRESS_BAR_OPERATIONS, lpol_file
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.fdr import FDRClient, fdr_type, start_fdr_thread
from pymobiledevice3.restore.ftab import Ftab
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore import Restore
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from pymobiledevice3.service_connection import LockdownServiceConnection
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.utils import plist_access_path
from remotezip import RemoteZip
from usb import USBError
from usb.backend.libusb1 import get_backend
from usb.core import find

# ------------- subclasses, overwritings -------------


def load_custom_manifest(self, custom_manifest):
    self._build_manifest = BuildManifest(self, custom_manifest)


IPSW.load_custom_manifest = load_custom_manifest


def BaseRestore__init__(
    self,
    ipsw: ZipFile,
    device: Device,
    tss: typing.Mapping = None,
    sepfw=None,
    sepbm=None,
    bbfw=None,
    bbbm=None,
    behavior: Behavior = Behavior.Update,
    logger=None,
):
    self.logger = (
        logging.getLogger(self.__class__.__name__) if logger is None else logger
    )
    self.ipsw = IPSW(ipsw)
    self.device = device
    self.tss = TSSResponse(tss) if tss is not None else None
    self.sepfw = sepfw
    self.bbfw = bbfw

    if not self.device.is_image4_supported:
        raise NotImplementedError('is_image4_supported is False')

    self.logger.info(
        f'connected device: <ecid: {self.device.ecid} hardware_model: {self.device.hardware_model} '
        f'image4-support: {self.device.is_image4_supported}>'
    )

    self.logger.debug('scanning BuildManifest.plist for the correct BuildIdentity')

    variant = {
        Behavior.Update: RESTORE_VARIANT_UPGRADE_INSTALL,
        Behavior.Erase: RESTORE_VARIANT_ERASE_INSTALL,
    }[behavior]

    if sepbm:
        self.logger.info('Getting custom SEP BuildIdentity')
        self.ipsw.load_custom_manifest(sepbm)
        self.sep_build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model, restore_behavior=behavior.value, variant=variant
        )
    if bbbm:
        self.logger.info('Getting custom Baseband BuildIdentity')
        self.ipsw.load_custom_manifest(bbbm)
        self.baseband_build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model, restore_behavior=behavior.value, variant=variant
        )
    try:
        self.build_identity = self.ipsw.build_manifest.get_build_identity(
            self.device.hardware_model, restore_behavior=behavior.value, variant=variant
        )
    except NoSuchBuildIdentityError:
        if behavior == Behavior.Update:
            self.build_identity = self.ipsw.build_manifest.get_build_identity(
                self.device.hardware_model, restore_behavior=behavior.value
            )
        else:
            raise

    self.macos_variant = None
    try:
        self.macos_variant = self.ipsw.build_manifest.get_build_identity(
            self.device.hardware_model, variant=RESTORE_VARIANT_MACOS_RECOVERY_OS
        )
        self.logger.info('Performing macOS restore')
    except NoSuchBuildIdentityError:
        pass

    build_info = self.build_identity.get('Info')
    if build_info is None:
        raise PyMobileDevice3Exception(
            'build identity does not contain an "Info" element'
        )

    device_class = build_info.get('DeviceClass')
    if device_class is None:
        raise PyMobileDevice3Exception(
            'build identity does not contain an "DeviceClass" element'
        )


BaseRestore.__init__ = BaseRestore__init__


Mode.NORMAL_MODE = 0x12A8

# ---------------------------------

PYFUTURERESTORE_TEMP_PATH = '/tmp/pyfuturerestore/'


def strmode(mode: Mode):
    if mode in (
        Mode.RECOVERY_MODE_1,
        Mode.RECOVERY_MODE_2,
        Mode.RECOVERY_MODE_3,
        Mode.RECOVERY_MODE_4,
    ):
        return 'Recovery'
    elif mode == Mode.DFU_MODE:
        return 'DFU'
    elif mode == Mode.NORMAL_MODE:
        return 'Normal'
    elif mode == Mode.WTF_MODE:
        return 'WTF'
    else:
        return None


class PyFuturerestore:
    def __init__(
        self,
        ipsw: ZipFile,
        logger,
        setnonce=False,
        serial=False,
        custom_gen=None,
        ignore_nonce_matching=False,
        noibss=False,
        skip_blob=False,
        pwndfu=False,
        no_cache=False,
        custom_usb_backend=None,
        verbose=False,
    ):
        if not os.path.isdir(PYFUTURERESTORE_TEMP_PATH):
            os.makedirs(PYFUTURERESTORE_TEMP_PATH)
        self.no_cache = no_cache
        self.serial = serial
        self._bootargs = None
        self.ramdiskdata = None
        self.rkrndata = None
        self.usb_backend = custom_usb_backend
        self.zipipsw = ipsw
        self.skip_blob = skip_blob
        self.setnonce = setnonce
        self.ignore_nonce_matching = ignore_nonce_matching
        self.pwndfu = pwndfu
        self.custom_gen = custom_gen
        self.tss = None
        self.ipsw: IPSW = IPSW(ipsw)
        self.verbose = verbose
        self.logger = logger
        asr.logger = logger
        fdr.logger = logger
        tss.logger = logger
        self.sepfw = None
        self.sepbm = None
        self.bbfw = None
        self.bbbm = None
        self.fwcomps = {
            'RoseFW': None,
            'SEFW': None,
            'VeridianFWM': None,
            'VeridianDGM': None,
            'SavageFW': {
                'Savage,B0-Prod-Patch': None,
                'Savage,B0-Dev-Patch': None,
                'Savage,B2-Prod-Patch': None,
                'Savage,B2-Dev-Patch': None,
                'Savage,BA-Prod-Patch': None,
                'Savage,BA-Dev-Patch': None,
            },
        }
        self.rosefw = None
        self.sefw = None
        self.savagefw = None
        self.verridianfw = None
        self.has_get_latest_fwurl = False
        self.noibss = noibss

    def reconnect_irecv(self, is_recovery=None):
        self.logger.debug('waiting for device to reconnect...')
        self.irecv = IRecv(ecid=self.device.ecid, is_recovery=is_recovery)
        self.logger.debug(f'connected mode: {self.irecv.mode}')

    def pyfuturerestore_get_mode(self):
        try:
            for device in find(find_all=True):
                try:
                    if device.idVendor is None:
                        continue
                    if device.idVendor == 0x05AC:
                        mode = Mode.get_mode_from_value(device.idProduct)
                        if mode is None:
                            continue
                        return mode
                except ValueError:
                    pass
        except Exception as e:
            if 'No backend available' in str(e):
                if self.usb_backend:
                    backend = self.usb_backend
                else:
                    retassure(
                        (backend := _get_backend()) != -1,
                        'Could not find backend for libusb',
                    )
                self.logger.debug(f'USB backend: {backend}')
                for device in find(
                    find_all=True, backend=get_backend(find_library=lambda _: backend)
                ):
                    try:
                        if device.idVendor is None:
                            continue
                        if device.idVendor == 0x05AC:
                            mode = Mode.get_mode_from_value(device.idProduct)
                            if mode is None:
                                continue
                            return mode
                    except ValueError:
                        pass
            else:
                reterror(f'Could not get mode: {e}')

    def init(self):
        self.lockdown_cli: LockdownClient = None
        self.irecv: IRecv = None
        self.init_mode = self.pyfuturerestore_get_mode()
        retassure(self.init_mode, 'Can\'t init, no device found')
        self.logger.info(f'Found device in {strmode(self.init_mode)} mode')
        if self.init_mode == Mode.NORMAL_MODE:
            for device in list_devices():
                try:
                    lockdown = create_using_usbmux(serial=device.serial)
                except IncorrectModeError:
                    continue
                if True:  # no idea
                    self.lockdown_cli = lockdown
                    break
        else:
            self.irecv = IRecv()
        self.device = Device(irecv=self.irecv, lockdown=self.lockdown_cli)

    def download_buffer(self, url, pz_path):
        try:
            with RemoteZip(url) as z:
                return z.read(pz_path)
        except:
            return -1

    def get_latest_fwurl(self):
        try:
            r = requests.get(
                f'http://api.ipsw.me/v2.1/{self.device.irecv.product_type}/latest/url'
            )
            return r.content
        except:
            return -1

    def load_ap_ticket(self, path):
        retassure(os.path.isfile(path), f'APTicket not found at {path}')
        with open(path, 'rb') as f:
            self.tss = plistlib.load(f)
        self.im4m = pyimg4.IM4M(self.tss['ApImg4Ticket'])
        self.logger.info(f'Done reading signing ticket {path}')

    def download_latest_bm(self):
        self.logger.info(
            f'Getting latest firmware URL for {self.device.irecv.product_type}'
        )
        retassure(
            (latest_url := self.get_latest_fwurl()) != -1,
            'Could not get latest firmware URL',
        )
        self.logger.debug(f'Latest firmware URL: {latest_url}')
        retassure(
            (latest_bm := self.download_buffer(latest_url, 'BuildManifest.plist'))
            != -1,
            'Could not download latest BuildManifest.plist',
        )
        return latest_url, latest_bm

    def download_latest_fw_components(self):
        self.load_latest_rose()
        self.load_latest_se()
        self.load_latest_veridian()
        self.load_latest_savages()
        self.logger.info('Finished downloading the latest firmware components!')

    def load_latest_rose(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        try:
            rose_path = build_identity.get_component_path('Rap,RTKitOS')
            self.logger.info('Downloading Rose firmware')
            retassure(
                (latest_rosefw := self.download_buffer(latest_url, rose_path)) != -1,
                'Could not download Rose firmware',
            )
            self.fwcomps['RoseFW'] = latest_rosefw
        except KeyError:
            self.logger.info('Rose firmware does not exist for this device, skipping')

    def load_latest_se(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        try:
            se_path = build_identity.get_component_path('SE,UpdatePayload')
            self.logger.info('Downloading SE firmware')
            retassure(
                (latest_sefw := self.download_buffer(latest_url, se_path)) != -1,
                'Could not download SE firmware',
            )
            self.fwcomps['SEFW'] = latest_sefw
        except KeyError:
            self.logger.info('Rose firmware does not exist for this device, skipping')

    def load_latest_savages(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        try:
            savageB0ProdPath = build_identity.get_component_path('Savage,B0-Prod-Patch')
            savageB0DevPath = build_identity.get_component_path('Savage,B0-Dev-Patch')
            savageB2ProdPath = build_identity.get_component_path('Savage,B2-Prod-Patch')
            savageB2DevPath = build_identity.get_component_path('Savage,B2-Dev-Patch')
            savageBAProdPath = build_identity.get_component_path('Savage,BA-Prod-Patch')
            savageBADevPath = build_identity.get_component_path('Savage,BA-Dev-Patch')
            self.logger.info('Downloading Savage,B0-Prod-Patch')
            retassure(
                (fw1 := self.download_buffer(latest_url, savageB0ProdPath)) != -1,
                'Could not download Savage,B0-Prod-Patch',
            )
            self.fwcomps['SavageFW']['Savage,B0-Prod-Patch'] = fw1
            self.logger.info('Downloading Savage,B0-Dev-Patch')
            retassure(
                (fw2 := self.download_buffer(latest_url, savageB0DevPath)) != -1,
                'Could not download Savage,B0-Dev-Patch',
            )
            self.fwcomps['SavageFW']['Savage,B0-Dev-Patch'] = fw2
            self.logger.info('Downloading Savage,B2-Prod-Patch')
            retassure(
                (fw3 := self.download_buffer(latest_url, savageB2ProdPath)) != -1,
                'Could not download Savage,B2-Prod-Patch',
            )
            self.fwcomps['SavageFW']['Savage,B2-Prod-Patch'] = fw3
            self.logger.info('Downloading Savage,B2-Dev-Patch')
            retassure(
                (fw4 := self.download_buffer(latest_url, savageB2DevPath)) != -1,
                'Could not download Savage,B2-Dev-Patch',
            )
            self.fwcomps['SavageFW']['Savage,B2-Dev-Patch'] = fw4
            self.logger.info('Downloading Savage,BA-Prod-Patch')
            retassure(
                (fw5 := self.download_buffer(latest_url, savageBAProdPath)) != -1,
                'Could not download Savage,BA-Prod-Patch',
            )
            self.fwcomps['SavageFW']['Savage,BA-Prod-Patch'] = fw5
            self.logger.info('Downloading Savage,BA-Dev-Patch')
            retassure(
                (fw6 := self.download_buffer(latest_url, savageBADevPath)) != -1,
                'Could not download Savage,BA-Dev-Patch',
            )
            self.fwcomps['SavageFW']['Savage,BA-Dev-Patch'] = fw6
        except KeyError:
            self.logger.info('Savage firmwares do not exist for this device, skipping')

    def load_latest_veridian(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        try:
            veridianDGM_path = build_identity.get_component_path('BMU,DigestMap')
            veridianFWM_path = build_identity.get_component_path('BMU,FirmwareMap')
            self.logger.info('Downloading Veridian DigestMap')
            retassure(
                (veridianDGM_fw := self.download_buffer(latest_url, veridianDGM_path))
                != -1,
                'Could not download Veridian DigestMap',
            )
            self.fwcomps['VeridianDGM'] = veridianDGM_fw
            self.logger.info('Downloading Veridian FirmwareMap')
            retassure(
                (veridianFWM_fw := self.download_buffer(latest_url, veridianFWM_path))
                != -1,
                'Could not download Veridian FirmwareMap',
            )
            self.fwcomps['VeridianFWM'] = veridianFWM_fw
        except KeyError:
            self.logger.info(
                'Veridian firmwares do not exist for this device, skipping'
            )

    def load_latest_sep(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        sep_path = build_identity.get_component_path('SEP')
        self.logger.info('Downloading SEP')
        retassure(
            (latest_sepfw := self.download_buffer(latest_url, sep_path)) != 1,
            'Could not download SEP firmware',
        )
        self.load_sep(latest_sepfw, latest_bm)
        self.logger.info('done loading latest SEP')

    def load_latest_baseband(self):
        latest_url, latest_bm = self.download_latest_bm()
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(
            self.device.hardware_model
        )
        bbfwpath = build_identity.get_component_path('BasebandFirmware')
        self.logger.info('Downloading Baseband')
        retassure(
            (latest_bbfw := self.download_buffer(latest_url, bbfwpath)) != 1,
            'Could not download Baseband firmware',
        )
        self.load_baseband(latest_bbfw, latest_bm)
        self.logger.info('done loading latest Baseband')

    def load_sep(self, data, bm):
        self.sepfw = data
        self.sepbm = bm

    def load_baseband(self, data, bm):
        self.bbfw = data
        self.bbbm = bm

    def set_bootargs(self, bootargs):
        self._bootargs = bootargs

    def load_ramdisk(self, path):
        retassure(os.path.isfile(path), f'Ramdisk not found at {path}')
        self.logger.warning('Custom RestoreRamdisk won\'t be verified')
        with open(path, 'rb') as f:
            self.ramdiskdata = f.read()

    def load_rkrn(self, path):
        retassure(os.path.isfile(path), f'RestoreKernelCache not found at {path}')
        self.logger.warning('Custom RestoreKernelCache won\'t be verified')
        with open(path, 'rb') as f:
            self.rkrndata = f.read()

    def enter_recovery(self):
        self.logger.info('Entering Recovery Mode')
        if self.init_mode in (
            Mode.RECOVERY_MODE_1,
            Mode.RECOVERY_MODE_2,
            Mode.RECOVERY_MODE_3,
            Mode.RECOVERY_MODE_4,
        ):
            self.logger.info('Device is already in Recovery Mode')
            return
        elif self.init_mode == Mode.NORMAL_MODE:
            retassure(
                self.lockdown_cli,
                'Lockdown client has not been created, cannot enter Recovery Mode from Normal Mode',
            )
            self.lockdown_cli.enter_recovery()
        elif self.init_mode == Mode.DFU_MODE:
            retassure(
                self.pwndfu,
                '--pwndfu was not specified but device is found in DFU Mode',
            )
            self.logger.info('--pwndfu specified, entering pwnRecovery later')
            return
        else:
            reterror('Device is in unsupported mode')
        self.logger.info('Waiting for device to enter Recovery Mode')
        self.reconnect_irecv(is_recovery=True)

    def exit_recovery(self):
        retassure(
            self.irecv
            or self.initMode
            in (
                Mode.RECOVERY_MODE_1,
                Mode.RECOVERY_MODE_2,
                Mode.RECOVERY_MODE_3,
                Mode.RECOVERY_MODE_4,
            ),
            "--exit-recovery was specified, but device is not in Recovery mode",
        )
        self.irecv.set_autoboot(True)
        self.irecv.reboot()

    def get_ap_nonce_from_im4m(self):
        if isinstance(self.im4m, pyimg4.IM4M):
            return self.im4m.apnonce.hex()

    def get_generator_from_shsh2(self):
        return self.tss['generator']

    def get_hex_ap_nonce(self):
        ap_nonce = binascii.hexlify(self.irecv.ap_nonce)
        return ap_nonce.decode()

    def enter_pwnrecovery(self, build_identity, bootargs=None):
        cache1 = False
        cache2 = False
        try:
            retassure(self.irecv, 'No IRecv client')
        except:
            reterror('No IRecv client')
        ibss_name = (
            PYFUTURERESTORE_TEMP_PATH
            + 'ibss.'
            + self.irecv.product_type
            + '.'
            + self.irecv.hardware_model
            + '.patched.img4'
        )
        ibec_name = (
            PYFUTURERESTORE_TEMP_PATH
            + 'ibec.'
            + self.irecv.product_type
            + '.'
            + self.irecv.hardware_model
            + '.patched.img4'
        )
        _ibss = None
        _ibec = None
        if not self.no_cache:
            try:
                with open(ibss_name, 'rb') as f:
                    _ibss = f.read()
                cache1 = True
            except:
                cache1 = False
            try:
                with open(ibec_name, 'rb') as f:
                    _ibec = f.read()
                cache2 = True
            except:
                cache2 = False

        if (not cache1) and (not cache2):
            ipc = IPatcher(self.verbose)
            self.logger.info(f'Getting firmware keys for {self.irecv.hardware_model}')
            retassure(
                (
                    ibss_keys := ipc.get_keys(
                        self.irecv.product_type,
                        self.ipsw.build_manifest.product_build_version,
                        'iBSS',
                    )
                )
                != -1,
                'Could not get iBSS keys',
            )
            retassure(
                (
                    ibec_keys := ipc.get_keys(
                        self.irecv.product_type,
                        self.ipsw.build_manifest.product_build_version,
                        'iBEC',
                    )
                )
                != -1,
                'Could not get iBEC keys',
            )
            self.logger.info('Patching iBSS')
            _ibss = build_identity.get_component('iBSS').data
            retassure(
                (_ibss := ipc.patch_iboot(_ibss, bootargs, kbag=ibss_keys)) != -1,
                'Failed to patch iBSS',
            )
            retassure(
                (_ibss := ipc.pack_into_img4(_ibss, self.im4m, 'ibss')) != -1,
                'Failed to repack iBSS',
            )
            with open(ibss_name, 'wb') as f:
                f.write(_ibss)
            self.logger.info('Patching iBEC')
            _ibec = build_identity.get_component('iBEC').data
            retassure(
                (_ibec := ipc.patch_iboot(_ibec, bootargs, kbag=ibec_keys)) != -1,
                'Failed to patch iBEC',
            )
            retassure(
                (_ibec := ipc.pack_into_img4(_ibec, self.im4m, 'ibec')) != -1,
                'Failed to repack iBEC',
            )
            with open(ibec_name, 'wb') as f:
                f.write(_ibec)
        dfu = False
        if not self.noibss:
            self.logger.info('Sending iBSS')
            self.irecv.send_buffer(_ibss)
            self.logger.info('waitng for reconnect')
            self.reconnect_irecv()
        if (0x7000 <= self.irecv.chip_id <= 0x8004) or (
            0x8900 <= self.irecv.chip_id <= 0x8965
        ):
            retassure(
                self.device.irecv.mode == Mode.DFU_MODE,
                'Unable to connect to device in DFU mode',
            )
            if self.ipsw.build_manifest.build_major > 8:
                self.irecv.set_configuration(1)
                self.logger.info('Sending iBEC')
                self.irecv.send_buffer(_ibec)
                self.logger.info('waiting for reconnect in Recovery mode')
                self.reconnect_irecv(is_recovery=True)
        elif (0x8006 <= self.irecv.chip_id <= 0x8030) or (
            0x8101 <= self.irecv.chip_id <= 0x8301
        ):
            dfu = True
            self.reconnect_irecv(is_recovery=True)
        else:
            reterror('Device not supported!')
        if self.irecv.is_image4_supported:
            if self.irecv.chip_id < 0x8015:
                self.irecv.send_command('bgcolor 255 0 0')
                sleep(2)
            self.logger.info('Sending iBEC')
            self.irecv.send_buffer(_ibec)
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
        self.logger.info(f'ApNonce pre-hax:\n {self.get_hex_ap_nonce()}')
        generator = (
            self.custom_gen if self.custom_gen else self.get_generator_from_shsh2()
        )
        self.logger.info(f'generator={generator}')
        if (not self.custom_gen) and self.setnonce:
            if not self.setnonce:
                self.logger.info(
                    'ApNonce from device doesn\'t match IM4M nonce, applying hax'
                )
            self.logger.info(f'generator={generator}, writing to nvram')
            self.irecv.send_command(
                f'setenv com.apple.System.boot-nonce {generator}', b_request=0
            )
            self.irecv.send_command('saveenv', b_request=0)
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
            self.irecv.reset()
            self.irecv.set_configuration(1)
            self.logger.info('Sending iBEC')
            self.irecv.send_buffer(_ibec)
            try:
                self.irecv.send_command('go')
            except:
                pass
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
            self.logger.info(f'ApNonce post-hax:\n {self.get_hex_ap_nonce()}')
            self.irecv.send_command('bgcolor 255 255 0')
            retassure(
                self.get_hex_ap_nonce() == self.get_ap_nonce_from_im4m()
                or self.ignore_nonce_matching
                or self.setnonce,
                'ApNonce from device doesn\'t match IM4M nonce after applying ApNonce hax. Aborting!',
            )
            if self.ignore_nonce_matching:
                self.logger.warning('IGNORING SETTING NONCE FAILURE! RESTORE MAY FAIL!')
        else:
            sleep(2)
            self.irecv.reset()
            self.irecv.set_configuration(1)
            self.logger.info('Sending iBEC')
            self.irecv.send_buffer(_ibec)
            try:
                self.irecv.send_command('go')
            except USBError:
                pass
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
            self.irecv.send_command('bgcolor 255 255 0')
            self.logger.info(
                'APNonce from device already matches IM4M nonce, no need for extra hax...'
            )
            sleep(2)
        self.irecv._device.set_interface_altsetting(0, 0)
        self.irecv.send_command(
            f'setenv com.apple.System.boot-nonce {generator}', b_request=0
        )
        self.irecv.send_command('saveenv', b_request=0)
        self.irecv.reset()

        if self.setnonce:
            self.logger.info('Done setting nonce!')
            self.logger.info(
                'Use pyfuturerestore --exit-recovery to go back to normal mode if you aren\'t restoring.'
            )
            self.irecv.set_autoboot(False)
            self.irecv.reboot()
            sys.exit(0)
        sleep(2)

    def do_restore(self):
        retassure(self.sepfw, 'SEP was not loaded')
        retassure(self.sepbm, 'SEP BuildManifest was not loaded')
        restore = Restore(
            self.zipipsw, self.device, tss=self.tss, behavior=Behavior.Erase
        )
        self.enter_recovery()
        self.logger.info('Checking if the APTicket is valid for this restore')
        if not self.skip_blob:
            retassure(
                self.irecv.ecid == self.im4m.ecid,
                'Device\'s ECID does not match APTicket\'s ECID',
            )
            self.logger.info('Verified ECID in APTicket matches the device\'s ECID')
        else:
            self.logger.warning('NOT VALIDATING SHSH BLOBS ECID!')
        if self.pwndfu:
            if self._bootargs:
                bootargs = self._bootargs
            else:
                bootargs = ''
                if self.serial:
                    bootargs += 'serial=0x3 '
                bootargs += 'rd=md0 '
                # Currently pyfuturerestore does not support update install
                bootargs += '-v -restore debug=0x2014e keepsyms=0x1 amfi=0xff amfi_allow_any_signature=0x1 amfi_get_out_of_my_way=0x1 cs_enforcement_disable=0x1'
            self.enter_pwnrecovery(restore.build_identity, bootargs=bootargs)
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
        # reinit restore
        self.reconnect_irecv()
        restore = Restore(
            self.zipipsw,
            self.device,
            tss=self.tss,
            sepfw=self.sepfw,
            sepbm=self.sepbm,
            bbfw=self.bbfw,
            bbbm=self.bbbm,
            rdskdata=self.ramdiskdata,
            rkrndata=self.rkrndata,
            fwcomps=self.fwcomps,
            behavior=Behavior.Erase,
        )
        restore.recovery.device = Device(irecv=self.irecv)
        self.logger.info('Getting SEP ticket')
        restore.recovery.sep_build_identity = restore.sep_build_identity
        restore.septss = restore.recovery.get_tss_response(sep=True)
        self.logger.info('Starting restore')
        restore.update()
