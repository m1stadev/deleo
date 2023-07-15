import binascii
from usb import USBError
import pyimg4
from pymobiledevice3.restore.restore import Restore
from pyipatcher.logger import get_my_logger
from pyipatcher.ipatcher import IPatcher
import logging
from pathlib import Path
import requests
import typing
from zipfile import ZipFile
from pymobiledevice3.exceptions import IncorrectModeError
import sys
import plistlib
from time import sleep
from ipsw_parser.exceptions import NoSuchBuildIdentityError
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from remotezip import RemoteZip
from io import BytesIO
import zipfile
from usb.core import find
from usb.backend.libusb1 import get_backend

from typing import Mapping, Optional
from m1n1Exception import retassure, reterror
from pymobiledevice3.irecv import IRecv, Mode
from ipsw_parser.ipsw import IPSW
from ipsw_parser.build_manifest import BuildManifest
from pymobiledevice3.restore.recovery import Recovery

from pymobiledevice3.exceptions import ConnectionFailedError, NoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.restore.asr import ASRClient
from pymobiledevice3.restore.base_restore import RESTORE_VARIANT_ERASE_INSTALL, RESTORE_VARIANT_MACOS_RECOVERY_OS, \
    RESTORE_VARIANT_UPGRADE_INSTALL, BaseRestore
from pymobiledevice3.restore.consts import PROGRESS_BAR_OPERATIONS, lpol_file
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.fdr import FDRClient, fdr_type, start_fdr_thread
from pymobiledevice3.restore.ftab import Ftab
from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.restore_options import RestoreOptions
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from pymobiledevice3.service_connection import ServiceConnection
from pymobiledevice3.utils import plist_access_path
import os

# ------------- subclasses, overwritings -------------

def load_custom_manifest(self, custom_manifest):
    self._build_manifest = BuildManifest(self, custom_manifest)

IPSW.load_custom_manifest = load_custom_manifest
def BaseRestore__init__(self, ipsw: ZipFile, device: Device, tss: typing.Mapping = None, sepfw=None, sepbm=None, bbfw=None, bbbm=None,
             behavior: Behavior = Behavior.Update, logger=None):
    self.logger = logging.getLogger(self.__class__.__name__) if logger is None else logger
    self.ipsw = IPSW(ipsw)
    self.device = device
    self.tss = TSSResponse(tss) if tss is not None else None
    self.sepfw = sepfw
    self.bbfw = bbfw

    if not self.device.is_image4_supported:
        raise NotImplementedError('is_image4_supported is False')

    self.logger.info(f'connected device: <ecid: {self.device.ecid} hardware_model: {self.device.hardware_model} '
                     f'image4-support: {self.device.is_image4_supported}>')

    self.logger.debug('scanning BuildManifest.plist for the correct BuildIdentity')

    variant = {
        Behavior.Update: RESTORE_VARIANT_UPGRADE_INSTALL,
        Behavior.Erase: RESTORE_VARIANT_ERASE_INSTALL,
    }[behavior]

    if sepbm:
        self.ipsw.load_custom_manifest(sepbm)
        self.sep_build_identity = self.ipsw._build_manifest.get_build_identity(self.device.hardware_model,
                                                                               restore_behavior=behavior.value,
                                                                               variant=variant)
    if bbbm:
        self.ipsw.load_custom_manifest(bbbm)
        self.baseband_build_identity = self.ipsw._build_manifest.get_build_identity(self.device.hardware_model,
                                                                                    restore_behavior=behavior.value,
                                                                                    variant=variant)
    try:
        self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model,
                                                                          restore_behavior=behavior.value,
                                                                          variant=variant)
    except NoSuchBuildIdentityError:
        if behavior == Behavior.Update:
            self.build_identity = self.ipsw.build_manifest.get_build_identity(self.device.hardware_model,
                                                                              restore_behavior=behavior.value)
        else:
            raise

    self.macos_variant = None
    try:
        self.macos_variant = self.ipsw.build_manifest.get_build_identity(
            self.device.hardware_model,
            variant=RESTORE_VARIANT_MACOS_RECOVERY_OS)
        self.logger.info('Performing macOS restore')
    except NoSuchBuildIdentityError:
        pass

    build_info = self.build_identity.get('Info')
    if build_info is None:
        raise PyMobileDevice3Exception('build identity does not contain an "Info" element')

    device_class = build_info.get('DeviceClass')
    if device_class is None:
        raise PyMobileDevice3Exception('build identity does not contain an "DeviceClass" element')

BaseRestore.__init__ = BaseRestore__init__

def Recovery__init__(self, ipsw: BytesIO, device: Device, tss: typing.Mapping = None, sepfw=None, sepbm=None, bbfw=None, bbbm=None, rdskdata=None, rkrndata=None, behavior: Behavior = Behavior.Update):
    BaseRestore.__init__(self, ipsw, device, tss, sepfw=sepfw, sepbm=sepbm, bbfw=bbfw, bbbm=bbbm, behavior=behavior,
                     logger=logging.getLogger(__name__))
    self.tss_localpolicy = None
    self.tss_recoveryos_root_ticket = None
    self.restore_boot_args = None
    self.rdskdata = rdskdata
    self.rkrndata = rkrndata

def get_tss_response(self):
    # populate parameters
    parameters = dict()

    parameters['ApECID'] = self.device.ecid
    if self.device.ap_nonce is not None:
        parameters['ApNonce'] = self.device.ap_nonce

    if self.device.sep_nonce is not None:
        parameters['ApSepNonce'] = self.device.sep_nonce

    parameters['ApProductionMode'] = True

    if self.device.is_image4_supported:
        parameters['ApSecurityMode'] = True
        parameters['ApSupportsImg4'] = True
    else:
        parameters['ApSupportsImg4'] = False

    if self.sepfw:
        self.sep_build_identity.populate_tss_request_parameters(parameters)
    else:
        self.build_identity.populate_tss_request_parameters(parameters)

    tss = TSSRequest()
    tss.add_common_tags(parameters)
    tss.add_ap_tags(parameters)

    # add personalized parameters
    if self.device.is_image4_supported:
        tss.add_ap_img4_tags(parameters)
    else:
        tss.add_ap_img3_tags(parameters)

    # normal mode; request baseband ticket as well
    if self.device.lockdown is not None:
        pinfo = self.device.preflight_info
        if pinfo:
            self.logger.debug('adding preflight info')

            node = pinfo.get('Nonce')
            if node is not None:
                parameters['BbNonce'] = node

            node = pinfo.get('ChipID')
            if node is not None:
                parameters['BbChipID'] = node

            node = pinfo.get('CertID')
            if node is not None:
                parameters['BbGoldCertId'] = node

            node = pinfo.get('ChipSerialNo')
            if node is not None:
                parameters['BbSNUM'] = node

            tss.add_baseband_tags(parameters)

            euiccchipid = pinfo.get('EUICCChipID')
            if euiccchipid:
                self.logger.debug('adding EUICCChipID info')
                parameters['eUICC,ChipID'] = euiccchipid

                if euiccchipid >= 5:
                    node = pinfo.get('EUICCCSN')
                    if node is not None:
                        parameters['eUICC,EID'] = node

                    node = pinfo.get('EUICCCertIdentifier')
                    if node is not None:
                        parameters['eUICC,RootKeyIdentifier'] = node

                    node = pinfo.get('EUICCGoldNonce')
                    if node is not None:
                        parameters['EUICCGoldNonce'] = node

                    node = pinfo.get('EUICCMainNonce')
                    if node is not None:
                        parameters['EUICCMainNonce'] = node

                    tss.add_vinyl_tags(parameters)

    # send request and grab response
    return tss.send_receive()

def send_ramdisk(self):
    component = 'RestoreRamDisk'
    ramdisk_size = self.device.irecv.getenv('ramdisk-size')
    self.logger.info(f'ramdisk-size: {ramdisk_size}')
    if self.rdskdata:
        self.device.irecv.send_buffer(self.rdskdata)
    else:
        self.send_component(component)
    ramdisk_delay = self.device.irecv.getenv('ramdisk-delay')
    self.logger.info(f'ramdisk-delay: {ramdisk_delay}')

    sleep(2)
    self.device.irecv.reset()
    self.device.irecv.send_command('ramdisk')

    sleep(2)

def send_kernelcache(self):
    component = 'RestoreKernelCache'
    if self.rkrndata:
        self.device.irecv.send_buffer(self.rkrndata)
    else:
        self.send_component(component)
    try:
        self.device.irecv.ctrl_transfer(0x21, 1)
    except USBError:
        pass

    if self.restore_boot_args:
        self.device.irecv.send_command(f'setenv boot-args {self.restore_boot_args}')

    try:
        self.device.irecv.send_command('bootx', b_request=1)
    except USBError:
        pass

def send_component(self, name: str):
    # Use a specific TSS ticket for the Ap,LocalPolicy component
    data = None
    tss = self.tss
    if name == 'Ap,LocalPolicy':
        tss = self.tss_localpolicy
        # If Ap,LocalPolicy => Inject an empty policy
        data = lpol_file
    if (name in ('RestoreSEP', 'SEP')) and self.sepfw:
        data = self.sep_build_identity.get_component(name, tss=tss, data=self.sepfw).personalized_data
    else:
        data = self.build_identity.get_component(name, tss=tss, data=data).personalized_data
    self.logger.info(f'Sending {name} ({len(data)} bytes)...')
    self.device.irecv.send_buffer(data)

Recovery.__init__ = Recovery__init__
Recovery.get_tss_response = get_tss_response
Recovery.send_ramdisk = send_ramdisk
Recovery.send_kernelcache = send_kernelcache
Recovery.send_component = send_component


def Restore__init__(self, ipsw: zipfile.ZipFile, device: Device, tss=None, sepfw=None, sepbm=None, bbfw=None, bbbm=None, rdskdata=None, rkrndata=None, behavior: Behavior = Behavior.Update,
             ignore_fdr=False):
    BaseRestore.__init__(self, ipsw, device, tss, sepfw=sepfw, bbfw=bbfw, sepbm=sepbm, bbbm=bbbm, behavior=behavior, logger=logging.getLogger(__name__))
    self.recovery = Recovery(ipsw, device, tss=tss, rdskdata=rdskdata, rkrndata=rkrndata, behavior=behavior)
    self.bbtss: Optional[TSSResponse] = None
    self._restored: Optional[RestoredClient] = None
    self._restore_finished = False

    # used when ignore_fdr=True, to store an active FDR connection just to make the device believe it can actually
    # perform an FDR communication, but without really establishing any
    self._fdr: Optional[ServiceConnection] = None
    self._ignore_fdr = ignore_fdr

    # query preflight info while device may still be in normal mode
    self._preflight_info = self.device.preflight_info

    # prepare progress bar for OS component verify
    self._pb_verify_restore = None
    self._pb_verify_restore_old_value = None

    self._handlers = {
        # data request messages are sent by restored whenever it requires
        # files sent to the server by the client. these data requests include
        # SystemImageData, RootTicket, KernelCache, NORData and BasebandData requests
        'DataRequestMsg': self.handle_data_request_msg,

        # restore logs are available if a previous restore failed
        'PreviousRestoreLogMsg': self.handle_previous_restore_log_msg,

        # progress notification messages sent by the restored inform the client
        # of it's current operation and sometimes percent of progress is complete
        'ProgressMsg': self.handle_progress_msg,

        # status messages usually indicate the current state of the restored
        # process or often to signal an error has been encountered
        'StatusMsg': self.handle_status_msg,

        # checkpoint notifications
        'CheckpointMsg': self.handle_checkpoint_msg,

        # baseband update message
        'BBUpdateStatusMsg': self.handle_bb_update_status_msg,

        # baseband updater output data request
        'BasebandUpdaterOutputData': self.handle_baseband_updater_output_data,
    }

    self._data_request_handlers = {
        # this request is sent when restored is ready to receive the filesystem
        'SystemImageData': self.send_filesystem,

        'BuildIdentityDict': self.send_buildidentity,
        'PersonalizedBootObjectV3': self.send_personalized_boot_object_v3,
        'SourceBootObjectV4': self.send_source_boot_object_v4,
        'RecoveryOSLocalPolicy': self.send_restore_local_policy,

        # this request is sent when restored is ready to receive the filesystem
        'RecoveryOSASRImage': self.send_filesystem,

        # Send RecoveryOS RTD
        'RecoveryOSRootTicketData': self.send_recovery_os_root_ticket,

        # send RootTicket (== APTicket from the TSS request)
        'RootTicket': self.send_root_ticket,

        'NORData': self.send_nor,
        'BasebandData': self.send_baseband_data,
        'FDRTrustData': self.send_fdr_trust_data,
        'FirmwareUpdaterData': self.send_firmware_updater_data,

        # TODO: verify
        'FirmwareUpdaterPreflight': self.send_firmware_updater_preflight,
    }

    self._data_request_components = {
        'KernelCache': self.send_component,
        'DeviceTree': self.send_component,
    }


def send_baseband_data(self, message: typing.Mapping):
    self.logger.info(f'About to send BasebandData: {message}')

    # NOTE: this function is called 2 or 3 times!

    # setup request data
    arguments = message['Arguments']
    bb_chip_id = arguments.get('ChipID')
    bb_cert_id = arguments.get('CertID')
    bb_snum = arguments.get('ChipSerialNo')
    bb_nonce = arguments.get('Nonce')
    bbtss = self.bbtss

    if (bb_nonce is None) or (self.bbtss is None):
        # populate parameters
        parameters = {'ApECID': self.device.ecid}
        if bb_nonce:
            parameters['BbNonce'] = bb_nonce
        parameters['BbChipID'] = bb_chip_id
        parameters['BbGoldCertId'] = bb_cert_id
        parameters['BbSNUM'] = bb_snum

        if self.bbfw:
            self.baseband_build_identity.populate_tss_request_parameters(parameters)
        else:
            self.build_identity.populate_tss_request_parameters(parameters)

        # create baseband request
        request = TSSRequest()

        # add baseband parameters
        request.add_common_tags(parameters)
        request.add_baseband_tags(parameters)

        if self.bbfw:
            fdr_support = self.baseband_build_identity['Info'].get('FDRSupport', False)
        else:
            fdr_support = self.build_identity['Info'].get('FDRSupport', False)
        if fdr_support:
            request.update({'ApProductionMode': True, 'ApSecurityMode': True})

        self.logger.info('Sending Baseband TSS request...')
        bbtss = request.send_receive()

        if bb_nonce:
            # keep the response for later requests
            self.bbtss = bbtss

    # get baseband firmware file path from build identity
    bbfwpath = self.build_identity['Manifest']['BasebandFirmware']['Info']['Path']

    # extract baseband firmware to temp file
    if self.bbfw:
        bbfw = self.bbfw
    else:
        bbfw = self.ipsw.read(bbfwpath)

    buffer = self.sign_bbfw(bbfw, bbtss, bb_nonce)

    self.logger.info('Sending BasebandData now...')
    self._restored.send({'BasebandData': buffer})

Restore.__init__ = Restore__init__
Restore.send_baseband_data = send_baseband_data

Mode.NORMAL_MODE = 0x12a8

# ---------------------------------

PYFUTURERESTORE_TEMP_PATH = '/tmp/pyfuturerestore/'
def strmode(mode: Mode):
    if mode in (Mode.RECOVERY_MODE_1, Mode.RECOVERY_MODE_2, Mode.RECOVERY_MODE_3, Mode.RECOVERY_MODE_4):
        return 'Recovery'
    elif mode == Mode.DFU_MODE:
        return 'DFU'
    elif mode ==  Mode.NORMAL_MODE:
        return 'Normal'
    elif mode == Mode.WTF_MODE:
        return 'WTF'
    else:
        return None

# thx m1sta
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
        return -1

    return str(libusb1)

class PyFuturerestore:
    def __init__(self, ipsw: ZipFile, logger, setnonce=False, serial=False, custom_gen=None, ignore_nonce_matching=False, noibss=False, skip_blob=False, pwndfu=False, no_cache=False, custom_usb_backend=None, verbose=False):
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
        self.sepfw = None
        self.sepbm = None
        self.bbfw = None
        self.bbbm = None
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
                    if device.idVendor == 0x05ac:
                        mode = Mode.get_mode_from_value(device.idProduct)
                        if mode is None:    continue
                        return mode
                except ValueError:
                    pass
        except Exception as e:
            if 'No backend available' in str(e):
                if self.usb_backend:
                    backend = self.usb_backend
                else:
                    retassure((backend := _get_backend()) != -1, 'Could not find backend for libusb')
                self.logger.debug(f'USB backend: {backend}')
                for device in find(find_all=True, backend=get_backend(find_library=lambda _: backend)):
                    try:
                        if device.idVendor is None:
                            continue
                        if device.idVendor == 0x05ac:
                            mode = Mode.get_mode_from_value(device.idProduct)
                            if mode is None:    continue
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
                if True: # no idea
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
            r = requests.get(f'http://api.ipsw.me/v2.1/{self.device.irecv.product_type}/latest/url')
            return r.content
        except:
            return -1

    def load_ap_ticket(self, path):
        retassure(os.path.isfile(path), f'APTicket not found at {path}')
        with open(path, 'rb') as f:
            self.tss = plistlib.load(f)
        self.im4m = pyimg4.IM4M(self.tss['ApImg4Ticket'])
        self.logger.info(f'Done reading signing ticket {path}')

    def load_latest_sep(self):
        self.logger.info(f'Getting latest firmware URL for {self.device.irecv.product_type}')
        retassure((latest_url := self.get_latest_fwurl()) != -1, 'Could not get latest firmware URL')
        self.logger.debug(f'Latest firmware URL: {latest_url}')
        retassure((latest_bm := self.download_buffer(latest_url, 'BuildManifest.plist')) != -1,
                  'Could not download latest BuildManifest.plist')
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(self.device.hardware_model)
        sep_path = build_identity.get_component_path('SEP')
        self.logger.info('Downloading SEP')
        retassure((latest_sepfw := self.download_buffer(latest_url, sep_path)) != 1, 'Could not download SEP firmware')
        self.load_sep(latest_sepfw, latest_bm)
        self.logger.info('done loading latest SEP')

    def load_latest_baseband(self):
        self.logger.info(f'Getting latest firmware URL for {self.device.irecv.product_type}')
        retassure((latest_url := self.get_latest_fwurl()) != -1, 'Could not get latest firmware URL')
        self.logger.debug(f'Latest firmware URL: {latest_url}')
        retassure((latest_bm := self.download_buffer(latest_url, 'BuildManifest.plist')) != -1, 'Could not download latest BuildManifest.plist')
        self.ipsw.load_custom_manifest(latest_bm)
        build_identity = self.ipsw._build_manifest.get_build_identity(self.device.hardware_model)
        bbfwpath = build_identity.get_component_path('BasebandFirmware')
        self.logger.info('Downloading Baseband')
        retassure((latest_bbfw := self.download_buffer(latest_url, bbfwpath)) != 1, 'Could not download Baseband firmware')
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
        if self.init_mode in (Mode.RECOVERY_MODE_1, Mode.RECOVERY_MODE_2, Mode.RECOVERY_MODE_3, Mode.RECOVERY_MODE_4):
            self.logger.info('Device is already in Recovery Mode')
            return
        elif self.init_mode == Mode.NORMAL_MODE:
            retassure(self.lockdown_cli, 'Lockdown client has not been created, cannot enter Recovery Mode from Normal Mode')
            self.lockdown_cli.enter_recovery()
        elif self.init_mode == Mode.DFU_MODE:
            retassure(self.pwndfu, '--pwndfu was not specified but device is found in DFU Mode')
            self.logger.info('--pwndfu specified, entering pwnRecovery later')
            return
        else:
            reterror('Device is in unsupported mode')
        self.logger.info('Waiting for device to enter Recovery Mode')
        self.init()
        self.logger.info('reinit done')
        self.logger.info('done entering Recovery Mode')

    def exit_recovery(self):
        retassure(self.irecv or self.initMode in (
        Mode.RECOVERY_MODE_1, Mode.RECOVERY_MODE_2, Mode.RECOVERY_MODE_3, Mode.RECOVERY_MODE_4),
                  "--exit-recovery was specified, but device is not in Recovery mode")
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
        ibss_name = PYFUTURERESTORE_TEMP_PATH + 'ibss.' + self.irecv.product_type + self.irecv.hardware_model + 'patched.img4'
        ibec_name = PYFUTURERESTORE_TEMP_PATH + 'ibec.' + self.irecv.product_type + self.irecv.hardware_model + 'patched.img4'
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
            retassure((ibss_keys := ipc.get_keys(self.irecv.product_type, self.ipsw.build_manifest.product_build_version, 'iBSS')) != -1,  'Could not get iBSS keys')
            retassure((ibec_keys := ipc.get_keys(self.irecv.product_type, self.ipsw.build_manifest.product_build_version, 'iBEC')) != -1, 'Could not get iBEC keys')
            self.logger.info('Patching iBSS')
            _ibss = build_identity.get_component('iBSS').data
            retassure((_ibss := ipc.patch_iboot(_ibss, bootargs, kbag=ibss_keys)) != -1, 'Failed to patch iBSS')
            retassure((_ibss := ipc.pack_into_img4(_ibss, self.im4m, 'ibss')) != -1, 'Failed to repack iBSS')
            with open(ibss_name, 'wb') as f:
                f.write(_ibss)
            self.logger.info('Patching iBEC')
            _ibec = build_identity.get_component('iBEC').data
            retassure((_ibec := ipc.patch_iboot(_ibec, bootargs, kbag=ibec_keys)) != -1, 'Failed to patch iBEC')
            retassure((_ibec := ipc.pack_into_img4(_ibec, self.im4m, 'ibec')) != -1, 'Failed to repack iBEC')
            with open(ibec_name, 'wb') as f:
                f.write(_ibec)
        dfu = False
        if not self.noibss:
            self.logger.info('Sending iBSS')
            self.irecv.send_buffer(_ibss)
            self.logger.info('waitng for reconnect')
            self.reconnect_irecv()
        if (0x7000 <= self.irecv.chip_id <= 0x8004) or (0x8900 <= self.irecv.chip_id <= 0x8965):
            retassure(self.device.irecv.mode == Mode.DFU_MODE, 'Unable to connect to device in DFU mode')
            if self.ipsw.build_manifest.build_major > 8:
                self.irecv.set_configuration(1)
                self.logger.info('Sending iBEC')
                self.irecv.send_buffer(_ibec)
                self.logger.info('waiting for reconnect in Recovery mode')
                self.reconnect_irecv(is_recovery=True)
        elif (0x8006 <= self.irecv.chip_id <= 0x8030) or (0x8101 <= self.irecv.chip_id <= 0x8301):
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
        generator = self.custom_gen if self.custom_gen is not None else self.get_generator_from_shsh2()
        if self.custom_gen is not None:
            if (not self.custom_gen) and self.setnonce:
                self.logger.info('ApNonce from device doesn\'t match IM4M nonce, applying hax')
            self.logger.info(f'generator={generator}, writing to nvram')
            self.irecv.send_command(f'setenv com.apple.System.boot-nonce {generator}')
            self.irecv.send_command('saveenv')
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
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
            retassure(self.get_hex_ap_nonce() == self.get_ap_nonce_from_im4m() or self.ignore_nonce_matching or self.setnonce, 'ApNonce from device doesn\'t match IM4M nonce after applying ApNonce hax. Aborting!')
            if self.ignore_nonce_matching:
                self.logger.warning('IGNORING SETTING NONCE FAILURE! RESTORE MAY FAIL!')
        else:
            self.irecv.set_configuration(1)
            self.logger.info('Sending iBEC')
            self.irecv.send_buffer(_ibec)
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
            self.irecv.send_buffer('bgcolor 255 255 0')
            self.logger.info('APNonce from device already matches IM4M nonce, no need for extra hax...')
        self.irecv.send_command(f'setenv com.apple.System.boot-nonce {generator}')
        self.irecv.send_command('saveenv')
        if self.setnonce:
            self.logger.info('Done setting nonce!')
            self.logger.info('Use futurerestore --exit-recovery to go back to normal mode if you aren\'t restoring.')
            self.irecv.set_autoboot(False)
            self.irecv.reboot()
            sys.exit(0)
        sleep(2)

    def do_restore(self):
        retassure(self.sepfw, 'SEP was not loaded')
        retassure(self.sepbm, 'SEP BuildManifest was not loaded')
        restore = Restore(self.zipipsw, self.device, tss=self.tss, sepfw=self.sepfw, sepbm=self.sepbm, bbfw=self.bbfw, bbbm=self.bbbm, rdskdata=self.ramdiskdata, rkrndata=self.rkrndata, behavior=Behavior.Erase)
        self.enter_recovery()
        self.logger.info('Checking if the APTicket is valid for this restore')
        if not self.skip_blob:
            retassure(self.irecv.ecid == self.im4m.ecid, 'Device\'s ECID does not match APTicket\'s ECID')
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
            self.enter_pwnrecovery(restore.build_identity ,bootargs=bootargs)
            self.logger.info('waiting for reconnect in Recovery mode')
            self.reconnect_irecv(is_recovery=True)
        self.logger.info('About to restore device')
        self.logger.info('Booting ramdisk')
        restore.recovery.boot_ramdisk()
        self.logger.info('Starting restore')
        restore.restore_device()

