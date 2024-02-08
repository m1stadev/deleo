import logging
import time
from typing import Mapping, Optional
from zipfile import ZipFile

from eyepatch.iboot import iBoot64Patcher
from ipsw_parser.build_manifest import BuildManifest
from ipsw_parser.component import Component
from ipsw_parser.ipsw import IPSW
from lykos import Client
from pyimg4 import IM4P, Keybag
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore import recovery
from pymobiledevice3.restore.base_restore import BaseRestore, Behavior
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import (
    RESTORE_VARIANT_ERASE_INSTALL,
    RESTORE_VARIANT_UPGRADE_INSTALL,
)
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from usb import USBError

RESTORE_VARIANT_OTA_UPGRADE = 'Customer Software Update'


class Recovery(recovery.Recovery):
    def __init__(
        self,
        ipsw: ZipFile,
        latest_ipsw: ZipFile,
        device: Device,
        shsh: Mapping,
        behavior: Behavior,
        tss: Optional[Mapping] = None,
        ota_manifest: Optional[bytes] = None,
    ):
        BaseRestore.__init__(
            self, ipsw, device, tss, behavior, logger=logging.getLogger(__name__)
        )
        self.tss_localpolicy = None
        self.tss_recoveryos_root_ticket = None
        self.restore_boot_args = None
        self.latest_ipsw = IPSW(latest_ipsw)
        self.shsh = TSSResponse(shsh)

        self.logger.debug(
            'scanning 2nd BuildManifest.plist for the correct BuildIdentity'
        )

        if ota_manifest:
            ota_manifest = BuildManifest(self.latest_ipsw, ota_manifest)
            self.latest_build_identity = ota_manifest.get_build_identity(
                self.device.hardware_model,
                restore_behavior=Behavior.Update.value,
                variant=RESTORE_VARIANT_OTA_UPGRADE,
            )

        else:
            variant = {
                Behavior.Update: RESTORE_VARIANT_UPGRADE_INSTALL,
                Behavior.Erase: RESTORE_VARIANT_ERASE_INSTALL,
            }[behavior]

            self.latest_build_identity = (
                self.latest_ipsw.build_manifest.get_build_identity(
                    self.device.hardware_model,
                    restore_behavior=behavior.value,
                    variant=variant,
                )
            )

        build_info = self.latest_build_identity.get('Info')
        if build_info is None:
            raise PyMobileDevice3Exception(
                'build identity does not contain an "Info" element'
            )

        device_class = build_info.get('DeviceClass')
        if device_class is None:
            raise PyMobileDevice3Exception(
                'build identity does not contain an "DeviceClass" element'
            )

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

        self.latest_build_identity.populate_tss_request_parameters(parameters)

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

    def send_component(self, name: str):
        if name == 'RestoreSEP':
            component = self.latest_build_identity.get_component(name, tss=self.tss)
        else:
            component = self.build_identity.get_component(name, tss=self.shsh)

        self.send_component_data(component)

    def send_component_data(self, component: Component):
        self.logger.info(
            f'Sending {component.name} ({len(component.personalized_data)} bytes)...'
        )
        self.device.irecv.send_buffer(component.personalized_data)

    def pwndfu_enter_pwnrecovery(self):
        if 'PWND' not in self.device.irecv._device_info.keys():
            self.logger.debug('device not in pwndfu')
            return

        # fetch decryption keys
        client = Client()
        key_data = client.get_key_data(
            device=self.device.irecv.product_type,
            buildid=self.ipsw.build_manifest.product_build_version,
            codename=self.build_identity['Info']['BuildTrain'],
        )
        self.logger.debug(key_data)

        # decrypt iBSS
        comp = self.build_identity.get_component('iBSS', tss=self.shsh)
        im4p = IM4P(comp.data)
        dec_key = next(key for key in key_data if key.name == 'ibss')
        im4p.payload.decrypt(Keybag(iv=dec_key.iv, key=dec_key.key))
        dec_data = im4p.payload.output().data

        # patch iBSS
        patcher = iBoot64Patcher(dec_data)
        patcher.patch_sigchecks()
        im4p.payload._data = patcher.data
        comp._data = im4p.output()

        # send iBSS
        self.send_component_data(comp)

        self.reconnect_irecv()

        if 'SRTG' in self.device.irecv._device_info:
            raise PyMobileDevice3Exception('Device failed to enter recovery')

        if self.build_identity.build_manifest.build_major > 8:
            # reconnect
            self.reconnect_irecv()

            self.device.irecv.set_configuration(1)

            # decrypt iBEC
            comp = self.build_identity.get_component('iBEC', tss=self.shsh)
            im4p = IM4P(comp.data)
            dec_key = next(key for key in key_data if key.name == 'ibec')
            im4p.payload.decrypt(Keybag(iv=dec_key.iv, key=dec_key.key))
            dec_data = im4p.payload.output().data

            # patch iBEC
            patcher = iBoot64Patcher(dec_data)
            patcher.patch_sigchecks()
            patcher.patch_nvram()
            patcher.patch_freshnonce()
            im4p.payload._data = patcher.data
            comp._data = im4p.output()

            # send iBEC
            mode = self.device.irecv.mode
            self.send_component_data(comp)

            if self.device.irecv and mode.is_recovery:
                time.sleep(1)
                self.device.irecv.send_command('go', b_request=1)

                if self.build_identity.build_manifest.build_major < 20:
                    try:
                        self.device.irecv.ctrl_transfer(0x21, 1, timeout=5000)
                    except USBError:
                        pass

                self.logger.debug('Waiting for device to disconnect...')
                time.sleep(10)

        self.logger.debug('Waiting for device to reconnect in pwnrecovery mode...')
        self.reconnect_irecv(is_recovery=True)

    def set_nonce(self):
        self.pwndfu_enter_pwnrecovery()
        time.sleep(1)
        self.logger.info(f"setenv com.apple.System.boot-nonce {self.shsh['generator']}")
        self.device.irecv.send_command(
            f"setenv com.apple.System.boot-nonce {self.shsh['generator']}"
        )
        self.set_autoboot(False)
        self.device.irecv.reboot()
