import logging
from typing import Mapping
from zipfile import ZipFile

from ipsw_parser.exceptions import NoSuchBuildIdentityError
from ipsw_parser.ipsw import IPSW
from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.restore import recovery
from pymobiledevice3.restore.base_restore import BaseRestore, Behavior
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.recovery import (
    RESTORE_VARIANT_ERASE_INSTALL,
    RESTORE_VARIANT_UPGRADE_INSTALL,
)
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse


class Recovery(recovery.Recovery):
    def __init__(
        self,
        ipsw: ZipFile,
        latest_ipsw: ZipFile,
        device: Device,
        shsh: Mapping,
        behavior: Behavior,
        tss: Mapping = None,
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

        variant = {
            Behavior.Update: RESTORE_VARIANT_UPGRADE_INSTALL,
            Behavior.Erase: RESTORE_VARIANT_ERASE_INSTALL,
        }[behavior]

        try:
            self.latest_build_identity = (
                self.latest_ipsw.build_manifest.get_build_identity(
                    self.device.hardware_model,
                    restore_behavior=behavior.value,
                    variant=variant,
                )
            )
        except NoSuchBuildIdentityError:
            if behavior == Behavior.Update:
                self.latest_build_identity = (
                    self.latest_ipsw.build_manifest.get_build_identity(
                        self.device.hardware_model, restore_behavior=behavior.value
                    )
                )
            else:
                raise

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
            data = self.latest_build_identity.get_component(
                name, tss=self.tss
            ).personalized_data
        else:
            data = self.build_identity.get_component(
                name, tss=self.shsh
            ).personalized_data

        self.logger.info(f'Sending {name} ({len(data)} bytes)...')
        self.device.irecv.send_buffer(data)
