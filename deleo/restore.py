import logging
import plistlib
import struct
from typing import Mapping, Optional
from zipfile import ZipFile

from ipsw_parser.ipsw import IPSW
from pymobiledevice3.exceptions import (
    ConnectionFailedError,
    NoDeviceConnectedError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.restore import restore
from pymobiledevice3.restore.base_restore import BaseRestore
from pymobiledevice3.restore.device import Device
from pymobiledevice3.restore.ftab import Ftab
from pymobiledevice3.restore.recovery import Behavior
from pymobiledevice3.restore.restored_client import RestoredClient
from pymobiledevice3.restore.tss import TSSRequest, TSSResponse
from pymobiledevice3.service_connection import LockdownServiceConnection
from pymobiledevice3.utils import plist_access_path
from tqdm import trange

from deleo.recovery import Recovery


class Restore(restore.Restore):
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
        self.recovery = Recovery(
            ipsw,
            latest_ipsw,
            device,
            shsh,
            behavior,
            tss=tss,
            ota_manifest=ota_manifest,
        )
        self.bbtss: Optional[TSSResponse] = None
        self._restored: Optional[RestoredClient] = None
        self._restore_finished = False

        # used when ignore_fdr=True, to store an active FDR connection just to make the device believe it can actually
        # perform an FDR communication, but without really establishing any
        self._fdr: Optional[LockdownServiceConnection] = None
        self._ignore_fdr = False

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

        self.latest_ipsw = IPSW(latest_ipsw)
        self.shsh = TSSResponse(shsh)

    def send_personalized_boot_object_v3(self, message: Mapping):
        self.logger.debug('send_personalized_boot_object_v3')
        image_name = message['Arguments']['ImageName']
        component_name = image_name
        self.logger.info(f'About to send {component_name}...')

        if image_name == '__GlobalManifest__':
            data = self.extract_global_manifest()
        elif image_name == '__RestoreVersion__':
            data = self.ipsw.restore_version
        elif image_name == '__SystemVersion__':
            data = self.ipsw.system_version
        else:
            data = self.build_identity.get_component(
                component_name, tss=self.recovery.shsh
            ).personalized_data

        self.logger.info(f'Sending {component_name} now...')
        chunk_size = 8192
        for i in trange(0, len(data), chunk_size):
            self._restored.send({'FileData': data[i : i + chunk_size]})

        # Send FileDataDone
        self._restored.send({'FileDataDone': True})

        self.logger.info(f'Done sending {component_name}')

    def send_source_boot_object_v4(self, message: Mapping):
        self.logger.debug('send_source_boot_object_v4')
        image_name = message['Arguments']['ImageName']
        component_name = image_name
        self.logger.info(f'About to send {component_name}...')

        if image_name == '__GlobalManifest__':
            data = self.extract_global_manifest()
        elif image_name == '__RestoreVersion__':
            data = self.ipsw.restore_version
        elif image_name == '__SystemVersion__':
            data = self.ipsw.system_version
        else:
            data = (
                self.get_build_identity_from_request(message)
                .get_component(component_name, tss=self.recovery.shsh)
                .data
            )

        self.logger.info(f'Sending {component_name} now...')
        chunk_size = 8192
        for i in trange(0, len(data), chunk_size):
            self._restored.send({'FileData': data[i : i + chunk_size]})

        # Send FileDataDone
        self._restored.send({'FileDataDone': True})

        self.logger.info(f'Done sending {component_name}')

    def send_root_ticket(self, message: Mapping):
        self.logger.info('About to send RootTicket...')

        if self.recovery.shsh is None:
            raise PyMobileDevice3Exception('Cannot send RootTicket without SHSH blob')

        self.logger.info('Sending RootTicket now...')
        self._restored.send({'RootTicketData': self.recovery.shsh.ap_img4_ticket})

    def send_nor(self, message: Mapping):
        self.logger.info('About to send NORData...')
        flash_version_1 = False
        llb_path = self.build_identity.get_component('LLB', tss=self.recovery.shsh).path
        llb_filename_offset = llb_path.find('LLB')

        arguments = message.get('Arguments')
        if arguments:
            flash_version_1 = arguments.get('FlashVersion1', False)

        if llb_filename_offset == -1:
            raise PyMobileDevice3Exception(
                'Unable to extract firmware path from LLB filename'
            )

        firmware_path = llb_path[: llb_filename_offset - 1]
        self.logger.info(f'Found firmware path: {firmware_path}')

        firmware_files = dict()
        try:
            firmware = self.ipsw.get_firmware(firmware_path)
            firmware_files = firmware.get_files()
        except KeyError:
            self.logger.info('Getting firmware manifest from build identity')
            build_id_manifest = self.build_identity['Manifest']
            for component, manifest_entry in build_id_manifest.items():
                if isinstance(manifest_entry, dict):
                    is_fw = plist_access_path(
                        manifest_entry, ('Info', 'IsFirmwarePayload'), bool
                    )
                    loaded_by_iboot = plist_access_path(
                        manifest_entry, ('Info', 'IsLoadedByiBoot'), bool
                    )
                    is_secondary_fw = plist_access_path(
                        manifest_entry, ('Info', 'IsSecondaryFirmwarePayload'), bool
                    )

                    if is_fw or (is_secondary_fw and loaded_by_iboot):
                        comp_path = plist_access_path(manifest_entry, ('Info', 'Path'))
                        if comp_path:
                            firmware_files[component] = comp_path

        if not firmware_files:
            raise PyMobileDevice3Exception('Unable to get list of firmware files.')

        component = 'LLB'
        llb_data = self.build_identity.get_component(
            component, tss=self.recovery.shsh, path=llb_path
        ).personalized_data
        req = {'LlbImageData': llb_data}

        if flash_version_1:
            norimage = {}
        else:
            norimage = []

        for component, comppath in firmware_files.items():
            if component in ('LLB', 'RestoreSEP'):
                # skip LLB, it's already passed in LlbImageData
                # skip RestoreSEP, it's passed in RestoreSEPImageData
                continue

            nor_data = self.build_identity.get_component(
                component, tss=self.recovery.shsh, path=comppath
            ).personalized_data

            if flash_version_1:
                norimage[component] = nor_data
            else:
                # make sure iBoot is the first entry in the array
                if component.startswith('iBoot'):
                    norimage = [nor_data] + norimage
                else:
                    norimage.append(nor_data)

        req['NorImageData'] = norimage

        for component in ('RestoreSEP', 'SEP'):
            comp = self.recovery.latest_build_identity.get_component(
                component, tss=self.recovery.tss
            )
            if comp.path:
                req[f'{component}ImageData'] = comp.personalized_data

        self.logger.info('Sending NORData now...')
        self._restored.send(req)

    def send_baseband_data(self, message: Mapping):
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

            self.recovery.latest_build_identity.populate_tss_request_parameters(
                parameters
            )

            # create baseband request
            request = TSSRequest()

            # add baseband parameters
            request.add_common_tags(parameters)
            request.add_baseband_tags(parameters)

            fdr_support = self.recovery.latest_build_identity['Info'].get(
                'FDRSupport', False
            )
            if fdr_support:
                request.update({'ApProductionMode': True, 'ApSecurityMode': True})

            self.logger.info('Sending Baseband TSS request...')
            bbtss = request.send_receive()

            if bb_nonce:
                # keep the response for later requests
                self.bbtss = bbtss

        # get baseband firmware file path from build identity
        bbfwpath = self.recovery.latest_build_identity['Manifest']['BasebandFirmware'][
            'Info'
        ]['Path']

        # extract baseband firmware to temp file
        bbfw = self.latest_ipsw.read(bbfwpath)

        buffer = self.sign_bbfw(bbfw, bbtss, bb_nonce)

        self.logger.info('Sending BasebandData now...')
        self._restored.send({'BasebandData': buffer})

    def send_image_data(self, message, image_list_k, image_type_k, image_data_k):
        self.logger.debug(f'send_image_data: {message}')
        arguments = message['Arguments']
        want_image_list = arguments.get(image_list_k)
        image_name = arguments.get('ImageName')
        build_id_manifest = self.build_identity['Manifest']

        if not want_image_list and image_name is not None:
            if image_name not in build_id_manifest:
                if image_name.startswith('Ap'):
                    image_name = image_name.replace('Ap', 'Ap,')
                    if image_name not in build_id_manifest:
                        raise PyMobileDevice3Exception(
                            f'{image_name} not in build_id_manifest'
                        )

        if image_type_k is None:
            image_type_k = arguments['ImageType']

        if image_type_k is None:
            raise PyMobileDevice3Exception('missing ImageType')

        if want_image_list is None and image_name is None:
            self.logger.info(f'About to send {image_data_k}...')

        matched_images = []
        data_dict = dict()

        for component, manifest_entry in build_id_manifest.items():
            if not isinstance(manifest_entry, dict):
                continue

            is_image_type = manifest_entry['Info'].get(image_type_k)
            if is_image_type:
                if want_image_list:
                    self.logger.info(f'found {component} component')
                    matched_images.append(component)
                elif image_name is None or image_name == component:
                    if image_name is None:
                        self.logger.info(
                            f"found {image_type_k} component '{component}'"
                        )
                    else:
                        self.logger.info(f"found component '{component}'")

                    data_dict[component] = self.build_identity.get_component(
                        component, tss=self.recovery.shsh
                    ).personalized_data

        req = dict()
        if want_image_list:
            req[image_list_k] = matched_images
            self.logger.info(f'Sending {image_type_k} image list')
        else:
            if image_name:
                if image_name in data_dict:
                    req[image_data_k] = data_dict[image_name]
                req['ImageName'] = image_name
                self.logger.info(f'Sending {image_type_k} for {image_name}...')
            else:
                req[image_data_k] = data_dict
                self.logger.info(f'Sending {image_type_k} now...')

        self._restored.send(req)

    def get_se_firmware_data(
        self, updater_name: str, info: Mapping, arguments: Mapping
    ):
        chip_id = info.get('SE,ChipID')
        if chip_id is None:
            chip_id = self.recovery.latest_build_identity['Manifest']['SE,ChipID']

        if chip_id == 0x20211:
            comp_name = 'SE,Firmware'
        elif chip_id in (0x73, 0x64, 0xC8, 0xD2, 0x2C, 0x36):
            comp_name = 'SE,UpdatePayload'
        else:
            self.logger.warning(
                f'Unknown SE,ChipID {chip_id} detected. Restore might fail.'
            )

            if self.recovery.latest_build_identity.has_component('SE,UpdatePayload'):
                comp_name = 'SE,UpdatePayload'
            elif self.recovery.latest_build_identity.has_component('SE,Firmware'):
                comp_name = 'SE,Firmware'
            else:
                raise NotImplementedError(
                    "Neither 'SE,Firmware' nor 'SE,UpdatePayload' found in build identity."
                )

        component_data = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data

        if 'DeviceGeneratedTags' in arguments:
            response = self.get_device_generated_firmware_data(
                updater_name, info, arguments
            )
        else:
            # create SE request
            request = TSSRequest()
            parameters = dict()

            # add manifest for latest build_identity to parameters
            self.recovery.latest_build_identity.populate_tss_request_parameters(
                parameters
            )

            # add SE,* tags from info dictionary to parameters
            parameters.update(info)

            # add required tags for SE TSS request
            request.add_se_tags(parameters, None)

            self.logger.info('Sending SE TSS request...')
            response = request.send_receive()

            if 'SE,Ticket' in response:
                self.logger.info('Received SE ticket')
            else:
                raise PyMobileDevice3Exception(
                    "No 'SE,Ticket' in TSS response, this might not work"
                )

        response['FirmwareData'] = component_data

        return response

    def get_yonkers_firmware_data(self, info: Mapping):
        # create Yonkers request
        request = TSSRequest()
        parameters = dict()

        # add manifest for latest build_identity to parameters
        self.recovery.latest_build_identity.populate_tss_request_parameters(parameters)

        # add Yonkers,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Yonkers TSS request
        comp_name = request.add_yonkers_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception(
                'Could not determine Yonkers firmware component'
            )

        self.logger.debug(f'restore_get_yonkers_firmware_data: using {comp_name}')

        self.logger.info('Sending SE Yonkers request...')
        response = request.send_receive()

        if 'Yonkers,Ticket' in response:
            self.logger.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception(
                "No 'Yonkers,Ticket' in TSS response, this might not work"
            )

        # now get actual component data
        component_data = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data

        firmware_data = {
            'YonkersFirmware': component_data,
        }

        response['FirmwareData'] = firmware_data

        return response

    def get_savage_firmware_data(self, info: Mapping):
        # create Savage request
        request = TSSRequest()
        parameters = dict()

        # add manifest for latest build_identity to parameters
        self.recovery.latest_build_identity.populate_tss_request_parameters(parameters)

        # add Savage,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Savage TSS request
        comp_name = request.add_savage_tags(parameters, None)

        if comp_name is None:
            raise PyMobileDevice3Exception(
                'Could not determine Savage firmware component'
            )

        self.logger.debug(f'restore_get_savage_firmware_data: using {comp_name}')

        self.logger.info('Sending SE Savage request...')
        response = request.send_receive()

        if 'Savage,Ticket' in response:
            self.logger.info('Received SE ticket')
        else:
            raise PyMobileDevice3Exception(
                "No 'Savage,Ticket' in TSS response, this might not work"
            )

        # now get actual component data
        component_data = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data
        component_data = struct.pack('<L', len(component_data)) + b'\x00' * 12

        response['FirmwareData'] = component_data

        return response

    def get_rose_firmware_data(
        self, updater_name: str, info: Mapping, arguments: Mapping
    ):
        self.logger.info(f'get_rose_firmware_data: {info}')

        if 'DeviceGeneratedTags' in arguments:
            response = self.get_device_generated_firmware_data(
                updater_name, info, arguments
            )
            return response
        else:
            # create Rose request
            request = TSSRequest()
            parameters = dict()

            # add manifest for latest build_identity to parameters
            self.recovery.latest_build_identity.populate_tss_request_parameters(
                parameters
            )

            parameters['ApProductionMode'] = True

            if self.device.is_image4_supported:
                parameters['ApSecurityMode'] = True
                parameters['ApSupportsImg4'] = True
            else:
                parameters['ApSupportsImg4'] = False

            # add Rap,* tags from info dictionary to parameters
            parameters.update(info)

            # add required tags for Rose TSS request
            request.add_rose_tags(parameters, None)

            self.logger.info('Sending Rose TSS request...')
            response = request.send_receive()

            rose_ticket = response.get('Rap,Ticket')
            if rose_ticket is None:
                self.logger.error(
                    'No "Rap,Ticket" in TSS response, this might not work'
                )

        comp_name = 'Rap,RTKitOS'
        component_data = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data

        ftab = Ftab(component_data)

        comp_name = 'Rap,RestoreRTKitOS'
        if self.recovery.latest_build_identity.has_component(comp_name):
            rftab = Ftab(
                self.recovery.latest_build_identity.get_component(comp_name).data
            )

            component_data = rftab.get_entry_data(b'rrko')
            if component_data is None:
                self.logger.error(
                    'Could not find "rrko" entry in ftab. This will probably break things'
                )
            else:
                ftab.add_entry(b'rrko', component_data)

        response['FirmwareData'] = ftab.data

        return response

    def get_veridian_firmware_data(
        self, updater_name: str, info: Mapping, arguments: Mapping
    ):
        self.logger.info(f'get_veridian_firmware_data: {info}')
        comp_name = 'BMU,FirmwareMap'

        if 'DeviceGeneratedTags' in arguments:
            response = self.get_device_generated_firmware_data(
                updater_name, info, arguments
            )
        else:
            # create Veridian request
            request = TSSRequest()
            parameters = dict()

            # add manifest for latest build_identity to parameters
            self.recovery.latest_build_identity.populate_tss_request_parameters(
                parameters
            )

            # add BMU,* tags from info dictionary to parameters
            parameters.update(info)

            # add required tags for Veridian TSS request
            request.add_veridian_tags(parameters, None)

            self.logger.info('Sending Veridian TSS request...')
            response = request.send_receive()

            ticket = response.get('BMU,Ticket')
            if ticket is None:
                self.logger.warning(
                    'No "BMU,Ticket" in TSS response, this might not work'
                )

        component_data = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data
        fw_map = plistlib.loads(component_data)
        fw_map['fw_map_digest'] = self.recovery.latest_build_identity['Manifest'][
            comp_name
        ]['Digest']

        bin_plist = plistlib.dumps(fw_map, fmt=plistlib.PlistFormat.FMT_BINARY)
        response['FirmwareData'] = bin_plist

        return response

    def get_tcon_firmware_data(self, info: Mapping):
        self.logger.info(f'restore_get_tcon_firmware_data: {info}')
        comp_name = 'Baobab,TCON'

        # create Baobab request
        request = TSSRequest()
        parameters = dict()

        # add manifest for latest build_identity to parameters
        self.recovery.latest_build_identity.populate_tss_request_parameters(parameters)

        # add Baobab,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Baobab TSS request
        request.add_tcon_tags(parameters, None)

        self.logger.info('Sending Baobab TSS request...')
        response = request.send_receive()

        ticket = response.get('Baobab,Ticket')
        if ticket is None:
            self.logger.warning(
                'No "Baobab,Ticket" in TSS response, this might not work'
            )

        response['FirmwareData'] = self.recovery.latest_build_identity.get_component(
            comp_name
        ).data

        return response

    def get_device_generated_firmware_data(
        self, updater_name: str, info: Mapping, arguments: Mapping
    ):
        self.logger.info(
            f'get_device_generated_firmware_data ({updater_name}): {arguments}'
        )
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.recovery.latest_build_identity.populate_tss_request_parameters(
            parameters, arguments['DeviceGeneratedTags']['BuildIdentityTags']
        )

        parameters['@BBTicket'] = True
        parameters['ApSecurityMode'] = True

        # by default, set it to True
        parameters['ApProductionMode'] = True

        for k, v in arguments['MessageArgInfo'].items():
            if k.endswith('ProductionMode'):
                # if ApProductionMode should be overridden
                parameters['ApProductionMode'] = bool(v)

        response_ticket = arguments['DeviceGeneratedTags']['ResponseTags'][0]

        parameters.update(arguments['DeviceGeneratedRequest'])
        request.add_common_tags(info)
        request.update(parameters)

        for redacted_field in ('RequiresUIDMode',):
            request.remove_key(redacted_field)

        self.logger.info(f'Sending {updater_name} TSS request...')
        response = request.send_receive()

        ticket = response.get(response_ticket)
        if ticket is None:
            self.logger.warning(
                f'No "{response_ticket}" in TSS response, this might not work'
            )
            self.logger.debug(response)

        return response

    def get_timer_firmware_data(self, info: Mapping):
        self.logger.info(f'get_timer_firmware_data: {info}')

        ftab = None

        # create Timer request
        request = TSSRequest()
        parameters = dict()

        # add manifest for latest build_identity to parameters
        self.recovery.latest_build_identity.populate_tss_request_parameters(parameters)

        parameters['ApProductionMode'] = True
        if self.device.is_image4_supported:
            parameters['ApSecurityMode'] = True
            parameters['ApSupportsImg4'] = True
        else:
            parameters['ApSupportsImg4'] = False

        # add Timer,* tags from info dictionary to parameters
        info_array = info['InfoArray']
        info_dict = info_array[0]
        hwid = info_dict['HardwareID']
        tag = info_dict['TagNumber']
        parameters['TagNumber'] = tag
        ticket_name = info_dict['TicketName']
        parameters['TicketName'] = ticket_name
        parameters[f'Timer,ChipID,{tag}'] = hwid['ChipID']
        parameters[f'Timer,BoardID,{tag}'] = hwid['BoardID']
        parameters[f'Timer,ECID,{tag}'] = hwid['ECID']
        parameters[f'Timer,Nonce,{tag}'] = hwid['Nonce']
        parameters[f'Timer,SecurityMode,{tag}'] = hwid['SecurityMode']
        parameters[f'Timer,SecurityDomain,{tag}'] = hwid['SecurityDomain']
        parameters[f'Timer,ProductionMode,{tag}'] = hwid['ProductionMode']

        ap_info = info['APInfo']
        parameters.update(ap_info)

        # add required tags for Timer TSS request
        request.add_timer_tags(parameters, None)

        self.logger.info(f'Sending {ticket_name} TSS request...')
        response = request.send_receive()

        ticket = response.get(ticket_name)
        if ticket is None:
            self.logger.warning(
                f'No "{ticket_name}" in TSS response, this might not work'
            )

        comp_name = f'Timer,RTKitOS,{tag}'
        if self.recovery.latest_build_identity.has_component(comp_name):
            ftab = Ftab(
                self.recovery.latest_build_identity.get_component(comp_name).data
            )
            if ftab.tag != b'rkos':
                self.logger.warning(f'Unexpected tag {ftab.tag}. continuing anyway.')
        else:
            self.logger.info(
                f'NOTE: Build identity does not have a "{comp_name}" component.'
            )

        comp_name = f'Timer,RestoreRTKitOS,{tag}'
        if self.recovery.latest_build_identity.has_component(comp_name):
            rftab = Ftab(
                self.recovery.latest_build_identity.get_component(comp_name).data
            )

            component_data = rftab.get_entry_data(b'rrko')
            if component_data is None:
                self.logger.error(
                    'Could not find "rrko" entry in ftab. This will probably break things'
                )
            else:
                if ftab is None:
                    raise PyMobileDevice3Exception('ftab is None')
                ftab.add_entry(b'rrko', component_data)
        else:
            self.logger.info(
                f'NOTE: Build identity does not have a "{comp_name}" component.'
            )

        response['FirmwareData'] = ftab.data

        return response

    def send_component(self, component, component_name=None):
        if component_name is None:
            component_name = component

        self.logger.info(f'Sending now {component_name}...')
        self._restored.send(
            {
                f'{component_name}File': self.build_identity.get_component(
                    component, tss=self.recovery.shsh
                ).personalized_data
            }
        )

    def _connect_to_restored_service(self):
        while True:
            try:
                self._restored = RestoredClient()
                break
            except (ConnectionFailedError, NoDeviceConnectedError):
                pass
