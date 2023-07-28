from pymobiledevice3.restore.restore import Restore


class FutureRestore(Restore):
    def __init__(
        self,
        ipsw: zipfile.ZipFile,
        device: Device,
        tss=None,
        sepfw=None,
        sepbm=None,
        bbfw=None,
        bbbm=None,
        rdskdata=None,
        rkrndata=None,
        fwcomps: dict = None,
        behavior: Behavior = Behavior.Update,
        ignore_fdr=False,
    ):
        self.recovery = Recovery(
            ipsw,
            device,
            tss=tss,
            rdskdata=rdskdata,
            rkrndata=rkrndata,
            behavior=behavior,
        )
        self.bbtss: Optional[TSSResponse] = None
        self._restored: Optional[RestoredClient] = None
        self._restore_finished = False
        self.fwcomps = fwcomps
        self.septss = None

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
                fdr_support = self.baseband_build_identity['Info'].get(
                    'FDRSupport', False
                )
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

    def send_nor(self, message: Mapping):
        self.logger.info('About to send NORData...')
        flash_version_1 = False
        llb_path = self.build_identity.get_component('LLB', tss=self.recovery.tss).path
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
            component, tss=self.recovery.tss, path=llb_path
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
                component, tss=self.recovery.tss, path=comppath
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
            comp = self.sep_build_identity.get_component(
                component, tss=self.septss, data=self.sepfw
            )
            if comp.path:
                req[f'{component}ImageData'] = comp.personalized_data

        self.logger.info('Sending NORData now...')
        self._restored.send(req)

    def get_savage_firmware_data(self, info: Mapping):
        # create Savage request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        self.build_identity.populate_tss_request_parameters(parameters)

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
                'No \'Savage,Ticket\' in TSS response, this might not work'
            )

        # now get actual component data
        component_data = (
            self.build_identity.get_component(comp_name).data
            if not self.fwcomps['SavageFW'][comp_name]
            else self.fwcomps['SavageFW'][comp_name]
        )
        component_data = struct.pack('<L', len(component_data)) + b'\x00' * 12

        response['FirmwareData'] = component_data

        return response

    def get_rose_firmware_data(self, info: Mapping):
        self.logger.info(f'get_rose_firmware_data: {info}')

        # create Rose request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        # if self.fwcomps['RoseFW']:
        #     self.sep_build_identity.populate_tss_request_parameters(parameters)
        # else:
        self.build_identity.populate_tss_request_parameters(parameters)

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
            self.logger.error('No "Rap,Ticket" in TSS response, this might not work')

        comp_name = 'Rap,RTKitOS'
        component_data = (
            self.build_identity.get_component(comp_name).data
            if not self.fwcomps['RoseFW']
            else self.fwcomps['RoseFW']
        )

        ftab = Ftab(component_data)

        comp_name = 'Rap,RestoreRTKitOS'
        if self.build_identity.has_component(comp_name):
            rftab = Ftab(self.build_identity.get_component(comp_name).data)

            component_data = rftab.get_entry_data(b'rrko')
            if component_data is None:
                self.logger.error(
                    'Could not find "rrko" entry in ftab. This will probably break things'
                )
            else:
                ftab.add_entry(b'rrko', component_data)

        response['FirmwareData'] = ftab.data

        return response

    def get_veridian_firmware_data(self, info: Mapping):
        self.logger.info(f'get_veridian_firmware_data: {info}')
        comp_name = 'BMU,FirmwareMap'

        # create Veridian request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        # if self.fwcomps['VeridianFWM']:
        #     self.sep_build_identity.populate_tss_request_parameters(parameters)
        # else:
        self.build_identity.populate_tss_request_parameters(parameters)

        # add BMU,* tags from info dictionary to parameters
        parameters.update(info)

        # add required tags for Veridian TSS request
        request.add_veridian_tags(parameters, None)

        self.logger.info('Sending Veridian TSS request...')
        response = request.send_receive()

        ticket = response.get('BMU,Ticket')
        if ticket is None:
            self.logger.warning('No "BMU,Ticket" in TSS response, this might not work')

        component_data = (
            self.build_identity.get_component(comp_name).data
            if not self.fwcomps['VeridianFWM']
            else self.fwcomps['VeridianFWM']
        )
        fw_map = plistlib.loads(component_data)
        fw_map['fw_map_digest'] = self.build_identity['Manifest'][comp_name]['Digest']

        bin_plist = plistlib.dumps(fw_map, fmt=plistlib.PlistFormat.FMT_BINARY)
        response['FirmwareData'] = bin_plist

        return response

    def get_se_firmware_data(self, info: Mapping):
        chip_id = info.get('SE,ChipID')
        if chip_id is None:
            chip_id = info.get('SEChipID')
            if chip_id is None:
                chip_id = self.build_identity['Manifest']['SEChipID']

        if chip_id == 0x20211:
            comp_name = 'SE,Firmware'
        elif chip_id in (0x73, 0x64, 0xC8, 0xD2):
            comp_name = 'SE,UpdatePayload'
        else:
            self.logger.warning(
                f'Unknown SE,ChipID {chip_id} detected. Restore might fail.'
            )

            if self.build_identity.has_component('SE,UpdatePayload'):
                comp_name = 'SE,UpdatePayload'
            elif self.build_identity.has_component('SE,Firmware'):
                comp_name = 'SE,Firmware'
            else:
                raise NotImplementedError(
                    'Neither \'SE,Firmware\' nor \'SE,UpdatePayload\' found in build identity.'
                )

        component_data = (
            self.build_identity.get_component(comp_name).data
            if not self.fwcomps['SEFW']
            else self.fwcomps['SEFW']
        )

        # create SE request
        request = TSSRequest()
        parameters = dict()

        # add manifest for current build_identity to parameters
        # if self.fwcomps['SEFW']:
        #     self.sep_build_identity.populate_tss_request_parameters(parameters)
        # else:
        self.build_identity.populate_tss_request_parameters(parameters)

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
                'No \'SE,Ticket\' in TSS response, this might not work'
            )

        response['FirmwareData'] = component_data

        return response


Restore.__init__ = Restore__init__
Restore.send_baseband_data = send_baseband_data
Restore.send_nor = send_nor
Restore.get_rose_firmware_data = get_rose_firmware_data
Restore.get_se_firmware_data = get_se_firmware_data
Restore.get_veridian_firmware_data = get_veridian_firmware_data
Restore.get_savage_firmware_data = get_savage_firmware_data
