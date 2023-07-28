from pymobiledevice3.restore.recovery import Behavior, Recovery
from pymobiledevice3.restore.device import Device
from typing import BytesIO, Mapping, Optional


class FutureRecovery(Recovery):
    def __init__(
        self,
        ipsw: BytesIO,
        device: Device,
        tss: Optional[Mapping] = None,
        sepfw=None,
        sepbm=None,
        bbfw=None,
        bbbm=None,
        rdskdata=None,
        rkrndata=None,
        behavior: Behavior = Behavior.Update,
    ):
        BaseRestore.__init__(
            self,
            ipsw,
            device,
            tss,
            sepfw=sepfw,
            sepbm=sepbm,
            bbfw=bbfw,
            bbbm=bbbm,
            behavior=behavior,
            logger=logging.getLogger(__name__),
        )
        self.tss_localpolicy = None
        self.tss_recoveryos_root_ticket = None
        self.restore_boot_args = None
        self.rdskdata = rdskdata
        self.rkrndata = rkrndata

    def get_tss_response(self, sep=False):
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

        if sep:
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
        if name in {'RestoreSEP', 'SEP'} and self.sepfw:
            data = self.sep_build_identity.get_component(
                name, tss=tss, data=self.sepfw
            ).personalized_data
        else:
            data = self.build_identity.get_component(
                name, tss=tss, data=data
            ).personalized_data
        self.logger.info(f'Sending {name} ({len(data)} bytes)...')
        self.device.irecv.send_buffer(data)
