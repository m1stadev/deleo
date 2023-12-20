import zipfile
from typing import Optional

from ipsw_parser import ipsw
from ipsw_parser.build_manifest import BuildManifest


class IPSW(ipsw.IPSW):
    def __init__(self, archive: zipfile.ZipFile, build_manifest: Optional[bytes]=None):
        super().__init__(archive)

        if build_manifest:
            self.build_manifest = BuildManifest(self, build_manifest)