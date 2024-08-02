from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    from ..io.io_handler import BaconIOInterface


class BaseDevice:
    def handle_io_exception(self, io_ifc: BaconIOInterface, ex: Exception):
        pass
