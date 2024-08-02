import logging
from logging.handlers import RotatingFileHandler
from typing import List, Optional, Dict


from scapy.packet import Packet
from scapy.base_classes import Packet_metaclass
from scapy.fields import FieldListField

from .config import BaconConfig
from .scapy_fields import CustomFieldListField


class Protocol:
    def __init__(self, crash_path=None):
        self.set_logger(crash_path)

    def set_logger(self, crash_path):
        if not crash_path:
            crash_path = "bacon.log"
        self._crash_logger = logging.getLogger(crash_path)
        fh = RotatingFileHandler(crash_path, maxBytes=10 * 1024 * 1024, backupCount=10)
        fh.level = logging.INFO
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        fh.setFormatter(formatter)
        self._crash_logger.addHandler(fh)

    def get_msg_names(self, io_interface_name: Optional[str] = None) -> Dict[str, bool]:
        """
        Get a dict of message names for the protocol where keys are names and values are booleans
        indicated if the message is enabled by default.
        """
        raise NotImplementedError()

    def fuzz_msg(
        self,
        msg_name: str,
        validate: bool,
        config_values: dict,
        io_interface,
        stop_flag: dict,
    ) -> bool:
        """
        Generate and send a single fuzzed message.
        :returns: True if crash; False if no crash
        """
        raise NotImplementedError()

    def validate_msg(self, msg, io_interface) -> bool:
        """
        Determine if the given message is valid.
        :return: True if valid; False if invalid
        """
        raise NotImplementedError()

    def get_config(
        self, selected_msgs: List[str], interface: str
    ) -> Optional[BaconConfig]:
        """
        Get the protocol-specific configuration object
        :param selected_msgs: A list of message names that were selected for fuzzing.
        :param interface: Name of the I/O interface
        :returns: An optional configuration object if any configuration is required.
        """
        raise NotImplementedError()

    def _apply_custom_fields(self, packet_meta: Packet_metaclass) -> Packet:
        for i in range(len(packet_meta.fields_desc)):
            field = packet_meta.fields_desc[i]
            if isinstance(field, FieldListField):
                packet_meta.fields_desc[i] = CustomFieldListField.from_fieldlistfield(
                    field,
                    packet_meta,
                )
        packet = packet_meta()
        packet.fields = {}
        return packet

    def _record_crash(self, io_interface, msg, raw_msg):
        self._crash_logger.warning(
            f"Crash detected on interface {io_interface.get_info()}"
        )
        self._crash_logger.warning(f"\tMessage: {msg}")
        self._crash_logger.warning(f"\tRaw message: {raw_msg}")
