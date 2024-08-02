import logging

from scapy.fields import BoundStrLenField
from scapy.packet import Packet, fuzz

from baconfuzzer.io.utils import get_serial_port
from baconfuzzer.message_formats.config import (
    BaconConfig,
    DropDown,
    FloatValue,
    IntValue,
    TextValue,
)

from ..protocol import Protocol

log = logging.getLogger(__name__)


class DumbSerialPacket(Packet):
    name = "Dumb Serial Spammer"

    fields_desc = [
        BoundStrLenField(
            "plchldr",
            "",
            minlen=0,
            maxlen=1024,
        )
    ]


class DumbSerial(Protocol):
    def __init__(self, crash_path=None):
        super().__init__(crash_path)
        self.msg_types = {msg().name: msg for msg in [DumbSerialPacket]}
        self.fuzzed_msgs = {}
        for name, msg_class in self.msg_types.items():
            msg = fuzz(msg_class())
            self.fuzzed_msgs[name] = msg

    def get_msg_names(self, io_interface_name=None):
        return {key: True for key in self.msg_types.keys()}

    def fuzz_msg(self, msg_name, validate, config_values, io_interface, stop_flag):
        fuzzed_msg = self.fuzzed_msgs[msg_name]
        raw_msg = fuzzed_msg.build()
        log.debug(f"Generated msg {fuzzed_msg}")
        rxd = io_interface.transmit(raw_msg, True)
        log.debug(f"received: {rxd}")
        if rxd is None:
            log.warning(f"Crash detected with input {raw_msg}")
            self._record_crash(io_interface, fuzzed_msg, raw_msg)
            return True
        log.debug(f"succeeded with input {raw_msg}")
        return False

    def get_config(self, selected_msgs, interface):
        # io defaults/hints
        opts = []
        if interface == "Serial":
            serial_ports = get_serial_port()
            opts.append(
                DropDown(
                    "Serial Port",
                    [s.device for s in serial_ports],
                    help_text="The physical or virtual serial/com port over which to talk",
                )
            )
            opts.append(IntValue("Baud Rate", default=9600, help_text="Data baud rate"))
            opts.append(
                FloatValue("Timeout", default=5, help_text="Read / response timeout")
            )
        elif interface == "TCP Socket":
            opts.append(
                TextValue(
                    "Destination IP",
                    default="localhost",
                    help_text="IP or hostname of SUT -- useful for IP->serial conversions",
                )
            )
            opts.append(
                IntValue(
                    "Destination Port",
                    default=8080,
                    help_text="Port on which SUT or translator is listening",
                )
            )

        # actual protocol config fields
        return BaconConfig(opts)
