import logging
from scapy.packet import fuzz

from baconfuzzer.io.utils import get_serial_port
from baconfuzzer.message_formats.config import (
    BaconConfig,
    FloatValue,
    IntValue,
    TextValue,
)

from .mil_std_1553_packets import (
    MILSTD1553CommandWord,
    MILSTD1553DataWord,
    MILSTD1553StatusWord,
)
from ..protocol import Protocol

log = logging.getLogger(__name__)


class MILSTD1553Protocol(Protocol):
    def __init__(self, crash_path=None):
        super().__init__(crash_path)
        self.msg_types = {
            msg().name: msg
            for msg in [MILSTD1553CommandWord, MILSTD1553DataWord, MILSTD1553StatusWord]
        }
        self.fuzzed_msgs = {}
        for name, msg_class in self.msg_types.items():
            msg = fuzz(msg_class())
            # msg.__padding = 0
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
            com_def = get_serial_port(default_only=True)
            opts.append(
                TextValue(
                    "Serial Port",
                    default=f"{com_def}",
                    help_text="The physical or virtual serial/com port over which to talk",
                )
            )
            opts.append(
                FloatValue("Timeout", default=5, help_text="Read / response timeout")
            )
            opts.append(IntValue("Baud Rate", default=9600, help_text="Data baud rate"))
        elif interface == "TCP Socket":
            opts.append(
                TextValue(
                    "Destination IP",
                    default="localhost",
                    help_text="IP or hostname of SUT",
                )
            )
            opts.append(
                IntValue(
                    "Destination Port",
                    default=502,
                    help_text="Port on which SUT is listening",
                )
            )

        # actual protocol config fields
        return BaconConfig(opts)
