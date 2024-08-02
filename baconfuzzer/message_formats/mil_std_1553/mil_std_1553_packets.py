from scapy.packet import Packet
from scapy.fields import BitField, XShortField


class MILSTD1553Packet(Packet):
    """
    MIL-STD-1553C packet. The data sync waveform is not included. Seven bits of padding are added
    to the end because scapy can only build packets containing a number of bits divisible by 8.
    """

    def post_build(self, pkt, pay):
        if len(pay):
            raise NotImplementedError("post_build must be modified to support payloads")
        if self.parity is None:
            parity_field = self.fields_desc[-2]
            assert parity_field.name == "parity"
            count = 0
            for byte in pkt:
                for i in range(8):
                    if byte & 1:
                        count += 1
                    byte >>= 1
            parity_bit = 0 if (count % 2) else 1
            pkt = pkt[:2] + bytes([parity_bit << 7])
        return pkt


class MILSTD1553CommandWord(MILSTD1553Packet):
    name = "MIL-STD-1553 Command Word"
    fields_desc = [
        BitField("remote_terminal_address", 1, 5),
        BitField("tr", 0, 1),
        BitField("subaddress_mode", 2, 5),
        BitField("data_word_count_mode_code", 0, 5),
        BitField("parity", None, 1),
        BitField("__padding", 0, 7),
    ]


class MILSTD1553DataWord(MILSTD1553Packet):
    name = "MIL-STD-1553 Data Word"
    fields_desc = [
        XShortField("data", 0),
        BitField("parity", None, 1),
        BitField("__padding", 0, 7),
    ]


class MILSTD1553StatusWord(MILSTD1553Packet):
    name = "MIL-STD-1553 Status Word"
    fields_desc = [
        BitField("remote_terminal_address", 1, 5),
        BitField("message_error", 0, 1),
        BitField("instrumentation", 0, 1),
        BitField("service_request", 0, 1),
        BitField("reserved", 0, 3),
        BitField("broadcast_command_received", 0, 1),
        BitField("busy", 0, 1),
        BitField("subsystem_flag", 0, 1),
        BitField("dynamic_bus_control_acceptance", 0, 1),
        BitField("terminal_flag", 0, 1),
        BitField("parity", None, 1),
        BitField("__padding", 0, 7),
    ]
