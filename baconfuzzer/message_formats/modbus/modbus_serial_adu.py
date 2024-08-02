import struct

from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
from scapy.fields import XByteField, FCSField


def crc16(data: bytes) -> int:
    """
    CRC-16-ANSI
    """
    crc = 0xFFFF
    for byte in data:
        crc = crc ^ byte
        for i in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc = crc >> 1
    return crc


class ModbusSerialADURequest(ModbusADURequest):
    fields_desc = [
        XByteField("address", 0),
        FCSField("crc", None, "H"),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.crc is None:
            p = p[:-2] + struct.pack("H", crc16(p[:-2]))
        return p


class ModbusSerialADUResponse(ModbusADUResponse):
    fields_desc = [
        XByteField("address", 0),
        FCSField("crc", None, "H"),
    ]

    def post_build(self, p, pay):
        p += pay
        if self.crc is None:
            p = p[:-2] + struct.pack("H", crc16(p[:-2]))
        return p
