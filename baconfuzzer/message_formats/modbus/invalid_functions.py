from scapy.contrib.modbus import _ModbusPDUNoPayload
from scapy.fields import StrField, XByteField
from scapy.volatile import RandChoice

_valid_function_codes = [
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0xB,
    0xC,
    0xF,
    0x10,
    0x11,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x2B,
]
_valid_error_codes = [
    0x81,
    0x82,
    0x83,
    0x84,
    0x85,
    0x86,
    0x87,
    0x88,
    0x8B,
    0x8C,
    0x8F,
    0x90,
    0x91,
    0x94,
    0x95,
    0x96,
    0x97,
    0x98,
    0xAB,
]
_all_valid_function_codes = _valid_function_codes + _valid_error_codes
_invalid_function_codes = set(range(256)) - set(_all_valid_function_codes)


class InvalidFuncCodeField(XByteField):
    def randval(self):
        return RandChoice(*_invalid_function_codes)


class ModbusPDUInvalidFuncCode(_ModbusPDUNoPayload):
    name = "Invalid function code"
    fields_desc = [InvalidFuncCodeField("funcCode", 0), StrField("data", "")]
