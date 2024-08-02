from typing import Dict, Type

from .protocol import Protocol
from .modbus.modbus import ModbusProtocol
from .mil_std_1553.mil_std_1553_protocol import MILSTD1553Protocol
from .dumb_serial.dumb_serial import DumbSerial

PROTOCOLS: Dict[str, Protocol] = {
    "modbus": ModbusProtocol(),
    "MIL-STD-1553": MILSTD1553Protocol(),
    "dumb-serial": DumbSerial(),
}


def GET_PROTO_STRING_FROM_TYPE(my_type: Type):
    for n, t in PROTOCOLS.items():
        if type(t) is type(my_type):
            return str(n).lower()
    return "unknown"
