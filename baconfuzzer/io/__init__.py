from .io_handler import BaconSerialIO, BaconSocketIO


IOINTERFACES = {
    "TCP Socket": BaconSocketIO,
    "Serial": BaconSerialIO,
}
