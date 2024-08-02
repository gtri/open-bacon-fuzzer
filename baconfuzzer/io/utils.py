import logging
import serial.tools.list_ports as port_list

log = logging.getLogger(__name__)


def get_serial_port(default_only=False) -> list:
    ports = list(port_list.comports())
    for p in ports:
        log.debug(p)
    if len(ports) > 0:
        if default_only:
            return ports[0].device
        else:
            return ports
    else:
        return []
