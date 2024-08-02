from __future__ import annotations

import logging
import socket
import time
import typing

import requests

from .generic import BaseDevice

if typing.TYPE_CHECKING:
    from ..io.io_handler import BaconIOInterface


class OpenPlcDevice(BaseDevice):
    def __init__(self):
        super().__init__()
        self.log = logging.getLogger(__name__)

    def handle_io_exception(self, io_ifc: BaconIOInterface, ex: Exception):
        if io_ifc.name == "TCP Socket":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                try:
                    sock.connect((io_ifc.ip, io_ifc.port))
                except Exception:
                    self.log.warning("Modbus server connection error")
                    web_server_addr = "http://{io_ifc.ip}:8080"
                    try:
                        requests.get(web_server_addr, timeout=5)
                    except Exception:
                        self.log.warning(
                            "Possible crash: Both webserver and "
                            + "modbus server not responding"
                        )
                    else:
                        self.log.info(
                            "Webserver running attempting modbus " + "server reset..."
                        )
                        requests.get(web_server_addr + "/start_plc")
                        self.log.warning("Modbus server restarted")
                        self.log.warning(
                            "Please wait for time buffer to ensure restart"
                        )
                        time.sleep(30)
                        self.log.warning("Continuing Fuzzing")
                else:
                    self.log.warning("server connection status: good")
