import logging
from typing import Optional
import serial
import socket


log = logging.getLogger(__name__)


class BaconIOInterface:
    """
    Base IO class.
    Abstracts the Input/Output of different physical or virtual interfaces
    such as serial, TCP, etc.
    """

    """
    Default values for configs if something isn't specified.
    """
    __defaults = {
        "Destination IP": "127.0.0.1",
        "Destination Port": 1337,
        "Serial Port": None,  # serial port
        "Baudrate": 9600,
    }

    def __init__(self, config, name, device):
        self._config = config
        self.name = name
        self.device = device()

    def configure(self, opts: dict):
        """
        Configure the IO interface.
        """
        raise NotImplementedError

    def teardown(self):
        """
        Teardown the IO interface.
        """
        raise NotImplementedError

    def transmit(self, msg, wait_for_reply=False) -> Optional[bytes]:
        """
        Transmit data on the IO interface.
        """
        raise NotImplementedError

    def receive(self) -> Optional[bytes]:
        """
        Receive data on the IO interface.
        """
        raise NotImplementedError

    def _get_io_config(self, *kwargs):
        """
        Helper method that gets configuration params for communication.
        """
        result = []
        for x in kwargs:
            result.append(self._config.get(x, BaconIOInterface.__defaults.get(x, None)))
        if len(result) > 1:
            return tuple(result)
        else:
            return result[0]

    @staticmethod
    def get_config_opts(selected_msgs, protocol):
        """
        Helper to return the options for the interface
        """
        raise NotImplementedError

    def get_info(self) -> str:
        """
        Return a string suitable for differentiating the interface from others.
        """
        raise NotImplementedError


class BaconSerialIO(BaconIOInterface):
    """
    Serial IO Class.
    Bacon goes well with "serial".
    """

    def __init__(self, config, device):
        super().__init__(config, "Serial", device)
        log.info("serial")
        self._ser = None
        self.port = None

    def configure(self, opts: dict):
        io_opts = self._get_io_config("Serial Port", "Baud Rate", "Timeout")
        self.port = io_opts[0]
        timeout = io_opts[2]
        if not timeout:
            timeout = 5
        self._ser = serial.Serial(port=io_opts[0], baudrate=io_opts[1], timeout=timeout)
        if self._ser.is_open:
            self._ser.close()
        self._ser.open()

    def teardown(self):
        self._ser.close()
        self._ser = None

    def transmit(self, msg, wait_for_reply=True) -> Optional[bytes]:
        try:
            self._ser.write(msg)
            if wait_for_reply:
                try:
                    data = self.receive()
                except:
                    return None
                return data
            else:
                return None
        except Exception:
            log.warning(f"Serial port disconnected. Attempting restart...")
            try:
                self.configure({})
            except Exception:
                log.warning(f"Reconnect failed")
                self.device.handle_io_exception(self)
            return None

    def receive(self) -> Optional[bytes]:
        # TO DO: this needs better logic if we want directed fuzzing
        t = self._ser.read(1024)
        if len(t):
            return t
        else:
            return None

    @staticmethod
    def get_config_opts(selected_msgs, protocol) -> list:
        """
        Helper to return the options for the interface based on the supplied protocol
        """
        return protocol.get_config(selected_msgs, interface="Serial")

    def get_info(self) -> str:
        return f"Serial Port {self.port}"


class BaconSocketIO(BaconIOInterface):
    """
    Socket IO Class
    TO DO: might need changes for additional socket options...
    """

    def __init__(self, config, device):
        super().__init__(config, "TCP Socket", device)
        log.info("socket")
        self.ip = None
        self.port = None

    def configure(self, opts: dict):
        self.ip, self.port = self._get_io_config("Destination IP", "Destination Port")
        # Test connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.ip, self.port))

    def teardown(self):
        pass

    def transmit(self, msg, wait_for_reply=True) -> Optional[bytes]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.ip, self.port))
                sock.send(msg)
                if wait_for_reply:
                    sock.settimeout(self._config.get("timeout", 5))
                    try:
                        data = sock.recv(self._config.get("bufsize", 1024))
                    except socket.timeout:
                        return None
                    return data
                else:
                    return None
        except Exception as ex:
            self.device.handle_io_exception(self, ex)
            return None

    def receive(self) -> Optional[bytes]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(self._get_io_config("Destination IP", "Destination Port"))
            sock.settimeout(self._config.get("timeout", 5))
            try:
                data = sock.recv(self._config.get("bufsize", 1024))
            except socket.timeout:
                return None
            return data

    @staticmethod
    def get_config_opts(selected_msgs, protocol) -> list:
        """
        Helper to return the options for the interface based on the supplied protocol
        """
        return protocol.get_config(selected_msgs, interface="TCP Socket")

    def get_info(self) -> str:
        return f"TCP {self.ip}:{self.port}"
