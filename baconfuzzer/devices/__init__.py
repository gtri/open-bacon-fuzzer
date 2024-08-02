from .generic import BaseDevice
from .openplc import OpenPlcDevice

DEVICES = {"generic": BaseDevice, "open_plc": OpenPlcDevice}
