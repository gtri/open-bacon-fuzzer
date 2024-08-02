import logging
import math
from .invalid_functions import ModbusPDUInvalidFuncCode

from fluent_validator import validate
from scapy.contrib.modbus import (
    ModbusADURequest,
    ModbusPDU01ReadCoilsRequest,
    ModbusPDU02ReadDiscreteInputsRequest,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU04ReadInputRegistersRequest,
    ModbusPDU05WriteSingleCoilRequest,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU07ReadExceptionStatusRequest,
    ModbusPDU08DiagnosticsRequest,
    ModbusPDU0BGetCommEventCounterRequest,
    ModbusPDU0CGetCommEventLogRequest,
    ModbusPDU0FWriteMultipleCoilsRequest,
    ModbusPDU10WriteMultipleRegistersRequest,
    ModbusPDU11ReportSlaveIdRequest,
    ModbusPDU14ReadFileRecordRequest,
    ModbusPDU15WriteFileRecordRequest,
    ModbusPDU16MaskWriteRegisterRequest,
    ModbusPDU17ReadWriteMultipleRegistersRequest,
    ModbusPDU18ReadFIFOQueueRequest,
)
from scapy.packet import fuzz
from scapy.volatile import RandByte

from baconfuzzer.io.utils import get_serial_port


from ..protocol import Protocol
from ..config import BaconConfig, FloatValue, TextValue, IntValue
from .modbus_serial_adu import ModbusSerialADURequest

log = logging.getLogger(__name__)


class ModbusProtocol(Protocol):
    REQUEST_MSGS = [
        ModbusPDU01ReadCoilsRequest,
        ModbusPDU02ReadDiscreteInputsRequest,
        ModbusPDU03ReadHoldingRegistersRequest,
        ModbusPDU04ReadInputRegistersRequest,
        ModbusPDU05WriteSingleCoilRequest,
        ModbusPDU06WriteSingleRegisterRequest,
        ModbusPDU07ReadExceptionStatusRequest,
        ModbusPDU08DiagnosticsRequest,
        ModbusPDU0BGetCommEventCounterRequest,
        ModbusPDU0CGetCommEventLogRequest,
        ModbusPDU0FWriteMultipleCoilsRequest,
        ModbusPDU10WriteMultipleRegistersRequest,
        ModbusPDU11ReportSlaveIdRequest,
        ModbusPDU14ReadFileRecordRequest,
        ModbusPDU15WriteFileRecordRequest,
        ModbusPDU16MaskWriteRegisterRequest,
        ModbusPDU17ReadWriteMultipleRegistersRequest,
        ModbusPDU18ReadFIFOQueueRequest,
        ModbusPDUInvalidFuncCode,
    ]

    def __init__(self, crash_path=None):
        super().__init__(crash_path)
        self.msg_types = {msg().name: msg for msg in self.REQUEST_MSGS}
        self.fuzzed_msgs = {}
        for name, msg_class in self.msg_types.items():
            msg = self._apply_custom_fields(msg_class)
            fuzzed_msg = fuzz(msg)
            func_code = fuzzed_msg.class_default_fields[msg_class]["funcCode"]
            fuzzed_msg.funcCode = func_code
            self.fuzzed_msgs[name] = fuzzed_msg
        self.transaction_identifier = 0

    def get_msg_names(self, io_interface_name=None):
        if io_interface_name is None or io_interface_name == "Serial":
            return {key: True for key in self.msg_types.keys()}
        elif io_interface_name == "TCP Socket":
            serial_only_msg_types = frozenset([7, 8, 0xB, 0xC, 0x11])
            msgs = {}
            for msg_name, msg in self.msg_types.items():
                msgs[msg_name] = msg.funcCode.default not in serial_only_msg_types
            return msgs
        else:
            raise NotImplementedError(
                f"Unsupported I/O interface ({io_interface_name}) for modbus"
            )

    def fuzz_msg(self, msg_name, validate, config_values, io_interface, stop_flag):
        fuzzed_msg = self.fuzzed_msgs[msg_name]
        unitId_config = config_values["Unit Identifier"]
        unitId = unitId_config if unitId_config is not None else RandByte()
        if io_interface.name == "Serial":
            adu = ModbusSerialADURequest(address=unitId)
        elif io_interface.name == "TCP Socket":
            adu = ModbusADURequest(transId=self.transaction_identifier, unitId=unitId)
            if self.transaction_identifier >= 0xFFFF:
                self.transaction_identifier = 0
            else:
                self.transaction_identifier += 1
        else:
            raise NotImplementedError(
                f"Unsupported I/O interface ({io_interface.name}) for modbus"
            )

        msg = adu / fuzzed_msg
        msg_valid = False
        while not msg_valid and not stop_flag():
            raw_msg = msg.build()
            if not validate:
                break
            msg_valid = self.validate_msg(raw_msg, io_interface)
        log.debug(f"Generated msg {msg}")
        rxd = io_interface.transmit(raw_msg, True)
        log.debug(f"received: {rxd}")
        if rxd is None:
            log.warning(f"Crash detected with input {raw_msg}")
            self._record_crash(io_interface, msg, raw_msg)
            return True
        log.debug(f"succeeded with input {raw_msg}")
        return False

    def validate_msg(self, msg, io_interface) -> bool:
        try:
            if io_interface.name == "Serial":
                adu = ModbusSerialADURequest(msg)
                validate(len(adu)).greater_than(3)
            elif io_interface.name == "TCP Socket":
                adu = ModbusADURequest(msg)
                validate(len(adu)).greater_than(7)
                validate(len(adu.payload)).equal(adu.len - 1)
            else:
                raise NotImplementedError(
                    f"Unsupported I/O interface ({io_interface.name}) for modbus"
                )

            payload = adu.payload
            validate(len(payload)).less_or_equal_than(253)
            if io_interface.name == "Serial":
                validate(payload.funcCode).is_in(
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
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
                )
            elif io_interface.name == "TCP Socket":
                validate(payload.funcCode).is_in(
                    1, 2, 3, 4, 5, 6, 0xF, 0x10, 0x14, 0x15, 0x16, 0x17, 0x18
                )

            if payload.funcCode == 1:
                validate(payload.quantity).greater_than(0).less_or_equal_than(0x7D0)
                validate(payload.startAddr + payload.quantity).less_or_equal_than(
                    0x10000
                )
            elif payload.funcCode == 2:
                validate(payload.quantity).greater_than(0).less_or_equal_than(0x7D0)
                validate(payload.startAddr + payload.quantity).less_or_equal_than(
                    0x10000
                )
            elif payload.funcCode == 3:
                validate(payload.quantity).greater_than(0).less_or_equal_than(0x7D)
                validate(payload.startAddr + payload.quantity).less_or_equal_than(
                    0x10000
                )
            elif payload.funcCode == 4:
                validate(payload.quantity).greater_than(0).less_or_equal_than(0x7D)
                validate(payload.startAddr + payload.quantity).less_or_equal_than(
                    0x10000
                )
            elif payload.funcCode == 5:
                validate(payload.outputValue).is_in(0x0000, 0xFF00)
            elif payload.funcCode == 6:
                pass
            elif payload.funcCode == 7:
                pass
            elif payload.funcCode == 8:
                validate(payload.subFunc).is_in(
                    0, 1, 2, 3, 4, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11, 0x12, 0x14
                )
                if payload.subFunc == 0:
                    pass
                elif payload.subFunc == 1:
                    validate(payload.data).is_in([0x0000], [0xFF00])
                elif payload.subFunc == 2:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 3:
                    validate(len(payload.data)).equal(1)
                    validate(payload.data[0]).greater_or_equal_than(
                        0x0000
                    ).less_or_equal_than(0xFF00)
                elif payload.subFunc == 4:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xA:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xB:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xC:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xD:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xE:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0xF:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0x10:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0x11:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0x12:
                    validate(payload.data).equal([0x0000])
                elif payload.subFunc == 0x14:
                    validate(payload.data).equal([0x0000])
            elif payload.funcCode == 0xB:
                pass
            elif payload.funcCode == 0xC:
                pass
            elif payload.funcCode == 0xF:
                validate(payload.quantityOutput).greater_than(0).less_or_equal_than(
                    0x7B0
                )
                validate(payload.byteCount).equal(math.ceil(payload.quantityOutput / 8))
                validate(len(payload.outputsValue)).equal(payload.byteCount)
                validate(payload.startAddr + payload.quantityOutput).less_or_equal_than(
                    0x10000
                )
            elif payload.funcCode == 0x10:
                validate(payload.quantityRegisters).greater_than(0).less_or_equal_than(
                    0x7B
                )
                validate(payload.byteCount).equal(2 * payload.quantityRegisters)
                validate(len(payload.outputsValue)).equal(payload.quantityRegisters)
                validate(
                    payload.startAddr + payload.quantityRegisters
                ).less_or_equal_than(0x10000)
            elif payload.funcCode == 0x11:
                pass
            elif payload.funcCode == 0x14:
                validate(payload.byteCount).greater_than(6).less_or_equal_than(
                    0xF5
                ).equal(len(payload.payload))
                validate(payload.byteCount % 7).equal(0)
                total_subresp_length = 2
                subreq = payload.payload
                while len(subreq):
                    validate(subreq.refType).equal(6)
                    validate(subreq.fileNumber).greater_than(0)
                    validate(subreq.recordNumber).less_or_equal_than(0x270F)
                    validate(
                        subreq.recordNumber + subreq.recordLength
                    ).less_or_equal_than(0x2710)
                    total_subresp_length += (2 * subreq.recordLength) + 2
                    subreq = subreq.payload
                validate(total_subresp_length).less_or_equal_than(253)
            elif payload.funcCode == 0x15:
                validate(payload.dataLength).greater_than(8).less_or_equal_than(
                    0xFB
                ).equal(len(payload.payload))
                subreq = payload.payload
                while len(subreq):
                    validate(subreq.refType).equal(6)
                    validate(subreq.fileNumber).greater_than(0)
                    validate(subreq.recordNumber).less_or_equal_than(0x270F)
                    validate(
                        subreq.recordNumber + subreq.recordLength
                    ).less_or_equal_than(0x2710)
                    validate(len(subreq.recordData)).equal(subreq.recordLength * 2)
                    subreq = subreq.payload
            elif payload.funcCode == 0x16:
                pass
            elif payload.funcCode == 0x17:
                validate(payload.readQuantityRegisters).greater_than(
                    0
                ).less_or_equal_than(0x7D)
                validate(
                    payload.readStartingAddr + payload.readQuantityRegisters
                ).less_or_equal_than(0x10000)
                validate(payload.writeQuantityRegisters).greater_than(
                    0
                ).less_or_equal_than(0x79)
                validate(
                    payload.writeStartingAddr + payload.writeQuantityRegisters
                ).less_or_equal_than(0x10000)
                validate(payload.byteCount).equal(2 * payload.writeQuantityRegisters)
                validate(len(payload.writeRegistersValue)).equal(payload.byteCount)
            elif payload.funcCode == 0x18:
                pass
            else:
                return False
        except ValueError:
            return False
        return True

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
            opts.append(IntValue("Baud Rate", default=9600, help_text="Data baud rate"))
            opts.append(
                FloatValue("Timeout", default=5, help_text="Read / response timeout")
            )
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
        opts.append(
            IntValue(
                "Unit Identifier", required=False, help_text="Leave blank to randomize"
            )
        )
        return BaconConfig(opts)
