import json
import logging
import os
from pathlib import Path
import random
import threading
from enum import Enum
from time import sleep
from typing import List, Optional, Type

from ..devices import BaseDevice
from ..io.io_handler import BaconIOInterface
from ..message_formats import GET_PROTO_STRING_FROM_TYPE, PROTOCOLS, Protocol

log = logging.getLogger(__name__)


class JOB_STAGE(Enum):
    """
    Stage of the Job (which is executed by a task)
    """

    RESERVED = 0
    CREATE_INITIAL = 1
    CREATE_MESSAGE_CONFIG = 2
    CREATE_PROTOCOL_CONFIG = 3
    CREATE_READY = 4
    RUNNING = 20
    TERMINATED = 90


JOB_STAGE_DESCRIPTIONS = {
    JOB_STAGE.RESERVED: {"description": "Reserved for future use", "link": "#"},
    JOB_STAGE.CREATE_INITIAL: {"description": "Create", "link": "/create_job"},
    JOB_STAGE.CREATE_MESSAGE_CONFIG: {
        "description": "Message Config",
        "link": "/message_config",
    },
    JOB_STAGE.CREATE_PROTOCOL_CONFIG: {
        "description": "Protocol Config",
        "link": "/protocol_config",
    },
    JOB_STAGE.CREATE_READY: {"description": "Created + Ready", "link": "/"},
    JOB_STAGE.RUNNING: {"description": "Running", "link": "/"},
    JOB_STAGE.TERMINATED: {"description": "Terminated (see task_status)", "link": "/"},
}


class TASK_STATUS(Enum):
    EXIT_SUCCESS = 0
    NOT_STARTED = 1
    RUNNING = 2
    EXITED_BY_USER = 3
    EXIT_ERROR = 4
    EXIT_UNKNOWN = 5
    DELETED = 6


STATUS_ICON_MAP = {
    TASK_STATUS.EXIT_SUCCESS: '<i class="bi bi-check2-square"></i>',
    TASK_STATUS.NOT_STARTED: '<i class="bi bi-hourglass"></i>',
    TASK_STATUS.RUNNING: """
    <div class="spinner-border" role="status">
       <span class="visually-hidden">Running...</span>
    </div>""",
    TASK_STATUS.EXITED_BY_USER: '<i class="bi bi-x-circle"></i>',
    TASK_STATUS.EXIT_ERROR: '<i class="bi bi-exclamation-diamond-fill"></i>',
    TASK_STATUS.EXIT_UNKNOWN: '<i class="bi bi-exclamation-lg"></i>',
    TASK_STATUS.DELETED: '<i class="bi bi-trash"></i>',
}


class FuzzerThread(threading.Thread):
    def __init__(
        self,
        protocol: Protocol,
        selected_msgs: List[str],
        validate: bool,
        config_values: dict,
        io_ifc: Type[BaconIOInterface],
        device: Type[BaseDevice],
    ):
        super().__init__()
        self.protocol = protocol
        self.selected_msgs = selected_msgs
        self.validate = validate
        self.config_values = config_values
        self._io_interface = io_ifc(self.config_values, device)
        self._stop_flag = False
        self.num_crashes = 0
        self.num_msgs_sent = 0
        self.exit_reason = ""
        self.lock = threading.Lock()
        self.status = TASK_STATUS.NOT_STARTED

    def stop_flag(self):
        """
        Helper function for really long running fuzz functions, or those who
        generate random data and then validate.
        """
        return self._stop_flag

    def get_crash_path(self):
        p = (
            "crashes/"
            + f"{GET_PROTO_STRING_FROM_TYPE(self.protocol)}/"
            + f"{self._io_interface.name}/"
            + f"{self.ident}"
        ).lower()
        return os.path.normpath(p.replace(" ", "_"))

    def save_config(self):
        config = {
            "protocol": GET_PROTO_STRING_FROM_TYPE(self.protocol),
            "io_interface": self._io_interface.name,
            "validation": self.validate,
            "msg_types": self.selected_msgs,
            "configuration": self.config_values,
        }
        config_json = json.dumps(config)
        return config_json

    def run(self):
        try:
            if self.protocol is None:
                raise ValueError("No protocol selected!")
            self.status = TASK_STATUS.RUNNING
            self._out_dir = Path(self.get_crash_path())
            self._out_dir.mkdir(exist_ok=True, parents=True)
            # dump config for crash logging
            with open(
                os.path.normpath(self.get_crash_path() + "/config.json"),
                mode="w",
            ) as f:
                f.write(self.save_config())

            # setup IO
            self._io_interface.configure(self.config_values)
            self.protocol.set_logger(self.get_crash_path() + "/crashes.log")
            while not self._stop_flag:
                msg_name = random.choice(self.selected_msgs)
                crash = self.protocol.fuzz_msg(
                    msg_name,
                    self.validate,
                    self.config_values,
                    self._io_interface,
                    self.stop_flag,
                )
                with self.lock:
                    self.num_msgs_sent += 1
                    if crash:
                        self.num_crashes += 1
            with self.lock:
                self._stop_flag = True
                self.status = TASK_STATUS.EXITED_BY_USER
                self.exit_reason = "Job stopped by user"
        except Exception as e:
            self.exit_reason = f"{e}"
            self.status = TASK_STATUS.EXIT_ERROR
        finally:
            try:
                # tear down IO
                self._io_interface.teardown()
            except Exception:
                self.status = TASK_STATUS.EXIT_ERROR

    def stop(self):
        if self.is_alive():
            self._stop_flag = True
            self.exit_reason = "Job stopped by user"
            self.status = TASK_STATUS.EXITED_BY_USER

    def get_num_crashes(self) -> int:
        with self.lock:
            return self.num_crashes

    def get_num_msgs_sent(self) -> int:
        with self.lock:
            return self.num_msgs_sent

    def get_exit_reason(self) -> str:
        with self.lock:
            return self.exit_reason

    def get_status(self) -> TASK_STATUS:
        with self.lock:
            return self.status


class Fuzzer:
    def __init__(self):
        self._threads = []
        self._out_dir = Path("crashes").mkdir(exist_ok=True)

    def is_running(self, job_id: Optional[int] = None) -> bool:
        if job_id is None:
            return any([thread.is_alive() for thread in self._threads])
        return self._threads[job_id].is_alive()

    def get_status(self, job_id: int) -> TASK_STATUS:
        return self._threads[job_id].get_status()

    def get_num_crashes(self, job_id: int) -> int:
        return self._threads[job_id].get_num_crashes()

    def get_num_msgs_sent(self, job_id: int) -> int:
        return self._threads[job_id].get_num_msgs_sent()

    def get_exit_reason(self, job_id) -> str:
        return self._threads[job_id].get_exit_reason()

    def start_job(
        self,
        protocol_name: str,
        selected_msgs: List[str],
        validate: bool,
        config_values: dict,
        io_ifc: Type[BaconIOInterface],
        device: Type[BaseDevice],
    ) -> int:
        """
        Fuzz the specified protocol
        """
        protocol = PROTOCOLS[protocol_name]
        job_id = len(self._threads)
        log.info(f"Starting job for protocol {protocol_name} with ID {job_id}")
        thread = FuzzerThread(
            protocol, selected_msgs, validate, config_values, io_ifc, device
        )
        thread.start()
        self._threads.append(thread)
        return job_id

    def stop_job(self, job_id: int):
        """
        Send stop signal to thread and block until thread stops
        """
        if not self.is_running(job_id):
            return
        log.info(f"Stopping job {job_id}")
        self._threads[job_id].stop()
        while self.is_running(job_id):
            self._threads[job_id].stop()
            sleep(0.1)

        log.info("Job stopped")
