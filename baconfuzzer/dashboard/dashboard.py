import json
from http import HTTPStatus
from io import BytesIO
import os
from typing import Tuple

import werkzeug
import werkzeug.exceptions
from flask import (
    Blueprint,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    send_from_directory,
)

from baconfuzzer.devices import DEVICES
from baconfuzzer.fuzzer.fuzzer import JOB_STAGE, JOB_STAGE_DESCRIPTIONS, STATUS_ICON_MAP
from baconfuzzer.io import IOINTERFACES

from ..bacon_fuzzer_app import app
from ..message_formats import PROTOCOLS

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    static_folder="../static",
    template_folder="./templates",
)

"""
This dict stores UI/path info for the front end
"""
main_nav = [
    {"name": "Dashboard", "page_route": "dashboard_main", "icon": "piggy-bank"},
    {
        "name": "Create New Job",
        "page_route": "create_job",
        "icon": "plus-circle-dotted",
    },
    {"name": "Upload a Saved Job", "page_route": "upload_job", "icon": "upload"},
    {"name": "About Bacon", "page_route": "about", "icon": "info-circle"},
]

"""
this list controls if the validation option is available through
the UI
"""
messages_with_validation_logic = []


# determine which message types implement validation
def identify_validation_configs():
    for p_name, p in PROTOCOLS.items():
        try:
            p.validate_msg(None, None)
        except NotImplementedError:
            continue  # don't add it
        except Exception:
            pass
        messages_with_validation_logic.append(str(p_name).lower())


identify_validation_configs()
# lookup for related routes on UI "active" indicator
related_page_routes = {
    "create_job": ["dashboard.message_config", "dashboard.protocol_config"]
}


def build_error_page(
    error_text: str, status_code: HTTPStatus, details=""
) -> Tuple[str, HTTPStatus]:
    return (
        render_template(
            "error.html",
            error_text=error_text,
            status_code=status_code,
            details=details,
            title=f"Error {status_code}",
        ),
        status_code,
    )


@dashboard_bp.context_processor
def inject_dashboard_ctx():
    return dict(
        main_nav=main_nav,
        related_page_routes=related_page_routes,
        STATUS_ICON_MAP=STATUS_ICON_MAP,
        messages_with_validation_logic=messages_with_validation_logic,
    )


@app.context_processor
def inject_app_ctx():
    return dict(
        main_nav=main_nav,
        related_page_routes=related_page_routes,
        STATUS_ICON_MAP=STATUS_ICON_MAP,
        messages_with_validation_logic=messages_with_validation_logic,
    )


def generic_error_handler(e):
    try:
        return build_error_page(
            error_text=e.name, status_code=e.code, details=e.description
        )
    except Exception:
        return "something went wrong"


# ----- Dashboard -----
@dashboard_bp.route("/dashboard_main")
@dashboard_bp.route("/")
def dashboard_main():
    for job_id, job in app.job_data.items():
        job["is_running"] = app.fuzzer.is_running(job_id)
        job["num_crashes"] = app.fuzzer.get_num_crashes(job_id)
        job["num_msgs_sent"] = app.fuzzer.get_num_msgs_sent(job_id)
        job["exit_reason"] = app.fuzzer.get_exit_reason(job_id)
        job["status"] = app.fuzzer.get_status(job_id)
    job_data_values = list(app.job_data.values())
    return render_template(
        "index.html", job_data=job_data_values, is_running=app.fuzzer.is_running()
    )


# ----- Job creation -----
@dashboard_bp.route("/create_job")
def create_job():
    protocol_options = [name for name in PROTOCOLS]
    io_options = [io for io in IOINTERFACES]
    devices = [dev for dev in DEVICES]
    return render_template(
        "create_job.html",
        prot_choices=protocol_options,
        io_choices=io_options,
        device_choices=devices,
        JOB_STAGES=JOB_STAGE,
        JOB_STAGE_DESCRIPTIONS=JOB_STAGE_DESCRIPTIONS,
    )


@dashboard_bp.route("/message_config", methods=["POST"])
def message_config():
    protocol_name = request.form.get("protocol")
    if protocol_name not in PROTOCOLS:
        return build_error_page(
            "Invalid protocol name provided.", HTTPStatus.BAD_REQUEST
        )
    protocol = PROTOCOLS[protocol_name]
    io_interface_name = request.form.get("io_interface")
    if io_interface_name not in IOINTERFACES:
        return build_error_page("Invalid interface provided.")
    device_name = request.form.get("device")
    if device_name not in DEVICES:
        return build_error_page("Invalid device provided.")
    validate = request.form.get("validate")

    comment = request.form.get("comment", "")

    return render_template(
        "message_config.html",
        protocol=protocol,
        protocol_name=protocol_name,
        io_interface_name=io_interface_name,
        device_name=device_name,
        validate=validate,
        comment=comment,
        JOB_STAGES=JOB_STAGE,
        JOB_STAGE_DESCRIPTIONS=JOB_STAGE_DESCRIPTIONS,
    )


@dashboard_bp.route("/protocol_config", methods=["POST"])
def protocol_config():
    protocol_name = request.form.get("protocol")
    if protocol_name not in PROTOCOLS:
        return build_error_page(
            "Invalid protocol name provided.", HTTPStatus.BAD_REQUEST
        )
    io_interface_name = request.form.get("io_interface")
    if io_interface_name not in IOINTERFACES:
        return build_error_page(
            "Invalid IO Interface name provided.", HTTPStatus.BAD_REQUEST
        )
    device_name = request.form.get("device")
    if device_name not in DEVICES:
        return build_error_page("Invalid device provided.", HTTPStatus.BAD_REQUEST)

    protocol = PROTOCOLS[protocol_name]
    selected_msgs = []
    for msg_name in protocol.get_msg_names():
        msg_check_value = request.form.get(msg_name)
        if msg_check_value == "on":
            selected_msgs.append(msg_name)
    if len(selected_msgs) == 0:
        return build_error_page("No message types selected", HTTPStatus.BAD_REQUEST)

    comment = request.form.get("comment", "")

    validate = request.form.get("validate")
    io_config = IOINTERFACES[io_interface_name].get_config_opts(selected_msgs, protocol)
    return render_template(
        "protocol_config.html",
        selected_msgs=selected_msgs,
        io_config=io_config,
        protocol_name=protocol_name,
        io_interface_name=io_interface_name,
        device_name=device_name,
        validate=validate,
        comment=comment,
        JOB_STAGES=JOB_STAGE,
        JOB_STAGE_DESCRIPTIONS=JOB_STAGE_DESCRIPTIONS,
    )


def start_fuzzer_job(
    protocol_name,
    io_interface_name,
    device_name,
    validate,
    selected_msgs,
    proto_config,
    comment,
):
    job_id = app.fuzzer.start_job(
        protocol_name,
        selected_msgs,
        validate,
        proto_config,
        IOINTERFACES[io_interface_name],
        DEVICES[device_name],
    )
    job_data = {
        "job_id": job_id,
        "is_running": True,
        "num_crashes": 0,
        "num_msgs_sent": 0,
        "protocol": protocol_name,
        "io_interface": io_interface_name,
        "device": device_name,
        "validate": validate,
        "selected_msgs": selected_msgs,
        "protocol_config": proto_config,
        "comment": comment,
    }
    app.job_data[job_id] = job_data


@dashboard_bp.route("/start", methods=["POST"])
def start():
    protocol_name = request.form.get("_protocol")
    if protocol_name not in PROTOCOLS:
        return build_error_page(
            "Invalid protocol name provided.", HTTPStatus.BAD_REQUEST
        )
    io_interface_name = request.form.get("io_interface")
    if io_interface_name not in IOINTERFACES:
        return build_error_page(
            "Invalid IO Interface name provided.", HTTPStatus.BAD_REQUEST
        )
    device_name = request.form.get("device")
    if device_name not in DEVICES:
        return build_error_page("Invalid device provided.", HTTPStatus.BAD_REQUEST)

    protocol = PROTOCOLS[protocol_name]
    validate = request.form.get("validate") == "on"
    selected_msgs = request.form.get("_selected_msgs").split(",")
    if len(selected_msgs) == 0:
        return build_error_page("No message types selected", HTTPStatus.BAD_REQUEST)

    comment = request.form.get("comment", "")

    io_config = IOINTERFACES[io_interface_name].get_config_opts(selected_msgs, protocol)
    config_values = io_config.parse_form(request.form)
    start_fuzzer_job(
        protocol_name,
        io_interface_name,
        device_name,
        validate,
        selected_msgs,
        config_values,
        comment,
    )
    return redirect(url_for("dashboard.dashboard_main"))


@dashboard_bp.route("/upload_job")
def upload_job():
    return render_template("upload_job.html")


def validate_job_config(config: dict) -> bool:
    if "protocol" not in config:
        return False
    protocol_name = config["protocol"]
    if protocol_name not in PROTOCOLS:
        return False

    if "io_interface" not in config:
        return False
    io_interface = config["io_interface"]
    if io_interface not in IOINTERFACES:
        return False

    if "device" not in config:
        return False
    device_name = config["device"]
    if device_name not in DEVICES:
        return False

    if "validate" not in config:
        return False

    if "msg_types" not in config or not isinstance(config["msg_types"], list):
        return False
    protocol_obj = PROTOCOLS[protocol_name]
    all_msg_types = protocol_obj.get_msg_names()
    msg_types = config["msg_types"]
    if len(msg_types) == 0:
        return False
    for msg_type in msg_types:
        if msg_type not in all_msg_types:
            return False

    if "protocol_config" not in config or not isinstance(
        config["protocol_config"], dict
    ):
        return False
    proto_config = config["protocol_config"]
    for config_item in protocol_obj.get_config(msg_types, io_interface).item_names:
        if config_item not in proto_config:
            return False
    return True


@dashboard_bp.route("/validate-upload", methods=["POST"])
def validate_upload():
    if "config-file" not in request.files:
        return build_error_page("File is missing.", HTTPStatus.BAD_REQUEST)
    file = request.files["config-file"]
    if file.filename == "":
        return build_error_page("File is missing.", HTTPStatus.BAD_REQUEST)
    try:
        config = json.load(file.stream)
    except Exception:
        return build_error_page(
            "Invalid file. File must be in json format.", HTTPStatus.BAD_REQUEST
        )
    if not validate_job_config(config):
        return build_error_page(
            "Invalid config file. Ensure all fields are present and correct.",
            HTTPStatus.BAD_REQUEST,
        )
    start_fuzzer_job(
        config["protocol"],
        config["io_interface"],
        config["device"],
        config["validate"],
        config["msg_types"],
        config["protocol_config"],
        config["comment"],
    )
    return redirect(url_for("dashboard.dashboard_main"))


# ----- Job management -----
@dashboard_bp.route("/stop", methods=["GET"])
def stop():
    try:
        job_id = int(request.args["job_id"])
        app.fuzzer.stop_job(job_id)
        return redirect(url_for("dashboard.dashboard_main"))
    except Exception:
        raise werkzeug.exceptions.Gone


@dashboard_bp.route("/remove", methods=["GET"])
def remove():
    try:
        job_id = int(request.args["job_id"])
        app.job_data.pop(job_id)
        return redirect(url_for("dashboard.dashboard_main"))
    except Exception:
        raise werkzeug.exceptions.Gone


@dashboard_bp.route("/save", methods=["GET"])
def save():
    job_id = int(request.args["job_id"])
    data = app.job_data[job_id]
    config = {
        "protocol": data["protocol"],
        "io_interface": data["io_interface"],
        "device": data["device"],
        "validate": data["validate"],
        "msg_types": data["selected_msgs"],
        "protocol_config": data["protocol_config"],
        "comment": data["comment"],
    }
    config_json = json.dumps(config)
    return send_file(
        BytesIO(config_json.encode()),
        as_attachment=True,
        download_name="bacon_job_config.json",
    )


# ----- Misc -----
@dashboard_bp.route("/about", methods=["GET"])
def about():
    return render_template("about.html")


# ----- Crash Download -----
# Creating the crash folder
crashes_folder = "crashes/"
if not os.path.exists(crashes_folder):
    os.mkdir(crashes_folder)

app.config["CRASHES_FOLDER"] = crashes_folder


@dashboard_bp.route("/crashes/<id>", methods=["GET"])
def get_crashes(id: int):
    try:
        # get job thread info:
        my_thread = app.fuzzer._threads[int(id)]
        return send_from_directory(
            "../" + my_thread.get_crash_path() + "/",
            "crashes.log",
        )
    except Exception as e:
        return build_error_page(
            "Could not fetch crash info", HTTPStatus.BAD_REQUEST, str(e)
        )
