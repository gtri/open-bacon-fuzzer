import werkzeug
import werkzeug.exceptions

from .api.api import api_bp
from .bacon_fuzzer_app import app
from .dashboard.dashboard import dashboard_bp, generic_error_handler

# Responsible for registering blueprints and common config

# Blueprint
app.register_blueprint(dashboard_bp)
app.register_blueprint(api_bp)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1000 * 1000
app.register_error_handler(werkzeug.exceptions.HTTPException, generic_error_handler)


def main():
    app.run()
