import logging
from logging.handlers import RotatingFileHandler
from flask import jsonify, request
from flask_jwt_extended.exceptions import JWTExtendedException

def register_error_handlers(app):
    def error_response(status_code, message, detail=None):
        response = {
            "success": False,
            "error": {
                "code": status_code,
                "message": message,
            }
        }
        if detail:
            response["error"]["detail"] = detail
        return jsonify(response), status_code

    # JWT-specific errors
    @app.errorhandler(JWTExtendedException)
    def handle_jwt_errors(error):
        app.logger.warning(f"JWT Error: {error}")
        return error_response(401, "Token error", str(error))

    @app.errorhandler(400)
    def bad_request(error):
        return error_response(400, "Bad request")

    @app.errorhandler(401)
    def unauthorized(error):
        return error_response(401, "Unauthorized")

    @app.errorhandler(403)
    def forbidden(error):
        return error_response(403, "Forbidden")

    @app.errorhandler(404)
    def not_found(error):
        return error_response(404, "Resource not found")

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        retry_after = getattr(error, "description", None)
        detail = f"Try again in {retry_after} seconds" if retry_after else None
        return error_response(429, "Rate limit exceeded", detail)

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(
            f"500 Internal Server Error: {error}, "
            f"Path: {request.path}, Method: {request.method}"
        )
        return error_response(500, "Internal server error")

    # Catch-all handler for unhandled exceptions
    @app.errorhandler(Exception)
    def unhandled_exception(error):
        app.logger.exception(f"Unhandled Exception: {error}")
        return error_response(500, "An unexpected error occurred")


def setup_logging(app):
    log_level = logging.DEBUG if app.config.get("DEBUG", False) else logging.INFO
    app.logger.setLevel(log_level)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
    )

    # Stream handler (console)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)
    app.logger.addHandler(stream_handler)

    # Rotating file handler (only in production)
    if not app.config.get("DEBUG", False):
        file_handler = RotatingFileHandler(
            "app.log", maxBytes=5 * 1024 * 1024, backupCount=5
        )
        file_handler.setLevel(logging.WARNING)  # log warnings and errors
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
