import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail

from config import config  # make sure you import your config dict

# Extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address)
csrf = CSRFProtect()
mail = Mail()


def setup_logging(app):
    """Configure logging for the app."""
    log_level = logging.DEBUG if app.debug else logging.INFO
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    app.logger.addHandler(console_handler)

    # File handler (only for production/staging)
    if not app.debug and not app.testing:
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "app.log"),
            maxBytes=5 * 1024 * 1024,  # 5MB per file
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)

    app.logger.setLevel(log_level)
    app.logger.info("Logging is set up.")


def create_app(config_name="default"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    CORS(app, origins=app.config["CORS_ORIGINS"])

    # Setup logging
    setup_logging(app)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.auth.api import auth_api_bp
    from app.home.routes import home_bp


    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(auth_api_bp, url_prefix="/api/auth")
    app.register_blueprint(home_bp)
    # Register error handlers
    from app.common.utils import register_error_handlers
    register_error_handlers(app)

    # JWT configuration
    from app.auth.utils import register_jwt_handlers
    register_jwt_handlers(jwt)

    # CLI commands
    from app.auth.commands import register_commands
    register_commands(app)

    app.logger.info("Flask app created successfully in %s mode.", config_name)

    return app
