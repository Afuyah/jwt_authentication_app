import os
from app import create_app
from app.auth.models import db, User, Role, Permission
from app.auth.services import AuthService

# Load config from environment or fallback
config_name = os.getenv("FLASK_CONFIG", "default")
app = create_app(config_name)

# Add useful objects to Flask shell
@app.shell_context_processor
def make_shell_context():
    return {
        "db": db,
        "User": User,
        "Role": Role,
        "Permission": Permission,
        "AuthService": AuthService,
    }

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_RUN_HOST", "0.0.0.0"),
        port=int(os.getenv("FLASK_RUN_PORT", 5000)),
        debug=app.config["DEBUG"],
    )
