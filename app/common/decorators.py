from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity
from app.auth.models import User
from app.auth.services import AuthService

# ---- Helpers ---- #
def _unauthorized_response(message: str, code: int = 403):
    """Standard JSON response for unauthorized/forbidden access"""
    return jsonify({
        "success": False,
        "code": code,
        "message": message
    }), code

def _get_jwt_claims():
    """Verify JWT and return claims"""
    verify_jwt_in_request()
    return get_jwt()

# ---- Decorators ---- #
def roles_required(*required_roles):
    """Restrict route access to users having at least one of the required roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = _get_jwt_claims()
            user_roles = claims.get("roles", [])
            
            if not any(role in user_roles for role in required_roles):
                AuthService.log_audit(
                    user_id=get_jwt_identity(),
                    action="role_denied",
                    resource_type="auth",
                    resource_id=request.path,
                    details={"required_roles": required_roles, "user_roles": user_roles}
                )
                return _unauthorized_response("Insufficient role privileges")

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def permissions_required(*required_permissions):
    """Restrict route access to users having ALL of the required permissions."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = _get_jwt_claims()
            user_permissions = claims.get("permissions", [])
            
            if not all(permission in user_permissions for permission in required_permissions):
                AuthService.log_audit(
                    user_id=get_jwt_identity(),
                    action="permission_denied",
                    resource_type="auth",
                    resource_id=request.path,
                    details={"required_permissions": required_permissions, "user_permissions": user_permissions}
                )
                return _unauthorized_response("Insufficient permissions")

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def superuser_required(fn):
    """Restrict route access to system superusers."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or not user.is_superuser:
            AuthService.log_audit(
                user_id=user_id,
                action="superuser_denied",
                resource_type="auth",
                resource_id=request.path
            )
            return _unauthorized_response("Superuser access required")

        return fn(*args, **kwargs)
    return wrapper
