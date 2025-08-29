import logging
from flask import jsonify
from app.auth.services import AuthService
from app.auth.models import User

logger = logging.getLogger(__name__)

def _error_response(message, status=401):
    """Helper to return standardized error responses."""
    logger.warning(f"JWT error: {message}")
    return jsonify({"error": message}), status


def register_jwt_handlers(jwt):
    """Register all JWT handlers for error handling, identity mapping, and claims."""

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        is_revoked = AuthService.is_token_revoked(jti)
        if is_revoked:
            logger.info(f"Revoked token attempted: jti={jti}, sub={jwt_payload.get('sub')}")
        return is_revoked
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return _error_response("The token has been revoked")

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return _error_response("The token has expired")

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return _error_response("Invalid token")

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return _error_response("Request does not contain an access token")

    @jwt.user_identity_loader
    def user_identity_lookup(identity):
        return identity   
      

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """Defines how to load a user from the JWT payload."""
        identity = jwt_data["sub"]  # subject claim = public_id
        user = User.query.filter_by(public_id=identity).first()
        if not user:
            logger.warning(f"JWT user lookup failed: user public_id {identity} not found")
        return user

    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
        """Add custom claims to access token (roles, permissions, etc.)."""
        user = User.query.filter_by(public_id=identity).first()
        if not user:
            logger.warning(f"Attempted to add claims for non-existent user public_id {identity}")
            return {}
        
        return {
            "roles": [role.name for role in user.roles] if user.roles else [],
            "permissions": AuthService.get_user_permissions(user),
            "is_superuser": getattr(user, "is_superuser", False),
            "public_id": user.public_id,
        }
