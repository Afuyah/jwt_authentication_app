from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter.util import get_remote_address

from app import db, limiter
from app.auth.services import ServiceManager
from app.auth.models import User, TokenBlacklist
from app.common.decorators import roles_required, permissions_required

auth_api_bp = Blueprint("auth_api", __name__)

@auth_api_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute", key_func=get_remote_address)
def api_login():
    """
    JWT login endpoint.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    identifier = data.get("identifier")
    password = data.get("password")

    if not identifier or not password:
        return jsonify({"error": "Identifier and password are required"}), 400

    user, error = ServiceManager.auth.authenticate_user(identifier=identifier, password=password)

    if not user:
        current_app.logger.warning(f"Failed login attempt for {identifier}")
        return jsonify({"error": error}), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    # Log audit event
    ServiceManager.audit.log_audit(
        user_id=user.id,
        action="api_login",
        resource_type="user",
        resource_id=user.public_id
    )

    current_app.logger.info(f"User {user.email} logged in via API")
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.public_id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
        }
    }), 200

@auth_api_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute", key_func=get_remote_address)
def api_register():
    """
    JWT registration endpoint.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    required_fields = ['email', 'username', 'first_name', 'last_name', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    try:
        user = ServiceManager.auth.create_user(
            email=data.get("email"),
            username=data.get("username"),
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            password=data.get("password"),
            phone=data.get("phone"),
        )

        # Generate tokens for immediate login
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        current_app.logger.info(f"New user registered: {user.email}")
        return jsonify({
            "message": "Account created successfully!",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.public_id,
                "email": user.email,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }), 201

    except ValueError as e:
        current_app.logger.error(f"Registration failed: {e}")
        return jsonify({"error": str(e)}), 400

@auth_api_bp.route("/logout", methods=["POST"])
@jwt_required()
def api_logout():
    """
    JWT logout endpoint (blacklists token).
    """
    jti = get_jwt()["jti"]
    user_id = get_jwt_identity()

    # Revoke the token
    ServiceManager.auth.revoke_token(jti, user_id, 'access', 'user_logout')

    ServiceManager.auth.log_audit(
        user_id=user_id,
        action="api_logout",
        resource_type="user",
        resource_id=user_id
    )

    current_app.logger.info(f"User {user_id} logged out via API")
    return jsonify({"message": "Successfully logged out"}), 200

@auth_api_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def api_refresh():
    """
    Refresh JWT token.
    """
    current_user_id = get_jwt_identity()
    new_token = create_access_token(identity=current_user_id)
    return jsonify({"access_token": new_token}), 200

@auth_api_bp.route("/profile", methods=["GET"])
@jwt_required()
def api_profile():
    """
    Profile endpoint (JWT protected).
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": {
            "id": user.public_id,
            "email": user.email,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "phone": user.phone,
            "is_verified": user.is_verified,
            "created_at": user.created_at.isoformat(),
            "roles": [role.name for role in user.roles],
            "permissions": user.get_all_permissions()
        }
    }), 200

@auth_api_bp.route("/change-password", methods=["POST"])
@jwt_required()
def api_change_password():
    """
    Change user password.
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not data.get('current_password') or not data.get('new_password'):
        return jsonify({"error": "Current and new password are required"}), 400
    
    user = User.query.get(user_id)
    
    if not user or not user.check_password(data['current_password']):
        return jsonify({"error": "Current password is incorrect"}), 400
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    # Log password change
    ServiceManager.auth.log_audit(
        user_id=user.id,
        action='password_changed',
        resource_type='user',
        resource_id=user.public_id
    )
    
    return jsonify({"message": "Password updated successfully"}), 200
