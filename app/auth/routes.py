from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, jsonify, make_response, current_app
)
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, set_access_cookies, set_refresh_cookies, unset_jwt_cookies, get_jwt
)
from sqlalchemy.exc import IntegrityError

from app import db, limiter
from app.auth.forms import LoginForm, RegistrationForm
from app.auth.services import ServiceManager 
from app.auth.models import User, TokenBlacklist
from app.common.decorators import roles_required, permissions_required

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", key_func=lambda: request.remote_addr)
def login():
    """Web login form (JWT-based, cookie storage)"""
    form = LoginForm()

    if request.method == "GET":
        return render_template("auth/login.html", form=form)

    if form.validate_on_submit():
        user, error = ServiceManager.auth.authenticate_user(
            form.identifier.data, form.password.data
        )

        if user:
            # Generate tokens using public_id
            access_token = create_access_token(identity=user.public_id)
            refresh_token = create_refresh_token(identity=user.public_id)

            # Set cookies
            response = make_response(redirect(url_for("home.dashboard")))
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            # Log audit
            ServiceManager.audit.log_audit(
                user_id=user.id,
                action="web_login",
                resource_type="user",
                resource_id=user.public_id,
            )

            flash("Login successful!", "success")
            return response

        flash(error, "danger")

    return render_template("auth/login.html", form=form)



@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", key_func=lambda: request.remote_addr)
def register():
    """Web registration form"""
    form = RegistrationForm()

    if request.method == "GET":
        return render_template("auth/register.html", form=form)

    if form.validate_on_submit():
        try:
            user = ServiceManager.auth.create_user(
                email=form.email.data,
                username=form.username.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                password=form.password.data,
                phone=form.phone.data,
            )

            # Auto-login after registration
            access_token = create_access_token(identity=user.public_id)
            refresh_token = create_refresh_token(identity=user.public_id)

            response = make_response(redirect(url_for("home.dashboard")))
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            flash("Account created successfully!", "success")
            return response

        except ValueError as e:
            flash(str(e), "danger")
            current_app.logger.error(f"Registration failed: {e}")

    return render_template("auth/register.html", form=form)


@auth_bp.route("/logout")
@jwt_required()
def logout():
    """Web logout (revoke + clear cookies)"""
    jti = get_jwt()["jti"]
    identity = get_jwt_identity()

    # Revoke access token
    ServiceManager.revoke_token(jti, identity, "access", "web_logout")

    response = make_response(redirect(url_for("home.index")))
    unset_jwt_cookies(response)

    flash("You have been logged out.", "info")
    return response


@auth_bp.route("/profile")
@jwt_required()
def profile():
    """Web profile page (JWT protected)"""
    identity = get_jwt_identity()
    user = User.query.filter_by(public_id=identity).first()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("auth.login"))

    return render_template("auth/profile.html", user=user)
