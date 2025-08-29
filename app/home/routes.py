from flask import render_template, redirect, url_for, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.home import home_bp
from app.auth.models import User

@home_bp.route('/')
def index():
    """Landing page for unauthorized users"""
    # For JWT projects, we can’t use current_user
    # Instead, just return a public landing page
    return render_template('home/index.html', title='Home')


@home_bp.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    public_id = get_jwt_identity()
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    return render_template("home/dashboard.html", user=user)



@home_bp.route('/about')
def about():
    """About page"""
    return render_template('home/about.html', title='About')
