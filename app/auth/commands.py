import click
from flask.cli import with_appcontext
from app import db
from app.auth.models import User, Role, Permission
from app.auth.services import AuthService

def register_commands(app):
    @app.cli.group()
    def auth():
        """Authentication management commands."""
        pass
    
    @auth.command()
    @click.argument('email')
    @click.argument('username')
    @click.argument('first_name')
    @click.argument('last_name')
    @click.argument('password')
    @with_appcontext
    def create_user(email, username, first_name, last_name, password):
        """Create a new user."""
        try:
            user = AuthService.create_user(
                email=email,
                username=username,
                first_name=first_name,
                last_name=last_name,
                password=password
            )
            print(f"User created successfully: {user.email}")
        except ValueError as e:
            print(f"Error: {e}")
    
    @auth.command()
    @click.argument('email')
    @with_appcontext
    def make_admin(email):
        """Make a user an administrator."""
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"User with email {email} not found")
            return
        
        # Create or get admin role
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = AuthService.create_role('admin', 'System Administrator')
        
        # Assign admin role
        AuthService.assign_role_to_user(user, 'admin')
        print(f"User {email} is now an administrator")
    
    @auth.command()
    @click.argument('name')
    @click.argument('description')
    @with_appcontext
    def create_role(name, description):
        """Create a new role."""
        try:
            role = AuthService.create_role(name, description)
            print(f"Role created successfully: {role.name}")
        except ValueError as e:
            print(f"Error: {e}")
    
    @auth.command()
    @click.argument('name')
    @click.argument('description')
    @with_appcontext
    def create_permission(name, description):
        """Create a new permission."""
        try:
            permission = AuthService.create_permission(name, description)
            print(f"Permission created successfully: {permission.name}")
        except ValueError as e:
            print(f"Error: {e}")
    
    @auth.command()
    @click.argument('role_name')
    @click.argument('permission_name')
    @with_appcontext
    def assign_permission(role_name, permission_name):
        """Assign a permission to a role."""
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            print(f"Role {role_name} not found")
            return
        
        try:
            AuthService.assign_permission_to_role(role, permission_name)
            print(f"Permission {permission_name} assigned to role {role_name}")
        except ValueError as e:
            print(f"Error: {e}")