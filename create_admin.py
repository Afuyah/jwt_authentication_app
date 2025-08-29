#!/usr/bin/env python3
import os
import sys
from app import create_app, db
from app.auth.models import User, Role, Permission
from app.auth.services import AuthService

def create_default_data():
    app = create_app()
    
    with app.app_context():
        # Create default roles
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = AuthService.create_role('admin', 'System Administrator')
        
        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            user_role = AuthService.create_role('user', 'Regular User', is_default=True)
        
        # Create default permissions
        permissions = [
            ('view_dashboard', 'View dashboard'),
            ('manage_users', 'Manage users'),
            ('manage_roles', 'Manage roles'),
            ('view_reports', 'View reports'),
            ('edit_content', 'Edit content')
        ]
        
        for perm_name, perm_desc in permissions:
            if not Permission.query.filter_by(name=perm_name).first():
                AuthService.create_permission(perm_name, perm_desc)
        
        # Assign permissions to admin role
        admin_permissions = ['manage_users', 'manage_roles', 'view_reports', 'view_dashboard']
        for perm_name in admin_permissions:
            AuthService.assign_permission_to_role(admin_role, perm_name)
        
        # Assign permissions to user role
        user_permissions = ['view_dashboard', 'edit_content']
        for perm_name in user_permissions:
            AuthService.assign_permission_to_role(user_role, perm_name)
        
        db.session.commit()
        print("Default roles and permissions created successfully!")

if __name__ == '__main__':
    create_default_data()