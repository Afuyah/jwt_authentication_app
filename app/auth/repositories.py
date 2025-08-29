from datetime import datetime, timezone
from app import db
from app.auth.models import User, Role, Permission, UserSession, TokenBlacklist, AuditLog

def utcnow():
    return datetime.now(timezone.utc)

class UserRepository:
    @staticmethod
    def find_by_id(user_id):
        return User.query.get(user_id)

    @staticmethod
    def find_by_email(email):
        return User.query.filter_by(email=email.lower().strip()).first()

    @staticmethod
    def find_by_username(username):
        return User.query.filter_by(username=username.strip()).first()

    @staticmethod
    def find_by_phone(phone):
        return User.query.filter_by(phone=phone.strip()).first()

    @staticmethod
    def find_by_identifier(identifier):
        return User.query.filter(
            (User.email == identifier) |
            (User.username == identifier) |
            (User.phone == identifier)
        ).first()

    @staticmethod
    def create(user_data):
        user = User(**user_data)
        db.session.add(user)
        return user

    @staticmethod
    def update(user, **kwargs):
        for key, value in kwargs.items():
            setattr(user, key, value)
        return user

    @staticmethod
    def delete(user):
        db.session.delete(user)

    @staticmethod
    def count():
        return User.query.count()

class RoleRepository:
    @staticmethod
    def find_by_id(role_id):
        return Role.query.get(role_id)

    @staticmethod
    def find_by_name(name):
        return Role.query.filter_by(name=name).first()

    @staticmethod
    def find_default():
        return Role.query.filter_by(is_default=True, is_active=True).first()

    @staticmethod
    def find_all_active():
        return Role.query.filter_by(is_active=True).all()

    @staticmethod
    def create(role_data):
        role = Role(**role_data)
        db.session.add(role)
        return role

    @staticmethod
    def delete(role):
        db.session.delete(role)

class PermissionRepository:
    @staticmethod
    def find_by_id(permission_id):
        return Permission.query.get(permission_id)

    @staticmethod
    def find_by_name(name):
        return Permission.query.filter_by(name=name).first()

    @staticmethod
    def find_all_active():
        return Permission.query.filter_by(is_active=True).all()

    @staticmethod
    def create(permission_data):
        permission = Permission(**permission_data)
        db.session.add(permission)
        return permission

class SessionRepository:
    @staticmethod
    def find_by_token(session_token):
        return UserSession.query.filter_by(session_token=session_token).first()

    @staticmethod
    def find_active_by_user(user_id):
        return UserSession.query.filter_by(user_id=user_id, is_active=True).all()

    @staticmethod
    def create(session_data):
        session = UserSession(**session_data)
        db.session.add(session)
        return session

    @staticmethod
    def delete(session):
        db.session.delete(session)

class TokenBlacklistRepository:
    @staticmethod
    def find_by_jti(jti):
        return TokenBlacklist.query.filter_by(jti=jti).first()

    @staticmethod
    def find_expired():
        return TokenBlacklist.query.filter(TokenBlacklist.expires_at <= utcnow()).all()

    @staticmethod
    def create(token_data):
        token = TokenBlacklist(**token_data)
        db.session.add(token)
        return token

    @staticmethod
    def delete(token):
        db.session.delete(token)

class AuditLogRepository:
    @staticmethod
    def create(audit_data):
        audit_log = AuditLog(**audit_data)
        db.session.add(audit_log)
        return audit_log

    @staticmethod
    def find_by_user(user_id, limit=100):
        return AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.created_at.desc()).limit(limit).all()

class RepositoryManager:
    """Centralized access to all repositories"""
    
    users = UserRepository
    roles = RoleRepository
    permissions = PermissionRepository
    sessions = SessionRepository
    tokens = TokenBlacklistRepository
    audit_logs = AuditLogRepository

    @staticmethod
    def commit():
        """Commit the current DB transaction"""
        db.session.commit()

    @staticmethod
    def rollback():
        """Rollback the current DB transaction"""
        db.session.rollback()

    @staticmethod
    def safe_commit():
        """Commit with error handling"""
        try:
            db.session.commit()
            return True
        except Exception as exc:
            db.session.rollback()
            from flask import current_app
            current_app.logger.exception("DB commit failed")
            raise
