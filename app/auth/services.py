from datetime import timedelta
from flask import current_app, request
from app.auth.repositories import RepositoryManager, utcnow
from app.common.validators import validate_phone_number, validate_password_strength, validate_email_address

class AuthService:
    """Business logic layer for authentication and authorization"""

    # -------------------------
    # User lifecycle
    # -------------------------
    @staticmethod
    def create_user(email, username, first_name, last_name, password, phone=None):
        """Create a new user with validation and default role assignment."""
        # Validation
        if not validate_email_address(email):
            raise ValueError("Invalid email format")

        if phone and not validate_phone_number(phone):
            raise ValueError("Invalid phone format")

        if not validate_password_strength(password):
            raise ValueError("Password does not meet security requirements")

        # Check uniqueness
        if RepositoryManager.users.find_by_email(email):
            raise ValueError("User with this email already exists")

        if RepositoryManager.users.find_by_username(username):
            raise ValueError("Username already taken")

        if phone and RepositoryManager.users.find_by_phone(phone):
            raise ValueError("Phone number already registered")

        # Create user
        user_data = {
            'email': email.lower().strip(),
            'username': username.strip(),
            'first_name': first_name.strip(),
            'last_name': last_name.strip(),
            'phone': phone.strip() if phone else None
        }
        
        user = RepositoryManager.users.create(user_data)
        user.set_password(password)

        # Assign default role
        default_role = RepositoryManager.roles.find_default()
        if default_role:
            user.roles.append(default_role)

        RepositoryManager.safe_commit()

        # Audit log
        AuditService.log_audit(
            user_id=user.id,
            action='user_registered',
            resource_type='user',
            resource_id=user.public_id
        )
        return user

    @staticmethod
    def deactivate_user(user, reason=None):
        """Soft-deactivate a user account."""
        RepositoryManager.users.update(user, is_active=False)
        RepositoryManager.safe_commit()
        
        AuditService.log_audit(
            user_id=user.id,
            action='user_deactivated',
            resource_type='user',
            resource_id=user.public_id,
            details=reason
        )
        return user

    @staticmethod
    def reactivate_user(user, reason=None):
        """Reactivate a soft-deactivated user account."""
        RepositoryManager.users.update(user, is_active=True, is_deleted=False)
        RepositoryManager.safe_commit()
        
        AuditService.log_audit(
            user_id=user.id,
            action='user_reactivated',
            resource_type='user',
            resource_id=user.public_id,
            details=reason
        )
        return user

    # -------------------------
    # Authentication
    # -------------------------
    @staticmethod
    def authenticate_user(identifier, password):
        """
        Authenticate by email, username, or phone.
        Returns: (user, error_message) where user is None on failure.
        """
        user = RepositoryManager.users.find_by_identifier(identifier)

        if not user or not user.is_active:
            return None, "Invalid credentials or account inactive"

        if user.locked_until and user.locked_until > utcnow():
            return None, "Account temporarily locked"

        if not user.check_password(password):
            # Failed attempt handling
            user.login_attempts = (user.login_attempts or 0) + 1
            max_attempts = current_app.config.get('MAX_LOGIN_ATTEMPTS', 5)
            lock_minutes = current_app.config.get('LOCKOUT_MINUTES', 30)

            if user.login_attempts >= max_attempts:
                user.locked_until = utcnow() + timedelta(minutes=lock_minutes)
                user.login_attempts = 0

            RepositoryManager.safe_commit()
            
            AuditService.log_audit(
                user_id=user.id,
                action='login_failed',
                resource_type='user',
                resource_id=user.public_id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string if request.user_agent else None,
                details=f"identifier={identifier}"
            )
            return None, "Invalid credentials"

        # Successful login
        user.login_attempts = 0
        user.locked_until = None
        user.last_login = utcnow()
        RepositoryManager.safe_commit()

        AuditService.log_audit(
            user_id=user.id,
            action='login_success',
            resource_type='user',
            resource_id=user.public_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None
        )

        return user, None

    # -------------------------
    # Sessions
    # -------------------------
    @staticmethod
    def create_user_session(user, refresh_token=None, expires_days=30):
        """Create a new session record for the authenticated user."""
        session_data = {
            'user_id': user.id,
            'refresh_token': refresh_token,
            'ip_address': request.remote_addr,
            'user_agent': request.user_agent.string if request.user_agent else None,
            'device_info': request.user_agent.platform if request.user_agent else 'Unknown',
            'expires_at': utcnow() + timedelta(days=expires_days)
        }
        
        session = RepositoryManager.sessions.create(session_data)
        RepositoryManager.safe_commit()

        AuditService.log_audit(
            user_id=user.id,
            action='session_created',
            resource_type='session',
            resource_id=session.session_token,
            ip_address=session.ip_address,
            user_agent=session.user_agent
        )
        return session

    @staticmethod
    def revoke_user_session(session_token):
        """Revoke a single session by token."""
        session = RepositoryManager.sessions.find_by_token(session_token)
        if not session or not session.is_active:
            return None
            
        RepositoryManager.sessions.update(session, is_active=False)
        RepositoryManager.safe_commit()

        AuditService.log_audit(
            user_id=session.user_id,
            action='session_revoked',
            resource_type='session',
            resource_id=session.session_token
        )
        return session

    @staticmethod
    def revoke_all_user_sessions(user):
        """Revoke all active sessions for a user."""
        sessions = RepositoryManager.sessions.find_active_by_user(user.id)
        for session in sessions:
            RepositoryManager.sessions.update(session, is_active=False)
            
        RepositoryManager.safe_commit()

        AuditService.log_audit(
            user_id=user.id,
            action='all_sessions_revoked',
            resource_type='session',
            resource_id=str(user.public_id)
        )
        return sessions

    # -------------------------
    # RBAC Helpers
    # -------------------------
    @staticmethod
    def get_user_roles(user):
        """Return list of role names for a given user."""
        return [role.name for role in user.roles if role.is_active]

    @staticmethod
    def get_user_permissions(user):
        """Return unique list of permission names for a given user via roles."""
        permissions = set()
        for role in user.roles:
            if role.is_active:
                for perm in role.permissions:
                    if perm.is_active:
                        permissions.add(perm.name)
        return list(permissions)

    # -------------------------
    # Token blacklisting
    # -------------------------
    @staticmethod
    def revoke_token(jti, user_id, token_type='access', reason=None, expires_at=None):
        """Persist a revoked token in TokenBlacklist."""
        if not expires_at:
            expires_at = utcnow() + timedelta(days=30)

        token_data = {
            'jti': jti,
            'token_type': token_type,
            'user_id': user_id,
            'expires_at': expires_at,
            'reason': reason
        }
        
        token = RepositoryManager.tokens.create(token_data)
        RepositoryManager.safe_commit()

        AuditService.log_audit(
            user_id=user_id,
            action='token_revoked',
            resource_type='token',
            resource_id=jti,
            details=reason
        )
        return token

    @staticmethod
    def is_token_revoked(jti):
        """Return True if token jti is present and not yet expired in blacklist."""
        token = RepositoryManager.tokens.find_by_jti(jti)
        if not token:
            return False
        return token.expires_at > utcnow()

    @staticmethod
    def purge_expired_blacklisted_tokens():
        """Cleanup expired blacklist tokens."""
        expired_tokens = RepositoryManager.tokens.find_expired()
        for token in expired_tokens:
            RepositoryManager.tokens.delete(token)
            
        RepositoryManager.safe_commit()
        return len(expired_tokens)

class RoleService:
    """Business logic for role management"""
    
    @staticmethod
    def create_role(name, description=None, is_default=False):
        if RepositoryManager.roles.find_by_name(name):
            raise ValueError(f"Role '{name}' already exists")
            
        role = RepositoryManager.roles.create({
            'name': name,
            'description': description,
            'is_default': is_default
        })
        RepositoryManager.safe_commit()
        
        AuditService.log_audit(
            action='role_created',
            resource_type='role',
            resource_id=name
        )
        return role

    @staticmethod
    def assign_role_to_user(user, role_name):
        role = RepositoryManager.roles.find_by_name(role_name)
        if not role or not role.is_active:
            raise ValueError(f"Role '{role_name}' does not exist or is inactive")
            
        if role not in user.roles:
            user.roles.append(role)
            RepositoryManager.safe_commit()
            
            AuditService.log_audit(
                user_id=user.id,
                action='role_assigned',
                resource_type='user',
                resource_id=user.public_id,
                details=f"Role: {role_name}"
            )

class PermissionService:
    """Business logic for permission management"""
    
    @staticmethod
    def create_permission(name, description=None, category='general'):
        if RepositoryManager.permissions.find_by_name(name):
            raise ValueError(f"Permission '{name}' already exists")
            
        permission = RepositoryManager.permissions.create({
            'name': name,
            'description': description,
            'category': category
        })
        RepositoryManager.safe_commit()
        
        AuditService.log_audit(
            action='permission_created',
            resource_type='permission',
            resource_id=name
        )
        return permission

class AuditService:
    """Business logic for audit logging"""
    
    @staticmethod
    def log_audit(user_id=None, action=None, resource_type=None, resource_id=None,
                  ip_address=None, user_agent=None, details=None):
        """Create an audit log entry with safe error handling."""
        try:
            audit_data = {
                'user_id': user_id,
                'action': action,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'ip_address': ip_address or (request.remote_addr if request else None),
                'user_agent': user_agent or (request.user_agent.string if request.user_agent else None),
                'details': details
            }
            
            audit_log = RepositoryManager.audit_logs.create(audit_data)
            RepositoryManager.safe_commit()
            return audit_log
            
        except Exception:
            # Don't block main flows if audit logging fails
            current_app.logger.exception("Failed to write audit log")
            return None

    @staticmethod
    def get_user_audit_logs(user_id, limit=100):
        """Get audit logs for a specific user"""
        return RepositoryManager.audit_logs.find_by_user(user_id, limit)

# Service access manager
class ServiceManager:
    """Centralized access to all services"""
    
    auth = AuthService
    roles = RoleService
    permissions = PermissionService
    audit = AuditService
    repository = RepositoryManager
