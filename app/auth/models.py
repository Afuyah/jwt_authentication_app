from app import db
from datetime import datetime, timezone
import uuid

def utcnow():
    return datetime.now(timezone.utc)


class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self, soft=True):
        if soft:
            self.is_deleted = True
            self.is_active = False
        else:
            db.session.delete(self)
        db.session.commit()

    def restore(self):
        self.is_deleted = False
        self.is_active = True
        db.session.commit()

    def to_dict(self):
        """Serialize model to dictionary"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class User(BaseModel):
    __tablename__ = 'users'
    
    public_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(64), nullable=False)
    last_name = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_superuser = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime, default=utcnow)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Relationships
    roles = db.relationship('Role', secondary='user_roles', backref=db.backref('users', lazy='dynamic'))
    sessions = db.relationship('UserSession', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        from app import bcrypt
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.last_password_change = utcnow()
    
    def check_password(self, password):
        from app import bcrypt
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name):
        return any(
            any(permission.name == permission_name for permission in role.permissions)
            for role in self.roles
        )
    
    def get_all_permissions(self):
        return list({p.name for r in self.roles for p in r.permissions})


class Role(BaseModel):
    __tablename__ = 'roles'
    
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255))
    is_default = db.Column(db.Boolean, default=False)

    # Relationships
    permissions = db.relationship('Permission', secondary='role_permissions', backref=db.backref('roles', lazy='dynamic'))
    
    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(BaseModel):
    __tablename__ = 'permissions'
    
    name = db.Column(db.String(64), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255))
    category = db.Column(db.String(64), default='general')
    
    def __repr__(self):
        return f'<Permission {self.name}>'


# Association tables
user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=utcnow)
)

role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True),
    db.Column('assigned_at', db.DateTime, default=utcnow)
)


class UserSession(BaseModel):
    __tablename__ = 'user_sessions'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    session_token = db.Column(db.String(64), unique=True, default=lambda: uuid.uuid4().hex)
    refresh_token = db.Column(db.String(64), unique=True, nullable=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    device_info = db.Column(db.String(255))
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=utcnow)
    
    def __repr__(self):
        return f'<UserSession {self.session_token}>'


class TokenBlacklist(BaseModel):
    __tablename__ = 'token_blacklist'
    
    jti = db.Column(db.String(36), nullable=False, index=True)
    token_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    revoked_at = db.Column(db.DateTime, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<TokenBlacklist {self.jti}>'


class AuditLog(BaseModel):
    __tablename__ = 'audit_logs'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    resource_type = db.Column(db.String(64), index=True)
    resource_id = db.Column(db.String(36))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    details = db.Column(db.Text)
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.user_id}>'
