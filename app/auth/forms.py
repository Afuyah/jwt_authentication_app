from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.auth.models import User
from app.common.validators import validate_phone_number, validate_password_strength, validate_email_address

class LoginForm(FlaskForm):
    identifier = StringField('Email, Username, or Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    phone = StringField('Phone Number', validators=[Length(min=10, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email_address(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken.')

    def validate_phone_number(self, field):
        if field.data and User.query.filter_by(phone=field.data).first():
            raise ValidationError('Phone number already registered.')
        
        if field.data and not validate_phone_number(field.data):
            raise ValidationError('Invalid phone number format.')

    def validate_password_strength(self, field):
        if not validate_password_strength(field.data):
            raise ValidationError('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.')