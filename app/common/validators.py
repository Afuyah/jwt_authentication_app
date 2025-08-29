import re
import phonenumbers
import logging
from email_validator import validate_email as lib_validate_email, EmailNotValidError

logger = logging.getLogger(__name__)

# ---------------------------
# Detailed Validators
# ---------------------------
def validate_email_address(email: str):
    """Validate email using email_validator library."""
    try:
        valid = lib_validate_email(email)
        logger.debug(f"Validated email: {valid.email}")
        return True, valid.email
    except EmailNotValidError as e:
        logger.warning(f"Invalid email attempted: {email} | Error: {e}")
        return False, "Invalid email address"


def validate_phone_number(phone: str):
    """Validate international phone number format using phonenumbers."""
    try:
        parsed = phonenumbers.parse(phone, None)
        if phonenumbers.is_valid_number(parsed):
            formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            logger.debug(f"Validated phone: {formatted}")
            return True, formatted
        logger.warning(f"Invalid phone number: {phone}")
        return False, "Invalid phone number"
    except Exception as e:
        logger.error(f"Phone validation error for {phone}: {e}")
        return False, "Invalid phone number format"


def validate_password_strength(password: str):
    """
    Validate password strength:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter  
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    logger.debug("Password strength validated successfully")
    return True, "Password is strong"


# ---------------------------
# Simplified (Boolean only) Validators
# ---------------------------
def is_valid_email(email: str) -> bool:
    try:
        lib_validate_email(email)
        return True
    except EmailNotValidError:
        return False


def is_valid_phone(phone: str) -> bool:
    try:
        parsed = phonenumbers.parse(phone, None)
        return phonenumbers.is_valid_number(parsed)
    except Exception:
        return False


def is_valid_password(password: str) -> bool:
    """Quick password check (boolean only)."""
    return (
        len(password) >= 8
        and re.search(r'[A-Z]', password)
        and re.search(r'[a-z]', password)
        and re.search(r'[0-9]', password)
        and re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )
