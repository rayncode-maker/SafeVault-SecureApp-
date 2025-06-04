from functools import wraps
from flask import request, session
import jwt
from datetime import datetime, timedelta

SECRET_KEY = "your_secure_key_here"  # Store in env vars in production

# User roles
ROLES = {
    'admin': 3,
    'editor': 2,
    'user': 1
}

def hash_password(password):
    """Bcrypt password hashing"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(stored_hash, input_password):
    """Secure password verification"""
    return bcrypt.checkpw(input_password.encode(), stored_hash)

def generate_token(user_id, role):
    """JWT token generation"""
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def role_required(required_role):
    """RBAC decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                abort(401)
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                if ROLES.get(payload['role'], 0) < ROLES[required_role]:
                    abort(403)
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                abort(401, "Token expired")
            except jwt.InvalidTokenError:
                abort(401, "Invalid token")
        return wrapped
    return decorator
