import re
from flask import abort
import bcrypt
from markupsafe import escape

def sanitize_input(input_str):
    """Secure input validation with Copilot-recommended patterns"""
    if not isinstance(input_str, str):
        raise ValueError("Input must be string")
    
    # Remove potentially harmful characters
    sanitized = re.sub(r'[<>"\';()&|]', '', input_str)
    return sanitized[:100]  # Length restriction

def safe_db_query(db, query, params):
    """Parameterized SQL query execution"""
    try:
        cursor = db.execute(query, params)
        return cursor.fetchall()
    except Exception as e:
        abort(500, "Database error")
