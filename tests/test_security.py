import pytest
from app import app, db
from auth import hash_password, verify_password

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_sql_injection_protection(client):
    malicious_input = "admin' OR '1'='1' --"
    response = client.post('/login', data={'username': malicious_input})
    assert response.status_code != 500  # Should fail gracefully

def test_password_hashing():
    pwd = "SecurePass123!"
    hashed = hash_password(pwd)
    assert verify_password(hashed, pwd)
    assert not verify_password(hashed, "wrongpass")

def test_xss_protection(client):
    xss_attempt = "<script>alert('hack')</script>"
    response = client.post('/comment', data={'text': xss_attempt})
    assert b"<script>" not in response.data
