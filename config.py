import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Secret key for signing tokens
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-very-secret-key-here')
    
    # Token settings
    TOKEN_EXPIRATION = 3600  # 1 hour
    REFRESH_TOKEN_EXPIRATION = 86400  # 24 hours
    
    # Trusted Identity Providers
    TRUSTED_IDPS = {
        'google': {
        'issuer': 'https://accounts.google.com',
        'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'
    },
    'microsoft': {
        'issuer': 'https://login.microsoftonline.com/common/v2.0',
        'jwks_uri': 'https://login.microsoftonline.com/common/discovery/v2.0/keys'
    },
    'mock-idp': {
        'issuer': 'mock-idp',
        'jwks_uri': 'http://localhost:5000/.well-known/jwks.json'
    }
    }
    

    API_ROUTES = {
        '/api/user': {
            'target': 'http://localhost:5000/mock/user',
            'required_claims': ['sub', 'email', 'role'],
            'allowed_roles': ['user', 'admin']
        },
        '/api/admin': {
            'target': 'http://localhost:5000/mock/admin',
            'required_claims': ['sub', 'email', 'role'],
            'allowed_roles': ['admin']
        }
    }