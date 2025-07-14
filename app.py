from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt
)
from functools import wraps

import jwt
from config import Config
import datetime

app = Flask(__name__)
app.config.from_object(Config)

jwt_manager = JWTManager(app)

# Mock user database
USERS_DB = {
    "shivasri": {
        "password": "shiva123",
        "email": "shivasri@gmail.com",
        "role": "user"
    },
    "nadhasri": {
        "password": "nadha@12",
        "email": "nadhasri@example.com",
        "role": "user"
    },
    "Anusree": {
        "password": "Anu@admin123",
        "email": "Anusree@example.com",
        "role": "admin"
    }
}

class TokenExchangeError(Exception):
    pass

def validate_identity_token(id_token):
    try:
        decoded = jwt.decode(id_token, options={"verify_signature": False})
        issuer = decoded.get('iss')
        if not any(idp['issuer'] == issuer for idp in Config.TRUSTED_IDPS.values()):
            raise TokenExchangeError("Untrusted issuer")
        return decoded
    except Exception as e:
        raise TokenExchangeError(f"Invalid identity token: {str(e)}")

def exchange_token(id_token):
    try:
        id_claims = validate_identity_token(id_token)
        additional_claims = {
            'iss': 'token-exchange-server',
            'original_issuer': id_claims.get('iss'),
            'email': id_claims.get('email'),
            'role': id_claims.get('role', 'user')
        }
        access_token = create_access_token(
            identity=id_claims.get('sub'),
            additional_claims=additional_claims
        )
        return access_token
    except TokenExchangeError as e:
        raise

def authorize_route(required_claims=None, allowed_roles=None):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_claims = get_jwt()
            if required_claims:
                missing_claims = [claim for claim in required_claims if claim not in current_claims]
                if missing_claims:
                    return jsonify({"error": f"Missing claims: {', '.join(missing_claims)}"}), 403
            if allowed_roles and current_claims.get('role') not in allowed_roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Authentication Endpoints
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = USERS_DB.get(username)
    if user and user['password'] == password:
        id_token = jwt.encode({
            'sub': username,
            'iss': 'mock-idp',
            'email': user['email'],
            'role': user['role']
        }, 'mock-secret', algorithm='HS256')
        
        return jsonify({
            'id_token': id_token,
            'token_type': 'Bearer'
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/token/exchange', methods=['POST'])
def token_exchange():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    
    id_token = auth_header.split(' ')[1]
    try:
        access_token = exchange_token(id_token)
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': Config.TOKEN_EXPIRATION
        })
    except TokenExchangeError as e:
        return jsonify({"error": str(e)}), 401

# User Endpoints
@app.route('/api/user/info', methods=['GET'])
@authorize_route()
def user_info():
    current_user = get_jwt_identity()
    user_data = USERS_DB.get(current_user, {})
    return jsonify({
        "service": "user-service",
        "endpoint": "/user/info",
        "user": current_user,
        "claims": get_jwt(),
        "data": {
            "user_id": current_user,
            "email": user_data.get('email', ''),
            "role": user_data.get('role', 'user')
        }
    })

# Admin Endpoints
@app.route('/api/admin/users', methods=['GET'])
@authorize_route(allowed_roles=['admin'])
def admin_users():
    return jsonify({
        "service": "admin-service",
        "endpoint": "/admin/users",
        "admin": get_jwt_identity(),
        "users": [
            {
                "username": username,
                "email": data["email"],
                "role": data["role"]
            }
            for username, data in USERS_DB.items()
        ],
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

@app.route('/api/admin/stats', methods=['GET'])
@authorize_route(allowed_roles=['admin'])
def admin_stats():
    return jsonify({
        "service": "admin-service",
        "endpoint": "/admin/stats",
        "stats": {
            "total_users": len(USERS_DB),
            "admin_count": sum(1 for user in USERS_DB.values() if user['role'] == 'admin'),
            "user_count": sum(1 for user in USERS_DB.values() if user['role'] == 'user')
        }
    })

# Mock Endpoints (for internal testing)
@app.route('/mock/user/info', methods=['GET'])
def mock_user_info():
    return user_info()

@app.route('/mock/admin/users', methods=['GET'])
def mock_admin_users():
    return admin_users()

# JWKS Endpoint
@app.route('/.well-known/jwks.json')
def jwks():
    return jsonify({
        "keys": [{
            "kty": "oct",
            "kid": "1",
            "use": "sig",
            "alg": "HS256",
            "k": Config.SECRET_KEY
        }]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)