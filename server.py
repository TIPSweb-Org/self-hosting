
import base64
import json
import os
from os import environ as env
from typing import Annotated, Tuple, Union
from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen

from authlib.integrations.flask_client import OAuth
import flask
import requests
from requests_oauthlib import OAuth2Session
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, logging, redirect, render_template, session, url_for
from functools import wraps
from flask_cors import cross_origin
from six.moves import http_client
import logging

import requests
from flask import request

from jose import ExpiredSignatureError, JWSError, JWTError, jws, jwt
from jose.exceptions import JWTClaimsError
import werkzeug

## protecting information from .env file
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


auth0_jwks_endpoint = env.get("JWKS_ENDPOINT")
auth0_jwks = requests.get(auth0_jwks_endpoint).json()["keys"]

# Google JWKS endpoint
google_jwks_endpoint = "https://www.googleapis.com/oauth2/v3/certs"
google_jwks = requests.get(google_jwks_endpoint).json()["keys"]


# def find_public_key(kid):
#     for key in jwks:
#         if key.get("kid") == kid:
#             print(f"Found public key for kid: {kid}")
#             return key
#     print(f"No public key found for kid: {kid}")
#     return None

def find_public_key(kid, provider="auth0"):
    keys = auth0_jwks if provider == "auth0" else google_jwks
    for key in keys:
        if key.get("kid") == kid:
            return key
    return None

def validate_token(token):
    # try:
    #     header = jws.get_unverified_header(token)
    #     kid = header.get("kid")
    #     public_key = find_public_key(kid)
    #     token_payload = jwt.decode(
    #         token=token,
    #         key=public_key,
    #         audience=env.get("AUTH0_AUDIENCE"),  
    #         issuer=f'https://{env.get("AUTH0_DOMAIN")}/',
    #         algorithms="RS256"
    #     )
    #     return token_payload
    # except (ExpiredSignatureError, JWTError, JWSError, JWTClaimsError) as error:
    #      return None
    try:
        header = jws.get_unverified_header(token)
        kid = header.get("kid")
        public_key = find_public_key(kid)
        
        if not public_key:
            return None
            
        token_payload = jwt.decode(
            token=token,
            key=public_key,
            audience=env.get("GOOGLE_CLIENT_ID"),  # Change audience to Google Client ID
            issuer="https://accounts.google.com",  # Update issuer for Google
            algorithms=["RS256"]
        )
        return token_payload
        
    except ExpiredSignatureError:
        print("Token expired")
        return None
    except (JWTError, JWSError, JWTClaimsError) as e:
        print(f"Token validation error: {str(e)}")
        return None
         
def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get("user")
        if not user or "token" not in user:
            return redirect(url_for("login"))
            
        token_payload = validate_token(user["token"]["access_token"])
        if token_payload and "admin" in token_payload.get("permissions", []):
            return f(*args, **kwargs)
        return redirect(url_for("index"))
    return decorated


app = Flask(__name__, template_folder='Frontend')
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

#oauth registration
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "offline_access openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Google registration
oauth.register(
    "google",
    client_id=env.get("GOOGLE_CLIENT_ID"),
    client_secret=env.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        "scope": "openid email profile"
    }
)

# Controllers API
@app.route("/")
def index():
    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    # token = oauth.auth0.authorize_access_token()
    # #print("Access Token:", token['access_token'])

    # token_payload = validate_token(token['access_token'])
    # #print("Decoded token payload:", json.dumps(token_payload, indent=2))
    
    # session["user"] = {
    #     "token": token,
    #     "permissions": token_payload.get("permissions", []) if token_payload else []
    # }
    # return redirect("/")
    try:
        # Determine which OAuth provider to use based on the state
        provider = session.get('oauth_provider', 'auth0')
        oauth_client = oauth.google if provider == 'google' else oauth.auth0
        
        logging.info(f"Using OAuth provider: {provider}")
        token = oauth_client.authorize_access_token()
        
        if provider == 'google':
            user = oauth_client.parse_id_token(token)
        else:
            token_payload = validate_token(token['access_token'])
            user = token_payload
            
        session["user"] = user
        return redirect("/")
        
    except Exception as e:
        logging.error(f"Callback error details: {str(e)}")
        return f"Authentication failed: {str(e)}", 401

# @app.route("/login")
# def login():
#     return oauth.auth0.authorize_redirect(
#         redirect_uri=url_for("callback", _external=True),
#         audience=env.get("AUTH0_AUDIENCE"),
#         response_type="code",
#         scope="offline_access openid profile email"
#     )

@app.route("/login")
def login():
    provider = request.args.get('provider', 'auth0')  # Default to auth0 if no provider specified
    session['oauth_provider'] = provider
    
    if provider == 'google':
        return oauth.google.authorize_redirect(
            redirect_uri=url_for("callback", _external=True),
            scope="openid email profile"
        )
    else:
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True),
            audience=env.get("AUTH0_AUDIENCE"),
            response_type="code",
            scope="offline_access openid profile email"
        )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/auth")
def auth():
    token = oauth.google.authorize_access_token()
    validated_token = validate_token(token['id_token'])
    if validated_token:
        session['user'] = validated_token
        return redirect(url_for('index'))
    return "Token validation failed", 401


@app.route('/admin')
@requires_admin
def admin_dashboard():
    #print("Current session user:", json.dumps(session.get("user"), indent=2))

    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "read:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    if 'error' in token:
        return render_template('admin-dash.html', error=token['error_description'])
        
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    users_response = requests.get(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users',
        headers=headers
    ).json()

    #users = users_response.json()
    
    return render_template('admin-dash.html', users=users_response)


@app.route('/admin/delete-user/<user_id>', methods=['DELETE'])
@requires_admin
def delete_user(user_id):
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "delete:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()
    
    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    delete_response = requests.delete(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users/{user_id}',
        headers=headers
    )
    
    return jsonify({"status": "success" if delete_response.ok else "error"})


@app.route('/admin/create-user', methods=['POST'])
@requires_admin
def create_user():
    data = request.get_json()
    
    payload = {
        "client_id": env.get("M2M_CLIENT_ID"),
        "client_secret": env.get("M2M_CLIENT_SECRET"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "grant_type": "client_credentials",
        "scope": "create:users"
    }
    
    token_response = requests.post(
        f"https://{env.get('AUTH0_DOMAIN')}/oauth/token",
        json=payload
    )
    token = token_response.json()

    headers = {'Authorization': f'Bearer {token["access_token"]}'}
    user_data = {
        "email": data['email'],
        "password": data['password'],
        "connection": "Username-Password-Authentication"
    }
    
    create_response = requests.post(
        f'https://{env.get("AUTH0_DOMAIN")}/api/v2/users',
        headers=headers,
        json=user_data
    )
    
    response_data = create_response.json()
    
    if create_response.ok:
        return jsonify({"status": "success"})
    else:
        return jsonify({
            "status": "error",
            "message": response_data.get('message', 'Unknown error occurred')
        }), 400
    

# Google Cloud Endpoints Authentication Information Retrieval
def _base64_decode(encoded_str):
    if encoded_str[0] == "b":
        encoded_str = encoded_str[1:]
    num_missed_paddings = 4 - len(encoded_str) % 4
    if num_missed_paddings != 4:
        encoded_str += "=" * num_missed_paddings
    return base64.b64decode(encoded_str).decode("utf-8")

def auth_info():
    encoded_info = request.headers.get("X-Endpoint-API-UserInfo", None)
    if encoded_info:
        info_json = _base64_decode(encoded_info)
        user_info = json.loads(info_json)
    else:
        user_info = {"id": "anonymous"}
    return jsonify(user_info)

@app.route("/auth/info/googlejwt", methods=["GET"])
def auth_info_google_jwt():
    return auth_info()

@app.route("/auth/info/googleidtoken", methods=["GET"])
def auth_info_google_id_token():
    return auth_info()

@app.route("/auth/info/firebase", methods=["GET"])
@cross_origin(send_wildcard=True)
def auth_info_firebase():
    return auth_info()

@app.errorhandler(http_client.INTERNAL_SERVER_ERROR)
def unexpected_error(e):
    logging.getLogger().error("An error occurred while processing the request.", exc_info=True)
    response = jsonify(
        {"code": http_client.INTERNAL_SERVER_ERROR, "message": f"Exception: {e}"}
    )
    response.status_code = http_client.INTERNAL_SERVER_ERROR
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
    #app.run(host="0.0.0.0", port=3000)

