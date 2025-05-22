import os
import atexit
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, request, Response, stream_with_context, abort
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from dotenv import find_dotenv, load_dotenv
from flask_cors import CORS
from dotenv import find_dotenv, load_dotenv

from sessionmanager import SessionManager

# Load environment variables
ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

# Initialize Flask app
app = Flask(__name__, template_folder='Frontend')
app.secret_key = os.environ.get("APP_SECRET_KEY")

# Configure CORS
CORS(app, supports_credentials=True)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin):
    def __init__(self, id, email, password, is_admin=False):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

    def get_id(self):
        return self.id

# Mock database - replace with real DB in production
users = {
    "1": User("1", "user@example.com", generate_password_hash("password1")),
    "2": User("2", "admin@example.com", generate_password_hash("password2"), is_admin=True)
}

# REQUIRED: User loader callback
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Constants
JSON_CONTENT_TYPE = "application/json"
ERROR_NOT_AUTHENTICATED = "Not authenticated"

# Helper functions
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Find user by email
        user = next((u for u in users.values() if u.email == email), None)
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_email'] = user.email
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            # Redirect to home.html instead of index.html
            return redirect(next_page or url_for('home'))  # Changed from index to home
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    # Clear local session if exists
    if 'simulation_session' in session:
        try:
            session_manager.delete_session(current_user.email)
        except Exception as e:
            flash('Error clearing session', 'error')
    
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if email already exists
        if any(u.email == email for u in users.values()):
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        # Generate new user ID
        new_id = str(int(max(users.keys(), default="0")) + 1)
        
        # Create and add new user
        users[new_id] = User(new_id, email, generate_password_hash(password))
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

    
@app.route('/home')
@login_required
def home():
    return render_template('home.html', user=current_user)


# Instantiate the session manager
max_sessions = 5
session_manager = SessionManager(max_sessions)


@app.route("/start_session", methods=["POST"])
@login_required
def start_session():
    try:
        sess = session_manager.start_session(current_user.email)
        return jsonify(sess.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/stream/<stream_id>", defaults={'subpath': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/stream/<stream_id>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def stream_proxy(stream_id, subpath):
    session = session_manager.get_session_by_stream_id(stream_id)
    if not session:
        abort(404)
    
    return _proxy_request(session, subpath)

def _proxy_request(session, subpath):
    """Helper function to proxy requests to the container"""
    container_url = f"http://24.250.182.57:{session.port}/{subpath}"
    headers = {key: value for (key, value) in request.headers if key.lower() != 'host'}
    
    # Remove encoding headers if present to get raw response
    headers.pop('Accept-Encoding', None)

    try:
        if request.method == 'GET':
            resp = requests.get(
                container_url,
                headers=headers,
                params=request.args,
                stream=True
            )
        elif request.method == 'POST':
            resp = requests.post(
                container_url,
                headers=headers,
                data=request.get_data(),
                cookies=request.cookies,
                stream=True
            )
        elif request.method == 'PUT':
            resp = requests.put(
                container_url,
                headers=headers,
                data=request.get_data(),
                stream=True
            )
        elif request.method == 'DELETE':
            resp = requests.delete(
                container_url,
                headers=headers,
                stream=True
            )
        else:
            abort(405)
            
        # Exclude certain headers from being forwarded
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                          if name.lower() not in excluded_headers]
        
        return Response(
            resp.iter_content(chunk_size=8192),
            status=resp.status_code,
            headers=response_headers
        )
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Proxy error: {str(e)}")
        abort(502, description="Bad Gateway to container")


@app.route("/get_session", methods=["POST"])
@login_required
def get_session_route():
    sess = session_manager.get_session(current_user.email)
    if not sess:
        return jsonify({"error": "No session found"}), 404
    session_data = sess.to_dict()
    session_data["stream_url"] = f"/stream/{sess.stream_id}"
    return jsonify(sess.to_dict())


@app.route("/delete_session", methods=["DELETE"])
@login_required
def delete_session_route():
    success = session_manager.delete_session(current_user.email)

    if success:
        return jsonify({"status": "Session deleted"})
    return jsonify({"error": "No session to delete"}), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=True)