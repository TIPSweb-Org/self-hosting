# app.py

from flask import Flask, request, session, jsonify
import random
import docker
from dotenv import find_dotenv, load_dotenv
import os 
from os import environ as env


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")  # same as server.py, im ps this is how it should b?
app.config["SESSION_TYPE"] = "filesystem"


class Session:
    def __init__(self, user_id, docker_id, port, control_port):
        self.user_id = user_id
        self.docker_id = docker_id
        self.port = port
        self.control_port = control_port

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "docker_id": self.docker_id,
            "port": self.port,
            "control_port": self.control_port
        }



class SessionManager:
    def __init__(self, max_sessions):
        self.sessions = {}
        self.max_sessions = max_sessions

    def start_session(self, user_id):
        if user_id in self.sessions:
            raise Exception("Session already exists.")
        if len(self.sessions) >= self.max_sessions:
            raise Exception("Max sessions reached.")
        
        # Generate a random port and control port for the session
        port = self.get_open_port()
        control_port = self.get_open_port(exclude={port})


        docker_id = 0  # Placeholder for actual Docker ID assignment logic

        session = Session(user_id, docker_id, port, control_port)
        self.sessions[user_id] = session
        return session

    def get_session(self, user_id):
        return self.sessions.get(user_id)

    def get_open_port(self, exclude: set[int] = None) -> int:
        """
        Returns a random port in [9000..10000] that isn't already in use
        by any existing session (or by the optional `exclude` set).
        """
        exclude = exclude or set()

        # gather all ports already in use by sessions
        used = {s.port for s in self.sessions.values()}
        used |= {s.control_port for s in self.sessions.values()}
        used |= exclude

        # build the list of candidates
        candidates = [p for p in range(9000, 10001) if p not in used]
        if not candidates:
            raise Exception("No available ports in range 9000–10000")

        return random.choice(candidates)

    def delete_session(self, user_id):
        if user_id in self.sessions:
            del self.sessions[user_id]
            return True
        return False



# Instantiate the session manager
max_sessions = 5
# image_name = "your_docker_image_name" 
session_manager = SessionManager(max_sessions)


@app.route("/start_session", methods=["POST"])
def start_session():

    data = request.get_json(silent=True) or {}
    print(data)
    user = data.get("user")
    
    if not user:
        return jsonify({"error": "User not logged in"}), 401

    try:
        sess = session_manager.start_session(user)
        return jsonify(sess.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/get_session", methods=["GET"])
def get_session_route():
    
    data = request.get_json(silent=True) or {}
    print(data)
    user = data.get("user")
    
    
    if not user:
        return jsonify({"error": "User not logged in"}), 401

    sess = session_manager.get_session(user)
    if not sess:
        return jsonify({"error": "No session found"}), 404
    return jsonify(sess.to_dict())


@app.route("/delete_session", methods=["DELETE"])
def delete_session_route():
    
    data = request.get_json(silent=True) or {}
    print(data)
    user = data.get("user")
    
    if not user:
        return jsonify({"error": "User not logged in"}), 401
    
    success = session_manager.delete_session(user)

    if success:
        return jsonify({"status": "Session deleted"})
    return jsonify({"error": "No session to delete"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 42823))
    app.run(host="0.0.0.0", port=port)
