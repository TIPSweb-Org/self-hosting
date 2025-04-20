# app.py

from flask import Flask, request, session, jsonify

app = Flask(__name__)
app.secret_key = "super-secret-key"  # Replace with a secure value
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
    def __init__(self, max_sessions=5):
        self.sessions = {}
        self.max_sessions = max_sessions

    def start_session(self, user_id, docker_id, port, control_port):
        if user_id in self.sessions:
            return self.sessions[user_id]
        if len(self.sessions) >= self.max_sessions:
            raise Exception("Max sessions reached.")
        session = Session(user_id, docker_id, port, control_port)
        self.sessions[user_id] = session
        return session

    def get_session(self, user_id):
        return self.sessions.get(user_id)

    def delete_session(self, user_id):
        if user_id in self.sessions:
            del self.sessions[user_id]
            return True
        return False


# Instantiate the session manager
session_manager = SessionManager()


@app.route("/start_session", methods=["POST"])
def start_session():
    user = session.get("user")
    if not user:
        return jsonify({"error": "User not logged in"}), 401

    user_id = user["sub"]

    # Dummy values; replace with real Docker logic
    docker_id = "dummy_docker_id"
    port = 5001
    control_port = 6001

    try:
        sess = session_manager.start_session(user_id, docker_id, port, control_port)
        return jsonify(sess.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/get_session", methods=["GET"])
def get_session_route():
    user = session.get("user")
    if not user:
        return jsonify({"error": "User not logged in"}), 401

    user_id = user["sub"]
    sess = session_manager.get_session(user_id)
    if not sess:
        return jsonify({"error": "No session found"}), 404
    return jsonify(sess.to_dict())


@app.route("/delete_session", methods=["DELETE"])
def delete_session_route():
    user = session.get("user")
    if not user:
        return jsonify({"error": "User not logged in"}), 401

    user_id = user["sub"]
    success = session_manager.delete_session(user_id)
    if success:
        return jsonify({"status": "Session deleted"})
    return jsonify({"error": "No session to delete"}), 404


if __name__ == "__main__":
    app.run(debug=True)
