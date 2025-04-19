# sessionmanager.py

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
            return self.sessions[user_id]  # session already exists
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
