
import random
import docker
import re
import hashlib
from datetime import datetime
import secrets
import atexit

# Session Management
class Session:
    def __init__(self, user_id, docker_id, port, control_port, stream_id):
        self.user_id = user_id
        self.docker_id = docker_id
        self.port = port
        self.control_port = control_port
        self.stream_id = stream_id
        self.created_at = datetime.now()

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "docker_id": self.docker_id,
            "port": self.port,
            "control_port": self.control_port,
            "stream_id": self.stream_id,
            "created_at": self.created_at.isoformat()
        }



class SessionManager:
    def __init__(self, max_sessions):
        self.sessions = {}
        self.max_sessions = max_sessions
        self.docker = docker.from_env()
        self.stream_ids = {}


    def start_session(self, email):
        user_id = self.generate_user_id(email)
        if user_id in self.sessions:
            raise Exception("Session already exists.")
        if len(self.sessions) >= self.max_sessions:
            raise Exception("Max sessions reached.")
        
        # Generate a random port and control port for the session
        port = 10000
        control_port = 10001

        env = {
            "TZ": "UTC",
            "DISPLAY_SIZEW": "1920",
            "DISPLAY_SIZEH": "1080",
            "DISPLAY_REFRESH": "60",
            "DISPLAY_DPI": "96",
            "DISPLAY_CDEPTH": "24",
            "SELKIES_ENABLE_BASIC_AUTH": "false",
            "SELKIES_ENCODER": "vp9enc",
            "SELKIES_VIDEO_BITRATE": "8000",
            "SELKIES_FRAMERATE": "60",
            "SELKIES_AUDIO_BITRATE": "128000",
            "LANG": "C.UTF-8"
        }

        try:
            container = self.docker.containers.run(
                image="sofa-tips-simple",
                name=user_id,
                detach=True,
                tty=True,
                tmpfs={"/dev/shm": "rw"},
                devices=["/dev/dri:/dev/dri:rwm"],
                environment=env,
                ports={8080 : 10000}
            )
        except docker.errors.APIError as e:
            raise Exception(f"Docker API error: {e.explanation}")
        
        stream_id = self._generate_stream_id()

        session = Session(user_id, container.id, port, control_port, stream_id
                          )
        self.sessions[user_id] = session
        self.stream_ids[stream_id] = session
        return session

    def _generate_stream_id(self):
        return secrets.token_urlsafe(16)
    
    def generate_user_id(self, id):
        clean = re.sub(r'[^a-zA-Z0-9.]', '', id.split('@')[0])
        hash_part = hashlib.sha256(id.encode()).hexdigest()[:8]
        return f"{clean}-{hash_part}"
    
    def get_session(self, email):
        user_id = self.generate_user_id(email)
        if not user_id:
            return None
        return self.sessions.get(user_id)
    
    def get_session_by_stream_id(self, stream_id):
        return self.stream_ids.get(stream_id)

    def delete_session(self, email):
        user_id = self.generate_user_id(email)
        session = self.sessions.get(user_id)

        if not session:
            return False
        
        try:
            c = self.docker.containers.get(session.docker_id)
            c.stop()
            c.remove()
        except docker.errors.NotFound:
            pass

        if session.stream_id in self.stream_ids:
            del self.stream_ids[session.stream_id]
        del self.sessions[user_id]

        return True
    
    def cleanup_all_sessions(self):
        print("cleaning up")
        for user_id, session in list(self.sessions.items()):
            try:
                c = self.docker.containers.get(session.docker_id)
                print("Found Docker Container: " + c.name)
                c.stop()
                print("Stopped Docker Container: " + c.name)
                c.remove()
                print("Removed Docker Container: "  + c.name)
            except docker.errors.NotFound:
                pass
            if session.stream_id in self.stream_ids:
                del self.stream_ids[session.stream_id]
            del self.sessions[user_id]
        return True
        
