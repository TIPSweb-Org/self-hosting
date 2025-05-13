
import random
import docker

# Session Management
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
        self.docker = docker.from_env()


    def start_session(self, user_id):
        user_id = user_id.split('@')[0]
        if user_id in self.sessions:
            raise Exception("Session already exists.")
        if len(self.sessions) >= self.max_sessions:
            raise Exception("Max sessions reached.")
        
        # Generate a random port and control port for the session
        picked = set()
        port = self.get_open_port(exclude=picked)
        picked.add(port)
        control_port = self.get_open_port(exclude=picked)
        picked.add(control_port)
        http_port = self.get_open_port(exclude=picked)
        picked.add(http_port)
        selkies_port = self.get_open_port(exclude=picked)
        picked.add(selkies_port)

        env = {
            "TZ": "UTC",
            "DISPLAY_SIZEW": "1920",
            "DISPLAY_SIZEH": "1080",
            "DISPLAY_REFRESH": "60",
            "DISPLAY_DPI": "96",
            "DISPLAY_CDEPTH": "24",
            "PASSWD": "mypasswd",
            "SELKIES_ENABLE_BASIC_AUTH": "true",
            "SELKIES_BASIC_AUTH_USER": "ubuntu",
            "SELKIES_BASIC_AUTH_PASSWORD": "mypasswd",
            "SELKIES_ENCODER": "vp9enc",
            "SELKIES_VIDEO_BITRATE": "8000",
            "SELKIES_FRAMERATE": "60",
            "SELKIES_AUDIO_BITRATE": "128000",
            "LANG": "C.UTF-8",
            "DISPLAY": ":22",
            "NGINX_PORT": port,
            "SELKIES_PORT": selkies_port,
            "SELKIES_METRICS_HTTP_PORT": http_port

        }

        try:
            container = self.docker.containers.run(
                image="sofa-tips-simple",
                network_mode="host",
                name=user_id,           
                detach=True,
                tty=True,
                tmpfs={"/dev/shm": "rw"},
                devices={"/dev/dri" : "rwm"},
                environment=env
            )
        except docker.errors.APIError as e:
            raise Exception(f"Docker API error: {e.explanation}")

        session = Session(user_id, container.id, port, control_port)
        self.sessions[user_id] = session
        return session

    def get_session(self, user_id):
        user_id = user_id.split('@')[0]
        return self.sessions.get(user_id)

    def get_open_port(self, exclude: set[int] = None) -> int:
        """
        Returns a random port in [9000..10000] that isn't already
        used by any existing session (or by the optional `exclude` set).
        """

        exclude = exclude or set()

        used = {
            p
            for sess in self.sessions.values()
            for p in (sess.port, sess.control_port)
        } | exclude

        if len(used) >= (10000 - 9000 + 1):
            raise Exception("No available ports in range 9000–10000")

        while True:
            candidate = random.randint(9000, 10000)
            if candidate not in used:
                return candidate


    def delete_session(self, user_id):
        user_id = user_id.split('@')[0]
        session = self.sessions.get(user_id)

        if not session:
            return False
        
        try:
            c = self.docker.containers.get(session.docker_id)
            c.stop()
            c.remove()
        except docker.errors.NotFound:
            pass

        del self.sessions[user_id]

        return True