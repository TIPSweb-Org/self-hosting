import docker

# 1) Connect to Docker
client = docker.from_env()

# 2) Pull the image (will be a no‑op if you already have it)
client.images.pull("hello-world")

# 3) Run the container
#    detach=True gives you back a Container object even though it immediately exits
container = client.containers.run(
    "hello-world",
    detach=True,
    remove=True   # auto‑remove the container when it’s done
)

# 4) Grab its short ID
print("Container short ID:", container.short_id)

# 5) If you want to see what it printed:
logs = container.logs().decode("utf-8")
print("Logs from hello-world:\n", logs)
