import os

# Set before anything imports app.core.config, which builds its settings (and
# the bcrypt context) at import time. Cost factor 4 instead of the real 12:
# the suite calls the hasher dozens of times and 12 costs ~370ms a call.
os.environ.setdefault("BCRYPT_ROUNDS", "4")
