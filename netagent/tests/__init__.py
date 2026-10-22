import os

# Tests must never offer to install tools, even when run from an interactive terminal.
os.environ.setdefault("NETAGENT_NO_INSTALL", "1")
