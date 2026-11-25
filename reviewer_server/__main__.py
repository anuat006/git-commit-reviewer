from reviewer.envfile import load_env_file
from reviewer.logsetup import setup_logging

setup_logging()      # level from REVIEWER_LOG_LEVEL; logs go to stderr
load_env_file()      # also works when the server is started on its own

from .server import mcp  # noqa: E402

if __name__ == "__main__":
    mcp.run()  # stdio transport
