"""Single source of truth for project-name-derived constants.

If the project is ever renamed, edit this file only. Code, config, and
docstrings reference these constants instead of hardcoding strings.
"""

PROJECT_NAME = "dshield_prism"
CLI_NAME = "dshield_prism"
ENV_PREFIX = "PRISM_"

DEFAULT_SERVICE_USER = PROJECT_NAME
DEFAULT_INSTALL_DIR = f"/opt/{PROJECT_NAME}"
DEFAULT_STATE_DIR = f"/var/lib/{PROJECT_NAME}"
