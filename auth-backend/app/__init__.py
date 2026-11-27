# Logged exceptions must never print local variables (bearer tokens, JWT claims, patient data). Installed on the first
# import of the package, so workers and scripts that log before (or without) setup_logging() are covered too.
# See app/core/log_safety.py.
from app.core.log_safety import install_safe_defaults as _install_safe_log_defaults

_install_safe_log_defaults()
