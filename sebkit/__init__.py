"""
sebkit - Safe Exam Browser configuration toolkit.

Built for MedTech: generate hardened .seb exam configurations, compute the
Config Key that Moodle uses to verify them, and audit existing configs for the
misconfigurations that silently disable SEB's protection.

Target client: Safe Exam Browser 3.x on Windows (developed against 3.10.2).
"""

__version__ = "1.0.0"

# The SEB client build this toolkit was developed and verified against.
SEB_TARGET_VERSION = "3.10.2"
