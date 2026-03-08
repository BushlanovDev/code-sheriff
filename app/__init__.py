"""GitLab security review agent"""

from app.constants import ExitCode
from app.prompts import get_security_audit_prompt

__version__ = "0.1.0"
__author__ = "Aleksandr Bushlanov"

__all__ = ["main", "ExitCode", "get_security_audit_prompt"]
