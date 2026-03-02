"""GitLab security review agent"""

from app.constants import ExitCode
from app.prompts import get_mr_review_prompt

__version__ = "0.1.0"
__author__ = "Aleksandr Bushlanov"

__all__ = ["main", "ExitCode", "get_mr_review_prompt"]
