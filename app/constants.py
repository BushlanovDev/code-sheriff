"""Application constants."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Application exit codes.

    Follows standard conventions:
    - 0: Success
    - 1: General errors
    - 2: Misconfiguration/invalid input
    """

    SUCCESS = 0
    GENERAL_ERROR = 1
    CONFIGURATION_ERROR = 2
