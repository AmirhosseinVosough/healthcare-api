"""Logging setup, so the audit trail actually goes somewhere.

Without this, `logging.getLogger("audit")` has no handler and Python's root
logger only emits WARNING and above. Audit lines are INFO, so they were being
dropped in silence — the code ran, the records were created, and nothing ever
came out.

The tests did not catch it because pytest's caplog attaches its own handler and
lowers the level, capturing records at the logger before anything decides
whether to emit them. That proves the audit code runs. It says nothing about
whether a human can ever read the result.
"""

import logging.config

from app.core.config import settings

LOGGING_CONFIG = {
    "version": 1,
    # Leave uvicorn's own loggers alone. Turning this on would silence the
    # access log the moment we configure ours.
    "disable_existing_loggers": False,
    "formatters": {
        # The audit record is already a JSON object. Wrapping it in a timestamp
        # and a level would make each line half JSON and half prose, and stop
        # anything downstream parsing it without stripping a prefix first.
        "raw": {"format": "%(message)s"},
    },
    "handlers": {
        "audit": {
            "class": "logging.StreamHandler",
            # "ext://sys.stdout" rather than sys.stdout itself: the string is
            # resolved when the config is applied, not when this module is
            # imported. Binding the object at import time means writing to
            # whatever stdout happened to be then, which breaks anything that
            # replaces it later — a test harness, or a process manager
            # redirecting output after start.
            "stream": "ext://sys.stdout",
            "formatter": "raw",
        },
    },
    "loggers": {
        "audit": {
            "handlers": ["audit"],
            "level": "INFO",
            # Not up to the root logger as well, or every line appears twice
            # once anything else configures a root handler.
            "propagate": False,
        },
    },
}


def configure_logging() -> None:
    """Called at startup, after uvicorn has set up its own logging."""
    config = dict(LOGGING_CONFIG)
    config["loggers"] = {
        name: {**spec, "level": settings.log_level}
        for name, spec in LOGGING_CONFIG["loggers"].items()
    }
    logging.config.dictConfig(config)
