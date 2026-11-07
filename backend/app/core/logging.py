"""Logging setup shared by the API and pipeline modules."""

import logging

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level, format=_FORMAT, force=True)
