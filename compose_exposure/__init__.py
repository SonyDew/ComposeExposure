"""Inspect Docker Compose port exposure without running Docker."""

from .audit import ComposeError, Exposure, compare, inspect

__all__ = ["ComposeError", "Exposure", "compare", "inspect"]
