"""Control-flow signals used by the JVMO interpreter."""

from __future__ import annotations


class BreakSignal(Exception):
    """break statement."""


class ContinueSignal(Exception):
    """continue statement."""


class ReturnSignal(Exception):
    """return statement carrying a value."""

    def __init__(self, value=None):
        self.value = value
        super().__init__()
