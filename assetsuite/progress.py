"""
progress.py

Progress reporting and cancellation for long operations (reading thousands of
assets, a SevOne with many devices...). The core functions take an optional
Progress; the default one does nothing, so the CLI behaves as before. The
QRadar App records it for its progress bars, and asks for cancellation
between two steps, never in the middle of a write.

A run is a sequence of phases ("QRadar assets", "SevOne devices"...); each
phase counts items done out of a total, when the total is known.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

from typing import Optional


class Cancelled(Exception):
    """The run was cancelled at a safe point."""


class Progress:
    """Receives the progress of a run. This base class ignores everything."""

    def phase(self, name: str, total: Optional[int] = None) -> None:
        """A new phase starts; total is the number of items when known."""

    def set_total(self, total: int) -> None:
        """The total of the current phase became known (e.g. from Content-Range)."""

    def advance(self, count: int = 1) -> None:
        """count more items of the current phase are done."""

    def note(self, text: str) -> None:
        """A message worth showing to the user."""

    def check_cancelled(self) -> None:
        """Raise Cancelled if the user asked to stop. Called only at safe points."""


NO_PROGRESS = Progress()


def or_none(progress: Optional[Progress]) -> Progress:
    return progress if progress is not None else NO_PROGRESS


def stop_requested(progress: Progress) -> bool:
    """True if the user asked to stop, for loops that must end cleanly (writes) instead of raising Cancelled."""
    try:
        progress.check_cancelled()
    except Cancelled:
        return True
    return False
