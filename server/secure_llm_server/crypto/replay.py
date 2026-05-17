"""Sliding-window replay protection over the AEAD counter."""

from __future__ import annotations

from dataclasses import dataclass, field

WINDOW_BITS = 1024


class ReplayDetected(Exception):
    pass


@dataclass(slots=True)
class ReplayWindow:
    """Anti-replay window. Accepts counters up to ``WINDOW_BITS`` behind the high
    watermark; older or duplicate counters are rejected.
    """

    high: int = 0
    bitmap: int = field(default=0)  # bit i set means counter (high - i) was seen

    def check_and_advance(self, counter: int) -> None:
        if counter < 0:
            raise ReplayDetected("negative counter")
        if counter > self.high:
            shift = counter - self.high
            if shift >= WINDOW_BITS:
                self.bitmap = 1
            else:
                self.bitmap = ((self.bitmap << shift) | 1) & ((1 << WINDOW_BITS) - 1)
            self.high = counter
            return
        offset = self.high - counter
        if offset >= WINDOW_BITS:
            raise ReplayDetected("counter outside window")
        mask = 1 << offset
        if self.bitmap & mask:
            raise ReplayDetected("duplicate counter")
        self.bitmap |= mask
