"""Sliding-window replay protection."""

import pytest

from secure_llm_server.crypto.replay import ReplayDetected, ReplayWindow


def test_forward_progress():
    w = ReplayWindow()
    for i in range(1, 10):
        w.check_and_advance(i)


def test_duplicate_rejected():
    w = ReplayWindow()
    w.check_and_advance(1)
    with pytest.raises(ReplayDetected):
        w.check_and_advance(1)


def test_old_outside_window_rejected():
    w = ReplayWindow()
    w.check_and_advance(2000)
    with pytest.raises(ReplayDetected):
        w.check_and_advance(1)


def test_out_of_order_within_window():
    w = ReplayWindow()
    w.check_and_advance(10)
    w.check_and_advance(5)
    w.check_and_advance(7)
    with pytest.raises(ReplayDetected):
        w.check_and_advance(5)
