"""
Pytest TDD tests for app.py (Wi-Fi Safety Checker).

Uses pytest fixtures and unittest.mock to patch the OS-level scan functions,
letting us verify the scoring logic in isolation.

Run:
    pytest test_pytest.py -v
"""

import pytest
from unittest.mock import MagicMock, patch, call
import tkinter as tk

# Import the module under test (lives alongside this file in python3/)
import app


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_widget():
    """Provides a mocked ScrolledText widget for every test."""
    return MagicMock()


def _netsh_block(ssid: str, auth: str) -> str:
    """Builds a minimal netsh-style output block for one network."""
    return f"SSID 1 : {ssid}\n    Authentication : {auth}\n"


# ── Test 1: Secure WPA2 network gets a perfect 100/100 ───────────────────────

@patch("app.get_current_connection", return_value=("", ""))
@patch("app.scan_wifi")
def test_secure_network_scores_100(mock_scan, _mock_conn, mock_widget):
    """
    RED  → wrote this test before any scoring logic existed (TDD step 1).
    GREEN → scoring logic returns 100 for WPA2 + clean SSID.
    """
    mock_scan.return_value = _netsh_block("SecureHome", "WPA2-Personal")

    app.analyze(mock_widget)

    # The widget should receive exactly one insert with score 100
    mock_widget.insert.assert_called_with(
        tk.END,
        "SecureHome → Security Score: 100/100\n",
    )


# ── Test 2: Open auth + suspicious keyword deducts correctly ─────────────────

@patch("app.get_current_connection", return_value=("", ""))
@patch("app.scan_wifi")
def test_open_suspicious_scores_40(mock_scan, _mock_conn, mock_widget):
    """
    Scoring: 100 − 50 (Open) − 10 ('wifi' keyword) = 40  →  HIGH risk.
    """
    mock_scan.return_value = _netsh_block("FreeWifi", "Open")

    app.analyze(mock_widget)

    mock_widget.insert.assert_called_with(
        tk.END,
        "FreeWifi → Security Score: 40/100\n",
    )


# ── Test 3: Duplicate SSIDs trigger Evil Twin penalty ────────────────────────

@patch("app.get_current_connection", return_value=("", ""))
@patch("app.scan_wifi")
def test_duplicate_ssid_evil_twin_penalty(mock_scan, _mock_conn, mock_widget):
    """
    Two networks with identical SSID → each gets −30 (Evil Twin).
    Scoring per entry: 100 − 30 = 70.
    """
    mock_scan.return_value = (
        _netsh_block("CoffeeShop", "WPA2-Personal")
        + _netsh_block("CoffeeShop", "WPA2-Personal")
    )

    app.analyze(mock_widget)

    expected = call(tk.END, "CoffeeShop → Security Score: 70/100\n")
    mock_widget.insert.assert_has_calls([expected, expected])


# ── Test 4: WEP encryption deducts 40 points ────────────────────────────────

@patch("app.get_current_connection", return_value=("", ""))
@patch("app.scan_wifi")
def test_wep_network_scores_60(mock_scan, _mock_conn, mock_widget):
    """
    Scoring: 100 − 40 (WEP) = 60  →  MEDIUM risk.
    """
    mock_scan.return_value = _netsh_block("OldRouter", "WEP")

    app.analyze(mock_widget)

    mock_widget.insert.assert_called_with(
        tk.END,
        "OldRouter → Security Score: 60/100\n",
    )


# ── Test 5: Currently connected network shows its IP ────────────────────────

@patch("app.get_current_connection", return_value=("MyNet", "192.168.1.42"))
@patch("app.scan_wifi")
def test_connected_network_displays_ip(mock_scan, _mock_conn, mock_widget):
    """
    When the scanned SSID matches the currently connected one,
    the display name should include the IP address.
    """
    mock_scan.return_value = _netsh_block("MyNet", "WPA2-Personal")

    app.analyze(mock_widget)

    mock_widget.insert.assert_called_with(
        tk.END,
        "MyNet (192.168.1.42) → Security Score: 100/100\n",
    )
