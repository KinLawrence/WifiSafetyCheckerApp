import unittest
from unittest.mock import MagicMock, patch
import tkinter as tk
import app

class TestWifiSafetyChecker(unittest.TestCase):
    def setUp(self):
        # Create a mock for the Tkinter ScrolledText widget
        self.mock_widget = MagicMock()

    @patch('app.scan_wifi')
    def test_secure_network_score(self, mock_scan):
        """
        Test that a standard secure network (WPA2) starts with a perfect score.
        """
        # Mocking a single secure network output from netsh
        mock_scan.return_value = "SSID 1 : Home_Network\n    Authentication : WPA2-Personal"
        
        app.analyze(self.mock_widget)
        
        # Verify the widget was cleared then updated with the correct SSID and score
        self.mock_widget.delete.assert_called_with(1.0, tk.END)
        self.mock_widget.insert.assert_called_with(tk.END, "Home_Network → Security Score: 100/100\n")

    @patch('app.scan_wifi')
    def test_open_network_penalties(self, mock_scan):
        """
        Test that 'Open' authentication and suspicious keywords trigger score penalties.
        Scoring: 100 - 50 (Open) - 10 (keyword 'wifi') = 40
        """
        mock_scan.return_value = "SSID 1 : Free_WiFi_Spot\n    Authentication : Open"
        
        app.analyze(self.mock_widget)
        
        # Result should reflect both the Open penalty (-50) and keyword penalty (-10)
        self.mock_widget.insert.assert_called_with(tk.END, "Free_WiFi_Spot → Security Score: 40/100\n")

    @patch('app.scan_wifi')
    def test_duplicate_ssid_evil_twin_penalty(self, mock_scan):
        """
        Test that multiple networks with the same SSID trigger an 'Evil Twin' penalty.
        Scoring: 100 - 30 (Duplicate) = 70
        """
        # Simulate two networks with the same name
        mock_scan.return_value = (
            "SSID 1 : CoffeeShop\n    Authentication : WPA2-Personal\n"
            "SSID 2 : CoffeeShop\n    Authentication : WPA2-Personal"
        )
        
        app.analyze(self.mock_widget)
        
        # Both instances should show a docked score
        expected_call = unittest.mock.call(tk.END, "CoffeeShop → Security Score: 70/100\n")
        self.mock_widget.insert.assert_has_calls([expected_call, expected_call])

if __name__ == '__main__':
    unittest.main()
