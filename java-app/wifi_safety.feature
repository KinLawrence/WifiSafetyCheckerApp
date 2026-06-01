Feature: WiFi Safety Checker scoring and risk assessment
  As a user scanning nearby WiFi networks
  I want each network scored based on its security posture
  So that I can identify dangerous networks before connecting

  Scenario: Secure WPA2 network receives a perfect safety score
    Given a WiFi network with SSID "HomeRouter" and authentication "WPA2-Personal"
    When the safety score is calculated
    Then the score should be 100
    And the risk level should be "LOW"

  Scenario: Open network with suspicious name is flagged as high risk
    Given a WiFi network with SSID "FreeWifi" and authentication "Open"
    When the safety score is calculated
    Then the score should be 40
    And the risk level should be "HIGH"
