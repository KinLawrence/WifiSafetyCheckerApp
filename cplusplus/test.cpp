#define main app_main
#include "app.cpp"
#undef main

#include <iostream>
#include <cassert>

void test_parseNetworks() {
    QString data = "SSID 1 : Home_Network\n    Authentication : WPA2-Personal\n"
                   "SSID 2 : Free_WiFi_Spot\n    Authentication : Open\n";
    auto networks = parseNetworks(data);
    assert(networks.size() == 2);
    assert(networks[0].ssid == "Home_Network");
    assert(networks[0].auth == "WPA2-Personal");
    assert(networks[1].ssid == "Free_WiFi_Spot");
    assert(networks[1].auth == "Open");
    std::cout << "test_parseNetworks passed\n";
}

void test_secure_network_score() {
    QVector<Network> all = {{"Home_Network", "WPA2-Personal"}};
    int score = calculateScore(all[0], all);
    assert(score == 100);
    assert(getRisk(score) == "LOW RISK");
    std::cout << "test_secure_network_score passed\n";
}

void test_open_network_penalty() {
    QVector<Network> all = {{"Free_WiFi_Spot", "Open"}};
    int score = calculateScore(all[0], all);
    assert(score == 40); // 100 baseline - 60 for 'Open'
    assert(getRisk(score) == "HIGH RISK"); // < 50 is HIGH RISK
    std::cout << "test_open_network_penalty passed\n";
}

void test_duplicate_ssid_penalty() {
    // Tests the "Evil Twin" penalty for multiple networks sharing a name
    QVector<Network> all = {{"CoffeeShop", "WPA2-Personal"}, {"CoffeeShop", "WPA2-Personal"}};
    int score = calculateScore(all[0], all);
    assert(score == 80); // 100 baseline - 20 for duplicate
    assert(getRisk(score) == "LOW RISK"); // >= 80 is LOW RISK
    std::cout << "test_duplicate_ssid_penalty passed\n";
}

int main() {
    std::cout << "Running WiFi Checker Tests...\n";
    
    test_parseNetworks();
    test_secure_network_score();
    test_open_network_penalty();
    test_duplicate_ssid_penalty();
    
    std::cout << "All C++ unit tests passed successfully!\n";
    return 0;
}
