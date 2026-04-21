#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QProcess>
#include <QStringList>
#include <QRegularExpression>

struct Network {
    QString ssid;
    QString auth;
};

// Parse netsh output
QVector<Network> parseNetworks(const QString &data) {
    QVector<Network> networks;
    Network current;

    QStringList lines = data.split("\n");

    for (QString line : lines) {
        line = line.trimmed();

        if (line.startsWith("SSID")) {
            if (!current.ssid.isEmpty()) {
                networks.append(current);
                current = Network();
            }
            QStringList parts = line.split(":");
            if (parts.size() > 1)
                current.ssid = parts[1].trimmed();
        }
        else if (line.contains("Authentication")) {
            QStringList parts = line.split(":");
            if (parts.size() > 1)
                current.auth = parts[1].trimmed();
        }
    }

    if (!current.ssid.isEmpty())
        networks.append(current);

    return networks;
}

// Score calculation
int calculateScore(const Network &net, const QVector<Network> &all) {
    int score = 100;

    if (net.auth.contains("Open"))
        score -= 60;

    if (net.auth.contains("WEP"))
        score -= 50;

    if (net.auth.contains("WPA") && !net.auth.contains("WPA2"))
        score -= 20;

    int count = 0;
    for (const auto &n : all) {
        if (n.ssid == net.ssid)
            count++;
    }

    if (count > 1)
        score -= 20;

    return qMax(score, 0);
}

// Risk label
QString getRisk(int score) {
    if (score < 50) return "HIGH RISK";
    if (score < 80) return "MEDIUM RISK";
    return "LOW RISK";
}

// Get current connection info (SSID and IP)
void getCurrentConnection(QString &currentSsid, QString &currentIp) {
    QProcess process;
    process.start("netsh", QStringList() << "wlan" << "show" << "interfaces");
    process.waitForFinished();
    QString ifData = process.readAllStandardOutput();

    QString interfaceName;
    QStringList lines = ifData.split("\n");
    for (const QString &line : lines) {
        if (line.contains("Name")) {
            QStringList parts = line.split(":");
            if (parts.size() > 1) interfaceName = parts[1].trimmed();
        } else if (line.contains("SSID") && !line.contains("BSSID")) {
            QStringList parts = line.split(":");
            if (parts.size() > 1) currentSsid = parts[1].trimmed();
        }
    }

    if (!interfaceName.isEmpty()) {
        process.start("netsh", QStringList() << "interface" << "ip" << "show" << "config" << "name=" + interfaceName);
        process.waitForFinished();
        QString cfgData = process.readAllStandardOutput();
        QStringList cfgLines = cfgData.split("\n");
        for (const QString &line : cfgLines) {
            if (line.contains("IP Address")) {
                QStringList parts = line.split(":");
                if (parts.size() > 1) {
                    currentIp = parts[1].trimmed();
                    break;
                }
            }
        }
    }
}

class WifiChecker : public QWidget {
public:
    WifiChecker() {
        setWindowTitle("WiFi Safety Checker (Qt)");

        QVBoxLayout *layout = new QVBoxLayout(this);

        scanButton = new QPushButton("Scan Networks");
        output = new QTextEdit();
        output->setReadOnly(true);

        layout->addWidget(scanButton);
        layout->addWidget(output);

        connect(scanButton, &QPushButton::clicked, this, &WifiChecker::scanNetworks);
    }

private:
    QPushButton *scanButton;
    QTextEdit *output;

    void scanNetworks() {
        output->clear();
        output->append("Scanning WiFi networks...\n");

        QProcess process;
        process.start("netsh", QStringList() << "wlan" << "show" << "networks" << "mode=bssid");
        process.waitForFinished();

        QString result = process.readAllStandardOutput();

        auto networks = parseNetworks(result);

        QString currentSsid, currentIp;
        getCurrentConnection(currentSsid, currentIp);

        for (const auto &net : networks) {
            int score = calculateScore(net, networks);

            QString displayName = net.ssid;
            if (net.ssid == currentSsid && !currentIp.isEmpty()) {
                displayName += " (" + currentIp + ")";
            }

            output->append("SSID: " + displayName);
            output->append("Auth: " + net.auth);
            output->append("Score: " + QString::number(score) + "/100 (" + getRisk(score) + ")");

            if (score < 50) {
                output->append("Warning: Avoid sensitive activity.");
            }

            output->append("-----------------------------");
        }
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    WifiChecker window;
    window.resize(600, 400);
    window.show();

    return app.exec();
}
