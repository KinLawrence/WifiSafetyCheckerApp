import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WiFi Safety Checker — JavaFX Edition
 *
 * A desktop application that scans nearby WiFi networks using the Windows
 * `netsh` command, evaluates each network's security posture, assigns a
 * safety score (0-100), and lets the user export the results to TXT or CSV.
 *
 * Scoring algorithm (mirrors the Python implementation):
 *   Base score: 100
 *   - Open authentication        : -50
 *   - WEP encryption             : -40
 *   - Suspicious SSID keywords   : -10  (free / guest / wifi)
 *   - Duplicate SSID (Evil Twin) : -30
 *
 * Risk levels:
 *   HIGH   (score < 50)  — red
 *   MEDIUM (score 50-79) — orange / yellow
 *   LOW    (score ≥ 80)  — green
 *
 * Build & run (Java 17+ with JavaFX 17+ on the module path):
 *   javac --module-path <javafx-sdk>/lib --add-modules javafx.controls App.java
 *   java  --module-path <javafx-sdk>/lib --add-modules javafx.controls App
 */
public class App extends Application {

    // ─── Palette ──────────────────────────────────────────────────────────────
    private static final String BG_DARK        = "#0f0f1a";
    private static final String BG_CARD        = "#1a1a2e";
    private static final String BG_HEADER      = "#16213e";
    private static final String ACCENT_BLUE    = "#0f3460";
    private static final String ACCENT_CYAN    = "#00d4ff";
    private static final String ACCENT_GREEN   = "#2ecc71";
    private static final String ACCENT_ORANGE  = "#e67e22";
    private static final String TEXT_PRIMARY   = "#e0e0e0";
    private static final String TEXT_SECONDARY = "#7f8c8d";
    private static final String BTN_SCAN_BG    = "#2ecc71";
    private static final String BTN_EXPORT_BG  = "#3498db";

    // ─── UI Nodes ─────────────────────────────────────────────────────────────
    private Label        clockLabel;
    private TextArea     outputArea;
    private Button       scanBtn;
    private Button       exportBtn;
    private ProgressBar  progressBar;
    private Label        statusLabel;

    // ─── State ────────────────────────────────────────────────────────────────
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "clock-thread");
        t.setDaemon(true);
        return t;
    });

    // ══════════════════════════════════════════════════════════════════════════
    //  JavaFX Entry Point
    // ══════════════════════════════════════════════════════════════════════════

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        stage.setTitle("WiFi Safety Checker");

        // ── Root layout ──
        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: " + BG_DARK + ";");

        // ── Header ──
        root.setTop(buildHeader());

        // ── Output area ──
        root.setCenter(buildOutputPanel());

        // ── Button bar ──
        root.setBottom(buildButtonBar(stage));

        // ── Scene sizing: half the primary screen ──
        double screenW = javafx.stage.Screen.getPrimary().getVisualBounds().getWidth();
        double screenH = javafx.stage.Screen.getPrimary().getVisualBounds().getHeight();
        Scene scene = new Scene(root, screenW / 2, screenH / 2);
        scene.getStylesheets();          // no external sheet needed

        stage.setScene(scene);
        stage.centerOnScreen();
        stage.toFront();
        stage.show();

        // ── Start real-time clock ──
        startClock();
    }

    @Override
    public void stop() {
        scheduler.shutdownNow();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  UI Builders
    // ══════════════════════════════════════════════════════════════════════════

    /** Top header: app title + real-time clock */
    private VBox buildHeader() {
        Label titleLabel = new Label("🛡️  WiFi Safety Checker");
        titleLabel.setStyle(
            "-fx-font-family: 'Segoe UI'; -fx-font-size: 22px; -fx-font-weight: bold;" +
            "-fx-text-fill: " + ACCENT_CYAN + ";"
        );

        clockLabel = new Label("System Time: --:--:--");
        clockLabel.setStyle(
            "-fx-font-family: 'Segoe UI'; -fx-font-size: 11px; -fx-font-style: italic;" +
            "-fx-text-fill: " + TEXT_SECONDARY + ";"
        );

        statusLabel = new Label("Ready — press Scan Networks to begin.");
        statusLabel.setStyle(
            "-fx-font-family: 'Segoe UI'; -fx-font-size: 11px;" +
            "-fx-text-fill: " + TEXT_SECONDARY + ";"
        );

        // Thin gradient separator line
        Region separator = new Region();
        separator.setPrefHeight(2);
        separator.setStyle(
            "-fx-background-color: linear-gradient(to right, " +
            ACCENT_CYAN + ", transparent);"
        );

        VBox header = new VBox(4, titleLabel, clockLabel, statusLabel, separator);
        header.setStyle("-fx-background-color: " + BG_HEADER + ";");
        header.setPadding(new Insets(14, 20, 10, 20));
        return header;
    }

    /** Scrollable monospace output area for scan results */
    private StackPane buildOutputPanel() {
        outputArea = new TextArea();
        outputArea.setEditable(false);
        outputArea.setWrapText(false);
        outputArea.setFont(Font.font("Consolas", 12));
        outputArea.setStyle(
            "-fx-background-color: " + BG_CARD + ";" +
            "-fx-control-inner-background: " + BG_CARD + ";" +
            "-fx-text-fill: " + TEXT_PRIMARY + ";" +
            "-fx-border-color: #2a2a4a;" +
            "-fx-border-radius: 6;" +
            "-fx-background-radius: 6;"
        );
        outputArea.setText(
            "  Network scan results will appear here after you click \"Scan Networks\".\n\n" +
            "  Each line shows:\n" +
            "    SSID (network name)  →  Security Score: X/100  [RISK LEVEL]\n\n" +
            "  Scoring deductions:\n" +
            "    Open authentication .............. -50\n" +
            "    WEP encryption ................... -40\n" +
            "    Suspicious SSID (free/guest/wifi) . -10\n" +
            "    Duplicate SSID (Evil Twin risk) .. -30\n"
        );

        progressBar = new ProgressBar(0);
        progressBar.setVisible(false);
        progressBar.setPrefWidth(Double.MAX_VALUE);
        progressBar.setStyle(
            "-fx-accent: " + ACCENT_CYAN + ";" +
            "-fx-background-color: #2a2a4a;"
        );

        VBox panel = new VBox(0, progressBar, outputArea);
        VBox.setVgrow(outputArea, Priority.ALWAYS);
        panel.setPadding(new Insets(10, 14, 0, 14));

        StackPane wrapper = new StackPane(panel);
        return wrapper;
    }

    /** Bottom action buttons */
    private HBox buildButtonBar(Stage stage) {
        scanBtn = styledButton("🔍  Scan Networks", BTN_SCAN_BG);
        exportBtn = styledButton("💾  Export Results…", BTN_EXPORT_BG);
        exportBtn.setDisable(true);         // enabled after first scan

        scanBtn.setOnAction(e -> runScan());
        exportBtn.setOnAction(e -> exportResults(stage));

        HBox bar = new HBox(24, scanBtn, exportBtn);
        bar.setAlignment(Pos.CENTER);
        bar.setPadding(new Insets(18, 20, 20, 20));
        bar.setStyle("-fx-background-color: " + BG_HEADER + ";");
        return bar;
    }

    /** Factory for styled buttons */
    private Button styledButton(String text, String bgColor) {
        Button btn = new Button(text);
        String base =
            "-fx-background-color: " + bgColor + ";" +
            "-fx-text-fill: white;" +
            "-fx-font-family: 'Segoe UI';" +
            "-fx-font-size: 14px;" +
            "-fx-font-weight: bold;" +
            "-fx-padding: 12 30 12 30;" +
            "-fx-background-radius: 8;" +
            "-fx-cursor: hand;";
        String hover =
            "-fx-background-color: derive(" + bgColor + ", -15%);" +
            "-fx-text-fill: white;" +
            "-fx-font-family: 'Segoe UI';" +
            "-fx-font-size: 14px;" +
            "-fx-font-weight: bold;" +
            "-fx-padding: 12 30 12 30;" +
            "-fx-background-radius: 8;" +
            "-fx-cursor: hand;";
        btn.setStyle(base);
        btn.setOnMouseEntered(e -> btn.setStyle(hover));
        btn.setOnMouseExited(e -> btn.setStyle(base));
        btn.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(btn, Priority.ALWAYS);
        return btn;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Real-Time Clock
    // ══════════════════════════════════════════════════════════════════════════

    private void startClock() {
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        scheduler.scheduleAtFixedRate(() -> {
            String time = LocalDateTime.now().format(fmt);
            Platform.runLater(() -> clockLabel.setText("System Time: " + time));
        }, 0, 1, TimeUnit.SECONDS);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  WiFi Scanning & Analysis (runs on background thread)
    // ══════════════════════════════════════════════════════════════════════════

    private void runScan() {
        scanBtn.setDisable(true);
        exportBtn.setDisable(true);
        progressBar.setVisible(true);
        progressBar.setProgress(ProgressIndicator.INDETERMINATE_PROGRESS);
        setStatus("Scanning nearby networks…");
        outputArea.clear();

        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                String raw    = scanWifi();
                String[] conn = getCurrentConnection();
                return buildResults(raw, conn[0], conn[1]);
            }
        };

        task.setOnSucceeded(e -> {
            outputArea.setText(task.getValue());
            progressBar.setVisible(false);
            scanBtn.setDisable(false);
            exportBtn.setDisable(false);
            setStatus("Scan complete — " +
                      LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
        });

        task.setOnFailed(e -> {
            Throwable ex = task.getException();
            outputArea.setText("ERROR: " + ex.getMessage());
            progressBar.setVisible(false);
            scanBtn.setDisable(false);
            setStatus("Scan failed.");
        });

        Thread t = new Thread(task, "wifi-scan-thread");
        t.setDaemon(true);
        t.start();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Core Logic
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Executes `netsh wlan show networks mode=bssid` and returns raw stdout.
     */
    private String scanWifi() throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("netsh", "wlan", "show", "networks", "mode=bssid");
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String out = readStream(proc.getInputStream());
        proc.waitFor();
        return out;
    }

    /**
     * Retrieves the currently connected WiFi SSID and local IP address.
     * Returns String[2] = { ssid, ip }.
     */
    private String[] getCurrentConnection() {
        String ssid = "";
        String ip   = "";
        String ifName = "";

        try {
            // ── get interface info ──
            ProcessBuilder pb = new ProcessBuilder("netsh", "wlan", "show", "interfaces");
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            String out = readStream(proc.getInputStream());
            proc.waitFor();

            for (String line : out.split("\\r?\\n")) {
                if (line.contains("Name") && !line.contains("SSID")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length > 1) ifName = parts[1].trim();
                } else if (line.contains("SSID") && !line.contains("BSSID")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length > 1) ssid = parts[1].trim();
                }
            }

            // ── get IP for the interface ──
            if (!ifName.isEmpty()) {
                ProcessBuilder pb2 = new ProcessBuilder(
                    "netsh", "interface", "ip", "show", "config", "name=" + ifName
                );
                pb2.redirectErrorStream(true);
                Process proc2 = pb2.start();
                String out2 = readStream(proc2.getInputStream());
                proc2.waitFor();

                for (String line : out2.split("\\r?\\n")) {
                    if (line.contains("IP Address")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length > 1) {
                            ip = parts[1].trim();
                            break;
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }

        return new String[]{ssid, ip};
    }

    /**
     * Parses the raw netsh output, scores each network, and builds the
     * display string that goes into the output area.
     */
    private String buildResults(String raw, String currentSsid, String currentIp) {
        // ── Parse networks ──
        List<Map<String, String>> networks = new ArrayList<>();
        Map<String, String> current = new LinkedHashMap<>();

        for (String line : raw.split("\\r?\\n")) {
            line = line.trim();

            if (line.startsWith("SSID") && !line.startsWith("BSSID")) {
                if (!current.isEmpty()) {
                    networks.add(current);
                    current = new LinkedHashMap<>();
                }
                String[] parts = line.split(":", 2);
                if (parts.length > 1) current.put("SSID", parts[1].trim());

            } else if (line.contains("Authentication")) {
                String[] parts = line.split(":", 2);
                if (parts.length > 1) current.put("Auth", parts[1].trim());
            }
        }
        if (!current.isEmpty()) networks.add(current);

        if (networks.isEmpty()) {
            return "No WiFi networks found.\n\nMake sure:\n" +
                   "  • Your wireless adapter is enabled\n" +
                   "  • You are running on Windows\n";
        }

        // ── Score & format ──
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-50s  %s%n", "Network (SSID)", "Score    Risk"));
        sb.append("─".repeat(70)).append("\n");

        for (Map<String, String> net : networks) {
            int score = 100;
            String ssid = net.getOrDefault("SSID", "Unknown SSID");
            String auth = net.getOrDefault("Auth", "Unknown");

            // Penalties
            if (auth.contains("Open")) score -= 50;
            if (auth.contains("WEP"))  score -= 40;
            if (ssidHasSuspiciousKeyword(ssid)) score -= 10;

            long dupes = networks.stream()
                .filter(n -> ssid.equals(n.get("SSID")))
                .count();
            if (dupes > 1) score -= 30;

            score = Math.max(score, 0);

            // Display name: append IP for the currently connected network
            String displayName = ssid;
            if (ssid.equals(currentSsid) && !currentIp.isEmpty()) {
                displayName = ssid + " (" + currentIp + ")";
            }

            String risk = riskLabel(score);

            sb.append(String.format("%-50s  %3d/100  %s%n",
                truncate(displayName, 48), score, risk));
        }

        sb.append("\n").append("─".repeat(70)).append("\n");
        sb.append(String.format("Total networks scanned: %d%n", networks.size()));
        sb.append(String.format("Scan time: %s%n",
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));

        return sb.toString();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Export
    // ══════════════════════════════════════════════════════════════════════════

    private void exportResults(Stage owner) {
        String content = outputArea.getText().strip();
        if (content.isBlank()) {
            showAlert(Alert.AlertType.WARNING, "No Results",
                "Please run a scan before exporting.");
            return;
        }

        FileChooser fc = new FileChooser();
        fc.setTitle("Save Scan Results");
        fc.setInitialFileName("wifi_scan_" +
            LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")));
        fc.getExtensionFilters().addAll(
            new FileChooser.ExtensionFilter("Text files", "*.txt"),
            new FileChooser.ExtensionFilter("CSV files", "*.csv"),
            new FileChooser.ExtensionFilter("All files", "*.*")
        );

        File file = fc.showSaveDialog(owner);
        if (file == null) return;

        try {
            if (file.getName().toLowerCase().endsWith(".csv")) {
                exportAsCsv(file, content);
            } else {
                exportAsTxt(file, content);
            }
            showAlert(Alert.AlertType.INFORMATION, "Export Successful",
                "Results saved to:\n" + file.getAbsolutePath());
        } catch (IOException ex) {
            showAlert(Alert.AlertType.ERROR, "Export Error",
                "Failed to save file:\n" + ex.getMessage());
        }
    }

    private void exportAsTxt(File file, String content) throws IOException {
        try (PrintWriter pw = new PrintWriter(file, StandardCharsets.UTF_8)) {
            pw.println("WiFi Safety Scan Results");
            pw.println("Date: " +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            pw.println("-".repeat(30));
            pw.println(content);
        }
    }

    private void exportAsCsv(File file, String content) throws IOException {
        // Pattern: "SSID  →  Security Score: X/100"  (original Python format)
        // or the tabular format written by this app: row contains "X/100"
        Pattern p = Pattern.compile("^(.+?)\\s{2,}(\\d+)/100\\s+(\\S+)\\s*$");

        try (PrintWriter pw = new PrintWriter(file, StandardCharsets.UTF_8)) {
            pw.println("SSID,Security Score,Scale,Risk");
            for (String line : content.split("\\r?\\n")) {
                Matcher m = p.matcher(line.trim());
                if (m.matches()) {
                    String ssid  = m.group(1).trim().replace("\"", "\"\"");
                    String score = m.group(2).trim();
                    String risk  = m.group(3).trim();
                    pw.printf("\"%s\",%s,100,%s%n", ssid, score, risk);
                }
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════════════════════

    private boolean ssidHasSuspiciousKeyword(String ssid) {
        String lower = ssid.toLowerCase();
        return lower.contains("free") || lower.contains("guest") || lower.contains("wifi");
    }

    private String riskLabel(int score) {
        if (score >= 80) return "🟢 LOW";
        if (score >= 50) return "🟡 MEDIUM";
        return "🔴 HIGH";
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    private String readStream(InputStream is) throws IOException {
        try (BufferedReader br = new BufferedReader(
                 new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        }
    }

    private void setStatus(String msg) {
        Platform.runLater(() -> statusLabel.setText(msg));
    }

    private void showAlert(Alert.AlertType type, String title, String msg) {
        Platform.runLater(() -> {
            Alert alert = new Alert(type, msg, ButtonType.OK);
            alert.setTitle(title);
            alert.setHeaderText(null);
            // Apply dark style to the dialog
            DialogPane dp = alert.getDialogPane();
            dp.setStyle(
                "-fx-background-color: " + BG_CARD + ";" +
                "-fx-font-family: 'Segoe UI';" +
                "-fx-font-size: 13px;" +
                "-fx-text-fill: " + TEXT_PRIMARY + ";"
            );
            alert.showAndWait();
        });
    }
}
