using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;

/// <summary>
/// Wi-Fi Safety Checker — WPF Edition (C#/.NET)
///
/// A desktop application that scans nearby Wi-Fi networks using the Windows
/// <c>netsh</c> command, evaluates each network's security posture, assigns a
/// safety score (0–100), and lets the user export the results to TXT or CSV.
///
/// Scoring algorithm (mirrors the Python / Java implementations):
///   Base score: 100
///   - Open authentication        : −50
///   - WEP encryption             : −40
///   - Suspicious SSID keywords   : −10  (free / guest / wifi)
///   - Duplicate SSID (Evil Twin) : −30
///
/// Risk levels:
///   HIGH   (score &lt; 50)   — red
///   MEDIUM (score 50–79)  — orange
///   LOW    (score ≥ 80)   — green
///
/// Build &amp; run (.NET 6+ with WPF workload):
///   dotnet new wpf -n WifiSafetyChecker
///   (replace the generated files with this one)
///   dotnet run
/// </summary>
namespace WifiSafetyChecker
{
    // ════════════════════════════════════════════════════════════════════════
    //  Data Model
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>Represents a single Wi-Fi network parsed from netsh output.</summary>
    public class Network
    {
        public string Ssid { get; set; } = "Unknown SSID";
        public string Auth { get; set; } = "Unknown";
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Scoring Engine (static, easily testable)
    // ════════════════════════════════════════════════════════════════════════

    /// <summary>
    /// Contains all pure-logic functions: parsing, scoring, risk labelling.
    /// Separated from the UI so that unit tests can exercise them directly.
    /// </summary>
    public static class WifiScorer
    {
        // ── Suspicious SSID keywords ────────────────────────────────────
        private static readonly string[] SuspiciousKeywords = { "free", "guest", "wifi" };

        /// <summary>Parses raw <c>netsh wlan show networks</c> output into a list of networks.</summary>
        public static List<Network> ParseNetworks(string rawOutput)
        {
            var networks = new List<Network>();
            Network current = null;

            foreach (string rawLine in rawOutput.Split('\n'))
            {
                string line = rawLine.Trim();

                if (line.StartsWith("SSID") && !line.StartsWith("BSSID"))
                {
                    if (current != null)
                        networks.Add(current);

                    current = new Network();
                    string[] parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length > 1)
                        current.Ssid = parts[1].Trim();
                }
                else if (line.Contains("Authentication"))
                {
                    string[] parts = line.Split(new[] { ':' }, 2);
                    if (parts.Length > 1 && current != null)
                        current.Auth = parts[1].Trim();
                }
            }

            if (current != null)
                networks.Add(current);

            return networks;
        }

        /// <summary>Returns true if the SSID contains a suspicious keyword.</summary>
        public static bool HasSuspiciousKeyword(string ssid)
        {
            string lower = ssid.ToLowerInvariant();
            return SuspiciousKeywords.Any(kw => lower.Contains(kw));
        }

        /// <summary>Calculates the safety score (0–100) for a single network.</summary>
        public static int CalculateScore(Network network, List<Network> allNetworks)
        {
            int score = 100;

            if (network.Auth.Contains("Open"))
                score -= 50;

            if (network.Auth.Contains("WEP"))
                score -= 40;

            if (HasSuspiciousKeyword(network.Ssid))
                score -= 10;

            int duplicates = allNetworks.Count(n => n.Ssid == network.Ssid);
            if (duplicates > 1)
                score -= 30;

            return Math.Max(score, 0);
        }

        /// <summary>Maps a numeric score to a risk label string.</summary>
        public static string GetRiskLabel(int score)
        {
            if (score >= 80) return "🟢 LOW";
            if (score >= 50) return "🟡 MEDIUM";
            return "🔴 HIGH";
        }

        /// <summary>Returns the <see cref="Brush"/> colour matching the risk level.</summary>
        public static Brush GetRiskBrush(int score)
        {
            if (score >= 80) return new SolidColorBrush(Color.FromRgb(0x2E, 0xCC, 0x71)); // green
            if (score >= 50) return new SolidColorBrush(Color.FromRgb(0xE6, 0x7E, 0x22)); // orange
            return new SolidColorBrush(Color.FromRgb(0xE7, 0x4C, 0x3C));                  // red
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Main Window
    // ════════════════════════════════════════════════════════════════════════

    public class MainWindow : Window
    {
        // ── Palette ─────────────────────────────────────────────────────
        private static readonly Color BgDark      = Color.FromRgb(0x0F, 0x0F, 0x1A);
        private static readonly Color BgCard      = Color.FromRgb(0x1A, 0x1A, 0x2E);
        private static readonly Color BgHeader    = Color.FromRgb(0x16, 0x21, 0x3E);
        private static readonly Color AccentCyan  = Color.FromRgb(0x00, 0xD4, 0xFF);
        private static readonly Color TextPrimary = Color.FromRgb(0xE0, 0xE0, 0xE0);
        private static readonly Color TextSecond  = Color.FromRgb(0x7F, 0x8C, 0x8D);
        private static readonly Color BtnScanBg   = Color.FromRgb(0x2E, 0xCC, 0x71);
        private static readonly Color BtnExportBg = Color.FromRgb(0x34, 0x98, 0xDB);

        // ── UI controls ─────────────────────────────────────────────────
        private TextBlock  _clockLabel;
        private TextBlock  _statusLabel;
        private TextBox    _outputArea;
        private Button     _scanBtn;
        private Button     _exportBtn;
        private ProgressBar _progressBar;

        // ── Clock timer ─────────────────────────────────────────────────
        private DispatcherTimer _clockTimer;

        // ── Constructor ─────────────────────────────────────────────────
        public MainWindow()
        {
            Title  = "Wi-Fi Safety Checker";
            Width  = SystemParameters.PrimaryScreenWidth  / 2;
            Height = SystemParameters.PrimaryScreenHeight / 2;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Background = new SolidColorBrush(BgDark);

            Content = BuildLayout();
            StartClock();
        }

        // ════════════════════════════════════════════════════════════════
        //  UI Builders
        // ════════════════════════════════════════════════════════════════

        private DockPanel BuildLayout()
        {
            var root = new DockPanel { LastChildFill = true };

            // ── Header (top) ──
            DockPanel.SetDock(BuildHeader(), Dock.Top);
            root.Children.Add(BuildHeader());

            // ── Button bar (bottom) ──
            var btnBar = BuildButtonBar();
            DockPanel.SetDock(btnBar, Dock.Bottom);
            root.Children.Add(btnBar);

            // ── Output area (fill) ──
            root.Children.Add(BuildOutputPanel());

            return root;
        }

        private UIElement BuildHeader()
        {
            var titleLabel = new TextBlock
            {
                Text       = "🛡️  Wi-Fi Safety Checker",
                FontFamily = new FontFamily("Segoe UI"),
                FontSize   = 22,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(AccentCyan),
                Margin     = new Thickness(0, 0, 0, 4)
            };

            _clockLabel = new TextBlock
            {
                Text       = "System Time: --:--:--",
                FontFamily = new FontFamily("Segoe UI"),
                FontSize   = 11,
                FontStyle  = FontStyles.Italic,
                Foreground = new SolidColorBrush(TextSecond)
            };

            _statusLabel = new TextBlock
            {
                Text       = "Ready — press Scan Networks to begin.",
                FontFamily = new FontFamily("Segoe UI"),
                FontSize   = 11,
                Foreground = new SolidColorBrush(TextSecond),
                Margin     = new Thickness(0, 2, 0, 6)
            };

            // Gradient separator line
            var separator = new Rectangle
            {
                Height = 2,
                Fill   = new LinearGradientBrush(AccentCyan, Colors.Transparent, 0)
            };

            var header = new StackPanel { Background = new SolidColorBrush(BgHeader) };
            header.Children.Add(titleLabel);
            header.Children.Add(_clockLabel);
            header.Children.Add(_statusLabel);
            header.Children.Add(separator);
            header.Margin = new Thickness(0);
            // Internal padding via child margins
            foreach (UIElement child in header.Children)
            {
                if (child is FrameworkElement fe)
                    fe.Margin = new Thickness(20, fe.Margin.Top, 20, fe.Margin.Bottom);
            }

            return header;
        }

        private UIElement BuildOutputPanel()
        {
            _progressBar = new ProgressBar
            {
                Height     = 4,
                Visibility = Visibility.Collapsed,
                Foreground = new SolidColorBrush(AccentCyan),
                Background = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x4A)),
                IsIndeterminate = true
            };

            _outputArea = new TextBox
            {
                IsReadOnly       = true,
                AcceptsReturn    = true,
                TextWrapping     = TextWrapping.NoWrap,
                FontFamily       = new FontFamily("Consolas"),
                FontSize         = 12,
                Foreground       = new SolidColorBrush(TextPrimary),
                Background       = new SolidColorBrush(BgCard),
                BorderBrush      = new SolidColorBrush(Color.FromRgb(0x2A, 0x2A, 0x4A)),
                BorderThickness  = new Thickness(1),
                VerticalScrollBarVisibility   = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(8),
                Text =
                    "  Network scan results will appear here after you click \"Scan Networks\".\n\n" +
                    "  Each line shows:\n" +
                    "    SSID (network name)  →  Security Score: X/100  [RISK LEVEL]\n\n" +
                    "  Scoring deductions:\n" +
                    "    Open authentication .............. -50\n" +
                    "    WEP encryption ................... -40\n" +
                    "    Suspicious SSID (free/guest/wifi) . -10\n" +
                    "    Duplicate SSID (Evil Twin risk) .. -30\n"
            };

            var panel = new DockPanel { Margin = new Thickness(14, 10, 14, 0) };
            DockPanel.SetDock(_progressBar, Dock.Top);
            panel.Children.Add(_progressBar);
            panel.Children.Add(_outputArea);

            return panel;
        }

        private UIElement BuildButtonBar()
        {
            _scanBtn   = StyledButton("🔍  Scan Networks",   BtnScanBg);
            _exportBtn = StyledButton("💾  Export Results…", BtnExportBg);
            _exportBtn.IsEnabled = false;

            _scanBtn.Click   += (_, __) => RunScan();
            _exportBtn.Click += (_, __) => ExportResults();

            var bar = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Center,
                Background = new SolidColorBrush(BgHeader),
                Margin = new Thickness(0)
            };

            _scanBtn.Margin   = new Thickness(20, 18, 12, 20);
            _exportBtn.Margin = new Thickness(12, 18, 20, 20);

            bar.Children.Add(_scanBtn);
            bar.Children.Add(_exportBtn);

            // Make bar stretch full width
            var wrapper = new Border
            {
                Background = new SolidColorBrush(BgHeader),
                Child = bar
            };

            return wrapper;
        }

        private Button StyledButton(string text, Color bgColor)
        {
            var btn = new Button
            {
                Content    = text,
                FontFamily = new FontFamily("Segoe UI"),
                FontSize   = 14,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White,
                Background = new SolidColorBrush(bgColor),
                Padding    = new Thickness(30, 12, 30, 12),
                Cursor     = Cursors.Hand,
                BorderThickness = new Thickness(0)
            };

            // Hover effect: darken on enter, restore on leave
            Color hoverColor = Color.FromRgb(
                (byte)(bgColor.R * 0.85),
                (byte)(bgColor.G * 0.85),
                (byte)(bgColor.B * 0.85));

            btn.MouseEnter += (_, __) => btn.Background = new SolidColorBrush(hoverColor);
            btn.MouseLeave += (_, __) => btn.Background = new SolidColorBrush(bgColor);

            return btn;
        }

        // ════════════════════════════════════════════════════════════════
        //  Real-Time Clock
        // ════════════════════════════════════════════════════════════════

        private void StartClock()
        {
            _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _clockTimer.Tick += (_, __) =>
            {
                _clockLabel.Text = "System Time: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            };
            _clockTimer.Start();
        }

        // ════════════════════════════════════════════════════════════════
        //  Wi-Fi Scanning & Analysis (async to keep UI responsive)
        // ════════════════════════════════════════════════════════════════

        private async void RunScan()
        {
            _scanBtn.IsEnabled   = false;
            _exportBtn.IsEnabled = false;
            _progressBar.Visibility = Visibility.Visible;
            _statusLabel.Text = "Scanning nearby networks…";
            _outputArea.Clear();

            try
            {
                string result = await Task.Run(() =>
                {
                    string raw = ScanWifi();
                    var (currentSsid, currentIp) = GetCurrentConnection();
                    return BuildResults(raw, currentSsid, currentIp);
                });

                _outputArea.Text = result;
                _exportBtn.IsEnabled = true;
                _statusLabel.Text = "Scan complete — " + DateTime.Now.ToString("HH:mm:ss");
            }
            catch (Exception ex)
            {
                _outputArea.Text = "ERROR: " + ex.Message;
                _statusLabel.Text = "Scan failed.";
            }
            finally
            {
                _progressBar.Visibility = Visibility.Collapsed;
                _scanBtn.IsEnabled = true;
            }
        }

        // ════════════════════════════════════════════════════════════════
        //  Core Logic
        // ════════════════════════════════════════════════════════════════

        /// <summary>Executes <c>netsh wlan show networks mode=bssid</c> and returns stdout.</summary>
        private static string ScanWifi()
        {
            var psi = new ProcessStartInfo
            {
                FileName               = "netsh",
                Arguments              = "wlan show networks mode=bssid",
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                StandardOutputEncoding = Encoding.UTF8
            };

            using var proc = Process.Start(psi);
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            return output;
        }

        /// <summary>Retrieves the currently connected Wi-Fi SSID and local IP.</summary>
        private static (string ssid, string ip) GetCurrentConnection()
        {
            string ssid = "", ip = "", ifName = "";

            try
            {
                // Get interface info
                var psi = new ProcessStartInfo
                {
                    FileName               = "netsh",
                    Arguments              = "wlan show interfaces",
                    RedirectStandardOutput = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    StandardOutputEncoding = Encoding.UTF8
                };

                using (var proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit();

                    foreach (string line in output.Split('\n'))
                    {
                        if (line.Contains("Name") && !line.Contains("SSID"))
                        {
                            string[] parts = line.Split(new[] { ':' }, 2);
                            if (parts.Length > 1) ifName = parts[1].Trim();
                        }
                        else if (line.Contains("SSID") && !line.Contains("BSSID"))
                        {
                            string[] parts = line.Split(new[] { ':' }, 2);
                            if (parts.Length > 1) ssid = parts[1].Trim();
                        }
                    }
                }

                // Get IP for the interface
                if (!string.IsNullOrEmpty(ifName))
                {
                    var psi2 = new ProcessStartInfo
                    {
                        FileName               = "netsh",
                        Arguments              = $"interface ip show config name={ifName}",
                        RedirectStandardOutput = true,
                        UseShellExecute        = false,
                        CreateNoWindow         = true,
                        StandardOutputEncoding = Encoding.UTF8
                    };

                    using var proc2 = Process.Start(psi2);
                    string output2 = proc2.StandardOutput.ReadToEnd();
                    proc2.WaitForExit();

                    foreach (string line in output2.Split('\n'))
                    {
                        if (line.Contains("IP Address"))
                        {
                            string[] parts = line.Split(new[] { ':' }, 2);
                            if (parts.Length > 1)
                            {
                                ip = parts[1].Trim();
                                break;
                            }
                        }
                    }
                }
            }
            catch
            {
                // Silently fail — connection info is supplementary
            }

            return (ssid, ip);
        }

        /// <summary>
        /// Parses the raw netsh output, scores each network, and builds the
        /// display string for the output area.
        /// </summary>
        private static string BuildResults(string raw, string currentSsid, string currentIp)
        {
            List<Network> networks = WifiScorer.ParseNetworks(raw);

            if (networks.Count == 0)
            {
                return "No Wi-Fi networks found.\n\nMake sure:\n" +
                       "  • Your wireless adapter is enabled\n" +
                       "  • You are running on Windows\n";
            }

            var sb = new StringBuilder();
            sb.AppendLine($"{"Network (SSID)",-50}  {"Score",-8}  Risk");
            sb.AppendLine(new string('─', 70));

            foreach (var net in networks)
            {
                int    score = WifiScorer.CalculateScore(net, networks);
                string risk  = WifiScorer.GetRiskLabel(score);

                string displayName = net.Ssid;
                if (net.Ssid == currentSsid && !string.IsNullOrEmpty(currentIp))
                    displayName = $"{net.Ssid} ({currentIp})";

                // Truncate long display names
                if (displayName.Length > 48)
                    displayName = displayName.Substring(0, 47) + "…";

                sb.AppendLine($"{displayName,-50}  {score,3}/100  {risk}");
            }

            sb.AppendLine();
            sb.AppendLine(new string('─', 70));
            sb.AppendLine($"Total networks scanned: {networks.Count}");
            sb.AppendLine($"Scan time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            return sb.ToString();
        }

        // ════════════════════════════════════════════════════════════════
        //  Export
        // ════════════════════════════════════════════════════════════════

        private void ExportResults()
        {
            string content = _outputArea.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(content))
            {
                MessageBox.Show("Please run a scan before exporting.",
                    "No Results", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dlg = new SaveFileDialog
            {
                Title    = "Save Scan Results",
                FileName = $"wifi_scan_{DateTime.Now:yyyyMMdd_HHmmss}",
                Filter   = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
            };

            if (dlg.ShowDialog() != true) return;

            try
            {
                if (dlg.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                    ExportAsCsv(dlg.FileName, content);
                else
                    ExportAsTxt(dlg.FileName, content);

                MessageBox.Show($"Results saved to:\n{dlg.FileName}",
                    "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save file:\n{ex.Message}",
                    "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static void ExportAsTxt(string path, string content)
        {
            using var writer = new StreamWriter(path, false, Encoding.UTF8);
            writer.WriteLine("Wi-Fi Safety Scan Results");
            writer.WriteLine($"Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            writer.WriteLine(new string('-', 30));
            writer.Write(content);
        }

        private static void ExportAsCsv(string path, string content)
        {
            var pattern = new Regex(@"^(.+?)\s{2,}(\d+)/100\s+(\S+)\s*$");

            using var writer = new StreamWriter(path, false, Encoding.UTF8);
            writer.WriteLine("SSID,Security Score,Scale,Risk");

            foreach (string line in content.Split('\n'))
            {
                Match m = pattern.Match(line.Trim());
                if (m.Success)
                {
                    string ssid  = m.Groups[1].Value.Trim().Replace("\"", "\"\"");
                    string score = m.Groups[2].Value.Trim();
                    string risk  = m.Groups[3].Value.Trim();
                    writer.WriteLine($"\"{ssid}\",{score},100,{risk}");
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    //  Application Entry Point
    // ════════════════════════════════════════════════════════════════════════

    public class App : Application
    {
        [STAThread]
        public static void Main()
        {
            var app = new App();
            var window = new MainWindow();
            app.Run(window);
        }
    }
}
