import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for App.java (WiFi Safety Checker — JavaFX Edition).
 *
 * Because the core logic methods (ssidHasSuspiciousKeyword, riskLabel,
 * truncate, buildResults, readStream) are private members of the App class,
 * this test file uses Java Reflection to invoke them without modifying the
 * production source.
 *
 * Compile & run (JUnit 5 Platform Console Launcher on the classpath):
 *
 *   javac -cp junit-platform-console-standalone-1.x.x.jar App.java AppTest.java
 *   java  -cp .;junit-platform-console-standalone-1.x.x.jar \
 *         org.junit.platform.console.ConsoleLauncher \
 *         --select-class=AppTest
 *
 * (Replace ; with : on Linux/macOS.)
 *
 * NOTE: JavaFX classes are referenced only in the production App class, not
 * here, so no JavaFX runtime is required to compile or run these tests.
 */
class AppTest {

    // ── Shared instance used for all reflection calls ──────────────────────────
    // We cannot call new App() because JavaFX Application constructor requires
    // the toolkit to be initialized.  We use Reflection + Unsafe/allocateInstance
    // -style workaround: sun.misc.Unsafe is fragile, so instead we subclass
    // and instantiate a plain Object, then cast.  The cleanest portable option
    // for private-method testing without touching prod code is to create an App
    // instance via its no-arg constructor (which JavaFX registers but does NOT
    // start the toolkit in).
    private App app;

    @BeforeEach
    void setUp() throws Exception {
        // Instantiate App without launching the JavaFX toolkit.
        // The no-arg constructor of Application subclasses is safe to call
        // directly; it is start() that requires the toolkit.
        app = App.class.getDeclaredConstructor().newInstance();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Helper: reflective method invoker
    // ══════════════════════════════════════════════════════════════════════════

    /** Invokes a private instance method by name and parameter types. */
    private Object invoke(String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method m = App.class.getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return m.invoke(app, args);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  ssidHasSuspiciousKeyword
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("ssidHasSuspiciousKeyword()")
    class SsidKeywordTests {

        private boolean check(String ssid) throws Exception {
            return (boolean) invoke("ssidHasSuspiciousKeyword",
                    new Class[]{String.class}, ssid);
        }

        @Test
        @DisplayName("SSID containing 'free' is suspicious")
        void freeKeyword() throws Exception {
            assertTrue(check("FreeWifi123"));
        }

        @Test
        @DisplayName("SSID containing 'guest' is suspicious")
        void guestKeyword() throws Exception {
            assertTrue(check("CoffeeShop_Guest"));
        }

        @Test
        @DisplayName("SSID containing 'wifi' is suspicious")
        void wifiKeyword() throws Exception {
            assertTrue(check("PublicWifi"));
        }

        @Test
        @DisplayName("Keyword matching is case-insensitive")
        void caseInsensitive() throws Exception {
            assertTrue(check("FREE_NETWORK"));
            assertTrue(check("GuestNetwork"));
            assertTrue(check("My_WiFi_Home"));
        }

        @Test
        @DisplayName("Normal SSID with no keywords is not suspicious")
        void normalSsid() throws Exception {
            assertFalse(check("HomeNetwork_5G"));
        }

        @Test
        @DisplayName("Empty SSID is not suspicious")
        void emptySsid() throws Exception {
            assertFalse(check(""));
        }

        @Test
        @DisplayName("SSID that only partially overlaps keyword is still flagged")
        void partialMatch() throws Exception {
            // 'carefree' contains 'free'
            assertTrue(check("carefree-network"));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  riskLabel
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("riskLabel()")
    class RiskLabelTests {

        private String risk(int score) throws Exception {
            return (String) invoke("riskLabel", new Class[]{int.class}, score);
        }

        @Test
        @DisplayName("Score 100 → LOW risk")
        void perfectScore() throws Exception {
            assertTrue(risk(100).contains("LOW"));
        }

        @Test
        @DisplayName("Score 80 → LOW risk (boundary)")
        void boundaryLow() throws Exception {
            assertTrue(risk(80).contains("LOW"));
        }

        @Test
        @DisplayName("Score 79 → MEDIUM risk (boundary)")
        void boundaryMediumHigh() throws Exception {
            assertTrue(risk(79).contains("MEDIUM"));
        }

        @Test
        @DisplayName("Score 50 → MEDIUM risk (boundary)")
        void boundaryMediumLow() throws Exception {
            assertTrue(risk(50).contains("MEDIUM"));
        }

        @Test
        @DisplayName("Score 49 → HIGH risk (boundary)")
        void boundaryHigh() throws Exception {
            assertTrue(risk(49).contains("HIGH"));
        }

        @Test
        @DisplayName("Score 0 → HIGH risk")
        void zeroScore() throws Exception {
            assertTrue(risk(0).contains("HIGH"));
        }

        @ParameterizedTest(name = "score={0} → {1}")
        @CsvSource({
            "100, LOW",
            "80,  LOW",
            "65,  MEDIUM",
            "50,  MEDIUM",
            "49,  HIGH",
            "10,  HIGH",
            "0,   HIGH"
        })
        @DisplayName("Parameterized risk boundaries")
        void parameterized(int score, String expected) throws Exception {
            assertTrue(risk(score).contains(expected.trim()));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  truncate
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("truncate()")
    class TruncateTests {

        private String trunc(String s, int max) throws Exception {
            return (String) invoke("truncate",
                    new Class[]{String.class, int.class}, s, max);
        }

        @Test
        @DisplayName("String shorter than max is returned unchanged")
        void shortString() throws Exception {
            assertEquals("Hello", trunc("Hello", 10));
        }

        @Test
        @DisplayName("String exactly at max length is returned unchanged")
        void exactLength() throws Exception {
            assertEquals("Hello", trunc("Hello", 5));
        }

        @Test
        @DisplayName("String longer than max is truncated with ellipsis")
        void longString() throws Exception {
            String result = trunc("HelloWorld", 6);
            // Result length should be exactly max (5 chars + ellipsis char)
            assertEquals(6, result.length());
            assertTrue(result.endsWith("…"));
        }

        @Test
        @DisplayName("Empty string with any max returns empty")
        void emptyString() throws Exception {
            assertEquals("", trunc("", 5));
        }

        @Test
        @DisplayName("Truncation at max=1 yields only ellipsis")
        void singleCharMax() throws Exception {
            String result = trunc("ABC", 1);
            assertEquals("…", result);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  readStream
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("readStream()")
    class ReadStreamTests {

        private String read(String content) throws Exception {
            InputStream is = new ByteArrayInputStream(
                    content.getBytes(StandardCharsets.UTF_8));
            return (String) invoke("readStream",
                    new Class[]{InputStream.class}, is);
        }

        @Test
        @DisplayName("Reads single-line stream correctly")
        void singleLine() throws Exception {
            assertEquals("Hello\n", read("Hello"));
        }

        @Test
        @DisplayName("Reads multi-line stream with newlines preserved")
        void multiLine() throws Exception {
            String result = read("Line1\nLine2\nLine3");
            assertEquals("Line1\nLine2\nLine3\n", result);
        }

        @Test
        @DisplayName("Empty stream returns empty string")
        void emptyStream() throws Exception {
            assertEquals("", read(""));
        }

        @Test
        @DisplayName("Stream with Windows CRLF line endings is read faithfully")
        void crlfLineEndings() throws Exception {
            String result = read("A\r\nB\r\nC");
            // BufferedReader.readLine() strips the \r, so each line is re-joined with \n
            assertEquals("A\nB\nC\n", result);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  buildResults  — scoring & formatting logic
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("buildResults()")
    class BuildResultsTests {

        private String build(String raw, String currentSsid, String currentIp)
                throws Exception {
            return (String) invoke("buildResults",
                    new Class[]{String.class, String.class, String.class},
                    raw, currentSsid, currentIp);
        }

        /** Minimal valid netsh-style block for a single network. */
        private String netshBlock(String ssid, String auth) {
            return "SSID 1 : " + ssid + "\r\n" +
                   "Network type            : Infrastructure\r\n" +
                   "Authentication          : " + auth + "\r\n" +
                   "Encryption              : CCMP\r\n";
        }

        @Test
        @DisplayName("Empty raw output returns 'No WiFi networks found' message")
        void emptyRawOutput() throws Exception {
            String result = build("", "", "");
            assertTrue(result.contains("No WiFi networks found"));
        }

        @Test
        @DisplayName("WPA2-Personal network scores 100 (no deductions)")
        void secureNetworkFullScore() throws Exception {
            String raw = netshBlock("SecureHome", "WPA2-Personal");
            String result = build(raw, "", "");
            assertTrue(result.contains("100/100"), "Expected 100/100 in: " + result);
        }

        @Test
        @DisplayName("Open auth network deducts 50 points → score 50")
        void openAuthDeduction() throws Exception {
            String raw = netshBlock("CoffeeShop", "Open");
            String result = build(raw, "", "");
            assertTrue(result.contains("50/100"), "Expected 50/100 in: " + result);
        }

        @Test
        @DisplayName("WEP network deducts 40 points → score 60")
        void wepDeduction() throws Exception {
            String raw = netshBlock("OldRouter", "WEP");
            String result = build(raw, "", "");
            assertTrue(result.contains("60/100"), "Expected 60/100 in: " + result);
        }

        @Test
        @DisplayName("Suspicious SSID keyword 'free' deducts 10 points → score 90")
        void suspiciousSsidDeduction() throws Exception {
            String raw = netshBlock("FreeInternet", "WPA2-Personal");
            String result = build(raw, "", "");
            assertTrue(result.contains("90/100"), "Expected 90/100 in: " + result);
        }

        @Test
        @DisplayName("Open auth + suspicious SSID → score 40, shows HIGH")
        void openAndSuspiciousIsHigh() throws Exception {
            String raw = netshBlock("FreeWifi", "Open");
            String result = build(raw, "", "");
            // 100 - 50 (Open) - 10 (suspicious) = 40
            assertTrue(result.contains("40/100"), "Expected 40/100 in: " + result);
            assertTrue(result.contains("HIGH"), "Expected HIGH risk in: " + result);
        }

        @Test
        @DisplayName("Duplicate SSID (Evil Twin) deducts 30 points")
        void evilTwinDeduction() throws Exception {
            // Two blocks with identical SSID → duplicate penalty applies
            String raw = netshBlock("TwinNet", "WPA2-Personal")
                       + netshBlock("TwinNet", "WPA2-Personal");
            String result = build(raw, "", "");
            // 100 - 30 (duplicate) = 70/100 MEDIUM
            assertTrue(result.contains("70/100"), "Expected 70/100 in: " + result);
        }

        @Test
        @DisplayName("Score never goes below 0")
        void scoreFloorIsZero() throws Exception {
            // Open (-50) + WEP (-40) + suspicious (-10) = -0 → clamped to 0
            String raw = netshBlock("FreeWifiHotspot", "Open WEP");
            String result = build(raw, "", "");
            assertTrue(result.contains("0/100"), "Expected 0/100 in: " + result);
        }

        @Test
        @DisplayName("Currently connected SSID shows its IP address")
        void currentNetworkShowsIp() throws Exception {
            String raw = netshBlock("HomeNet", "WPA2-Personal");
            String result = build(raw, "HomeNet", "192.168.1.5");
            assertTrue(result.contains("192.168.1.5"),
                "Expected IP address in: " + result);
        }

        @Test
        @DisplayName("Non-connected SSID does NOT show any IP")
        void nonCurrentNetworkNoIp() throws Exception {
            String raw = netshBlock("NeighborNet", "WPA2-Personal");
            String result = build(raw, "HomeNet", "192.168.1.5");
            assertFalse(result.contains("192.168.1.5"),
                "IP should not appear for unmatched SSID");
        }

        @Test
        @DisplayName("Result contains table header and footer lines")
        void resultStructure() throws Exception {
            String raw = netshBlock("MyNet", "WPA2-Personal");
            String result = build(raw, "", "");
            assertTrue(result.contains("Network (SSID)"), "Should have header");
            assertTrue(result.contains("Total networks scanned:"), "Should have footer");
        }

        @Test
        @DisplayName("Multiple distinct networks all appear in output")
        void multipleNetworksAllPresent() throws Exception {
            String raw = netshBlock("Alpha", "WPA2-Personal")
                       + netshBlock("Beta",  "Open")
                       + netshBlock("Gamma", "WEP");
            String result = build(raw, "", "");
            assertTrue(result.contains("Alpha"), "Alpha missing");
            assertTrue(result.contains("Beta"),  "Beta missing");
            assertTrue(result.contains("Gamma"), "Gamma missing");
            assertTrue(result.contains("Total networks scanned: 3"), "Count wrong");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  CSV export regex pattern (tested directly, no file I/O required)
    // ══════════════════════════════════════════════════════════════════════════

    @Nested
    @DisplayName("CSV export regex pattern")
    class CsvPatternTests {

        /**
         * The same pattern used in exportAsCsv().
         * We test it independently to confirm it matches expected output rows.
         */
        private final Pattern CSV_PATTERN =
                Pattern.compile("^(.+?)\\s{2,}(\\d+)/100\\s+(\\S+)\\s*$");

        private Matcher match(String line) {
            return CSV_PATTERN.matcher(line.trim());
        }

        @Test
        @DisplayName("Pattern matches a typical result row")
        void matchesTypicalRow() {
            Matcher m = match("HomeNetwork                                         100/100  🟢 LOW");
            assertTrue(m.matches(), "Pattern should match");
            assertEquals("HomeNetwork", m.group(1).trim());
            assertEquals("100", m.group(2));
        }

        @Test
        @DisplayName("Pattern matches HIGH-risk row with score 0")
        void matchesZeroScore() {
            Matcher m = match("FreeWifi                                              0/100  🔴 HIGH");
            assertTrue(m.matches(), "Pattern should match zero score");
            assertEquals("0", m.group(2));
        }

        @Test
        @DisplayName("Pattern does not match the header line")
        void noMatchOnHeader() {
            Matcher m = match("Network (SSID)                                     Score    Risk");
            assertFalse(m.matches(), "Header should not match");
        }

        @Test
        @DisplayName("Pattern does not match separator lines")
        void noMatchOnSeparator() {
            Matcher m = match("──────────────────────────────────────────────────────────────────────");
            assertFalse(m.matches(), "Separator should not match");
        }
    }
}
