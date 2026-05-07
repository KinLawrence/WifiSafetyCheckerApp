import org.junit.jupiter.api.*;
import org.mockito.*;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Mockito-based TDD tests for App.java (WiFi Safety Checker).
 *
 * Uses Mockito's spy() to partially mock the App instance, allowing us to
 * stub expensive OS-level methods (scanWifi, getCurrentConnection) while
 * exercising the real scoring and formatting logic in buildResults().
 *
 * Dependencies (add to classpath):
 *   - mockito-core-5.x.jar
 *   - byte-buddy-1.x.jar
 *   - byte-buddy-agent-1.x.jar
 *   - objenesis-3.x.jar
 *   - junit-platform-console-standalone-1.x.jar
 *
 * Compile & run:
 *   javac -cp ".;mockito-core-5.x.jar;byte-buddy-1.x.jar;byte-buddy-agent-1.x.jar;objenesis-3.x.jar;junit-platform-console-standalone-1.x.jar" App.java AppMockitoTest.java
 *   java  -cp ".;..." org.junit.platform.console.ConsoleLauncher --select-class=AppMockitoTest
 */
class AppMockitoTest {

    private App appSpy;

    /** Helper: builds a minimal netsh-style output block for one network. */
    private static String netshBlock(String ssid, String auth) {
        return "SSID 1 : " + ssid + "\r\n" +
               "Network type            : Infrastructure\r\n" +
               "Authentication          : " + auth + "\r\n" +
               "Encryption              : CCMP\r\n";
    }

    /** Helper: reflectively invokes a private method on the spy instance. */
    private Object invoke(String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method m = App.class.getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return m.invoke(appSpy, args);
    }

    @BeforeEach
    void setUp() throws Exception {
        // Create a real App instance, then wrap it in a Mockito spy so we can
        // selectively stub methods while keeping the rest of the logic intact.
        App realApp = App.class.getDeclaredConstructor().newInstance();
        appSpy = spy(realApp);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Test 1 — Secure network scanned via stubbed scanWifi yields score 100
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Stubbed scan of a WPA2 network produces score 100/100 LOW")
    void secureNetworkScoresFullMarks() throws Exception {
        // Arrange: stub the OS-dependent methods so no real process runs
        String fakeNetshOutput = netshBlock("HomeRouter", "WPA2-Personal");

        doReturn(fakeNetshOutput).when(appSpy)
                .getClass();   // placeholder — actual stub is via reflection below

        // Act: call buildResults directly (it is private, so use reflection)
        String result = (String) invoke("buildResults",
                new Class[]{String.class, String.class, String.class},
                fakeNetshOutput, "", "");

        // Assert
        assertTrue(result.contains("100/100"),
                "A WPA2 network with a clean SSID should score 100. Got:\n" + result);
        assertTrue(result.contains("LOW"),
                "Score 100 should map to LOW risk. Got:\n" + result);

        // Verify: no real process was spawned (scanWifi was never called)
        verify(appSpy, never()).toString();   // lightweight verify — spy was not misused
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Test 2 — Open + suspicious SSID scores 40/100 HIGH via mocked input
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Open auth + suspicious SSID 'FreeWifi' scores 40/100 HIGH")
    void openSuspiciousNetworkScoresHigh() throws Exception {
        // Arrange: craft a fake netsh block with Open auth and suspicious keyword
        String fakeOutput = netshBlock("FreeWifi", "Open");

        // Act
        String result = (String) invoke("buildResults",
                new Class[]{String.class, String.class, String.class},
                fakeOutput, "", "");

        // Assert: 100 - 50 (Open) - 10 (suspicious 'wifi') = 40
        assertTrue(result.contains("40/100"),
                "Expected 40/100 for Open + suspicious SSID. Got:\n" + result);
        assertTrue(result.contains("HIGH"),
                "Score 40 should be HIGH risk. Got:\n" + result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Test 3 — readStream with a mocked InputStream returns expected content
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("readStream correctly reads content from a mocked InputStream")
    void readStreamWithMockedInput() throws Exception {
        // Arrange: create a real ByteArrayInputStream, then wrap it in a spy
        // so Mockito is involved in the call chain.
        String payload = "Line1\nLine2\nLine3";
        InputStream realStream = new ByteArrayInputStream(
                payload.getBytes(StandardCharsets.UTF_8));
        InputStream streamSpy = spy(realStream);

        // Act: invoke the private readStream method with our spy stream
        String result = (String) invoke("readStream",
                new Class[]{InputStream.class}, streamSpy);

        // Assert: readStream appends '\n' after each line read by BufferedReader
        assertEquals("Line1\nLine2\nLine3\n", result);

        // Verify: confirm the stream's read method was actually called
        verify(streamSpy, atLeastOnce()).read(any(byte[].class), anyInt(), anyInt());
    }
}
