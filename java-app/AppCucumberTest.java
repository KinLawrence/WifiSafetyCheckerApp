import io.cucumber.java.en.*;
import io.cucumber.junit.Cucumber;
import io.cucumber.junit.CucumberOptions;
import org.junit.runner.RunWith;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Cucumber BDD step definitions for App.java (WiFi Safety Checker).
 *
 * These steps map to the Gherkin scenarios in wifi_safety.feature and exercise
 * the private scoring/risk logic inside App via reflection — no JavaFX toolkit
 * required.
 *
 * Dependencies (add to classpath):
 *   - cucumber-java-7.x.jar
 *   - cucumber-junit-7.x.jar
 *   - cucumber-core-7.x.jar
 *   - junit-platform-console-standalone-1.x.jar
 *
 * Run with:
 *   javac -cp ".;cucumber-java-7.x.jar;cucumber-junit-7.x.jar;cucumber-core-7.x.jar;junit-platform-console-standalone-1.x.jar" App.java AppCucumberTest.java
 *   java  -cp ".;..." io.cucumber.core.cli.Main --glue "" --plugin pretty wifi_safety.feature
 */

// ══════════════════════════════════════════════════════════════════════════════
//  Runner (JUnit 4-style — Cucumber's standard entry point)
// ══════════════════════════════════════════════════════════════════════════════

@RunWith(Cucumber.class)
@CucumberOptions(
    features = "wifi_safety.feature",
    glue     = "",
    plugin   = {"pretty"}
)
class AppCucumberRunner {
    // Marker class — Cucumber discovers step definitions via the glue path
}

// ══════════════════════════════════════════════════════════════════════════════
//  Step Definitions
// ══════════════════════════════════════════════════════════════════════════════

class AppCucumberTest {

    // ── State shared across steps within a single scenario ───────────────────
    private App app;
    private String rawNetshOutput;
    private String buildResultsOutput;
    private int    calculatedScore;
    private String calculatedRisk;

    // ── Reflection helper ───────────────────────────────────────────────────
    private Object invoke(String methodName, Class<?>[] paramTypes, Object... args)
            throws Exception {
        Method m = App.class.getDeclaredMethod(methodName, paramTypes);
        m.setAccessible(true);
        return m.invoke(app, args);
    }

    /** Builds a minimal netsh-style output block. */
    private static String netshBlock(String ssid, String auth) {
        return "SSID 1 : " + ssid + "\r\n" +
               "Network type            : Infrastructure\r\n" +
               "Authentication          : " + auth + "\r\n" +
               "Encryption              : CCMP\r\n";
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Given
    // ─────────────────────────────────────────────────────────────────────────

    @Given("a WiFi network with SSID {string} and authentication {string}")
    public void a_wifi_network(String ssid, String auth) throws Exception {
        app = App.class.getDeclaredConstructor().newInstance();
        rawNetshOutput = netshBlock(ssid, auth);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  When
    // ─────────────────────────────────────────────────────────────────────────

    @When("the safety score is calculated")
    public void the_safety_score_is_calculated() throws Exception {
        // Call buildResults — it parses the raw output, scores, and formats
        buildResultsOutput = (String) invoke("buildResults",
                new Class[]{String.class, String.class, String.class},
                rawNetshOutput, "", "");

        // Extract the numeric score (pattern: "NN/100") from the output
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d+)/100")
                .matcher(buildResultsOutput);
        assertTrue(m.find(), "Expected a score in format NN/100 in:\n" + buildResultsOutput);
        calculatedScore = Integer.parseInt(m.group(1));

        // Determine risk from the output
        if (buildResultsOutput.contains("HIGH"))       calculatedRisk = "HIGH";
        else if (buildResultsOutput.contains("MEDIUM")) calculatedRisk = "MEDIUM";
        else if (buildResultsOutput.contains("LOW"))    calculatedRisk = "LOW";
        else fail("No risk level found in output:\n" + buildResultsOutput);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Then
    // ─────────────────────────────────────────────────────────────────────────

    @Then("the score should be {int}")
    public void the_score_should_be(int expectedScore) {
        assertEquals(expectedScore, calculatedScore,
                "Score mismatch. Full output:\n" + buildResultsOutput);
    }

    @And("the risk level should be {string}")
    public void the_risk_level_should_be(String expectedRisk) {
        assertEquals(expectedRisk, calculatedRisk,
                "Risk mismatch. Full output:\n" + buildResultsOutput);
    }
}
