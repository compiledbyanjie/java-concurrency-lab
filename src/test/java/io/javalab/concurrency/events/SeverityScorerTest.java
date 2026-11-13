package io.javalab.concurrency.events;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SeverityScorerTest {
    private static final Instant NOW = Instant.parse("2026-11-13T10:00:00Z");

    // Sample 1: checks a scoring rule
    @Test
    void loginFailed_10OrMoreAttempts_isHigh() {
        // Arrange: build the input
        var event = new LoginFailed("10.0.0.1", "anjita", 10, NOW);

        // Act: call the method you're testing
        Severity result = SeverityScorer.score(event);

        // Assert: check the result
        assertEquals(Severity.HIGH, result);
    }

    // Sample 2: checks that bad input throws
    @Test
    void loginFailed_blankIp_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new LoginFailed(" ", "anjita", 3, NOW));
    }

    @Test
    void loginFailed_attemptsLessThan1_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new LoginFailed("10.0.0.1", "anjita", 0, NOW));
    }

    @Test
    void loginFailed_5OrMoreAttempts_isMedium() {
        // Arrange: build the input
        var event = new LoginFailed("10.0.0.1", "anjita", 7, NOW);

        // Act: call the method you're testing
        Severity result = SeverityScorer.score(event);

        // Assert: check the result
        assertEquals(Severity.MEDIUM, result);
    }

    @Test
    void loginFailed_between1And4Attempts_isLow() {
        // Arrange: build the input
        var event = new LoginFailed("10.0.0.1", "anjita", 3, NOW);

        // Act: call the method you're testing
        Severity result = SeverityScorer.score(event);

        // Assert: check the result
        assertEquals(Severity.LOW, result);
    }

    @Test
    void portScan_moreThan100PortsScanned_isHigh() {
        // Arrange: build the input
        var event = new PortScan("10.0.0.1", 200, NOW);

        // Act: call the method you're testing
        Severity result = SeverityScorer.score(event);

        // Assert: check the result
        assertEquals(Severity.HIGH, result);
    }

    @Test
    void portScan_100orLessPortsScanned_isMedium() {
        // Arrange: build the input
        var event = new PortScan("10.0.0.1", 100, NOW);

        // Act: call the method you're testing
        Severity result = SeverityScorer.score(event);

        // Assert: check the result
        assertEquals(Severity.MEDIUM, result);
    }

    @Test
    void malwareDetected_notQuarantined_isCritical() {
        var event = new MalwareDetected("host", "malware", false, NOW);

        Severity result = SeverityScorer.score(event);

        assertEquals(Severity.CRITICAL, result);
    }

    @Test
    void malwareDetected_quarantined_isMedium() {
        var event = new MalwareDetected("host", "malware", true, NOW);

        Severity result = SeverityScorer.score(event);

        assertEquals(Severity.MEDIUM, result);
    }
}
