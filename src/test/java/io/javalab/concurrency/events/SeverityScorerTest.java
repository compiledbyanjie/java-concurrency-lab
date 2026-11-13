package io.javalab.concurrency.events;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SeverityScorerTest {
    private static final Instant NOW = Instant.parse("2026-11-13T10:00:00Z");


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

    @ParameterizedTest(name = "{0} attempts -> {1}")
    @CsvSource({
            "1, LOW",
            "4, LOW",
            "5, MEDIUM",
            "9, MEDIUM",
            "10, HIGH"
    })
    void loginFailed_severityByAttempts(int attempts, Severity expected) {
        var event = new LoginFailed("10.0.0.1", "anjita", attempts, NOW);
        assertEquals(expected, SeverityScorer.score(event));
    }

    @Test
    void portScan_blankIp_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new PortScan(" ", 100, NOW));
    }

    @Test
    void portScan_portsScannedLessThan1_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new PortScan("10.0.0.1", -5, NOW));
    }

    @ParameterizedTest(name = "{0} ports scanned -> {1}")
    @CsvSource({
            "1, MEDIUM",
            "1000, MEDIUM",
            "1001, HIGH"
    })
    void portScan_severityByPortScanned(int portScanned, Severity expected) {
        var event = new PortScan("10.0.0.1", portScanned, NOW);
        assertEquals(expected, SeverityScorer.score(event));
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
