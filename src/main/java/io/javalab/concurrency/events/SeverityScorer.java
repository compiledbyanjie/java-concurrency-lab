package io.javalab.concurrency.events;

public class SeverityScorer {

    public static Severity score(SecurityEvent e) {
        return switch (e) {
            case LoginFailed l when l.attempts() >= 10 -> Severity.HIGH;
            case LoginFailed l when l.attempts() >= 5 -> Severity.MEDIUM;
            case LoginFailed _ -> Severity.LOW;
            case PortScan p when p.portsScanned() > 1000 -> Severity.HIGH;
            case PortScan _ -> Severity.MEDIUM;
            case MalwareDetected m when !m.quarantined() -> Severity.CRITICAL;
            case MalwareDetected _ -> Severity.MEDIUM;
        };
    }
}
