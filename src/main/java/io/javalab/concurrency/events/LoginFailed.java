package io.javalab.concurrency.events;

import java.time.Instant;

public record LoginFailed(String sourceIp, String username, int attempts, Instant at) implements SecurityEvent {
    public LoginFailed {
        if (sourceIp == null || sourceIp.isBlank())
            throw new IllegalArgumentException("sourceIp is required");
        if (attempts < 1)
            throw new IllegalArgumentException("attempts must be >= 1");
    }
}
