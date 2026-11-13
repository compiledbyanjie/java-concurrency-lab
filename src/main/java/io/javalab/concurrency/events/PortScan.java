package io.javalab.concurrency.events;

import java.time.Instant;

public record PortScan(String sourceIp, int portsScanned, Instant at) implements SecurityEvent {
    public PortScan {
        if(sourceIp == null || sourceIp.isBlank())
            throw new IllegalArgumentException("sourceIp is required");
        if(portsScanned < 1)
            throw new IllegalArgumentException("portsScanned must be >= 1");
    }
}
