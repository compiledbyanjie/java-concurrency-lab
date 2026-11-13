package io.javalab.concurrency.events;

import java.time.Instant;

public record PortScan(String sourceIp, int portsScanned, Instant at) implements SecurityEvent {
}
