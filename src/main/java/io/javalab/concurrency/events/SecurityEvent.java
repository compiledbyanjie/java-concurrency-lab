package io.javalab.concurrency.events;

import java.time.Instant;

public sealed interface SecurityEvent permits LoginFailed, PortScan, MalwareDetected {
    Instant at();
}
