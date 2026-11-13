package io.javalab.concurrency.events;

import javax.sound.sampled.Port;
import java.time.Instant;

public sealed interface SecurityEvent permits LoginFailed, PortScan, MalwareDetected {
    Instant at();
}
