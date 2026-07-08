package io.astis.example.workload;

import org.springframework.stereotype.Component;

/** Holds the result of the startup database probe, surfaced by {@link SecretController}. */
@Component
public class DbStatus {
    public volatile boolean connected = false;
    public volatile String version;
    public volatile String dbUser;
    public volatile String database;
    public volatile String error;
}
