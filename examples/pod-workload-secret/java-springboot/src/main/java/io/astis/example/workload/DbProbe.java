package io.astis.example.workload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Proves the whole chain end to end: at startup, open a real PostgreSQL connection
 * using the credentials ASTIS decrypted into {@code spring.datasource.username} /
 * {@code spring.datasource.password}, and read something basic.
 *
 * <p>The {@link JdbcTemplate} is autoconfigured by Spring from those properties — this
 * code never touches the password. Failure is recorded, not fatal (the app still serves
 * {@code /healthz} so the failure is observable).
 */
@Component
public class DbProbe implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DbProbe.class);

    private final JdbcTemplate jdbc;
    private final DbStatus status;

    public DbProbe(JdbcTemplate jdbc, DbStatus status) {
        this.jdbc = jdbc;
        this.status = status;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            status.version = jdbc.queryForObject("select version()", String.class);
            status.dbUser = jdbc.queryForObject("select current_user", String.class);
            status.database = jdbc.queryForObject("select current_database()", String.class);
            status.connected = true;
            log.info("[astis] PostgreSQL connected with ASTIS-decrypted credentials — user={} db={} ({})",
                    status.dbUser, status.database, status.version);
        } catch (Exception e) {
            status.connected = false;
            status.error = e.getMessage();
            log.error("[astis] PostgreSQL connection failed: {}", e.getMessage());
        }
    }
}
