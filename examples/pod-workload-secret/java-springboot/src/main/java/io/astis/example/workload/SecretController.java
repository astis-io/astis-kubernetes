package io.astis.example.workload;

import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Proves the decrypted credentials are live in the Spring Environment — exactly where
 * the DataSource / Redis connection factories read them — WITHOUT exposing plaintext.
 * Reports only a sha256 prefix and length per secret property.
 */
@RestController
public class SecretController {

    /** The properties our EnvironmentPostProcessor injects. Reported by digest only. */
    private static final String[] SECRET_PROPERTIES = {
            "spring.datasource.username",
            "spring.datasource.password",
    };

    private final Environment env;
    private final DbStatus db;

    public SecretController(Environment env, DbStatus db) {
        this.env = env;
        this.db = db;
    }

    @GetMapping("/healthz")
    public Map<String, Object> healthz() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", db.connected ? "ok" : "degraded");

        Map<String, Object> secrets = new LinkedHashMap<>();
        for (String prop : SECRET_PROPERTIES) {
            String value = env.getProperty(prop);
            if (value == null) {
                secrets.put(prop, Map.of("loaded", false));
            } else {
                secrets.put(prop, Map.of(
                        "loaded", true,
                        "sha256", sha256Prefix(value),
                        "length", value.length()));
            }
        }
        out.put("secrets", secrets);

        // Proof the decrypted credentials actually open a real PostgreSQL connection.
        Map<String, Object> database = new LinkedHashMap<>();
        database.put("connected", db.connected);
        if (db.connected) {
            database.put("current_user", db.dbUser);
            database.put("database", db.database);
            database.put("version", db.version);
        } else if (db.error != null) {
            database.put("error", db.error);
        }
        out.put("database", database);

        out.put("note", "credentials decrypted in pod RAM; never exposed — sha256 prefix only");
        return out;
    }

    private static String sha256Prefix(String value) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                sb.append(Character.forDigit((d[i] >> 4) & 0xf, 16)).append(Character.forDigit(d[i] & 0xf, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            return "?";
        }
    }
}
