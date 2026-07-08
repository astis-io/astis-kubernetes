package io.astis.example.workload;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Demo: a Spring Boot service whose datasource/redis credentials are decrypted from
 * ASTIS-sealed envelopes at startup by the {@code astis-spring-boot-starter}'s
 * {@code AstisEnvironmentPostProcessor}, then consumed by the normal connection
 * factories — no code change to the factories, and no ASTIS code in this app.
 *
 * <p>By the time any {@code @Bean} (DataSource, RedisConnectionFactory, ...) is
 * created, {@code spring.datasource.password} / {@code spring.data.redis.password}
 * already hold the decrypted values. The plaintext lives only in this process's RAM.
 */
@SpringBootApplication
public class WorkloadSecretApplication {
    public static void main(String[] args) {
        SpringApplication.run(WorkloadSecretApplication.class, args);
    }
}
