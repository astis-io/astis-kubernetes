// Demo app: decrypt the PostgreSQL credentials from ASTIS at startup, then open a real
// connection and read something basic — mirroring the Java/Spring Boot example.
//
// The plaintext exists only in this process's RAM. By default the credentials are never
// printed (only a sha256 prefix); printing is fail-closed (see plaintextPrintAllowed).
package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// plaintextPrintAllowed is fail-closed: the secret is printed only when the operator
// opts in AND declares a non-production environment. A deployed pod leaves ASTIS_ENV at
// its default ("production"), so the secret can never reach the logs there.
func plaintextPrintAllowed() bool {
	e := env("ASTIS_ENV", "production")
	return os.Getenv("ASTIS_DEMO_PRINT_SECRET") == "true" && e != "production" && e != "prod" && e != ""
}

func sha256Prefix(s []byte) string { d := sha256.Sum256(s); return fmt.Sprintf("%x", d)[:12] }

func main() {
	apiURL := env("ASTIS_API_URL", "https://api.astis.io")

	// No declared identity (RFC-020 §12.2): the gateway derives it from the API-key
	// binding + the verified SA JWT read from the standard pod mounts.
	log.Printf("[astis] RFC-020 workload-secret (Go) — api=%s", apiURL)

	client, err := FromKubernetes(apiURL)
	if err != nil {
		log.Fatalf("[astis] init failed: %v", err)
	}

	user := decrypt(client, env("ASTIS_DB_USER_ENVELOPE", "/etc/astis-sealed/db-user"))
	pass := decrypt(client, env("ASTIS_DB_PASS_ENVELOPE", "/etc/astis-sealed/db-password"))
	log.Printf("[astis] username decrypted (sha256=%s, %d bytes)", sha256Prefix(user), len(user))
	log.Printf("[astis] password decrypted (sha256=%s, %d bytes) — edge saw only HPKE-sealed blobs",
		sha256Prefix(pass), len(pass))
	if plaintextPrintAllowed() {
		fmt.Printf("  DB_USER=%s DB_PASSWORD=%s\n", user, pass)
	}

	// Connect with the ASTIS-decrypted credentials and read something basic.
	dsn := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s connect_timeout=5",
		env("DB_HOST", "db.example.com"), env("DB_PORT", "5432"), env("DB_NAME", "postgres"),
		string(user), string(pass), env("DB_SSLMODE", "disable")) // lib/pq: require|disable|verify-* (no "prefer")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("[astis] open: %v", err)
	}
	defer db.Close()

	var version, who, dbname string
	if err := db.QueryRow("select version()").Scan(&version); err != nil {
		log.Fatalf("[astis] PostgreSQL query failed: %v", err)
	}
	db.QueryRow("select current_user, current_database()").Scan(&who, &dbname)
	log.Printf("[astis] PostgreSQL connected with ASTIS-decrypted credentials — user=%s db=%s (%s)",
		who, dbname, version)

	log.Printf("[astis] done — sleeping to keep the demo pod alive")
	for {
		time.Sleep(time.Hour)
	}
}

func decrypt(c *Client, path string) []byte {
	wire, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[astis] read %s: %v", path, err)
	}
	secret, err := c.OpenSecret(trim(string(wire)))
	if err != nil {
		log.Fatalf("[astis] unwrap %s failed: %v", path, err)
	}
	return secret
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
