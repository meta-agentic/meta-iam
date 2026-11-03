// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import dev.tessera.iam.adapter.rest.support.FakeWorkloads;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * A local stand-in for the external issuers of keyless client authentication: one HTTPS server on
 * the loopback interface that publishes each issuer's JWK Set, and signs the tokens a platform
 * would give its workload with that issuer's current key.
 *
 * <p>The server's certificate is generated for this run by the JDK's {@code keytool}, so no private
 * key is committed. Only {@link #clientTls()} trusts it; the JDK's default trust store does not, so
 * the fetch is real TLS with host-name verification against a certificate nothing else accepts.
 *
 * <p>Besides the trusted issuers' key sets it serves two that must never be used: one behind a
 * redirect and one over the 64 KiB size limit. Each would verify its issuer's tokens if it were
 * fetched, so a test that sees them refused shows the fetch refused them, not the key.
 */
public final class StubIssuer {

    /**
     * The system property that carries the stub's port. A Quarkus test profile is loaded apart from
     * the application, so a static in this class is not shared between the two: the profile only
     * reserves the port ({@link #jwksUriFor}) and the application side starts the one server on it.
     */
    private static final String PORT_PROPERTY = "tessera.test.stub-issuer.port";

    private static StubIssuer instance;

    private final HttpsServer server;
    private final SSLContext clientTls;
    private final Map<String, RSAKey> keys = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> fetches = new ConcurrentHashMap<>();
    private final AtomicReference<Duration> ahead = new AtomicReference<>(Duration.ZERO);

    /** The one stub of this test run, started on first use. */
    public static synchronized StubIssuer get() {
        if (instance == null) {
            try {
                instance = new StubIssuer();
            } catch (Exception e) {
                throw new IllegalStateException("cannot start the stub issuer", e);
            }
        }
        return instance;
    }

    private StubIssuer() throws Exception {
        char[] password = UUID.randomUUID().toString().toCharArray();
        KeyStore serverKeys = generateServerKeyStore(password);
        Certificate certificate = serverKeys.getCertificate("stub");

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKeys, password);
        SSLContext serverTls = SSLContext.getInstance("TLS");
        serverTls.init(kmf.getKeyManagers(), null, null);

        KeyStore trusted = KeyStore.getInstance(KeyStore.getDefaultType());
        trusted.load(null, null);
        trusted.setCertificateEntry("stub", certificate);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trusted);
        clientTls = SSLContext.getInstance("TLS");
        clientTls.init(null, tmf.getTrustManagers(), null);

        for (String issuer : new String[] {FakeWorkloads.GOOGLE, FakeWorkloads.CLUSTER, FakeWorkloads.PER_REQUEST,
                FakeWorkloads.REDIRECTING, FakeWorkloads.OVERSIZED, FakeWorkloads.UNLISTED}) {
            keys.put(issuer, newKey());
            fetches.put(issuer, new AtomicInteger());
        }

        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port()), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverTls));
        server.createContext("/", this::handle);
        server.start();
    }

    /** The TLS context that trusts this stub's certificate, and nothing else. */
    public SSLContext clientTls() {
        return clientTls;
    }

    /**
     * The key-set URL tessera is configured with for {@code issuer}, without starting the stub: for a
     * test profile, which runs before the application and in another class loader.
     */
    public static String jwksUriFor(String issuer) {
        return "https://localhost:" + port() + "/" + path(issuer);
    }

    /** The stub's port: a free one, reserved once per JVM and shared through a system property. */
    private static synchronized int port() {
        String reserved = System.getProperty(PORT_PROPERTY);
        if (reserved == null) {
            try (ServerSocket probe = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
                reserved = Integer.toString(probe.getLocalPort());
            } catch (IOException e) {
                throw new IllegalStateException("cannot reserve a port for the stub issuer", e);
            }
            System.setProperty(PORT_PROPERTY, reserved);
        }
        return Integer.parseInt(reserved);
    }

    /** How many times {@code issuer}'s key-set URL was requested. */
    public int fetches(String issuer) {
        return fetches.get(issuer).get();
    }

    /** How far the key-set cache's clock runs ahead of the real one, to pass a refresh interval without waiting. */
    public Duration ahead() {
        return ahead.get();
    }

    /** Moves the key-set cache's clock forward. */
    public void advance(Duration by) {
        ahead.updateAndGet(current -> current.plus(by));
    }

    /** {@code issuer} rotates: its key set now holds only a new key, under a new {@code kid}. */
    public void rotate(String issuer) {
        keys.put(issuer, newKey());
    }

    /** A token {@code issuer} signs with its current key (RS256, under that key's {@code kid}). */
    public String sign(String issuer, JWTClaimsSet claims) {
        RSAKey key = keys.get(issuer);
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID())
                    .type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("cannot sign the stub token", e);
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            String requested = exchange.getRequestURI().getPath().substring(1);
            for (Map.Entry<String, RSAKey> entry : keys.entrySet()) {
                String issuer = entry.getKey();
                if (requested.equals(path(issuer))) {
                    fetches.get(issuer).incrementAndGet();
                    if (FakeWorkloads.REDIRECTING.equals(issuer)) {
                        // Where it points serves the issuer's real key set: only a fetch that follows it would verify.
                        exchange.getResponseHeaders().add("Location", "/redirect-target/" + path(issuer));
                        exchange.sendResponseHeaders(302, -1);
                        return;
                    }
                    String jwks = jwks(entry.getValue());
                    if (FakeWorkloads.OVERSIZED.equals(issuer)) {
                        // Valid JSON, the issuer's real key set, padded past the limit.
                        jwks = jwks.substring(0, jwks.length() - 1) + " ".repeat(TrustedIssuerJwks.MAX_BYTES) + "}";
                    }
                    respond(exchange, 200, jwks);
                    return;
                }
                if (requested.equals("redirect-target/" + path(issuer))) {
                    respond(exchange, 200, jwks(entry.getValue()));
                    return;
                }
            }
            respond(exchange, 404, "{}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String jwks(RSAKey key) {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    private static String path(String issuer) {
        return issuer.replaceFirst("^https://", "").replaceAll("[^A-Za-z0-9.-]", "_") + "/jwks";
    }

    private static RSAKey newKey() {
        try {
            return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256).generate();
        } catch (Exception e) {
            throw new IllegalStateException("cannot generate a stub issuer key", e);
        }
    }

    /** A self-signed certificate for {@code localhost}, valid two days, generated by the JDK's keytool. */
    private static KeyStore generateServerKeyStore(char[] password) throws Exception {
        Path dir = Files.createTempDirectory("stub-issuer");
        Path store = dir.resolve("stub.p12");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "stub",
                "-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", new String(password), "-keypass", new String(password))
                .redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException("keytool failed: " + output);
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(store)) {
            keyStore.load(in, password);
        } finally {
            Files.deleteIfExists(store);
            Files.deleteIfExists(dir);
        }
        return keyStore;
    }
}
