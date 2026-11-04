// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.tessera.iam.adapter.rest.signin.SignInThemeConfig.Unthemed;
import dev.tessera.iam.adapter.rest.signin.ThemeDirectory.Asset;
import dev.tessera.iam.adapter.rest.support.SignedThemes;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.event.Observes;
import java.io.IOException;
import java.lang.reflect.Parameter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Sign-in theme directory — what a boot accepts, and what it refuses")
class ThemeDirectoryTest {

    private static final byte[] CSS = "body {}".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path root;

    private ECKey signing;
    private ECKey key;

    @BeforeEach
    void keys() {
        signing = SignedThemes.newKey();
        key = signing.toPublicJWK();
    }

    private Path theme(String name) throws IOException {
        return SignedThemes.write(root, signing, name, Map.of("theme.css", CSS));
    }

    private void assertRefused(String reason) {
        assertThatThrownBy(() -> ThemeDirectory.read(root, key))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(reason);
    }

    @Test
    @DisplayName("reads each signed theme's files, by path relative to the theme, without its manifest")
    void reads() throws IOException {
        SignedThemes.write(root, signing, "acme", Map.of("theme.css", CSS, "fonts/a.woff2", new byte[] {1, 2}));
        theme("zenith-2");

        Map<String, Map<String, Asset>> themes = ThemeDirectory.read(root, key);

        assertThat(themes).containsOnlyKeys("acme", "zenith-2");
        assertThat(themes.get("acme")).containsOnlyKeys("theme.css", "fonts/a.woff2");
        assertThat(themes.get("acme").get("fonts/a.woff2").contentType()).isEqualTo("font/woff2");
    }

    @Test
    @DisplayName("a directory with no themes needs no key")
    void emptyNeedsNoKey() {
        assertThat(ThemeDirectory.read(root, null)).isEmpty();
    }

    @Test
    @DisplayName("a theme with no key configured fails the boot")
    void themeWithoutKey() throws IOException {
        theme("acme");
        assertThatThrownBy(() -> ThemeDirectory.read(root, null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no public key");
    }

    @Test
    @DisplayName("a missing directory fails the boot")
    void missingDirectory() {
        assertThatThrownBy(() -> ThemeDirectory.read(root.resolve("absent"), key))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("a missing manifest fails the boot")
    void missingManifest() throws IOException {
        Files.delete(theme("acme").resolve("manifest.jws"));
        assertRefused("manifest.jws");
    }

    @Test
    @DisplayName("a signature from another key fails the boot")
    void otherKey() throws IOException {
        SignedThemes.write(root, SignedThemes.newKey(), "acme", Map.of("theme.css", CSS));
        assertRefused("does not verify");
    }

    @Test
    @DisplayName("a corrupted signature fails the boot")
    void corruptSignature() throws IOException {
        Path manifest = theme("acme").resolve("manifest.jws");
        String jws = Files.readString(manifest);
        int last = jws.length() - 8;
        Files.writeString(manifest, jws.substring(0, last) + (jws.charAt(last) == 'A' ? 'B' : 'A') + jws.substring(last + 1));
        assertRefused("Sign-in theme acme is refused");
    }

    @Test
    @DisplayName("a manifest that is not a JWS fails the boot")
    void notAJws() throws IOException {
        Files.writeString(theme("acme").resolve("manifest.jws"), "{\"alg\":\"none\"}");
        assertRefused("not a JWS");
    }

    @Test
    @DisplayName("an unsigned manifest (alg none) fails the boot")
    void algNone() throws IOException {
        // eyJhbGciOiJub25lIn0 is {"alg":"none"}: a plain JOSE object, with an empty signature.
        Files.writeString(theme("acme").resolve("manifest.jws"), "eyJhbGciOiJub25lIn0.e30.");
        assertRefused("Sign-in theme acme is refused");
    }

    @Test
    @DisplayName("a manifest signed with another algorithm fails the boot, even under the right key")
    void otherAlgorithm() throws Exception {
        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        Files.writeString(theme("acme").resolve("manifest.jws"), SignedThemes.manifest(p384, JWSAlgorithm.ES384,
                "tessera-theme-manifest+jws", Map.of("theme", "acme", "files", Map.of())));
        assertRefused("not ES256");
    }

    @Test
    @DisplayName("a token of another type from the same key fails the boot")
    void otherType() throws IOException {
        Files.writeString(theme("acme").resolve("manifest.jws"), SignedThemes.manifest(signing, JWSAlgorithm.ES256,
                "JWT", Map.of("theme", "acme", "files", Map.of("theme.css", SignedThemes.sha256(CSS)))));
        assertRefused("wrong type");
    }

    @Test
    @DisplayName("a pack copied to another theme's name fails the boot")
    void otherTheme() throws IOException {
        Path acme = theme("acme");
        Path zenith = Files.createDirectories(root.resolve("zenith"));
        Files.write(zenith.resolve("theme.css"), CSS);
        Files.copy(acme.resolve("manifest.jws"), zenith.resolve("manifest.jws"));
        assertRefused("different theme");
    }

    @Test
    @DisplayName("a changed file fails the boot")
    void changedFile() throws IOException {
        Files.writeString(theme("acme").resolve("theme.css"), "body { background: url(https://evil.example/x) }");
        assertRefused("differs");
    }

    @Test
    @DisplayName("an added file fails the boot")
    void addedFile() throws IOException {
        Files.write(theme("acme").resolve("extra.png"), new byte[] {1});
        assertRefused("does not list");
    }

    @Test
    @DisplayName("a missing file fails the boot")
    void missingFile() throws IOException {
        Path acme = SignedThemes.write(root, signing, "acme", Map.of("theme.css", CSS, "mark.png", new byte[] {1}));
        Files.delete(acme.resolve("mark.png"));
        assertRefused("is missing");
    }

    @Test
    @DisplayName("a manifest whose files are not a map fails the boot")
    void malformedFiles() throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("theme", "acme");
        payload.put("files", "theme.css");
        Files.writeString(theme("acme").resolve("manifest.jws"),
                SignedThemes.manifest(signing, JWSAlgorithm.ES256, "tessera-theme-manifest+jws", payload));
        assertRefused("lists no files");
    }

    @Test
    @DisplayName("a file listed twice in a signed manifest fails the boot, whichever value is right")
    void duplicateFileKey() throws Exception {
        String good = SignedThemes.sha256(CSS);
        String payload = "{\"theme\":\"acme\",\"files\":{\"theme.css\":\"" + "0".repeat(64)
                + "\",\"theme.css\":\"" + good + "\"}}";
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(ThemeManifest.TYPE)).build(),
                new Payload(payload));
        jws.sign(new ECDSASigner(signing));
        Files.writeString(theme("acme").resolve("manifest.jws"), jws.serialize());
        assertRefused("unique keys");
    }

    @Test
    @DisplayName("what is served is what was verified, whatever later happens on disk")
    void servesVerifiedBytes() throws IOException {
        Path acme = theme("acme");
        SignInThemes themes = new SignInThemes(ThemeDirectory.read(root, key), Unthemed.NEUTRAL);

        Files.writeString(acme.resolve("theme.css"), "body { background: url(https://evil.example/x) }");

        assertThat(themes.asset("acme", "theme.css").bytes()).isEqualTo(CSS);
    }

    @Test
    @DisplayName("the public key must be a public P-256 JWK, and a bad value is not repeated")
    void publicKey() {
        assertThat(ThemeManifest.publicKey(key.toJSONString())).isEqualTo(key);
        assertThatThrownBy(() -> ThemeManifest.publicKey(signing.toJSONString()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("private key material")
                .hasMessageNotContaining(signing.getD().toString());
        assertThatThrownBy(() -> ThemeManifest.publicKey("not-a-jwk-secret"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("not-a-jwk-secret");
    }

    @ParameterizedTest
    @ValueSource(strings = {"evil.js", "page.html", "mark.svg", "no-extension", ".hidden"})
    @DisplayName("a file type a theme may not hold fails the boot")
    void refusesFileType(String file) throws IOException {
        Files.writeString(theme("acme").resolve(file), "x");
        assertRefused("not allowed");
    }

    @Test
    @DisplayName("a manifest anywhere but the theme's root is an unknown file")
    void nestedManifest() throws IOException {
        Path nested = Files.createDirectories(theme("acme").resolve("fonts"));
        Files.writeString(nested.resolve("manifest.jws"), "x");
        assertRefused("not allowed");
    }

    @Test
    @DisplayName("a link fails the boot, even one to an allowed file")
    void refusesLink() throws IOException {
        Path outside = Files.writeString(Files.createTempDirectory(root.getParent(), "outside").resolve("x.css"), "x");
        Files.createSymbolicLink(theme("acme").resolve("link.css"), outside);
        assertRefused("not a regular file");
    }

    @Test
    @DisplayName("a linked manifest fails the boot")
    void refusesLinkedManifest() throws IOException {
        Path acme = theme("acme");
        Path outside = Files.createTempDirectory(root.getParent(), "outside").resolve("manifest.jws");
        Files.move(acme.resolve("manifest.jws"), outside);
        Files.createSymbolicLink(acme.resolve("manifest.jws"), outside);
        assertRefused("not a regular file");
    }

    @Test
    @DisplayName("a theme directory that is a link fails the boot")
    void refusesLinkedTheme() throws IOException {
        Path outside = Files.createTempDirectory(root.getParent(), "outside");
        Files.writeString(outside.resolve("theme.css"), "x");
        Files.createSymbolicLink(root.resolve("acme"), outside);
        assertRefused("Not a sign-in theme");
    }

    @Test
    @DisplayName("a signed theme with no stylesheet fails the boot")
    void refusesNoStylesheet() throws IOException {
        SignedThemes.write(root, signing, "acme", Map.of("mark.png", new byte[] {1}));
        assertRefused("theme.css");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Upper", "under_score", "-leading", "dot.ted"})
    @DisplayName("a directory whose name is not a theme name fails the boot")
    void refusesName(String name) throws IOException {
        theme(name);
        assertRefused("Not a sign-in theme");
    }

    /**
     * ADR-IAM-008 D6 says tessera refuses to start, not that it refuses a request later. Without this
     * observer the bean is built lazily and a bad pack surfaces only when someone signs in, while every
     * other test here still passes.
     */
    @Test
    @DisplayName("the themes are read when tessera starts, not on the first sign-in")
    void themesAreReadAtStartup() throws NoSuchMethodException {
        Parameter event = SignInThemes.class.getDeclaredMethod("onStart", StartupEvent.class).getParameters()[0];
        assertThat(event.isAnnotationPresent(Observes.class)).isTrue();
    }

    @Test
    @DisplayName("the setting decides what a client with no theme gets")
    void choice() {
        Map<String, Map<String, Asset>> held = Map.of("acme", Map.of());
        SignInThemes neutral = new SignInThemes(held, Unthemed.NEUTRAL);
        assertThat(neutral.choose("acme")).isEqualTo(new SignInThemes.Choice.Themed("acme"));
        assertThat(neutral.choose(null)).isEqualTo(new SignInThemes.Choice.Neutral());
        assertThat(neutral.choose("gone")).isEqualTo(new SignInThemes.Choice.Neutral());

        SignInThemes refuse = new SignInThemes(held, Unthemed.REFUSE);
        assertThat(refuse.choose("acme")).isEqualTo(new SignInThemes.Choice.Themed("acme"));
        assertThat(refuse.choose(null)).isEqualTo(new SignInThemes.Choice.Refused());
        assertThat(refuse.choose("gone")).isEqualTo(new SignInThemes.Choice.Refused());
    }
}
