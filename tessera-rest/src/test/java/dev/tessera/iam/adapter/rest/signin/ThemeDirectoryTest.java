// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.rest.signin.SignInThemeConfig.Unthemed;
import dev.tessera.iam.adapter.rest.signin.ThemeDirectory.Asset;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Sign-in theme directory — what a boot accepts, and what it refuses")
class ThemeDirectoryTest {

    @TempDir
    Path root;

    private Path theme(String name) throws IOException {
        Path dir = Files.createDirectories(root.resolve(name));
        Files.writeString(dir.resolve("theme.css"), "body {}");
        return dir;
    }

    @Test
    @DisplayName("reads each theme's files, by path relative to the theme")
    void reads() throws IOException {
        Path acme = theme("acme");
        Files.createDirectories(acme.resolve("fonts"));
        Files.write(acme.resolve("fonts/a.woff2"), new byte[] {1, 2});
        theme("zenith-2");

        Map<String, Map<String, Asset>> themes = ThemeDirectory.read(root);

        assertThat(themes).containsOnlyKeys("acme", "zenith-2");
        assertThat(themes.get("acme")).containsOnlyKeys("theme.css", "fonts/a.woff2");
        assertThat(themes.get("acme").get("fonts/a.woff2").contentType()).isEqualTo("font/woff2");
    }

    @Test
    @DisplayName("an empty directory holds no themes")
    void empty() {
        assertThat(ThemeDirectory.read(root)).isEmpty();
    }

    @Test
    @DisplayName("a missing directory fails the boot")
    void missingDirectory() {
        assertThatThrownBy(() -> ThemeDirectory.read(root.resolve("absent")))
                .isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"evil.js", "page.html", "mark.svg", "no-extension", ".hidden"})
    @DisplayName("a file type a theme may not hold fails the boot")
    void refusesFileType(String file) throws IOException {
        Files.writeString(theme("acme").resolve(file), "x");
        assertThatThrownBy(() -> ThemeDirectory.read(root))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not allowed");
    }

    @Test
    @DisplayName("a link fails the boot, even one to an allowed file")
    void refusesLink() throws IOException {
        Path outside = Files.writeString(Files.createTempDirectory(root.getParent(), "outside").resolve("x.css"), "x");
        Files.createSymbolicLink(theme("acme").resolve("link.css"), outside);
        assertThatThrownBy(() -> ThemeDirectory.read(root)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("a theme directory that is a link fails the boot")
    void refusesLinkedTheme() throws IOException {
        Path outside = Files.createTempDirectory(root.getParent(), "outside");
        Files.writeString(outside.resolve("theme.css"), "x");
        Files.createSymbolicLink(root.resolve("acme"), outside);
        assertThatThrownBy(() -> ThemeDirectory.read(root)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("a theme with no stylesheet fails the boot")
    void refusesNoStylesheet() throws IOException {
        Files.delete(theme("acme").resolve("theme.css"));
        assertThatThrownBy(() -> ThemeDirectory.read(root))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("theme.css");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Upper", "under_score", "-leading", "dot.ted"})
    @DisplayName("a directory whose name is not a theme name fails the boot")
    void refusesName(String name) throws IOException {
        theme(name);
        assertThatThrownBy(() -> ThemeDirectory.read(root)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the setting decides what a client with no theme gets, and it defaults by configuration to neutral")
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
