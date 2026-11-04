// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import com.nimbusds.jose.jwk.ECKey;
import dev.tessera.iam.domain.client.SignInTheme;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Reads a theme directory into memory, once, so what is served is what was read at boot and no
 * request path ever reaches the file system.
 *
 * <p>A directory that breaks the rules fails the boot. Links are not followed and fail, because
 * one could point outside the pack, and only the file types a theme may hold are accepted
 * (ADR-IAM-008 D1 and D4). Every theme must also carry a manifest signed by the operator's CI,
 * covering exactly the files read here (ADR-IAM-008 D6). What is served is the verified bytes,
 * whatever later happens on disk.
 */
final class ThemeDirectory {

    /** The stylesheet every theme has; the page links this file. */
    static final String STYLESHEET = "theme.css";

    /** The signed manifest every theme has, beside its stylesheet. It is verified, never served. */
    static final String MANIFEST = "manifest.jws";

    private static final Map<String, String> CONTENT_TYPES = Map.of(
            "css", "text/css;charset=UTF-8",
            "woff2", "font/woff2",
            "png", "image/png",
            "webp", "image/webp",
            "avif", "image/avif");

    /** A file of a theme. */
    record Asset(byte[] bytes, String contentType) {
    }

    private ThemeDirectory() {
    }

    /**
     * Reads every theme under {@code root}.
     *
     * @param root the directory holding one directory per theme
     * @param key  the public key manifests must verify under, or {@code null} when none is
     *             configured, which only a directory with no themes accepts
     * @return the themes by name, each its assets by path relative to the theme, with {@code /}
     * @throws IllegalStateException when the directory breaks a rule or a theme fails verification
     */
    static Map<String, Map<String, Asset>> read(Path root, ECKey key) {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Sign-in theme directory is not a directory: " + root);
        }
        Map<String, Map<String, Asset>> themes = new HashMap<>();
        try (Stream<Path> entries = Files.list(root)) {
            for (Path theme : (Iterable<Path>) entries::iterator) {
                String name = theme.getFileName().toString();
                if (!SignInTheme.isValid(name) || !Files.isDirectory(theme, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IllegalStateException("Not a sign-in theme: " + theme);
                }
                if (key == null) {
                    throw new IllegalStateException("Sign-in theme " + name
                            + " is present but no public key is configured (iam.signin.themes.public-key)");
                }
                themes.put(name, Map.copyOf(verified(theme, name, key)));
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read sign-in themes from " + root, e);
        }
        return Map.copyOf(themes);
    }

    private static Map<String, Asset> verified(Path theme, String name, ECKey key) throws IOException {
        byte[][] manifest = new byte[1][];
        Map<String, Asset> assets = assets(theme, manifest);
        if (manifest[0] == null) {
            throw new IllegalStateException("Sign-in theme " + name + " has no " + MANIFEST);
        }
        ThemeManifest.verify(name, manifest[0], assets, key);
        return assets;
    }

    private static Map<String, Asset> assets(Path theme, byte[][] manifest) throws IOException {
        Map<String, Asset> assets = new HashMap<>();
        Files.walkFileTree(theme, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                if (!attributes.isRegularFile()) {
                    throw new IllegalStateException("Sign-in theme file is not a regular file: " + file);
                }
                if (file.getParent().equals(theme) && MANIFEST.equals(file.getFileName().toString())) {
                    manifest[0] = Files.readAllBytes(file);
                    return FileVisitResult.CONTINUE;
                }
                String contentType = contentType(file);
                if (contentType == null) {
                    throw new IllegalStateException("Sign-in theme file type is not allowed: " + file);
                }
                String path = theme.relativize(file).toString().replace(file.getFileSystem().getSeparator(), "/");
                assets.put(path, new Asset(Files.readAllBytes(file), contentType));
                return FileVisitResult.CONTINUE;
            }
        });
        if (!assets.containsKey(STYLESHEET)) {
            throw new IllegalStateException("Sign-in theme has no " + STYLESHEET + ": " + theme);
        }
        return assets;
    }

    private static String contentType(Path file) {
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        return dot < 0 ? null : CONTENT_TYPES.get(name.substring(dot + 1).toLowerCase(Locale.ROOT));
    }
}
