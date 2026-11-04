// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.jwk.ECKey;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Gives a {@code @QuarkusTest} a theme directory, signed under a key made for the run. */
public class SignedThemesResource implements QuarkusTestResourceLifecycleManager {

    @Override
    public Map<String, String> start() {
        try {
            ECKey key = SignedThemes.newKey();
            Path root = Files.createTempDirectory("tessera-themes");
            SignedThemes.write(root, key, "acme", Map.of(
                    "theme.css", "/* acme test theme */\nbody { background-image: url(mark.png); }\n"
                            .getBytes(StandardCharsets.UTF_8),
                    "mark.png", new byte[] {(byte) 0x89, 'P', 'N', 'G'},
                    "fonts/test.woff2", new byte[] {'w', 'O', 'F', '2'}));
            SignedThemes.write(root, key, "zenith", Map.of(
                    "theme.css", "/* zenith test theme */\n".getBytes(StandardCharsets.UTF_8)));
            return Map.of(
                    "iam.signin.themes.directory", root.toString(),
                    "iam.signin.themes.public-key", key.toPublicJWK().toJSONString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void stop() {
        // The directory is under the system's temporary directory.
    }
}
