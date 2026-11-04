// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import com.nimbusds.jose.jwk.ECKey;
import dev.tessera.iam.adapter.rest.signin.SignInThemeConfig.Unthemed;
import dev.tessera.iam.adapter.rest.signin.ThemeDirectory.Asset;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;

/**
 * The themes this deployment holds, and which one a sign-in page shows (ADR-IAM-008).
 *
 * <p>Themes are read at boot. Client registrations cannot be: listing them needs a read of
 * {@code oauth_client} with no tenant, which row-level security forbids. So a client naming a
 * theme the deployment lacks is found only when its page renders, and is reported then, once per
 * theme name per instance.
 */
@ApplicationScoped
public class SignInThemes {

    private static final Logger LOG = Logger.getLogger(SignInThemes.class);

    private final Map<String, Map<String, Asset>> themes;
    private final Unthemed unthemed;
    private final Set<String> reported = ConcurrentHashMap.newKeySet();

    /** What a sign-in page does for its client's theme. */
    sealed interface Choice {

        /** @param name the theme to show */
        record Themed(String name) implements Choice {
        }

        /** Show tessera's own page. */
        record Neutral() implements Choice {
        }

        /** Show no form. */
        record Refused() implements Choice {
        }
    }

    @Inject
    SignInThemes(SignInThemeConfig config) {
        this(read(config), config.unthemed());
    }

    SignInThemes(Map<String, Map<String, Asset>> themes, Unthemed unthemed) {
        this.themes = themes;
        this.unthemed = unthemed;
    }

    private static Map<String, Map<String, Asset>> read(SignInThemeConfig config) {
        ECKey key = config.publicKey().map(ThemeManifest::publicKey).orElse(null);
        return config.directory().map(directory -> ThemeDirectory.read(Path.of(directory), key)).orElse(Map.of());
    }

    /** Reads and verifies the themes at boot, so a directory that breaks the rules or a theme that fails verification stops the rollout. */
    void onStart(@Observes StartupEvent event) {
        LOG.infof("Sign-in themes: %s; a client with no theme gets: %s", new TreeSet<>(themes.keySet()), unthemed);
    }

    /**
     * Chooses what a page shows.
     *
     * @param name the theme the client's registration names, or {@code null} when it names none
     * @return the choice
     */
    Choice choose(String name) {
        if (name != null) {
            if (themes.containsKey(name)) {
                return new Choice.Themed(name);
            }
            if (reported.add(name)) {
                LOG.warnf("A client names sign-in theme '%s', which this deployment does not hold; it gets: %s",
                        name, unthemed);
            }
        }
        return unthemed == Unthemed.REFUSE ? new Choice.Refused() : new Choice.Neutral();
    }

    /**
     * A file of a theme.
     *
     * @param theme the theme's name
     * @param path  the file's path inside the theme
     * @return the file, or {@code null} when there is none
     */
    Asset asset(String theme, String path) {
        Map<String, Asset> assets = themes.get(theme);
        return assets == null ? null : assets.get(path);
    }
}
