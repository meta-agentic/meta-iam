package dev.tessera.iam.adapter.persistence.user;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Applies the operator's user declaration at startup: the email address and the full name of named,
 * existing users (OIDC Core §5.4 claims). It is the only writer of those fields until a provisioning
 * API exists, and that API calls the same repository operation.
 *
 * <p>The declaration is a JSON file named by {@code iam.users.declaration-file}:
 * <pre>{"users": [{"username": "alice", "email": "alice@example.com", "name": "Alice Example",
 *              "tenant": "&lt;uuid&gt;", "baseline": "&lt;uuid&gt;"}]}</pre>
 * {@code tenant} defaults to the fixed tenant of a single-tenant deployment, and {@code baseline} to
 * the zero baseline. Only a stated field writes: an absent field leaves the stored value, and an
 * explicit {@code null} clears it. A declared address is stored as verified, because only the
 * operator can set it.
 *
 * <p>It never creates a user and never touches a credential. A declared user that does not exist is
 * a warning, so a declaration may name a user before it is created. A malformed file, or a value the
 * schema would refuse, fails startup, so a typo never half-applies. Each change is logged with the
 * user and the fields that changed, never their values. It runs after first-boot provisioning, so
 * the user that step creates can be declared in the same start.
 */
@ApplicationScoped
public class UserDeclaration {

    private static final Logger LOG = Logger.getLogger(UserDeclaration.class);
    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(2);
    private static final UUID ZERO = new UUID(0L, 0L);
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+$");

    @Inject
    UserRepository users;

    @Inject
    @ConfigProperty(name = "iam.users.declaration-file")
    Optional<String> declarationFile;

    @Inject
    @ConfigProperty(name = "iam.tenancy.fixed-tenant")
    Optional<String> fixedTenant;

    /** One declared user, parsed and checked. */
    record Entry(UUID tenant, UUID baseline, String username,
                 boolean emailStated, String email, boolean nameStated, String name) {
    }

    void onStart(@Observes @Priority(Interceptor.Priority.APPLICATION + 600) StartupEvent event) {
        Optional<String> file = declarationFile.map(String::trim).filter(path -> !path.isEmpty());
        if (file.isEmpty()) {
            return;
        }
        List<Entry> entries = parse(read(Path.of(file.get())), fixedTenant);
        apply(entries).await().atMost(STARTUP_TIMEOUT);
    }

    private static String read(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new IllegalStateException("user declaration: cannot read " + path, e);
        }
    }

    /**
     * Parses and checks a declaration.
     *
     * @throws IllegalStateException on any malformed entry, naming it by position
     */
    static List<Entry> parse(String json, Optional<String> fixedTenant) {
        JsonNode root;
        try {
            root = new ObjectMapper().readTree(json);
        } catch (IOException e) {
            throw new IllegalStateException("user declaration: not valid JSON", e);
        }
        JsonNode list = root == null ? null : root.get("users");
        if (list == null || !list.isArray()) {
            throw new IllegalStateException("user declaration: expected an object with a \"users\" array");
        }
        Optional<UUID> fixed = fixedTenant.map(String::trim).filter(v -> !v.isEmpty()).map(UUID::fromString);
        List<Entry> entries = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            entries.add(entry(list.get(i), i, fixed));
        }
        return entries;
    }

    private static Entry entry(JsonNode node, int index, Optional<UUID> fixed) {
        String where = "user declaration: users[" + index + "]";
        if (node == null || !node.isObject()) {
            throw new IllegalStateException(where + " is not an object");
        }
        String username = text(node, "username", where);
        if (username == null || username.isBlank()) {
            throw new IllegalStateException(where + " has no username");
        }
        UUID tenant = Optional.ofNullable(text(node, "tenant", where)).map(v -> uuid(v, where + ".tenant"))
                .or(() -> fixed)
                .orElseThrow(() -> new IllegalStateException(
                        where + " names no tenant, and no fixed tenant is configured"));
        UUID baseline = Optional.ofNullable(text(node, "baseline", where))
                .map(v -> uuid(v, where + ".baseline")).orElse(ZERO);
        String email = text(node, "email", where);
        if (email != null && !EMAIL.matcher(email).matches()) {
            throw new IllegalStateException(where + ".email is not an address");
        }
        String name = text(node, "name", where);
        if (name != null && (name.isEmpty() || !name.equals(name.strip()))) {
            throw new IllegalStateException(where + ".name is empty or padded");
        }
        return new Entry(tenant, baseline, username, node.has("email"), email, node.has("name"), name);
    }

    private static String text(JsonNode node, String field, String where) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw new IllegalStateException(where + "." + field + " is not a string");
        }
        return value.asText();
    }

    private static UUID uuid(String value, String where) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(where + " is not a UUID", e);
        }
    }

    /** Applies the entries in order; each reads the user and writes only when something changes. */
    Uni<Void> apply(List<Entry> entries) {
        Uni<Void> chain = Uni.createFrom().voidItem();
        for (Entry entry : entries) {
            chain = chain.chain(() -> applyOne(entry));
        }
        return chain;
    }

    private Uni<Void> applyOne(Entry entry) {
        return users.findByUsername(entry.tenant(), entry.baseline(), entry.username()).chain(current -> {
            if (current == null) {
                LOG.warnf("user declaration: no user %s in tenant %s, baseline %s; nothing set",
                        entry.username(), entry.tenant(), entry.baseline());
                return Uni.createFrom().voidItem();
            }
            String email = entry.emailStated() ? entry.email() : current.email;
            String name = entry.nameStated() ? entry.name() : current.name;
            boolean verified = email != null && (entry.emailStated() || current.emailVerified);
            List<String> changed = changes(current, email, verified, name);
            if (changed.isEmpty()) {
                return Uni.createFrom().voidItem();
            }
            return users.updateProfile(entry.tenant(), entry.baseline(), entry.username(), email, verified, name)
                    .invoke(() -> LOG.infof("user declaration: user %s in tenant %s, baseline %s: %s changed",
                            entry.username(), entry.tenant(), entry.baseline(), String.join(", ", changed)))
                    .replaceWithVoid();
        });
    }

    static List<String> changes(UserEntity current, String email, boolean verified, String name) {
        List<String> changed = new ArrayList<>();
        if (!Objects.equals(current.email, email)) {
            changed.add("email");
        }
        if (current.emailVerified != verified) {
            changed.add("email_verified");
        }
        if (!Objects.equals(current.name, name)) {
            changed.add("name");
        }
        return changed;
    }
}
