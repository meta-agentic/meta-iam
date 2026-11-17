package dev.tessera.iam.adapter.persistence.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("UserDeclaration.parse — a declaration is checked whole before anything is written")
class UserDeclarationTest {

    private static final String FIXED = "7e5a0000-0000-4000-a000-0000000000aa";

    @Test
    @DisplayName("tenant defaults to the fixed tenant and baseline to zero; stated and absent fields are told apart")
    void defaultsAndStatedFields() {
        List<UserDeclaration.Entry> entries = UserDeclaration.parse("""
                {"users": [
                  {"username": "ada", "email": "ada@example.com", "name": "Ada Lovelace"},
                  {"username": "bob", "email": null}
                ]}""", Optional.of(FIXED));
        assertThat(entries).hasSize(2);
        UserDeclaration.Entry ada = entries.get(0);
        assertThat(ada.tenant()).isEqualTo(UUID.fromString(FIXED));
        assertThat(ada.baseline()).isEqualTo(new UUID(0L, 0L));
        assertThat(ada.emailStated()).isTrue();
        assertThat(ada.nameStated()).isTrue();
        UserDeclaration.Entry bob = entries.get(1);
        assertThat(bob.emailStated()).as("an explicit null clears").isTrue();
        assertThat(bob.email()).isNull();
        assertThat(bob.nameStated()).as("an absent field leaves the stored value").isFalse();
    }

    @Test
    @DisplayName("an entry without a tenant, when no fixed tenant is configured, fails startup")
    void noTenant() {
        assertThatThrownBy(() -> UserDeclaration.parse("{\"users\": [{\"username\": \"ada\"}]}", Optional.empty()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("users[0]");
    }

    @Test
    @DisplayName("malformed values fail startup, naming the entry")
    void malformed() {
        assertThatThrownBy(() -> UserDeclaration.parse("not json", Optional.of(FIXED)))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> UserDeclaration.parse("{\"users\": [{\"email\": \"a@b\"}]}", Optional.of(FIXED)))
                .hasMessageContaining("no username");
        assertThatThrownBy(() -> UserDeclaration.parse(
                "{\"users\": [{\"username\": \"ada\", \"email\": \"not-an-address\"}]}", Optional.of(FIXED)))
                .hasMessageContaining("users[0].email");
        assertThatThrownBy(() -> UserDeclaration.parse(
                "{\"users\": [{\"username\": \"ada\", \"name\": \" Ada\"}]}", Optional.of(FIXED)))
                .hasMessageContaining("users[0].name");
        assertThatThrownBy(() -> UserDeclaration.parse(
                "{\"users\": [{\"username\": \"ada\", \"tenant\": \"acme\"}]}", Optional.of(FIXED)))
                .hasMessageContaining("users[0].tenant");
    }
}
