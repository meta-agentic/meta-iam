package dev.tessera.iam.adapter.rest.tenancy;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Where the realm is chosen by a request header, discovery and the JWKS answer differently on one
 * shared URL, so they must not be kept by a shared cache: they are private to one client.
 */
@QuarkusTest
@DisplayName("Header mode: discovery and the JWKS are private to one client")
class SharedCacheTest {

    private static void assertPrivate(String path) {
        given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .when().get(path)
                .then().statusCode(200)
                .header("Cache-Control", containsString("private"))
                .header("Cache-Control", not(containsString("public")))
                .header("Cache-Control", not(containsString("s-maxage")));
    }

    @Test
    @DisplayName("the discovery document is private")
    void discoveryIsPrivate() {
        assertPrivate("/.well-known/openid-configuration");
    }

    @Test
    @DisplayName("/jwks is private")
    void jwksIsPrivate() {
        assertPrivate("/jwks");
    }

    @Test
    @DisplayName("/.well-known/jwks.json is private")
    void wellKnownJwksIsPrivate() {
        assertPrivate("/.well-known/jwks.json");
    }
}
