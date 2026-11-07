package dev.tessera.iam.adapter.rest.tenancy;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * In header mode the realm is chosen by {@code X-Tenant-Id} and {@code X-Baseline-Id}, and discovery
 * and the JWKS are publicly cacheable on one shared URL, so each response must name both headers in
 * {@code Vary}; otherwise a shared cache can serve one tenant's keys to another.
 */
@QuarkusTest
@DisplayName("Header mode: discovery and JWKS vary on the realm-selecting headers")
class SharedCacheVaryTest {

    private static void assertVariesOnRealmHeaders(String path) {
        given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .when().get(path)
                .then().statusCode(200)
                .header("Vary", containsString("X-Tenant-Id"))
                .header("Vary", containsString("X-Baseline-Id"));
    }

    @Test
    @DisplayName("the discovery document carries Vary: X-Tenant-Id, X-Baseline-Id")
    void discoveryVaries() {
        assertVariesOnRealmHeaders("/.well-known/openid-configuration");
    }

    @Test
    @DisplayName("/jwks carries Vary: X-Tenant-Id, X-Baseline-Id")
    void jwksVaries() {
        assertVariesOnRealmHeaders("/jwks");
    }

    @Test
    @DisplayName("/.well-known/jwks.json carries Vary: X-Tenant-Id, X-Baseline-Id")
    void wellKnownJwksVaries() {
        assertVariesOnRealmHeaders("/.well-known/jwks.json");
    }
}
