// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Request;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.Route;
import com.microsoft.playwright.options.Cookie;
import com.microsoft.playwright.options.LoadState;
import com.microsoft.playwright.options.SameSiteAttribute;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import dev.tessera.iam.adapter.rest.support.HostileThemeResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The claims of ADR-IAM-008 D5, in real browsers against tessera's real page. Each attack also runs
 * with the browser told to ignore the policy: if the attack does nothing there, the test cannot
 * fail, and proves nothing.
 */
@QuarkusTest
@QuarkusTestResource(value = HostileThemeResource.class, restrictToAnnotatedClass = true)
@DisplayName("Sign-in page in real browsers — a hostile theme reaches nothing off the origin")
class SignInPageBrowserIT {

    private static final String TENANT = UUID.randomUUID().toString();
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String INJECT_SCRIPTS = """
            () => {
                const inline = document.createElement('script');
                inline.textContent = 'window.inlineRan = true';
                document.head.append(inline);
                const file = document.createElement('script');
                file.src = '/evil.js';
                document.head.append(file);
            }""";

    private static Playwright playwright;

    @TestHTTPResource("/")
    URL base;

    @BeforeAll
    static void start() {
        playwright = Playwright.create();
    }

    @AfterAll
    static void stop() {
        playwright.close();
    }

    private static BrowserType type(String browser) {
        return switch (browser) {
            case "chromium" -> playwright.chromium();
            case "firefox" -> playwright.firefox();
            case "webkit" -> playwright.webkit();
            default -> throw new IllegalArgumentException(browser);
        };
    }

    /** One browser with a page waiting at the sign-in form of the hostile theme's client. */
    private final class Session implements AutoCloseable {
        final Browser browser;
        final BrowserContext context;
        final Page page;
        final List<String> ownAssets = new CopyOnWriteArrayList<>();
        final List<String> scriptFetches = new CopyOnWriteArrayList<>();

        Session(String browserName, boolean withPolicy) throws Exception {
            browser = type(browserName).launch();
            context = browser.newContext(new Browser.NewContextOptions()
                    .setBypassCSP(!withPolicy)
                    .setExtraHTTPHeaders(Map.of("X-Tenant-Id", TENANT)));
            context.route("**/evil.js", route -> {
                scriptFetches.add(route.request().url());
                route.fulfill(new Route.FulfillOptions()
                        .setContentType("text/javascript")
                        .setBody("window.fileRan = true"));
            });
            page = context.newPage();
            page.onResponse(response -> {
                if (response.url().contains("/assets/themes/hostile/") && response.status() == 200) {
                    ownAssets.add(response.url().substring(response.url().indexOf("/hostile/") + 9));
                }
            });
            HostileThemeResource.clearRequests();
            page.navigate(signInUrl());
            settle();
        }

        private String signInUrl() throws Exception {
            String verifier = UUID.randomUUID() + "-" + UUID.randomUUID();
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest
                    .getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
            String authorize = base + "authorize?response_type=code&scope=openid&state=browser"
                    + "&code_challenge_method=S256&code_challenge=" + challenge
                    + "&client_id=" + FakeClientRepository.HOSTILE_THEME_CLIENT_ID
                    + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8);
            HttpResponse<Void> answer = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(authorize)).header("X-Tenant-Id", TENANT).build(),
                    HttpResponse.BodyHandlers.discarding());
            assertThat(answer.statusCode()).isEqualTo(303);
            // The binding cookie is Secure, which WebKit will not keep on http://localhost. The server
            // does not read that flag, so the browser gets the same value without it.
            HttpCookie binding = answer.headers().allValues("set-cookie").stream()
                    .flatMap(header -> HttpCookie.parse(header).stream())
                    .filter(cookie -> SignInCookies.NAME.equals(cookie.getName()))
                    .findFirst()
                    .orElseThrow();
            context.addCookies(List.of(new Cookie(binding.getName(), binding.getValue())
                    .setDomain(base.getHost())
                    .setPath(binding.getPath())
                    .setSameSite(SameSiteAttribute.LAX)));
            return URI.create(base.toString()).resolve(answer.headers().firstValue("location").orElseThrow()).toString();
        }

        void settle() {
            page.waitForLoadState(LoadState.NETWORKIDLE);
            page.waitForTimeout(300);
        }

        void typePassword() {
            page.fill("#username", FakePasswordCredentialVerifier.USERNAME);
            page.fill("#password", FakePasswordCredentialVerifier.CORRECT_PASSWORD);
            settle();
        }

        @Override
        public void close() {
            browser.close();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"chromium", "firefox", "webkit"})
    @DisplayName("control: with the policy ignored, every attack reaches the off-origin server and script runs")
    void attacksWorkWithoutThePolicy(String browserName) throws Exception {
        try (Session session = new Session(browserName, false)) {
            session.typePassword();
            assertThat(HostileThemeResource.requests()).containsAll(HostileThemeResource.ATTACKS);

            session.page.evaluate(INJECT_SCRIPTS);
            session.page.waitForFunction("() => window.inlineRan === true && window.fileRan === true");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"chromium", "firefox", "webkit"})
    @DisplayName("with the policy, nothing reaches the off-origin server and no script runs")
    void policyStopsEveryAttack(String browserName) throws Exception {
        try (Session session = new Session(browserName, true)) {
            session.typePassword();
            assertThat(HostileThemeResource.requests()).isEmpty();

            session.page.evaluate(INJECT_SCRIPTS);
            session.settle();
            assertThat(session.page.evaluate("() => window.inlineRan === undefined && window.fileRan === undefined"))
                    .isEqualTo(true);
            assertThat(session.scriptFetches).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"chromium", "firefox", "webkit"})
    @DisplayName("with the policy, the theme's own font and image load, and the form completes a real sign-in")
    void pageStillWorks(String browserName) throws Exception {
        try (Session session = new Session(browserName, true)) {
            assertThat(session.ownAssets).contains("theme.css", "mark.png", "fonts/own.woff2");

            session.typePassword();
            // The browser follows the redirect to the client, so the form policy allowed the last hop too.
            Request callback = session.page.waitForRequest(
                    request -> request.url().startsWith(REDIRECT_URI + "?"),
                    () -> session.page.click("button[type=submit]"));

            assertThat(callback.url()).contains("code=", "state=browser");
            assertThat(HostileThemeResource.requests()).isEmpty();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"chromium", "firefox", "webkit"})
    @DisplayName("hostile values are escaped: no script runs, and each stays an attribute value")
    void valuesAreEscaped(String browserName) {
        String hostile = "\"><script>window.escaped = false</script><input value=\"";
        String html = new SignInResource.signin(hostile, hostile, false, null).render();

        assertThat(html).doesNotContain("<script>");
        try (Browser browser = type(browserName).launch()) {
            Page page = browser.newPage();
            page.setContent(html);
            assertThat(page.evaluate("() => window.escaped === undefined")).isEqualTo(true);
            assertThat(page.getAttribute("input[name=txn]", "value")).isEqualTo(hostile);
            assertThat(page.getAttribute("input[name=csrf]", "value")).isEqualTo(hostile);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"chromium"})
    @DisplayName("a transaction id from the URL is not reflected in the page")
    void transactionIdIsNotReflected(String browserName) {
        String hostile = "\"><script>window.escaped=false</script>";
        try (Browser browser = type(browserName).launch()) {
            BrowserContext context = browser.newContext(new Browser.NewContextOptions()
                    .setExtraHTTPHeaders(Map.of("X-Tenant-Id", TENANT)));
            Page page = context.newPage();
            Response response = page.navigate(base + "signin?txn=" + URLEncoder.encode(hostile, StandardCharsets.UTF_8));
            assertThat(response.status()).isEqualTo(400);
            assertThat(page.content()).doesNotContain("window.escaped");
        }
    }
}
