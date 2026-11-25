package io.javacryptokit.key.vault;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.javacryptokit.TestKeytool;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * 테스트 전용 HTTPS 서버(JDK 내장 HttpsServer). 인증서는 테스트 시작 때 JDK keytool로 새로 만든다(저장소에 인증서·키를 두지 않음).
 */
final class TlsTestServer implements AutoCloseable {
    /** 만든 인증서(키 저장소 + PEM). */
    static final class Certificate {
        final Path keystore;
        final Path pem;

        Certificate(Path keystore, Path pem) {
            this.keystore = keystore;
            this.pem = pem;
        }
    }

    private static final String PASSWORD = "changeit";
    private final HttpsServer server;

    TlsTestServer(Certificate certificate, HttpHandler handler) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(certificate.keystore)) {
            store.load(in, PASSWORD.toCharArray());
        }
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, null);
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", handler);
        server.start();
    }

    int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    /** keytool로 자체 서명 인증서를 만든다(실행은 공용 {@link TestKeytool}). */
    static Certificate generate(Path dir, String name, String commonName, String san) throws Exception {
        Path keystore = dir.resolve(name + ".p12");
        Path pem = dir.resolve(name + ".pem");
        TestKeytool.run(dir, "-genkeypair", "-alias", name, "-keyalg", "RSA", "-keysize", "2048", "-validity", "3",
                "-dname", "CN=" + commonName, "-ext", "SAN=" + san, "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-keypass", PASSWORD, "-noprompt");
        TestKeytool.run(dir, "-exportcert", "-rfc", "-alias", name, "-keystore", keystore.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD, "-file", pem.toString());
        return new Certificate(keystore, pem);
    }

    /** 응답을 보낸다. */
    static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }
}
