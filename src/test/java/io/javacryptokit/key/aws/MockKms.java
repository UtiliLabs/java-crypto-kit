package io.javacryptokit.key.aws;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * 테스트 전용 모의 AWS KMS(JSON 1.1 프로토콜, HTTP). 실제 AWS를 호출하지 않는다. 데이터 키 "암호문"은 KMS 키 ARN·Encryption
 * Context·평문을 담은 모의 표현이며, Decrypt는 KeyId·Context가 다르면 실제 KMS처럼 오류를 돌려준다. 실제 AWS SDK 2.x 클라이언트가
 * 요청을 만들고(SigV4 서명 포함) 응답·오류를 해석하는 경로를 시험한다.
 */
public final class MockKms implements AutoCloseable {
    /** 모의 KMS 키 ARN(alias/test가 가리킴). */
    public static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555";
    /** 다른 모의 KMS 키 ARN(alias/other). */
    public static final String OTHER_ARN = "arn:aws:kms:us-east-1:111122223333:key/99999999-2222-3333-4444-555555555555";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final HttpServer server;
    /** 받은 요청(대상 작업 + 본문). */
    public final List<String> requests = Collections.synchronizedList(new ArrayList<>());
    /** 받은 Authorization 헤더. */
    public final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());
    /** 지정하면 모든 요청에 이 AWS 오류 코드로 응답한다. */
    public volatile String forcedError;

    public MockKms() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    /** 이 모의 서버에 연결하는 실제 SDK 클라이언트를 쓰도록 연결한다. */
    public void install() {
        AwsKmsSupport.clientFactoryForTests = settings -> client(URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
    }

    /** 닫힌 포트(네트워크 장애)로 연결하도록 바꾼다. */
    public static void installUnreachable(int port) {
        AwsKmsSupport.clientFactoryForTests = settings -> client(URI.create("http://127.0.0.1:" + port));
    }

    /** 테스트 연결을 해제한다. */
    public static void uninstall() {
        AwsKmsSupport.clientFactoryForTests = null;
    }

    private static KmsClient client(URI endpoint) {
        return KmsClient.builder()
                .endpointOverride(endpoint)
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")))
                .httpClient(UrlConnectionHttpClient.builder().build())
                .overrideConfiguration(o -> o.apiCallTimeout(Duration.ofSeconds(10)))
                .build();
    }

    @Override
    public void close() {
        uninstall();
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String target = exchange.getRequestHeaders().getFirst("X-Amz-Target");
        String body = new String(readAll(exchange.getRequestBody()), StandardCharsets.UTF_8);
        requests.add(target + " " + body);
        authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
        if (forcedError != null) {
            error(exchange, forcedError);
            return;
        }
        String keyId = field(body, "KeyId");
        String context = context(body);
        if ("TrentService.GenerateDataKey".equals(target) || "TrentService.Encrypt".equals(target)) {
            String arn = resolve(keyId);
            if (arn == null) {
                error(exchange, "NotFoundException");
                return;
            }
            byte[] plain;
            if ("TrentService.Encrypt".equals(target)) {
                plain = Base64.getDecoder().decode(field(body, "Plaintext"));
            } else {
                plain = new byte[32];
                RANDOM.nextBytes(plain);
            }
            String blob = Base64.getEncoder().encodeToString(("MOCK|" + arn + "|" + context + "|"
                    + Base64.getEncoder().encodeToString(plain)).getBytes(StandardCharsets.UTF_8));
            String json = "{\"CiphertextBlob\":\"" + blob + "\",\"KeyId\":\"" + arn + "\""
                    + ("TrentService.GenerateDataKey".equals(target)
                    ? ",\"Plaintext\":\"" + Base64.getEncoder().encodeToString(plain) + "\"" : "") + "}";
            ok(exchange, json);
        } else if ("TrentService.Decrypt".equals(target)) {
            String decoded = new String(Base64.getDecoder().decode(field(body, "CiphertextBlob")), StandardCharsets.UTF_8);
            String[] parts = decoded.split("\\|", -1);
            if (parts.length != 4 || !"MOCK".equals(parts[0])) {
                error(exchange, "InvalidCiphertextException");
                return;
            }
            String requested = keyId == null ? parts[1] : resolve(keyId);
            if (requested == null) {
                error(exchange, "NotFoundException");
                return;
            }
            if (!requested.equals(parts[1])) {
                error(exchange, "IncorrectKeyException");
                return;
            }
            if (!parts[2].equals(context)) {
                error(exchange, "InvalidCiphertextException");
                return;
            }
            ok(exchange, "{\"KeyId\":\"" + parts[1] + "\",\"Plaintext\":\"" + parts[3] + "\",\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\"}");
        } else {
            error(exchange, "UnsupportedOperationException");
        }
    }

    private static String resolve(String keyId) {
        if (keyId == null) return null;
        if ("alias/test".equals(keyId) || KEY_ARN.equals(keyId)) return KEY_ARN;
        if ("alias/other".equals(keyId) || OTHER_ARN.equals(keyId)) return OTHER_ARN;
        return null;
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static String context(String json) {
        Matcher m = Pattern.compile("\"EncryptionContext\"\\s*:\\s*(\\{[^}]*\\})").matcher(json);
        return m.find() ? m.group(1).replace(" ", "") : "";
    }

    private static void ok(HttpExchange exchange, String json) throws IOException {
        send(exchange, 200, json);
    }

    private static void error(HttpExchange exchange, String code) throws IOException {
        send(exchange, 400, "{\"__type\":\"" + code + "\",\"message\":\"mock " + code + " for arn:aws:kms:secret-detail\"}");
    }

    private static void send(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/x-amz-json-1.1");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
        exchange.close();
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
        return out.toByteArray();
    }
}
