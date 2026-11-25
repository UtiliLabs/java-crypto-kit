package io.javacryptokit.ha;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.jwt.JwtVerifier;
import io.javacryptokit.oauth.AccessTokenVerifier;
import io.javacryptokit.oauth.AccessTokens;
import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.HybridEncryption;
import io.javacryptokit.security.PemKeys;
import io.javacryptokit.security.RsaOaep;
import io.javacryptokit.security.SecureRandoms;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link MultiJvmTest}가 띄우는 독립 JVM의 진입점(서버 A·B·C 역할). 공개 API만 쓴다. 키는 부모(배포 담당)가 준비해 파일로 주며
 * 각 서버가 새 키를 만들지 않는다. 결과는 표준 출력의 {@code RESULT 이름=값} 줄과 작업 폴더의 파일로 돌려준다.
 */
public final class MultiJvmNode {
    static final String ISSUER = "https://server-a.example";
    static final String AUDIENCE = "orders-api";
    static final String MESSAGE = "dummy-서버간-메시지";

    private MultiJvmNode() { }

    public static void main(String[] args) throws Exception {
        Path dir = Paths.get(args[1]);
        String node = args[2];
        if ("issue".equals(args[0])) issue(dir);
        else verify(dir);
        List<String> tokens = new ArrayList<>();
        for (int i = 0; i < 1000; i++) tokens.add(SecureRandoms.token());
        Files.write(dir.resolve(node + ".tokens"), tokens, StandardCharsets.UTF_8);
        System.out.println("RESULT done=" + node);
    }

    /** 서버 A: 배포받은 개인키(현재·이전)와 공유 HS256 키로 토큰을, 수신자 공개키로 암호문을 만든다. */
    private static void issue(Path dir) throws IOException {
        PrivateKey current = PemKeys.readPrivateKeyFile(dir.resolve("issuer-current.pem"));
        PrivateKey previous = PemKeys.readPrivateKeyFile(dir.resolve("issuer-previous.pem"));
        PublicKey receiver = PemKeys.readPublicKeyFile(dir.resolve("receiver.pub.pem"));
        byte[] hs = Encoding.BASE64.decode(new String(Files.readAllBytes(dir.resolve("shared-hs256.key")), StandardCharsets.US_ASCII).trim());
        write(dir, "rs-current.jwt", Jwt.builder().issuer(ISSUER).subject("user-1").audience(AUDIENCE).expiresIn(Duration.ofMinutes(5))
                .randomJwtId().sign(JwtKey.rs256(current).withKeyId("2026-11")));
        write(dir, "rs-previous.jwt", Jwt.builder().issuer(ISSUER).subject("user-2").audience(AUDIENCE).expiresIn(Duration.ofMinutes(5))
                .randomJwtId().sign(JwtKey.rs256(previous).withKeyId("2026-05")));
        write(dir, "rs-other-audience.jwt", Jwt.builder().issuer(ISSUER).subject("user-3").audience("billing-api").expiresIn(Duration.ofMinutes(5))
                .sign(JwtKey.rs256(current).withKeyId("2026-11")));
        write(dir, "hs.jwt", Jwt.builder().issuer(ISSUER).subject("user-4").audience(AUDIENCE).expiresIn(Duration.ofMinutes(5))
                .sign(JwtKey.hs256(hs)));
        write(dir, "access.jwt", AccessTokens.builder().issuer(ISSUER).subject("user-5").audience(AUDIENCE).clientId("web")
                .scopes("orders.read").expiresIn(Duration.ofMinutes(5)).sign(JwtKey.rs256(current).withKeyId("2026-11")));
        write(dir, "message.hybrid", HybridEncryption.encryptText(receiver, MESSAGE, "order:7", Encoding.BASE64_URL));
        write(dir, "key.oaep", RsaOaep.encryptText(receiver, "dummy-데이터-키", Encoding.BASE64));
        System.out.println("RESULT issued=7");
    }

    /** 서버 B·C: 공개키·공유 키로 A의 토큰을 검증하고, 수신자 개인키로 A의 암호문을 복호화한다(시계 차 30초 허용). */
    private static void verify(Path dir) throws IOException {
        PublicKey current = PemKeys.readPublicKeyFile(dir.resolve("issuer-current.pub.pem"));
        PublicKey previous = PemKeys.readPublicKeyFile(dir.resolve("issuer-previous.pub.pem"));
        PrivateKey receiver = PemKeys.readPrivateKeyFile(dir.resolve("receiver.pem"));
        byte[] hs = Encoding.BASE64.decode(new String(Files.readAllBytes(dir.resolve("shared-hs256.key")), StandardCharsets.US_ASCII).trim());
        JwtVerifier both = JwtVerifier.builder().key(JwtKey.rs256(current).withKeyId("2026-11")).key(JwtKey.rs256(previous).withKeyId("2026-05"))
                .key(JwtKey.hs256(hs)).issuer(ISSUER).audience(AUDIENCE).clockSkew(Duration.ofSeconds(30)).build();
        JwtVerifier currentOnly = JwtVerifier.builder().key(JwtKey.rs256(current).withKeyId("2026-11")).issuer(ISSUER).audience(AUDIENCE)
                .clockSkew(Duration.ofSeconds(30)).build();
        AccessTokenVerifier access = AccessTokenVerifier.rfc9068().issuer(ISSUER).audience(AUDIENCE).key(JwtKey.rs256(current).withKeyId("2026-11"))
                .requireScopes("orders.read").clockSkew(Duration.ofSeconds(30)).build();
        result("rs-current", outcome(both, read(dir, "rs-current.jwt")));
        result("rs-previous", outcome(both, read(dir, "rs-previous.jwt")));
        result("rs-previous-after-rotation", outcome(currentOnly, read(dir, "rs-previous.jwt")));
        result("rs-other-audience", outcome(both, read(dir, "rs-other-audience.jwt")));
        result("hs", outcome(both, read(dir, "hs.jwt")));
        result("access-as-jwt", outcome(both, read(dir, "access.jwt")));
        try {
            result("access", access.verify(read(dir, "access.jwt")).hasScope("orders.read") ? "VALID" : "NO_SCOPE");
        } catch (JwtException e) {
            result("access", e.getReason().name());
        }
        try {
            result("jwt-as-access", access.verify(read(dir, "rs-current.jwt")).subject());
        } catch (JwtException e) {
            result("jwt-as-access", e.getReason().name());
        }
        result("hybrid", decrypt(() -> HybridEncryption.decryptText(receiver, read(dir, "message.hybrid"), "order:7", Encoding.BASE64_URL)));
        result("hybrid-wrong-aad", decrypt(() -> HybridEncryption.decryptText(receiver, read(dir, "message.hybrid"), "order:8", Encoding.BASE64_URL)));
        result("oaep", decrypt(() -> RsaOaep.decryptText(receiver, read(dir, "key.oaep"), Encoding.BASE64)));
    }

    interface Decryption {
        String run() throws CredentialCryptoException, IOException;
    }

    private static String decrypt(Decryption decryption) throws IOException {
        try {
            String plain = decryption.run();
            return MESSAGE.equals(plain) || "dummy-데이터-키".equals(plain) ? "OK" : "DIFF";
        } catch (CredentialCryptoException e) {
            return e.getReason().name();
        }
    }

    private static String outcome(JwtVerifier verifier, String token) {
        try {
            verifier.verify(token);
            return "VALID";
        } catch (JwtException e) {
            return e.getReason().name();
        }
    }

    private static void result(String name, String value) {
        System.out.println("RESULT " + name + "=" + value);
    }

    private static String read(Path dir, String name) throws IOException {
        return new String(Files.readAllBytes(dir.resolve(name)), StandardCharsets.US_ASCII);
    }

    private static void write(Path dir, String name, String value) throws IOException {
        Files.write(dir.resolve(name), value.getBytes(StandardCharsets.US_ASCII));
    }
}
