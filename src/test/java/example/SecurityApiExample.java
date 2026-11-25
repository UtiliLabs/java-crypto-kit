package example;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.security.AesGcm;
import io.javacryptokit.security.AesKeySize;
import io.javacryptokit.security.Bytes;
import io.javacryptokit.security.CertificateInfo;
import io.javacryptokit.security.Certificates;
import io.javacryptokit.security.DigestAlgorithm;
import io.javacryptokit.security.Digests;
import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.Hkdf;
import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.HmacAlgorithm;
import io.javacryptokit.security.HybridEncryption;
import io.javacryptokit.security.KeyStoreReader;
import io.javacryptokit.security.KeyStoreType;
import io.javacryptokit.security.Passwords;
import io.javacryptokit.security.Pbkdf2Algorithm;
import io.javacryptokit.security.PemKeys;
import io.javacryptokit.security.RequestAuth;
import io.javacryptokit.security.RsaOaep;
import io.javacryptokit.security.SecureRandoms;
import io.javacryptokit.security.SignatureAlgorithm;
import io.javacryptokit.security.Signatures;
import io.javacryptokit.security.Totp;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.OptionalLong;

/**
 * 사용자 가이드 13장(범용 보안 Java API)의 예제와 같은 코드다. 라이브러리 패키지 밖에서 공개 API만 쓰며,
 * {@code SecurityApiExampleTest}가 JDK 8·21에서 컴파일·실행해 예제가 맞는지 확인한다. 가이드의 예제 블록은
 * {@code // 예제: SecurityApiExample.<메서드>} 표시로 이 파일과 연결되고 문서 정합성 시험이 내용 일치를 검사한다.
 */
public final class SecurityApiExample {
    private SecurityApiExample() { }

    /** AES-GCM + AAD: 고객 ID를 AAD로 묶어 다른 고객 레코드로 옮긴 암호문을 탐지한다. */
    public static String aesGcmWithAad(byte[] key, String customerId, String cardNumber) throws CredentialCryptoException {
        // 예제: SecurityApiExample.aesGcmWithAad
        AesGcm gcm = AesGcm.of(AesKeySize.AES_256, key);                 // key: 애플리케이션이 확보한 32바이트
        String sealed = gcm.encryptText(cardNumber, "customer:" + customerId, Encoding.BASE64_URL);
        // DB에는 sealed만 저장(IV·태그 포함). AAD(customer:ID)는 저장하지 않고 복호화할 때 다시 만든다.
        return gcm.decryptText(sealed, "customer:" + customerId, Encoding.BASE64_URL); // AAD가 다르면 INTEGRITY
    }

    /** Passphrase로 AES-128 + PBKDF2-SHA512 키를 만들어 바이트를 암복호화한다. */
    public static byte[] aesGcmFromPassphrase(char[] passphrase, byte[] salt, byte[] data) throws CredentialCryptoException {
        // 예제: SecurityApiExample.aesGcmFromPassphrase
        AesGcm gcm = AesGcm.fromPassphrase(AesKeySize.AES_128, Pbkdf2Algorithm.SHA512, passphrase, salt,
                Pbkdf2Algorithm.SHA512.recommendedIterations());          // 파생은 여기서 한 번(객체 재사용)
        byte[] sealed = gcm.encrypt(data);                                // IV(12) ‖ 암호문 ‖ 태그(16)
        return gcm.decrypt(sealed);
    }

    /** HMAC: 외부 시스템(웹훅)이 보낸 서명 헤더를 검증한다. */
    public static boolean verifyWebhook(byte[] partnerSecret, byte[] body, String signatureHeader) {
        // 예제: SecurityApiExample.verifyWebhook
        Hmac hmac = Hmac.ofExternalKey(HmacAlgorithm.SHA256, partnerSecret); // 상대가 정한 기존 비밀(짧을 수 있음)
        String hex = signatureHeader.startsWith("sha256=") ? signatureHeader.substring(7) : signatureHeader;
        return hmac.verify(body, hex, Encoding.HEX);                      // 값이 다르면 false, 형식이 틀리면 예외
    }

    /** HMAC: 새 공유 키를 만들고 메시지 MAC을 만든다. */
    public static boolean macRoundTrip(String message) {
        // 예제: SecurityApiExample.macRoundTrip
        byte[] key = Hmac.generateKey();                                  // 32바이트 보안 난수(양쪽이 안전하게 나눠 보관)
        Hmac hmac = Hmac.of(key);
        String mac = hmac.sign(message, Encoding.BASE64_URL);
        return hmac.verify(message, mac, Encoding.BASE64_URL);
    }

    /** API 요청 인증: 보내는 쪽 서명 → 받는 쪽 확인(재전송 방지는 하지 않음). */
    public static RequestAuth.Result requestAuth(byte[] sharedKey, String method, String pathAndQuery, byte[] body) {
        // 예제: SecurityApiExample.requestAuth
        byte[] request = (method + "\n" + pathAndQuery + "\n" + Digests.sha256Hex(body)).getBytes(StandardCharsets.UTF_8);
        RequestAuth auth = RequestAuth.of(Hmac.of(sharedKey));            // 허용 오차 5분, 시스템 UTC 시계
        RequestAuth.Signed signed = auth.sign(request);                   // 헤더: X-Timestamp·X-Nonce·X-Signature 등
        RequestAuth.Result result = auth.verify(request, signed.timestamp(), signed.nonce(), signed.mac());
        return result;
    }

    /** 보안 난수: 비밀번호 재설정 토큰, 추적 ID. */
    public static String[] randomValues() {
        // 예제: SecurityApiExample.randomValues
        String resetToken = SecureRandoms.token();                        // 32바이트 → Base64URL 43자
        String apiKey = SecureRandoms.token(32, Encoding.HEX);            // 32바이트 → 16진수 64자
        String traceId = SecureRandoms.uuidV4().toString();               // 추적용(비밀·절대 유일성 아님)
        String code = SecureRandoms.string(6, SecureRandoms.Alphabet.DIGITS, "R-");
        return new String[] {resetToken, apiKey, traceId, code};
    }

    /** 해시: 받은 파일이 공지된 SHA-256과 같은지 확인한다. */
    public static boolean fileMatches(Path file, String publishedSha256) throws IOException {
        // 예제: SecurityApiExample.fileMatches
        return Digests.verifyFile(DigestAlgorithm.SHA256, file, publishedSha256, Encoding.HEX); // 스트리밍
    }

    /** 비밀번호 해시: 가입 때 저장값을 만든다. */
    public static String register(char[] password) {
        // 예제: SecurityApiExample.register
        return Passwords.hash(password);                                  // $pbkdf2-sha256$v=1$i=600000$...$...
    }

    /** 로그인 확인과 재해시 판단. 결과[0] = 로그인 성공, 결과[1] = 다시 저장할 새 해시(없으면 null). */
    public static String[] login(char[] password, String stored) {
        // 예제: SecurityApiExample.login
        if (!Passwords.verify(password, stored)) return new String[] {"false", null};
        String upgraded = Passwords.needsRehash(stored) ? Passwords.hash(password) : null; // 정책이 강해졌으면 교체
        return new String[] {"true", upgraded};
    }

    /** HKDF: 원본 키 하나에서 용도별 키를 나눈다. */
    public static byte[][] splitKeys(byte[] masterKey, byte[] salt) {
        // 예제: SecurityApiExample.splitKeys
        byte[] encryptionKey = Hkdf.derive(HmacAlgorithm.SHA256, masterKey, salt, "orders/enc/v1", 32);
        byte[] macKey = Hkdf.derive(HmacAlgorithm.SHA256, masterKey, salt, "orders/mac/v1", 32);
        return new byte[][] {encryptionKey, macKey};
    }

    /** 인코딩·안전 비교. */
    public static boolean encodingAndCompare(String storedToken, String presentedToken) {
        // 예제: SecurityApiExample.encodingAndCompare
        byte[] raw = Encoding.BASE64_URL.decode(SecureRandoms.token());   // 형식이 틀리면 IllegalArgumentException
        String hex = Encoding.HEX.encode(raw);                            // 인코딩은 암호화가 아니다
        return hex.length() == 64 && Bytes.equalsConstantTime(storedToken, presentedToken); // null·빈 값은 false
    }

    /** 전자서명: 키 쌍을 PEM으로 저장·배포하고 파일에 서명·검증한다. */
    public static boolean signFile(Path file) throws IOException {
        // 예제: SecurityApiExample.signFile
        KeyPair pair = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        String privatePem = PemKeys.toPem(pair.getPrivate());             // 서명 서버만 보관(비밀)
        String publicPem = PemKeys.toPem(pair.getPublic());               // 검증하는 쪽에 배포
        PrivateKey signingKey = PemKeys.readPrivateKey(privatePem);
        byte[] signature = Signatures.signFile(SignatureAlgorithm.ECDSA_P256_SHA256, signingKey, file);
        PublicKey verifyKey = PemKeys.readPublicKey(publicPem);
        return Signatures.verifyFile(SignatureAlgorithm.ECDSA_P256_SHA256, verifyKey, file, signature);
    }

    /** 인증서: 만료 점검과 호출자 루트로 신뢰 체인 확인. */
    public static long daysLeft(Path serverPem, Path rootPem) throws Exception {
        // 예제: SecurityApiExample.daysLeft
        X509Certificate server = Certificates.readFile(serverPem);
        CertificateInfo info = Certificates.info(server);                 // 분석만(신뢰·호스트명·폐기 확인 아님)
        X509Certificate root = Certificates.readFile(rootPem);
        Certificates.validateChain(Collections.singletonList(server), Collections.singletonList(root),
                Instant.now());                                           // 실패하면 CertPathValidatorException
        return info.daysUntilExpiry(Instant.now());
    }

    /** TOTP: 등록 URI를 만들고 입력 코드를 확인한다. 반환 = 일치한 시간 구간(없으면 빈 값). */
    public static OptionalLong totp(byte[] secret, String code) {
        // 예제: SecurityApiExample.totp
        Totp totp = Totp.of(secret);                                      // SHA1·6자리·30초(인증 앱 호환)
        String uri = totp.otpauthUri("예제 서비스", "user@example.com");   // QR로만 보여 주고 로그에 남기지 않는다
        OptionalLong step = totp.verify(code, Instant.now(), 1);          // 앞뒤 1구간(±30초)
        return uri.startsWith("otpauth://totp/") ? step : OptionalLong.empty();
    }

    /** RSA-OAEP: 수신자 공개키로 짧은 비밀값(데이터 키)을 보호하고, 개인키를 가진 쪽이 꺼낸다. */
    public static byte[] protectDataKey(PublicKey recipient, PrivateKey recipientKey, byte[] dataKey) throws CredentialCryptoException {
        // 예제: SecurityApiExample.protectDataKey
        byte[] wrapped = RsaOaep.encrypt(recipient, dataKey);             // SHA-256 + MGF1-SHA256, RSA 2048이면 최대 190바이트
        return RsaOaep.decrypt(recipientKey, wrapped);                    // 실패는 원인 구분 없이 INTEGRITY
    }

    /** Hybrid: 상대 공개키로 큰 업무 메시지를 암호화해 보내고, 상대가 개인키로 푼다. */
    public static String sendToPartner(PublicKey partnerKey, PrivateKey partnerPrivateKey, String orderJson) throws CredentialCryptoException {
        // 예제: SecurityApiExample.sendToPartner
        String envelope = HybridEncryption.encryptText(partnerKey, orderJson, "batch:2026-11-24", Encoding.BASE64);
        // 받는 쪽(개인키 보유): 같은 업무 AAD가 있어야 풀린다(봉투에는 AAD가 들어 있지 않음)
        return HybridEncryption.decryptText(partnerPrivateKey, envelope, "batch:2026-11-24", Encoding.BASE64);
    }

    /** PKCS12 키 저장소의 개인키로 서명하고 인증서 공개키로 검증한다. */
    public static boolean signWithKeyStore(Path p12, char[] storePassword, char[] keyPassword, byte[] document) throws Exception {
        // 예제: SecurityApiExample.signWithKeyStore
        KeyStoreReader store = KeyStoreReader.load(p12, KeyStoreType.PKCS12, storePassword); // 읽기 전용, 파일 불변
        PrivateKey signingKey = store.privateKey("signer", keyPassword);  // 별칭·엔트리 비밀번호를 명시
        byte[] signature = Signatures.sign(SignatureAlgorithm.RSA_SHA256, signingKey, document);
        return Signatures.verify(SignatureAlgorithm.RSA_SHA256, store.publicKey("signer"), document, signature);
    }
}
