package example;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 사용자 가이드 6.7절(개발자가 직접 키를 주는 API)의 예제와 같은 코드다. 라이브러리 패키지 밖(example 패키지)에서 공개 API만
 * 사용하며, {@code DirectKeyExampleTest}가 실제로 컴파일·실행해 예제가 맞는지 증명한다.
 */
public final class DirectKeyExample {
    /** Passphrase 키 파생 반복 횟수(기존 pass 유형의 기본값과 같다). Salt·Key ID와 함께 보관한다. */
    public static final int ITERATIONS = 600_000;

    private DirectKeyExample() { }

    /**
     * 32바이트 AES 키로 암호화한 뒤 복호화한다.
     *
     * @param key    애플리케이션이 안전하게 확보한 32바이트 키(이 메서드는 바꾸지 않는다)
     * @param secret 암호화할 텍스트
     * @return 복호화한 텍스트
     * @throws CredentialCryptoException 입력·키·암호문 문제(사유는 getReason())
     */
    public static String rawKeyRoundTrip(byte[] key, String secret) throws CredentialCryptoException {
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("app-key-01", key);
        String token = crypto.encryptText(secret);          // ENC[v1:app-key-01:...]
        return crypto.decryptText(token);
    }

    /**
     * 처음 한 번: Passphrase 키의 Salt(16바이트 보안 난수)를 만든다. Salt·반복 횟수·Key ID는 비밀이 아니지만 복호화에 꼭
     * 필요하므로 암호문과 함께(또는 설정에) 보관하고, Passphrase는 별도의 비밀 저장소에 둔다.
     *
     * @return 새 Salt
     */
    public static byte[] newSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Passphrase로 암호화한다.
     *
     * @param passphrase Passphrase(이 메서드는 바꾸지 않는다. 다 쓰면 호출자가 지운다)
     * @param salt       보관해 둔 Salt
     * @param secret     암호화할 텍스트
     * @return 암호문
     * @throws CredentialCryptoException 입력 문제(INVALID_INPUT) 등
     */
    public static String encryptWithPassphrase(char[] passphrase, byte[] salt, String secret) throws CredentialCryptoException {
        CredentialCrypto crypto = CredentialCrypto.fromPassphrase("app-pass-01", passphrase, salt, ITERATIONS);
        return crypto.encryptText(secret);                   // ENC[v1:app-pass-01:...] (Salt·반복 횟수는 들어 있지 않다)
    }

    /**
     * 애플리케이션을 다시 시작한 뒤: 같은 Key ID·Passphrase·Salt·반복 횟수로 객체를 다시 만들어 복호화한다.
     *
     * @param passphrase Passphrase
     * @param salt       암호화할 때 쓴 Salt
     * @param token      암호문
     * @return 복호화한 텍스트
     * @throws CredentialCryptoException 값이 하나라도 다르면 INTEGRITY, Key ID가 다르면 KEY_ID_MISMATCH
     */
    public static String decryptAfterRestart(char[] passphrase, byte[] salt, String token) throws CredentialCryptoException {
        CredentialCrypto crypto = CredentialCrypto.fromPassphrase("app-pass-01", passphrase, salt, ITERATIONS);
        return crypto.decryptText(token);
    }

    /**
     * 서로 다른 Key ID·키를 쓰는 객체 여러 개와 설정 기반 객체(JAR 내장 키)를 한 JVM에서 함께 쓴다. 각 객체는 자기 키만 쓰며 서로의
     * 암호문을 다른 키로 바꿔 풀지 않는다.
     *
     * @param orderKey   주문 서비스용 32바이트 키
     * @param paymentKey 결제 서비스용 32바이트 키
     * @return 세 객체가 각자 자기 암호문을 복호화하고, 서로의 암호문은 거부하면 true
     * @throws CredentialCryptoException 설정·키 문제
     */
    public static boolean separateKeys(byte[] orderKey, byte[] paymentKey) throws CredentialCryptoException {
        CredentialCrypto orders = CredentialCrypto.fromRawKey("order-key-01", orderKey);
        CredentialCrypto payments = CredentialCrypto.fromRawKey("payment-key-01", paymentKey);
        CredentialCrypto managed = CredentialCrypto.fromDefaultConfiguration();   // JAR·외부 설정의 키(그대로 둔다)

        String orderToken = orders.encryptText("dummy-order");
        String paymentToken = payments.encryptText("dummy-payment");
        String managedToken = managed.encryptText("dummy-managed");

        boolean ownTokens = "dummy-order".equals(orders.decryptText(orderToken))
                && "dummy-payment".equals(payments.decryptText(paymentToken))
                && "dummy-managed".equals(managed.decryptText(managedToken));
        return ownTokens && rejected(orders, paymentToken) && rejected(payments, managedToken) && rejected(managed, orderToken);
    }

    /**
     * 실패 사유를 구분해 처리하는 예(예외 메시지에는 키·Passphrase·평문이 들어 있지 않다).
     *
     * @param crypto 직접 키를 준 객체
     * @param token  복호화할 암호문
     * @return 처리 결과 설명
     */
    public static String describeFailure(CredentialCrypto crypto, String token) {
        try {
            crypto.decryptText(token);
            return "OK";
        } catch (CredentialCryptoException e) {
            switch (e.getReason()) {
                case INTEGRITY:
                    return "키·Passphrase·Salt·반복 횟수가 암호화할 때와 다르거나 암호문이 변조됨";
                case KEY_ID_MISMATCH:
                    return "다른 Key ID의 암호문";
                case INVALID_TOKEN:
                    return "암호문 형식 오류";
                default:
                    return "입력 또는 키 문제: " + e.getReason();
            }
        }
    }

    /**
     * 호출자 배열 정리 예: 객체를 만든 뒤 원본 키 배열을 지워도 객체는 자기 복사본으로 계속 동작한다.
     *
     * @param key 32바이트 키(이 메서드가 지운다)
     * @return 지운 뒤에도 암복호화되면 true
     * @throws CredentialCryptoException 입력 문제
     */
    public static boolean wipeCallerKey(byte[] key) throws CredentialCryptoException {
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("app-key-01", key);
        Arrays.fill(key, (byte) 0);                           // 원본 배열은 호출자가 정리한다
        return "dummy".equals(crypto.decryptText(crypto.encryptText("dummy")));
    }

    private static boolean rejected(CredentialCrypto crypto, String token) {
        try {
            crypto.decryptText(token);
            return false;
        } catch (CredentialCryptoException e) {
            return true;
        }
    }
}
