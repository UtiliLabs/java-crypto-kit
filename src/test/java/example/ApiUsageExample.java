package example;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import java.nio.file.Path;

/**
 * README "Java API" 절의 예제와 같은 코드다. 라이브러리 패키지 밖(example 패키지)에서 공개 API만 사용하며,
 * {@code ApiUsageExampleTest}가 실제로 컴파일·실행해 예제가 맞는지 증명한다.
 */
public final class ApiUsageExample {
    private ApiUsageExample() { }

    /**
     * 텍스트를 암호화하고, 평문 없이 검증한 뒤, 필요할 때 복호화한다.
     *
     * @param configFile 외부 설정 파일(null이면 WAS와 같은 기본 탐색 규칙: JVM 속성 → 환경변수 → JAR 기본값)
     * @param secret     암호화할 텍스트(예제에서는 더미 값)
     * @return 복호화한 텍스트
     * @throws CredentialCryptoException 설정·키·암호문 문제(사유는 getReason()으로 확인)
     */
    public static String roundTrip(Path configFile, String secret) throws CredentialCryptoException {
        // 1) 설정 선택: 운영은 외부 설정 파일, 개발은 기본 탐색
        CredentialCrypto crypto = configFile == null
                ? CredentialCrypto.fromDefaultConfiguration()
                : CredentialCrypto.fromConfigFile(configFile);
        // 2) 텍스트 암호화: 결과 토큰(ENC[v1:...] 또는 B64[...])만 저장한다
        String token = crypto.encryptText(secret);
        // 3) 평문을 꺼내지 않고 복호화 가능 여부만 확인
        if (!crypto.verify(token)) {
            throw new IllegalStateException("현재 키로 복호화할 수 없는 토큰입니다.");
        }
        // 4) 꼭 필요할 때만 복호화
        return crypto.decryptText(token);
    }

    /**
     * 바이트 데이터를 변환 없이 암호화·복호화한다.
     *
     * @param configFile 외부 설정 파일
     * @param data       원본 바이트
     * @return 복호화한 바이트(원본과 같음)
     * @throws CredentialCryptoException 설정·키·암호문 문제
     */
    public static byte[] binaryRoundTrip(Path configFile, byte[] data) throws CredentialCryptoException {
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(configFile);
        String token = crypto.encryptBytes(data);
        return crypto.decryptBytes(token);
    }

    /**
     * 실패 사유를 구분해 처리하는 예. 예외 메시지에는 평문·키·암호문·경로가 들어 있지 않다.
     *
     * @param configFile 외부 설정 파일
     * @param token      복호화할 토큰
     * @return 처리 결과 설명
     */
    public static String describeFailure(Path configFile, String token) {
        try {
            CredentialCrypto.fromConfigFile(configFile).decryptText(token);
            return "OK";
        } catch (CredentialCryptoException e) {
            switch (e.getReason()) {
                case INTEGRITY:
                    return "키가 다르거나 암호문이 변조됨";
                case KEY_ID_MISMATCH:
                    return "키ID 불일치";
                case INVALID_TOKEN:
                    return "암호문 형식 오류";
                default:
                    return "설정 또는 키 문제: " + e.getReason();
            }
        }
    }
}
