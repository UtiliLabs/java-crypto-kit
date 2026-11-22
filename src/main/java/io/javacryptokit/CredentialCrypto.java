package io.javacryptokit;

import io.javacryptokit.core.CryptoService;
import io.javacryptokit.core.TokenCodec;
import io.javacryptokit.i18n.Messages;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * <b>java-crypto-kit의 공개 Java API</b>다. 일반 Java 애플리케이션·배치가 JDBC 비밀번호 외의 값(API 토큰, 설정 비밀값,
 * 작은 바이너리 등)을 Tomcat 연동과 같은 규칙으로 암호화·복호화할 때 사용한다. 이 패키지의 이 클래스와
 * {@link CredentialCryptoException}만 공개 API이며, 하위 패키지(core·key·config 등)는 내부 구현이다.
 *
 * <p><b>사용 예</b></p>
 * <pre>{@code
 * CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration(); // WAS와 같은 설정 탐색 규칙
 * String token = crypto.encryptText("dummy-secret");                      // ENC[v1:...] (또는 B64[...])
 * String plain = crypto.decryptText(token);
 * boolean ok   = crypto.verify(token);                                     // 평문을 돌려주지 않는 확인
 *
 * // 파일 암복호화(배치 등): 원본은 그대로 두고, 출력 파일이 이미 있으면 덮어쓰지 않는다.
 * crypto.encryptFile(Paths.get("report.csv"), Paths.get("report.csv.jck"));
 * crypto.decryptFile(Paths.get("report.csv.jck"), Paths.get("report-restored.csv"));
 * }</pre>
 *
 * <p><b>설정과 수명</b></p>
 * <ul>
 *   <li>{@link #fromDefaultConfiguration()}: JVM 속성 {@code -Dcrypto.config.file} → 환경변수 {@code CRYPTO_CONFIG_FILE}
 *       순서로 외부 설정을 찾고, 없으면 JAR 내부 설정(기본은 공개 내장 키, 개발·테스트용. {@code config set}·{@code config embed-key}로
 *       바꾼 키 내장 JAR면 그 값)을 쓴다. Tomcat 어댑터와 같은 규칙이다.</li>
 *   <li>{@link #fromConfigFile(Path)}: 지정한 외부 설정 파일을 사용한다(CLI {@code --config}와 같은 의미).</li>
 *   <li>두 방법 모두 JVM 개별 속성({@code -Dcrypto.key.source=file}, {@code -Dcrypto.warning.enabled=false} 등)을 같은 규칙으로
 *       적용한다. 우선순위는 JVM 속성 &gt; 외부 설정 파일 &gt; JAR 기본값이며, 외부 설정이나 JAR 기본값의
 *       {@code crypto.jvm.override.enabled=false}이면 개별 JVM 속성을 무시한다. 키 원문은 JVM 속성으로 받지 않는다.</li>
 *   <li>설정은 객체를 만들 때 한 번 읽고 바뀌지 않는다. 로컬 키(embedded·file·env)는 호출할 때마다 읽고, 원격 키(vault·aws-kms)는
 *       객체마다 처음 한 번만 조회해 재사용한다. 변경 감지·핫 리로드 기능은 없으므로 설정·키를 바꾸면 새 객체를 만든다.</li>
 *   <li>예외·경고 문구는 설정 {@code crypto.lang}(auto/ko/en)의 언어로 만든다.</li>
 *   <li>객체는 불변이라 여러 스레드가 공유해도 된다.</li>
 * </ul>
 *
 * <p><b>텍스트와 바이트</b>: {@code encryptText}는 텍스트를 UTF-8로 바꿔 암호화하고 {@code decryptText}는 결과가 올바른
 * UTF-8일 때만 텍스트로 돌려준다. {@code encryptBytes}/{@code decryptBytes}는 바이트를 변환 없이 그대로 보존한다.
 * 두 경우 모두 같은 {@code ENC[v1:...]} 형식(AES-256-GCM, AAD, 키ID 규칙)이다. 값 하나의 크기는 평문 약 12KB(암호문 16,384자)까지다.</p>
 *
 * <p><b>출력 형식</b>: 기본은 {@code ENC[v1:...]}이고 설정 {@code crypto.output.encoding=base64}일 때만 {@code B64[...]}로
 * 한 번 더 포장한다. 복호화는 설정과 관계없이 두 형식을 모두 받는다. B64 포장은 보안 기능이 아니다.</p>
 *
 * <p><b>실패 처리</b>: 모든 메서드는 실패하면 {@link CredentialCryptoException}을 던지고 평문을 일부라도 돌려주지 않는다.
 * 예외에는 평문·키·암호문·경로가 들어 있지 않으며, {@link CredentialCryptoException#getReason()}으로 사유를 구분할 수 있다.
 * 외부 키(파일·환경변수·Vault·AWS KMS)를 지정했는데 읽지 못하면 내장 키로 바꾸지 않고 실패한다.</p>
 *
 * <p><b>알고리즘</b>: AES-256-GCM(v1)만 지원한다. 임의 알고리즘·Provider를 고르는 기능은 없다.</p>
 */
public final class CredentialCrypto {
    /** 실제 처리를 맡는 공통 서비스(CLI·Tomcat 어댑터와 같은 구현). */
    private final CryptoService service;

    private CredentialCrypto(CryptoService service) {
        this.service = service;
    }

    /**
     * WAS(Tomcat 어댑터)와 같은 규칙으로 설정을 찾아 객체를 만든다.
     *
     * @return 설정이 적용된 객체
     * @throws CredentialCryptoException CONFIGURATION: 지정한 외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님,
     *                                   허용되지 않은 설정값, 설정 경로 충돌, 모호한 키 설정
     */
    public static CredentialCrypto fromDefaultConfiguration() throws CredentialCryptoException {
        return new CredentialCrypto(CryptoService.load(null));
    }

    /**
     * 지정한 외부 설정 파일(UTF-8 Properties)을 기본값 위에 덮어써 객체를 만든다.
     *
     * @param configFile 외부 설정 파일 경로
     * @return 설정이 적용된 객체
     * @throws CredentialCryptoException CONFIGURATION: 경로가 없거나, 파일을 읽을 수 없거나, 설정값이 올바르지 않은 경우
     */
    public static CredentialCrypto fromConfigFile(Path configFile) throws CredentialCryptoException {
        if (configFile == null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("api.err.configPath"));
        }
        return new CredentialCrypto(CryptoService.load(configFile.toString()));
    }

    /**
     * 텍스트를 암호화한다. 텍스트는 UTF-8로 변환한다.
     * Java String은 메모리에서 지울 수 없으므로, 비밀번호처럼 민감한 값은 가능하면 {@link #encryptText(char[])}를 쓴다.
     *
     * @param plainText 암호화할 텍스트(비어 있으면 안 됨)
     * @return 설정한 출력 형식의 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})
     * @throws CredentialCryptoException INVALID_INPUT(빈 값·너무 긴 값·UTF-8 불가 문자), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(String plainText) throws CredentialCryptoException {
        if (plainText == null || plainText.isEmpty()) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                    Messages.get("service.err.empty"));
        }
        char[] chars = plainText.toCharArray();
        try {
            return service.encryptText(chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * 텍스트(char[])를 암호화한다. 이 메서드는 전달받은 배열을 지우지 않으므로 호출자가 사용 후 지운다.
     *
     * @param plainText 암호화할 문자 배열(비어 있으면 안 됨)
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText) throws CredentialCryptoException {
        return service.encryptText(plainText);
    }

    /**
     * 토큰을 복호화해 텍스트로 돌려준다. {@code ENC[v1:...]}와 {@code B64[...]}를 모두 받는다.
     *
     * @param token 암호문 토큰
     * @return 복호화한 텍스트(결과가 올바른 UTF-8이 아니면 실패)
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, INVALID_INPUT(텍스트 아님), KEY_SOURCE,
     *                                   CRYPTO_PROVIDER
     */
    public String decryptText(String token) throws CredentialCryptoException {
        return service.decryptText(token);
    }

    /**
     * 바이트를 변환 없이 그대로 암호화한다.
     *
     * @param data 암호화할 바이트(비어 있으면 안 됨). 이 메서드는 배열을 바꾸지 않는다.
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data) throws CredentialCryptoException {
        return service.encryptBytes(data);
    }

    /**
     * 토큰을 복호화해 원본 바이트를 돌려준다. 호출자가 사용 후 배열을 지우는 것을 권장한다.
     *
     * @param token 암호문 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})
     * @return 원본 바이트
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public byte[] decryptBytes(String token) throws CredentialCryptoException {
        return service.decryptBytes(token);
    }

    /**
     * 토큰을 현재 키로 복호화할 수 있는지 확인한다. 평문은 돌려주지 않고 내부에서 바로 지운다.
     *
     * @param token 확인할 토큰
     * @return 토큰이 올바르고 현재 키·키ID로 복호화되면 true, 토큰 자체의 문제(형식·키ID·무결성)면 false
     * @throws CredentialCryptoException 토큰이 아니라 환경의 문제(KEY_SOURCE, CRYPTO_PROVIDER)인 경우.
     *                                   설정 오류를 "검증 실패"로 숨기지 않기 위해 예외로 알린다.
     */
    public boolean verify(String token) throws CredentialCryptoException {
        return service.verify(token);
    }

    /**
     * 값이 이 라이브러리의 토큰처럼 보이는지({@code ENC[} 또는 {@code B64[}로 시작하는지)만 확인한다. 복호화하지 않는다.
     *
     * @param value 검사할 값(null 허용)
     * @return 토큰 접두어로 시작하면 true
     */
    public static boolean isToken(String value) {
        return TokenCodec.looksLikeToken(value);
    }

    /** @return 현재 설정의 키 식별자(비밀값 아님) */
    public String keyId() {
        return service.settings().keyId();
    }

    /** @return 현재 설정의 키 공급 방식: embedded, file, env, vault, aws-kms */
    public String keySource() {
        return service.settings().keySource();
    }

    /**
     * 파일을 암호화한다(텍스트·CSV·JSON·PDF·이미지 등 형식 무관). 결과는 독립된 버전 관리 바이너리 형식(JCKF v1,
     * AES-256-GCM, 64KiB 청크 스트리밍)이며 {@code ENC[v1:...]} 문자열 형식과는 별개다.
     *
     * <ul>
     *   <li>원본 파일은 바꾸지 않는다. 출력 파일이 이미 있으면 덮어쓰지 않고 실패한다(입력과 같은 경로도 거부).</li>
     *   <li>큰 파일도 전체를 메모리에 올리지 않는다(청크 하나씩 처리).</li>
     *   <li>결과는 출력 폴더의 임시 파일에 쓴 뒤 다 쓰면 최종 이름으로 옮긴다. 실패하면 임시 파일을 지운다.</li>
     *   <li>파일마다 청크별 새 난수 IV를 쓰고, 헤더(버전·키ID)·청크 순서·마지막 청크를 인증한다.</li>
     * </ul>
     *
     * <pre>{@code
     * CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
     * crypto.encryptFile(Paths.get("data/report.csv"), Paths.get("data/report.csv.jck"));
     * }</pre>
     *
     * @param in  입력 파일(일반 파일)
     * @param out 출력 파일(없어야 하며 상위 폴더는 있어야 한다)
     * @throws CredentialCryptoException INVALID_INPUT(입력 없음·출력 있음·같은 경로·입출력 실패), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void encryptFile(Path in, Path out) throws CredentialCryptoException {
        requirePaths(in, out);
        service.encryptFile(in, out);
    }

    /**
     * {@link #encryptFile}로 만든 파일을 복호화한다. 모든 청크의 인증 태그와 마지막 청크까지 검증이 끝난 경우에만 출력 파일이
     * 나타난다. 변조·손상·잘림·다른 키는 실패하며, 이때 인증 전 평문을 담은 임시 파일은 지워진다.
     *
     * <pre>{@code
     * CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
     * crypto.decryptFile(Paths.get("data/report.csv.jck"), Paths.get("data/report.csv"));
     * }</pre>
     *
     * @param in  암호화 파일
     * @param out 출력 파일(없어야 한다). POSIX에서는 소유자만 읽을 수 있는 권한(600)으로 만들어진다.
     * @throws CredentialCryptoException INVALID_TOKEN(형식 아님), KEY_ID_MISMATCH, INTEGRITY(변조·손상·잘림·다른 키),
     *                                   INVALID_INPUT(입출력), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void decryptFile(Path in, Path out) throws CredentialCryptoException {
        requirePaths(in, out);
        service.decryptFile(in, out);
    }

    private static void requirePaths(Path in, Path out) throws CredentialCryptoException {
        if (in == null || out == null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get("api.err.filePath"));
        }
    }
}
