package io.javacryptokit;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.core.Kdf;
import io.javacryptokit.core.TokenCodec;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import io.javacryptokit.security.Pbkdf2Algorithm;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * <b>java-crypto-kit의 공개 Java API</b>다. 일반 Java 애플리케이션·배치가 JDBC 비밀번호 외의 값(API 토큰, 설정 비밀값,
 * 작은 바이너리 등)을 Tomcat 연동과 같은 규칙으로 암호화·복호화할 때 사용한다. 이 패키지의 이 클래스, {@link KeyType},
 * {@link KeyInfo}, {@link CredentialCryptoException}만 공개 API이며, 하위 패키지(core·key·config 등)는 내부 구현이다.
 *
 * <p><b>사용 예</b></p>
 * <pre>{@code
 * CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration(); // WAS와 같은 설정 탐색 규칙
 * String token = crypto.encryptText("dummy-secret");                 // 기본 유형(pass)의 기본 키
 * String aes   = crypto.encryptText("dummy-secret", KeyType.KEY);    // AES Key 유형의 기본 키
 * String biz   = crypto.withKeyId("biz-01").encryptText("dummy-secret"); // Key ID로 선택(유형 자동)
 * String plain = crypto.decryptText(token);                         // 암호문의 Key ID로 키를 자동 선택
 * boolean ok   = crypto.verify(token);                              // 평문을 돌려주지 않는 확인
 *
 * // 파일 암복호화(배치 등): 원본은 그대로 두고, 출력 파일이 이미 있으면 덮어쓰지 않는다.
 * crypto.encryptFile(Paths.get("report.csv"), Paths.get("report.csv.jck"));
 * crypto.decryptFile(Paths.get("report.csv.jck"), Paths.get("report-restored.csv"));
 * }</pre>
 *
 * <p><b>키 선택</b>: 새 암호화는 다음 순서로 키를 고르고, 고르지 못하면 다른 키로 바꾸지 않고 실패한다(CONFIGURATION).</p>
 * <ul>
 *   <li>유형·Key ID를 정하지 않음: 설정 {@code crypto.key.type}(기본 {@code pass})의 기본 키</li>
 *   <li>{@link KeyType}만 정함: 그 유형의 기본 키({@code pass}는 {@code crypto.key.active.pass}, {@code key}는
 *       {@code crypto.key.active.key}, 비어 있으면 {@code crypto.key.*}의 AES 키)</li>
 *   <li>Key ID를 정함({@link #withKeyId(String)}): 그 키(유형은 등록된 키에서 자동으로 정해진다)</li>
 *   <li>유형과 Key ID를 함께 정함: 그 키의 유형이 같은지 확인한 뒤 사용</li>
 * </ul>
 * <p>복호화({@code decryptText}·{@code decryptBytes}·{@code verify}·{@code decryptFile})에는 유형이 필요 없다. 암호문(파일은
 * 헤더)에 기록된 Key ID로 등록된 키를 고르며, 등록되지 않은 Key ID는 다른 키로 시도하지 않고 KEY_ID_MISMATCH로 끝난다.
 * 두 유형 모두 같은 {@code ENC[v1:...]}·JCKF v1 형식이며 유형은 "AES 키를 어떻게 준비하느냐"만 다르다.</p>
 *
 * <p><b>설정과 수명</b></p>
 * <ul>
 *   <li>{@link #fromDefaultConfiguration()}: JVM 속성 {@code -Dcrypto.config.file} → 환경변수 {@code CRYPTO_CONFIG_FILE}
 *       순서로 외부 설정을 찾고, 없으면 JAR 내부 설정을 쓴다. 공식 JAR의 내장 키는 공개 예제 키 두 개({@code pass-default},
 *       {@code default})로 개발·테스트용이다({@code config set}·{@code config embed-key}·{@code config key}로 바꾼 JAR면 그 값).
 *       Tomcat 어댑터와 같은 규칙이다.</li>
 *   <li>{@link #fromConfigFile(Path)}: 지정한 외부 설정 파일을 사용한다(CLI {@code --config}와 같은 의미).</li>
 *   <li>{@link #fromRawKey(String, byte[])}·{@link #fromPassphrase(String, char[], byte[], int)}: 개발자가 직접 준 키 하나만 쓴다.
 *       JAR 내장 키·키 목록·외부 설정 파일·JVM 속성을 읽거나 바꾸지 않고, 변경 이력·CLI 관리자 비밀번호와 무관하다. 키는 그 객체만
 *       복사본으로 보관하며(다른 객체·정적 저장소와 공유하지 않음), 같은 JVM의 설정 기반 객체와 서로 영향을 주지 않는다. 키의 확보·보관·
 *       교체·폐기와 업무상 감사 기록은 호출하는 애플리케이션의 책임이다.</li>
 *   <li>두 방법 모두 JVM 개별 속성({@code -Dcrypto.key.source=file}, {@code -Dcrypto.warning.enabled=false} 등)을 같은 규칙으로
 *       적용한다. 우선순위는 JVM 속성 &gt; 외부 설정 파일 &gt; JAR 기본값이며, 외부 설정이나 JAR 기본값의
 *       {@code crypto.jvm.override.enabled=false}이면 개별 JVM 속성을 무시한다. 키 원문은 JVM 속성으로 받지 않는다.</li>
 *   <li>설정은 객체를 만들 때 한 번 읽고 바뀌지 않는다. 로컬 키(embedded·file·env)는 호출할 때마다 읽고(Passphrase에서 파생한
 *       키는 JVM 안에서 한 번만 계산), 원격 키(vault·aws-kms)는 객체마다 키별로 처음 한 번만 조회해 재사용한다. 변경 감지·핫 리로드
 *       기능은 없으므로 설정·키를 바꾸면 새 객체를 만든다.</li>
 *   <li>예외·경고 문구는 설정 {@code crypto.lang}(auto/ko/en)의 언어로 만든다.</li>
 *   <li>객체는 불변이라 여러 스레드가 공유해도 된다({@link #withKeyId(String)}가 돌려주는 객체도 같다).</li>
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
 * <p><b>알고리즘</b>: AES-256-GCM(v1)만 지원한다. Passphrase는 PBKDF2-HMAC-SHA256으로 AES 키를 파생한다. 임의 알고리즘·
 * Provider를 고르는 기능은 없다.</p>
 */
public final class CredentialCrypto {
    /** 직접 주는 AES 키 길이(AES-256). */
    private static final int RAW_KEY_BYTES = 32;
    /** 실제 처리를 맡는 공통 서비스(CLI·Tomcat 어댑터와 같은 구현). */
    private final CryptoService service;
    /** {@link #withKeyId(String)}로 정한 Key ID. null이면 설정의 기본 선택 규칙을 따른다. */
    private final String boundKeyId;

    private CredentialCrypto(CryptoService service, String boundKeyId) {
        this.service = service;
        this.boundKeyId = boundKeyId;
    }

    /**
     * WAS(Tomcat 어댑터)와 같은 규칙으로 설정을 찾아 객체를 만든다.
     *
     * @return 설정이 적용된 객체
     * @throws CredentialCryptoException CONFIGURATION: 지정한 외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님,
     *                                   허용되지 않은 설정값, 설정 경로 충돌, 모호한 키 설정, 잘못된 키 등록
     */
    public static CredentialCrypto fromDefaultConfiguration() throws CredentialCryptoException {
        return new CredentialCrypto(CryptoService.load(null), null);
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
        return new CredentialCrypto(CryptoService.load(configFile.toString()), null);
    }

    /**
     * 개발자가 직접 준 AES-256 키(32바이트)만으로 암복호화하는 객체를 만든다. JAR 내장 키·키 목록·외부 설정 파일·JVM 속성을 읽거나
     * 바꾸지 않고, 변경 이력·CLI 관리자 비밀번호와도 무관하다. 키는 이 객체만 복사본으로 메모리에 보관한다(다른 객체·정적 저장소와
     * 공유하지 않음). 같은 Key ID와 같은 키로 다시 만든 객체(예: 애플리케이션 재시작 뒤)는 이전 암호문을 그대로 복호화한다.
     *
     * <pre>{@code
     * byte[] key = loadKeyFromMySecretStore();                        // 애플리케이션이 안전하게 확보한 32바이트 키
     * CredentialCrypto crypto = CredentialCrypto.fromRawKey("app-key-01", key);
     * Arrays.fill(key, (byte) 0);                                     // 원본 배열은 호출자가 정리(객체는 복사본을 쓴다)
     * String token = crypto.encryptText("dummy-secret");             // ENC[v1:app-key-01:...]
     * String plain = crypto.decryptText(token);
     * }</pre>
     *
     * <p>암호문(파일은 헤더)에 기록된 Key ID가 이 객체의 Key ID와 같을 때만 복호화하며(다르면 KEY_ID_MISMATCH), 다른 키로 바꿔
     * 시도하지 않는다. 출력은 늘 {@code ENC[v1:...]}이고 예외 문구는 라이브러리 기본 언어(한국어)로 만든다.</p>
     *
     * @param keyId Key ID(영문·숫자·{@code -}·{@code _} 1~64자, 암호문에 기록된다)
     * @param key   32바이트 AES 키(바꾸지 않고 복사한다)
     * @return 그 키 하나만 쓰는 객체(유형 {@link KeyType#KEY}, 공급 방식 {@code direct})
     * @throws CredentialCryptoException INVALID_INPUT: Key ID 없음·형식 오류, 키 없음·32바이트가 아님
     */
    public static CredentialCrypto fromRawKey(String keyId, byte[] key) throws CredentialCryptoException {
        requireDirectKeyId(keyId);
        if (key == null || key.length != RAW_KEY_BYTES) throw directInput("api.err.rawKeyLength");
        return new CredentialCrypto(CryptoService.direct(keyId, KeyType.KEY, key), null);
    }

    /**
     * 개발자가 직접 준 Passphrase로 암복호화하는 객체를 만든다. 기존 pass 유형과 같은 규칙(NFC 정규화·UTF-8, PBKDF2-HMAC-SHA256,
     * 32바이트 키)으로 키를 한 번 파생해 이 객체만 보관하며, JAR·설정·이력·CLI 관리자 비밀번호와 무관하다({@link #fromRawKey}와 같음).
     *
     * <pre>{@code
     * char[] passphrase = readPassphraseFromMySecretStore();
     * byte[] salt = loadSalt();          // 처음 한 번 SecureRandom으로 16바이트를 만들어 Key ID·반복 횟수와 함께 보관한 값
     * CredentialCrypto crypto = CredentialCrypto.fromPassphrase("app-pass-01", passphrase, salt, 600_000);
     * Arrays.fill(passphrase, '\0');     // 원본 배열은 호출자가 정리
     * String token = crypto.encryptText("dummy-secret");             // ENC[v1:app-pass-01:...]
     * }</pre>
     *
     * <p><b>복호화에 필요한 값은 호출자가 보관한다:</b> 암호문에는 Key ID만 기록되고 Salt·반복 횟수는 들어 있지 않다. 같은 Key ID·
     * Passphrase·Salt·반복 횟수로 다시 만든 객체만 이전 암호문을 복호화하며, 하나라도 다르면 다른 키가 되어 INTEGRITY로 실패한다.</p>
     *
     * @param keyId      Key ID(영문·숫자·{@code -}·{@code _} 1~64자)
     * @param passphrase Passphrase(비어 있거나 공백만·제어문자 불가, UTF-8 1KiB 이하. 바꾸지 않는다)
     * @param salt       Salt 16바이트(바꾸지 않는다)
     * @param iterations PBKDF2 반복 횟수(100,000~5,000,000, 권장 600,000)
     * @return 그 키 하나만 쓰는 객체(유형 {@link KeyType#PASS}, 공급 방식 {@code direct})
     * @throws CredentialCryptoException INVALID_INPUT: Key ID·Passphrase·Salt·반복 횟수가 규칙에 맞지 않음
     */
    public static CredentialCrypto fromPassphrase(String keyId, char[] passphrase, byte[] salt, int iterations)
            throws CredentialCryptoException {
        return fromPassphrase(keyId, passphrase, salt, iterations, Pbkdf2Algorithm.SHA256);
    }

    /**
     * {@link #fromPassphrase(String, char[], byte[], int)}와 같지만 PBKDF2의 HMAC 해시를 고른다. 결과 키는 언제나 AES-256(32바이트)이고
     * 출력은 {@code ENC[v1:...]}·JCKF v1 그대로다. 암호문에는 KDF 정보가 들어 있지 않으므로 알고리즘도 Salt·반복 횟수와 함께 호출자가
     * 보관해야 한다(SHA512로 만든 암호문은 같은 Passphrase·Salt라도 SHA256 객체로는 INTEGRITY로 실패한다). 관리형 pass 키(JAR·설정)는
     * 이 선택과 무관하게 PBKDF2-HMAC-SHA256을 쓴다. AES-128이나 업무용 AAD가 필요하면 {@code security.AesGcm}을 쓴다.
     *
     * <pre>{@code
     * CredentialCrypto crypto = CredentialCrypto.fromPassphrase("app-pass-02", passphrase, salt,
     *         Pbkdf2Algorithm.SHA512.recommendedIterations(), Pbkdf2Algorithm.SHA512);   // 210,000회
     * }</pre>
     *
     * @param keyId      Key ID(영문·숫자·{@code -}·{@code _} 1~64자)
     * @param passphrase Passphrase(비어 있거나 공백만·제어문자 불가, UTF-8 1KiB 이하. 바꾸지 않는다)
     * @param salt       Salt 16바이트(바꾸지 않는다)
     * @param iterations PBKDF2 반복 횟수(100,000~5,000,000, 권장 SHA256 600,000·SHA512 210,000)
     * @param algorithm  PBKDF2 알고리즘
     * @return 그 키 하나만 쓰는 객체(유형 {@link KeyType#PASS}, 공급 방식 {@code direct})
     * @throws CredentialCryptoException INVALID_INPUT: Key ID·Passphrase·Salt·반복 횟수·알고리즘이 규칙에 맞지 않음
     */
    public static CredentialCrypto fromPassphrase(String keyId, char[] passphrase, byte[] salt, int iterations,
                                                  Pbkdf2Algorithm algorithm) throws CredentialCryptoException {
        requireDirectKeyId(keyId);
        if (algorithm == null) throw directInput("api.err.kdfAlgorithm");
        if (salt == null || salt.length != PassKdf.SALT_BYTES) throw directInput("api.err.saltLength");
        if (iterations < SettingCatalog.KDF_MIN_ITERATIONS || iterations > SettingCatalog.KDF_MAX_ITERATIONS) {
            throw directInput("api.err.iterations", SettingCatalog.KDF_MIN_ITERATIONS, SettingCatalog.KDF_MAX_ITERATIONS);
        }
        char[] normalized;
        try (Messages.Scope ignored = Messages.use(CryptoService.DIRECT_LANGUAGE)) {
            normalized = PassKdf.normalize(passphrase);
        } catch (IllegalArgumentException e) {
            // 빈 값·공백만·제어문자·깨진 문자: 이 라이브러리의 고정 문구(Passphrase 값은 들어 있지 않음)
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, e.getMessage());
        }
        byte[] key = null;
        try {
            if (Kdf.utf8Length(normalized) > PassKdf.MAX_FILE_BYTES) throw directInput("api.err.passphraseLong", PassKdf.MAX_FILE_BYTES);
            key = Kdf.pbkdf2(algorithm.jcaName(), normalized, salt.clone(), iterations, RAW_KEY_BYTES);
            return new CredentialCrypto(CryptoService.direct(keyId, KeyType.PASS, key), null);
        } finally {
            Arrays.fill(normalized, '\0');
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * 새 암호화가 지정한 Key ID의 키를 쓰는 객체를 돌려준다(유형은 등록된 키에서 자동으로 정해진다). 복호화·조회 동작과 설정은
     * 원래 객체와 같고, 원래 객체는 바뀌지 않는다.
     *
     * <pre>{@code
     * CredentialCrypto biz = crypto.withKeyId("biz-01");
     * String token = biz.encryptText("dummy-secret");       // biz-01 키로 암호화
     * biz.encryptText("dummy-secret", KeyType.KEY);         // biz-01이 key 유형인지 확인한 뒤 암호화
     * }</pre>
     *
     * @param keyId 등록된 Key ID
     * @return 그 키로 암호화하는 객체
     * @throws CredentialCryptoException INVALID_INPUT(Key ID 없음), CONFIGURATION(등록되지 않은 Key ID)
     */
    public CredentialCrypto withKeyId(String keyId) throws CredentialCryptoException {
        requireKeyId(keyId);
        service.select(null, keyId); // 등록되어 있는지 바로 확인한다(키 값은 읽지 않음).
        return new CredentialCrypto(service, keyId);
    }

    /**
     * 텍스트를 기본 키로 암호화한다(키 선택은 클래스 설명 참고). 텍스트는 UTF-8로 변환한다.
     * Java String은 메모리에서 지울 수 없으므로, 비밀번호처럼 민감한 값은 가능하면 {@link #encryptText(char[])}를 쓴다.
     *
     * @param plainText 암호화할 텍스트(비어 있으면 안 됨)
     * @return 설정한 출력 형식의 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})
     * @throws CredentialCryptoException INVALID_INPUT(빈 값·너무 긴 값·UTF-8 불가 문자), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(String plainText) throws CredentialCryptoException {
        return encryptString(plainText, null, boundKeyId);
    }

    /**
     * 텍스트를 지정한 유형의 기본 키로 암호화한다({@link #withKeyId(String)} 객체에서는 그 키의 유형이 같은지 확인한다).
     *
     * @param plainText 암호화할 텍스트(비어 있으면 안 됨)
     * @param type      {@link KeyType#PASS} 또는 {@link KeyType#KEY}
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT(빈 값·유형 없음), CONFIGURATION(그 유형의 기본 키 없음·유형 불일치),
     *                                   KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(String plainText, KeyType type) throws CredentialCryptoException {
        return encryptString(plainText, requireType(type), boundKeyId);
    }

    /**
     * 텍스트를 지정한 Key ID의 키로 암호화한다. 그 키의 유형이 {@code type}과 다르면 실패한다.
     *
     * @param plainText 암호화할 텍스트(비어 있으면 안 됨)
     * @param type      기대하는 유형
     * @param keyId     등록된 Key ID({@link #withKeyId(String)} 객체에서도 이 값이 우선한다)
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT(빈 값·유형 없음·Key ID 없음), CONFIGURATION(등록되지 않은 Key ID·유형 불일치),
     *                                   KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(String plainText, KeyType type, String keyId) throws CredentialCryptoException {
        return encryptString(plainText, requireType(type), requireKeyId(keyId));
    }

    /**
     * 텍스트(char[])를 기본 키로 암호화한다. 이 메서드는 전달받은 배열을 지우지 않으므로 호출자가 사용 후 지운다.
     *
     * @param plainText 암호화할 문자 배열(비어 있으면 안 됨)
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText) throws CredentialCryptoException {
        return service.encryptText(plainText, null, boundKeyId);
    }

    /**
     * 텍스트(char[])를 지정한 유형의 기본 키로 암호화한다. 배열은 호출자가 지운다.
     *
     * @param plainText 암호화할 문자 배열(비어 있으면 안 됨)
     * @param type      {@link KeyType#PASS} 또는 {@link KeyType#KEY}
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText, KeyType type) throws CredentialCryptoException {
        return service.encryptText(plainText, requireType(type), boundKeyId);
    }

    /**
     * 텍스트(char[])를 지정한 Key ID의 키로 암호화한다(유형이 다르면 실패). 배열은 호출자가 지운다.
     *
     * @param plainText 암호화할 문자 배열(비어 있으면 안 됨)
     * @param type      기대하는 유형
     * @param keyId     등록된 Key ID
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText, KeyType type, String keyId) throws CredentialCryptoException {
        return service.encryptText(plainText, requireType(type), requireKeyId(keyId));
    }

    /**
     * 토큰을 복호화해 텍스트로 돌려준다. {@code ENC[v1:...]}와 {@code B64[...]}를 모두 받고, 암호문의 Key ID로 키를 고른다.
     *
     * @param token 암호문 토큰
     * @return 복호화한 텍스트(결과가 올바른 UTF-8이 아니면 실패)
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH(등록되지 않은 Key ID), INTEGRITY, INVALID_INPUT(텍스트 아님),
     *                                   KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String decryptText(String token) throws CredentialCryptoException {
        return service.decryptText(token);
    }

    /**
     * 바이트를 기본 키로 변환 없이 그대로 암호화한다.
     *
     * @param data 암호화할 바이트(비어 있으면 안 됨). 이 메서드는 배열을 바꾸지 않는다.
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data) throws CredentialCryptoException {
        return service.encryptBytes(data, null, boundKeyId);
    }

    /**
     * 바이트를 지정한 유형의 기본 키로 암호화한다.
     *
     * @param data 암호화할 바이트(비어 있으면 안 됨)
     * @param type {@link KeyType#PASS} 또는 {@link KeyType#KEY}
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data, KeyType type) throws CredentialCryptoException {
        return service.encryptBytes(data, requireType(type), boundKeyId);
    }

    /**
     * 바이트를 지정한 Key ID의 키로 암호화한다(유형이 다르면 실패).
     *
     * @param data  암호화할 바이트(비어 있으면 안 됨)
     * @param type  기대하는 유형
     * @param keyId 등록된 Key ID
     * @return 설정한 출력 형식의 토큰
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data, KeyType type, String keyId) throws CredentialCryptoException {
        return service.encryptBytes(data, requireType(type), requireKeyId(keyId));
    }

    /**
     * 토큰을 복호화해 원본 바이트를 돌려준다(암호문의 Key ID로 키를 고른다). 호출자가 사용 후 배열을 지우는 것을 권장한다.
     *
     * @param token 암호문 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})
     * @return 원본 바이트
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public byte[] decryptBytes(String token) throws CredentialCryptoException {
        return service.decryptBytes(token);
    }

    /**
     * 토큰을 등록된 키로 복호화할 수 있는지 확인한다(암호문의 Key ID로 키를 고른다). 평문은 돌려주지 않고 내부에서 바로 지운다.
     *
     * @param token 확인할 토큰
     * @return 토큰이 올바르고 등록된 키로 복호화되면 true, 토큰 자체의 문제(형식·Key ID·무결성)면 false
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

    /** @return 유형·Key ID를 정하지 않은 새 암호화({@code encryptText(value)})가 실제로 쓰는 키의 Key ID(비밀값 아님) */
    public String keyId() {
        return selected().id();
    }

    /** @return {@code encryptText(value)}가 실제로 쓰는 키의 유형 */
    public KeyType keyType() {
        return selected().type();
    }

    /** @return {@code encryptText(value)}가 실제로 쓰는 키의 공급 방식: embedded, file, env, vault, aws-kms, direct(직접 준 키) */
    public String keySource() {
        return selected().source();
    }

    /**
     * 등록된 모든 키의 정보를 돌려준다({@code crypto.key.*}의 AES 키가 먼저, 그다음 {@code crypto.keys.<id>.*}를 Key ID 순서로).
     * 각 키를 실제로 읽어 사용 가능 여부·공개 기본 키 여부·짧은 지문을 확인하며, 원격 키(vault·aws-kms)는 이때 처음 조회할 수 있다.
     * 읽지 못한 키도 목록에 넣고 {@link KeyInfo#isAvailable()}과 사유로 알린다. 키 상태를 직접 돌려주는 조회이므로 공개 기본 키
     * 자동 경고를 내지 않는다.
     *
     * @return 키 정보 목록(변경 불가)
     */
    public List<KeyInfo> keys() {
        KeyProfile chosen = selected();
        CryptoSettings settings = service.settings();
        List<KeyInfo> result = new ArrayList<>();
        try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
            for (CryptoService.KeyCheck check : service.checkKeys()) {
                KeyProfile profile = check.profile();
                KeyProfile active = settings.activeProfile(profile.type());
                result.add(new KeyInfo(profile.id(), profile.type(), profile.source(),
                        active != null && active.id().equals(profile.id()), chosen.id().equals(profile.id()),
                        check.publicDefaultKey(), check.available(), check.failureReason(), check.failure(),
                        check.available() ? KeyResolver.shortFingerprint(check.fingerprint()) : null));
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * 파일을 기본 키로 암호화한다(텍스트·CSV·JSON·PDF·이미지 등 형식 무관). 결과는 독립된 버전 관리 바이너리 형식(JCKF v1,
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
        service.encryptFile(in, out, null, boundKeyId);
    }

    /**
     * 파일을 지정한 유형의 기본 키로 암호화한다(그 밖의 규칙은 {@link #encryptFile(Path, Path)}와 같다).
     *
     * @param in   입력 파일
     * @param out  출력 파일(없어야 한다)
     * @param type {@link KeyType#PASS} 또는 {@link KeyType#KEY}
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void encryptFile(Path in, Path out, KeyType type) throws CredentialCryptoException {
        requirePaths(in, out);
        service.encryptFile(in, out, requireType(type), boundKeyId);
    }

    /**
     * 파일을 지정한 Key ID의 키로 암호화한다(유형이 다르면 실패, 그 밖의 규칙은 {@link #encryptFile(Path, Path)}와 같다).
     *
     * @param in    입력 파일
     * @param out   출력 파일(없어야 한다)
     * @param type  기대하는 유형
     * @param keyId 등록된 Key ID
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void encryptFile(Path in, Path out, KeyType type, String keyId) throws CredentialCryptoException {
        requirePaths(in, out);
        service.encryptFile(in, out, requireType(type), requireKeyId(keyId));
    }

    /**
     * {@link #encryptFile}로 만든 파일을 복호화한다. 헤더의 Key ID로 키를 고르며, 모든 청크의 인증 태그와 마지막 청크까지 검증이
     * 끝난 경우에만 출력 파일이 나타난다. 변조·손상·잘림·다른 키는 실패하며, 이때 인증 전 평문을 담은 임시 파일은 지워진다.
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

    /** 문자열 평문을 char[]로 바꿔 암호화하고 임시 배열을 지운다(빈 값 검사는 서비스가 설정 언어로 한다). */
    private String encryptString(String plainText, KeyType type, String keyId) throws CredentialCryptoException {
        char[] chars = plainText == null ? null : plainText.toCharArray();
        try {
            return service.encryptText(chars, type, keyId);
        } finally {
            if (chars != null) Arrays.fill(chars, '\0');
        }
    }

    /** @return 이 객체의 {@code encryptText(value)}가 쓰는 키(생성 시 확인했으므로 항상 있다) */
    private KeyProfile selected() {
        return boundKeyId == null ? service.defaultProfile() : service.settings().profile(boundKeyId);
    }

    /** 직접 주는 키의 Key ID 검사(설정의 Key ID 규칙과 같다): 필수, 영문·숫자·-·_ 1~64자. */
    private static void requireDirectKeyId(String keyId) throws CredentialCryptoException {
        if (keyId == null || keyId.isEmpty()) throw directInput("api.err.keyId");
        if (!keyId.matches("[A-Za-z0-9_-]{1,64}")) throw directInput("api.err.keyIdFormat");
    }

    /** 직접 주는 키 객체의 INVALID_INPUT(라이브러리 기본 언어, 값은 넣지 않음). */
    private static CredentialCryptoException directInput(String messageKey, Object... arguments) {
        try (Messages.Scope ignored = Messages.use(CryptoService.DIRECT_LANGUAGE)) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get(messageKey, arguments));
        }
    }

    private KeyType requireType(KeyType type) throws CredentialCryptoException {
        if (type == null) throw service.invalidInput("api.err.keyType");
        return type;
    }

    private String requireKeyId(String keyId) throws CredentialCryptoException {
        if (keyId == null || keyId.isEmpty()) throw service.invalidInput("api.err.keyId");
        return keyId;
    }

    private void requirePaths(Path in, Path out) throws CredentialCryptoException {
        if (in == null || out == null) throw service.invalidInput("api.err.filePath");
    }
}
