package io.javacryptokit.key;

import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.LightObfuscation;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.aws.AwsKmsKeyProvider;
import io.javacryptokit.key.vault.VaultKeyProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 설정된 키 공급원({@link KeyProvider})에서 AES-256 키(정확히 32바이트)를 읽어 오는
 * 키 관리 진입점이다. CLI, 공개 Java API, Tomcat 연동 어댑터가 같은 방식으로 키를 읽으므로 같은 설정을 쓰면 암호화(CLI)와
 * 복호화(WAS)에 같은 키와 키ID가 사용된다.
 *
 * <p><b>지원하는 키 공급원</b>({@code crypto.key.source}, 같은 JAR에서 설정으로 선택. 아래 고정 등록표 외의 공급원은 없다)</p>
 * <ul>
 *   <li>{@code embedded}: JAR 안 {@code crypto.key.embedded}. 별도 준비 없이 동작하지만 JAR을 가진 누구나 키를 꺼낼 수 있다
 *       (JAR 안에는 경량 난독화 obf1 표현으로 저장하지만 이것은 단순 열람 방지일 뿐 추출 방지가 아니다).</li>
 *   <li>{@code file}: {@code crypto.key.file} 파일 안의 표준 Base64 한 줄({@code keygen} 출력 형식).</li>
 *   <li>{@code env}: {@code crypto.key.env}가 가리키는 환경변수의 표준 Base64 값.</li>
 *   <li>{@code vault}: HashiCorp Vault KV v2 Secret의 필드(JDK 표준 HTTPS만 사용, 추가 의존성 없음).</li>
 *   <li>{@code aws-kms}: AWS KMS로 보호한 데이터 키(Envelope Encryption). AWS SDK 2.x JAR를 따로 설치해야 하며 이 공급원을
 *       고를 때만 필요하다.</li>
 * </ul>
 *
 * <p><b>보안 원칙</b></p>
 * <ul>
 *   <li>JVM 시스템 속성({@code -D})이나 CLI 인자로 키 값을 받지 않는다(프로세스 목록·셸 기록 노출 방지).</li>
 *   <li>키를 읽지 못하면 예외로 끝낸다. 내장 키 등 다른 키로 자동 전환(fallback)하지 않는다(원격 장애 포함).</li>
 *   <li>예외 메시지에 키 값, 환경변수 값, 파일 내용, 토큰을 넣지 않는다.</li>
 *   <li>반환한 키 배열은 호출자가 사용 직후 0으로 지운다. 다만 Base64 원문은 String이라 지울 수 없다(Java 한계).</li>
 * </ul>
 */
public final class KeyResolver {
    /** 키 지문 계산에 붙이는 고정 구분 문자열(다른 용도의 SHA-256 값과 섞이지 않게 한다). */
    private static final byte[] FINGERPRINT_LABEL = "java-crypto-kit/key-fingerprint/v1\0".getBytes(StandardCharsets.US_ASCII);
    /** 명시적으로 허용한 공급원 등록표(이름 → 구현). 순서는 {@link SettingCatalog#KEY_SOURCES}와 같다. */
    private static final Map<String, KeyProvider> PROVIDERS;

    static {
        Map<String, KeyProvider> providers = new LinkedHashMap<>();
        register(providers, new LocalKeyProviders.Embedded());
        register(providers, new LocalKeyProviders.File());
        register(providers, new LocalKeyProviders.Env());
        register(providers, new VaultKeyProvider());
        // AwsKmsKeyProvider는 AWS SDK 클래스를 필드·메서드 형식에 쓰지 않으므로, SDK가 없어도 등록표 생성에는 영향이 없다.
        register(providers, new AwsKmsKeyProvider());
        PROVIDERS = Collections.unmodifiableMap(providers);
    }

    private KeyResolver() { }

    private static void register(Map<String, KeyProvider> providers, KeyProvider provider) {
        providers.put(provider.source(), provider);
    }

    /** @return 등록된 공급원 이름(설정 허용값과 같아야 한다. 테스트가 검사) */
    public static Set<String> sources() {
        return PROVIDERS.keySet();
    }

    /**
     * @param source 공급원 이름({@code crypto.key.source})
     * @return 공급원 구현
     * @throws IllegalArgumentException 등록되지 않은 이름({@link SafeMessageException})
     */
    public static KeyProvider provider(String source) {
        KeyProvider provider = PROVIDERS.get(source);
        if (provider == null) {
            // CryptoSettings에서 이미 검증하지만, 검증 누락에 대비해 알 수 없는 값은 다시 거부한다.
            throw new SafeMessageException(Messages.get("config.err.choice." + CryptoSettings.KEY_SOURCE));
        }
        return provider;
    }

    /**
     * 프로필의 공급원에서 재료를 읽어 32바이트 키로 만든다. key 유형은 Base64 키, pass 유형은 Passphrase 파생(내장·KMS는 등록 때
     * 파생한 키를 저장). 외부 공급 키는 등록할 때 고정한 지문과 같아야 쓴다(외부 비밀값이 바뀌면 같은 Key ID로 조용히 받지 않음).
     * 공개 기본 키이면 경고 정책에 따라 한 줄 경고를 남길 수 있다({@link DefaultKeyWarning}, 공급 방식과 무관, JVM당 1회).
     *
     * @param settings 검증된 설정(공통 연결 정보·경고 정책)
     * @param profile  키 프로필
     * @return 32바이트 원시 키. 호출자가 반드시 사용 후 {@code Arrays.fill(key, (byte) 0)}으로 지워야 한다.
     * @throws IOException              파일이 없거나(NoSuchFileException) 읽을 권한이 없거나, 원격 공급원 통신 실패
     * @throws IllegalArgumentException 설정·형식 오류, 32바이트가 아닌 키, 지문 불일치({@link SafeMessageException})
     */
    public static byte[] resolve(CryptoSettings settings, KeyProfile profile) throws IOException {
        KeyProvider provider = provider(profile.source());
        byte[] material = provider.loadMaterial(settings, profile);
        byte[] key;
        try {
            key = materialToKey(profile, material, provider.textMaterial());
        } finally {
            Arrays.fill(material, (byte) 0);
        }
        // AES-128/192 키로 낮추는 다운그레이드를 막기 위해 공급원과 관계없이 정확히 32바이트만 허용한다.
        if (key == null || key.length != 32) {
            if (key != null) Arrays.fill(key, (byte) 0);
            throw new SafeMessageException(Messages.get("key.err.length"));
        }
        String pin = profile.pinnedFingerprint();
        if (pin != null && !MessageDigest.isEqual(pin.getBytes(StandardCharsets.US_ASCII),
                fingerprint(key).getBytes(StandardCharsets.US_ASCII))) {
            Arrays.fill(key, (byte) 0);
            throw new SafeMessageException(Messages.get("key.err.pinMismatch", profile.id()));
        }
        // 공개 기본 키 여부는 공급 방식과 관계없이 키 값으로 확인하고, 실제 출력은 경고 정책(crypto.warning.enabled)을 따른다.
        DefaultKeyWarning.warnIfNeeded(settings, key);
        return key;
    }

    /**
     * 레거시 AES 슬롯({@code crypto.key.*})의 키를 읽는다(이전 형식와 같은 의미: "crypto.key.source가 가리키는 키").
     *
     * @param settings 검증된 설정
     * @return 32바이트 키(호출자가 지운다)
     * @throws IOException {@link #resolve(CryptoSettings, KeyProfile)}와 같다
     */
    public static byte[] resolve(CryptoSettings settings) throws IOException {
        return resolve(settings, settings.legacyProfile());
    }

    /**
     * 등록 전 임시 프로필({@link KeyProfile#probe})의 공급원을 한 번 읽어 32바이트 키를 만든다. 지문 고정 검사와 공개 기본 키 자동
     * 경고를 하지 않는다(등록 명령이 결과 키를 직접 확인한다).
     *
     * @param settings 공급원 연결 설정(Vault 주소·토큰, AWS 지역 등)
     * @param probe    임시 프로필
     * @return 32바이트 키(호출자가 지운다)
     * @throws IOException              공급원을 읽지 못한 경우
     * @throws IllegalArgumentException 재료 형식이 올바르지 않은 경우({@link SafeMessageException} 포함)
     */
    public static byte[] probeKey(CryptoSettings settings, KeyProfile probe) throws IOException {
        KeyProvider provider = provider(probe.source());
        byte[] material = provider.loadMaterial(settings, probe);
        byte[] key;
        try {
            key = materialToKey(probe, material, provider.textMaterial());
        } finally {
            Arrays.fill(material, (byte) 0);
        }
        if (key == null || key.length != 32) {
            if (key != null) Arrays.fill(key, (byte) 0);
            throw new SafeMessageException(Messages.get("key.err.length"));
        }
        return key;
    }

    /**
     * 공급원 재료를 프로필 유형에 맞게 32바이트 키로 바꾼다({@code config key add}가 등록 전 지문을 계산할 때도 같은 규칙을 쓴다).
     *
     * @param profile  키 프로필(유형·공급원·KDF 메타데이터)
     * @param material 재료(바꾸지 않는다)
     * @param text     재료가 문자열의 UTF-8 바이트면 true(file·env·vault), 32바이트 키면 false
     * @return 32바이트 키(호출자가 지운다)
     */
    public static byte[] materialToKey(KeyProfile profile, byte[] material, boolean text) {
        if (!text) return material.clone();
        if (profile.type() == KeyType.KEY) return decodeKey(new String(material, StandardCharsets.UTF_8));
        char[] chars = PassKdf.decodeUtf8(material, "file".equals(profile.source()));
        char[] normalized = null;
        try {
            normalized = PassKdf.normalize(chars);
            return PassKdf.deriveCached(profile.id(), normalized, profile.salt(), profile.iterations());
        } finally {
            Arrays.fill(chars, '\0');
            if (normalized != null) Arrays.fill(normalized, '\0');
        }
    }

    /**
     * 키 파일({@code keygen} 형식: 표준 Base64 한 줄)을 읽어 32바이트 AES-256 키로 검증해 돌려준다. {@code config embed-key},
     * {@code fingerprint --key-file}, {@code kms datakey --from-file}이 {@code file} 공급원과 같은 규칙을 쓰도록 공유한다.
     *
     * @param keyPath 키 파일 경로
     * @param label   오류 메시지에 쓸 이름(예: {@code --from-file})
     * @return 32바이트 키. 호출자가 사용 후 반드시 지운다.
     * @throws IOException              파일이 없거나 읽을 권한이 없는 경우
     * @throws IllegalArgumentException 일반 파일이 아니거나, 512바이트 초과, Base64 형식 오류, 32바이트가 아닌 경우
     */
    public static byte[] readKeyFile(Path keyPath, String label) throws IOException {
        return decodeKey(SecretFiles.readText(keyPath, LocalKeyProviders.MAX_KEY_FILE_BYTES, label));
    }

    /**
     * 내장 키 값({@code crypto.key.embedded}·{@code crypto.keys.<id>.embedded})을 32바이트 키로 바꾼다. JAR 내부 저장 표현(obf1,
     * 경량 난독화)과 표준 Base64(구형 JAR·외부 Properties)를 모두 받는다. 외부 공급원(키 파일·환경변수·Vault)의 값은
     * {@link #decodeKey}로 읽는다(표준 Base64만, obf1은 JAR 내부 표현이라 받지 않음).
     *
     * @param encoded {@code obf1:...} 또는 표준 Base64(앞뒤 공백 허용)
     * @return 32바이트 키. 호출자가 사용 후 반드시 지운다.
     * @throws IllegalArgumentException 손상되었거나 모르는 obf 표현, Base64 형식 오류, 32바이트가 아닌 경우
     */
    public static byte[] decodeEmbedded(String encoded) {
        String text = encoded == null ? "" : encoded.trim();
        if (!LightObfuscation.isEncoded(text)) return decodeKey(text);
        byte[] key = LightObfuscation.decode(text);
        if (key.length != 32) {
            Arrays.fill(key, (byte) 0);
            throw new SafeMessageException(Messages.get("key.err.length"));
        }
        return key;
    }

    /**
     * 표준 Base64 문자열(keygen 키 파일 한 줄·환경변수·Vault 값)을 32바이트 AES-256 키로 바꾼다. 형식·길이가 틀리면 키 일부가
     * 메시지에 섞이지 않도록 고정 문구로 거부한다.
     *
     * @param encoded 표준 Base64 문자열(앞뒤 공백 허용)
     * @return 32바이트 키. 호출자가 사용 후 반드시 지운다.
     * @throws IllegalArgumentException Base64 형식 오류이거나 32바이트가 아닌 경우
     */
    public static byte[] decodeKey(String encoded) {
        String text = encoded == null ? "" : encoded.trim();
        byte[] key;
        try {
            // keygen과 같은 표준 Base64(+, /)를 사용한다. 암호문 봉투의 Base64URL과는 다르다.
            key = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            // 디코더 메시지에는 문제 문자의 코드값(= 키 일부)이 들어갈 수 있으므로 원래 메시지를 버린다.
            throw new SafeMessageException(Messages.get("key.err.base64"));
        }
        if (key.length != 32) {
            // 잘못된 길이라도 키 재료이므로 버리기 전에 지운다.
            Arrays.fill(key, (byte) 0);
            throw new SafeMessageException(Messages.get("key.err.length"));
        }
        return key;
    }

    /**
     * JAR 내부 설정에 저장할 내장 키 표현(obf1)을 만든다. 경량 난독화(단순 열람 방지)이며 암호화가 아니다.
     *
     * @param key 32바이트 키(바꾸지 않는다)
     * @return {@code obf1:...}
     */
    public static String encodeEmbedded(byte[] key) {
        if (key == null || key.length != 32) throw new SafeMessageException(Messages.get("key.err.length"));
        return LightObfuscation.encode(key);
    }

    /**
     * 키 지문(fingerprint): 키 원문을 보이지 않고 "같은 키인지"만 비교하기 위한 식별값이다.
     * {@code SHA-256("java-crypto-kit/key-fingerprint/v1" || 0x00 || 키)}의 16진수 64자이며 OS와 관계없이 같다.
     * 충분히 무작위적인 256비트 키에서만 의미가 있고, 사용자 인증·키 소유 증명·비밀 보호 수단이 아니다.
     *
     * @param key 32바이트 키(바꾸거나 보관하지 않는다)
     * @return 소문자 16진수 64자
     */
    public static String fingerprint(byte[] key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(FINGERPRINT_LABEL);
            byte[] hash = digest.digest(key);
            StringBuilder hex = new StringBuilder(64);
            for (byte b : hash) hex.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

    /**
     * 일반 조회 화면({@code info}·{@code config show})용 짧은 키 지문: 64자 지문의 앞 12자 + {@code ...} + 뒤 8자
     * (예: {@code ab12cd34ef56...7890abcd}). 키 원문이 아니라 지문의 일부다. 정확히 비교할 때는 {@code fingerprint} 명령의
     * 64자 전체를 쓴다. 지문 계산 방식·길이는 바꾸지 않고 표시만 줄인다.
     *
     * @param fingerprint {@link #fingerprint(byte[])}가 만든 소문자 16진수 64자
     * @return 축약한 지문(23자)
     * @throws IllegalStateException 64자 소문자 16진수가 아닌 경우(다른 값을 조용히 만들지 않는다)
     */
    public static String shortFingerprint(String fingerprint) {
        if (fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) throw new IllegalStateException("fingerprint");
        return fingerprint.substring(0, 12) + "..." + fingerprint.substring(56);
    }
}
