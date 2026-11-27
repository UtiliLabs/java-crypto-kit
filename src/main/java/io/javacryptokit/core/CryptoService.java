package io.javacryptokit.core;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.file.FileCipher;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.Diagnostic;
import io.javacryptokit.key.KeyResolver;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 설정·Keyring·키 공급·토큰 Codec·암호 엔진을 하나로 묶은 공통 서비스다.
 *
 * <p>공개 API {@code io.javacryptokit.CredentialCrypto}, CLI, Tomcat 연동 어댑터가 모두 이 클래스를 거치므로 설정 해석·키 선택·
 * 키 공급·출력 형식·실패 정제·메시지 언어 규칙이 한 곳에만 존재한다(중복 구현 금지). 객체는 만든 뒤 설정이 바뀌지 않아 여러 스레드가
 * 공유해도 된다.</p>
 *
 * <p><b>키 선택</b>: 새 암호화는 Key ID(유형 자동 식별) → 지정한 유형의 기본 키 → 기본 유형({@code crypto.key.type}, 기본 pass)의
 * 기본 키 순서로 고른다({@link CryptoSettings#select}). 복호화는 암호문·파일 헤더의 Key ID로 등록된 키를 고르며 유형이 필요 없다.
 * 등록되지 않은 Key ID는 다른 키로 시도하지 않고 {@code KEY_ID_MISMATCH}로 끝낸다.</p>
 *
 * <p><b>키를 읽는 시점</b>: 로컬 공급원(embedded·file·env)은 호출할 때마다 읽고 사용 직후 지운다(pass 파생 결과는 JVM 안에 한 번만
 * 계산). 원격 공급원(vault·aws-kms)은 이 객체에서 프로필마다 처음 필요할 때 한 번만 조회해 보관하고 재사용한다. 조회에 실패하면
 * 보관하지 않고 다음 호출에서 다시 시도하며, 다른 키로 바꾸지 않는다. 키·설정을 바꾸려면 객체를 새로 만든다(WAS는 재시작).</p>
 *
 * <p><b>메시지 언어</b>: 모든 공개 동작은 설정 {@code crypto.lang}의 언어 범위 안에서 실행된다.</p>
 *
 * <p><b>실패 정제</b>: 모든 메서드는 실패하면 {@link CredentialCryptoException}을 던진다. JDK 예외 객체와 메시지는 버리고 예외 종류만
 * 남기며(이 라이브러리의 고정 문구 제외), 평문·키·암호문·경로·토큰은 예외에 들어가지 않는다.</p>
 */
public final class CryptoService {
    /** 검증된 설정(불변). */
    private final CryptoSettings settings;
    /** 원격 공급원 키 보관 잠금. */
    private final Object keyLock = new Object();
    /** 원격 공급원에서 한 번 조회한 키(Key ID → 키). 로컬 공급원은 보관하지 않는다. */
    private final Map<String, byte[]> remoteKeys = new HashMap<>();
    /** 공개 API로 직접 준 키(이 객체만 보관하는 32바이트 복사본, 바꾸지 않음). 설정 기반 서비스는 null. */
    private final byte[] directKey;

    private CryptoService(CryptoSettings settings) {
        this(settings, null);
    }

    private CryptoService(CryptoSettings settings, byte[] directKey) {
        this.settings = settings;
        this.directKey = directKey;
    }

    /** 직접 준 키 객체의 메시지 언어: 라이브러리 기본값(설정·JVM 속성을 읽지 않는다). */
    public static final Messages.Language DIRECT_LANGUAGE = Messages.Language.KO;

    /**
     * 공개 API로 직접 준 키 하나로 서비스를 만든다({@code CredentialCrypto.fromRawKey}·{@code fromPassphrase}). JAR 내부 설정·외부
     * 설정 파일·JVM 속성을 읽지 않고, 키 목록·이력·공개 기본 키 경고·다른 객체와 무관하다(정적 보관소 없음, 키는 이 객체만 보관).
     * 암복호화·토큰·파일 처리는 설정 기반 서비스와 같은 코드를 쓴다.
     *
     * @param keyId Key ID(형식은 호출자가 확인)
     * @param type  유형(key: 원시 AES 키, pass: Passphrase에서 파생한 키)
     * @param key   32바이트 AES 키(복사해 보관하며 원본은 바꾸지 않는다)
     * @return 서비스
     */
    public static CryptoService direct(String keyId, KeyType type, byte[] key) {
        return new CryptoService(CryptoSettings.direct(KeyProfile.direct(keyId, type), DIRECT_LANGUAGE), key.clone());
    }

    /**
     * 설정을 읽어 서비스를 만든다.
     *
     * @param explicitConfigPath 직접 지정한 외부 설정 경로(CLI {@code --config}, 공개 API {@code fromConfigFile}).
     *                           null이면 JVM 속성 → 환경변수 → JAR 내부 설정 순서(WAS와 같은 규칙)
     * @return 서비스
     * @throws CredentialCryptoException CONFIGURATION: 외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님, 허용되지 않은 값,
     *                                   설정 경로 문제, 모호한 키 설정, 잘못된 키 프로필
     */
    public static CryptoService load(String explicitConfigPath) throws CredentialCryptoException {
        try {
            return new CryptoService(CryptoSettings.load(explicitConfigPath));
        } catch (SafeMessageException e) {
            // 이 라이브러리가 쓴 고정 문구이므로 그대로 보여 줘도 안전하다.
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, e.getMessage());
        } catch (IOException | RuntimeException e) {
            // JDK 예외 메시지에는 경로가 들어 있을 수 있으므로 예외 종류만 남긴다.
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("service.err.configRead"), e);
        }
    }

    /**
     * 이미 검증된 설정으로 서비스를 만든다(rekey의 이전·신규 설정, JAR 내부 설정 검증, 테스트).
     *
     * @param settings 검증된 설정
     * @return 서비스
     */
    public static CryptoService of(CryptoSettings settings) {
        return new CryptoService(settings);
    }

    /** @return 검증된 설정(CLI {@code info}·Tomcat 어댑터용) */
    public CryptoSettings settings() {
        return settings;
    }

    /** @return 설정 언어 범위(닫으면 이전 언어로 돌아간다) */
    private Messages.Scope scope() {
        return Messages.use(settings.language());
    }

    /**
     * 새 암호화에 쓸 키를 고른다(키 값은 읽지 않는다).
     *
     * @param type  유형(없으면 null)
     * @param keyId Key ID(없으면 null, 주면 그 키의 유형을 그대로 쓴다)
     * @return 고른 프로필
     * @throws CredentialCryptoException CONFIGURATION: 등록되지 않은 Key ID, 유형 불일치, 그 유형의 기본 키 없음
     */
    public KeyProfile select(KeyType type, String keyId) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            try {
                if (settings.profiles().isEmpty() && type == null && keyId == null) throw missingKey();
                return settings.select(type, keyId);
            } catch (SafeMessageException e) {
                throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, e.getMessage());
            }
        }
    }

    /** @return 유형·Key ID를 정하지 않은 새 암호화가 쓰는 키(해당 유형의 활성 키가 없으면 null) */
    public KeyProfile defaultProfile() {
        return settings.activeProfile(settings.defaultType());
    }

    /**
     * 설정 언어({@code crypto.lang})로 INVALID_INPUT 예외를 만든다. 공개 API가 인자를 검사할 때 쓴다(예외 문구는 만들 때의
     * 언어로 정해지므로 설정 언어 범위 안에서 만든다).
     *
     * @param messageKey 메시지 번들 키(고정 문구)
     * @return 정제된 예외
     */
    public CredentialCryptoException invalidInput(String messageKey) {
        try (Messages.Scope ignored = scope()) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get(messageKey));
        }
    }

    /**
     * 텍스트(char[])를 기본 키로 암호화한다(유형·Key ID 미지정).
     *
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText) throws CredentialCryptoException {
        return encryptText(plainText, null, null);
    }

    /**
     * 텍스트(char[])를 암호화해 설정한 출력 형식의 토큰을 만든다. 전달받은 배열은 지우지 않는다(호출자 책임).
     *
     * @param type  유형(없으면 null)
     * @param keyId Key ID(없으면 null)
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION(키 선택), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText, KeyType type, String keyId) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            if (plainText == null || plainText.length == 0) throw emptyInput();
            KeyProfile profile = select(type, keyId);
            byte[] key = null;
            try {
                key = key(profile);
                return TokenCodec.format(CredentialCipher.encryptChars(plainText, profile.id(), key), settings.outputFormat());
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})을 복호화해 텍스트로 돌려준다. 암호문의 Key ID로 키를 고른다.
     *
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String decryptText(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                String envelope = TokenCodec.toEnvelope(token);
                // 형식·Key ID 검사를 먼저 해서 잘못된 입력에는 키를 꺼내지도 않는다.
                KeyProfile profile = profileOf(envelope);
                key = key(profile);
                return CredentialCipher.decryptText(envelope, profile.id(), key);
            } catch (Exception e) {
                throw decryptFailure(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 바이트를 기본 키로 변환 없이 암호화한다.
     *
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data) throws CredentialCryptoException {
        return encryptBytes(data, null, null);
    }

    /**
     * 바이트를 변환 없이 암호화한다.
     *
     * @param type  유형(없으면 null)
     * @param keyId Key ID(없으면 null)
     * @throws CredentialCryptoException INVALID_INPUT, CONFIGURATION(키 선택), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data, KeyType type, String keyId) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            if (data == null || data.length == 0) throw emptyInput();
            KeyProfile profile = select(type, keyId);
            byte[] key = null;
            try {
                key = key(profile);
                return TokenCodec.format(CredentialCipher.encryptBytes(data, profile.id(), key), settings.outputFormat());
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰을 복호화해 원본 바이트를 돌려준다(호출자가 사용 후 지운다). 암호문의 Key ID로 키를 고른다.
     *
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public byte[] decryptBytes(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                String envelope = TokenCodec.toEnvelope(token);
                KeyProfile profile = profileOf(envelope);
                key = key(profile);
                return CredentialCipher.decryptToBytes(envelope, profile.id(), key);
            } catch (Exception e) {
                throw decryptFailure(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰을 등록된 키로 복호화할 수 있는지 확인한다. 평문은 돌려주지 않고 내부에서 바로 지운다.
     *
     * @return 복호화되면 true, 토큰 자체의 문제(형식·Key ID·무결성)면 false
     * @throws CredentialCryptoException 토큰이 아니라 환경의 문제(KEY_SOURCE, CRYPTO_PROVIDER)인 경우
     */
    public boolean verify(String token) throws CredentialCryptoException {
        byte[] plain = null;
        try {
            plain = decryptBytes(token);
            return true;
        } catch (CredentialCryptoException e) {
            if (e.getReason().isTokenProblem()) return false;
            throw e;
        } finally {
            if (plain != null) Arrays.fill(plain, (byte) 0);
        }
    }

    /**
     * 토큰에 기록된 Key ID를 돌려준다(형식만 검사, 키를 읽지 않음).
     *
     * @param token 토큰
     * @return Key ID
     * @throws CredentialCryptoException INVALID_TOKEN
     */
    public String keyIdOf(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            return CredentialCipher.keyIdOf(TokenCodec.toEnvelope(token));
        }
    }

    /** 파일을 기본 키로 JCKF v2 형식으로 암호화한다. */
    public void encryptFile(Path in, Path out) throws CredentialCryptoException {
        encryptFile(in, out, null, null);
    }

    /**
     * 파일을 JCKF v2 형식으로 암호화한다. 원본을 바꾸지 않고, 출력 파일이 있으면 덮어쓰지 않는다.
     *
     * @param in    입력 파일
     * @param out   출력 파일(없어야 한다)
     * @param type  유형(없으면 null)
     * @param keyId Key ID(없으면 null)
     * @throws CredentialCryptoException INVALID_INPUT(경로·입출력), CONFIGURATION(키 선택), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void encryptFile(Path in, Path out, KeyType type, String keyId) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            KeyProfile profile = select(type, keyId);
            byte[] key = null;
            try {
                FileCipher.checkPaths(in, out);
                key = key(profile);
                FileCipher.encryptFile(in, out, profile.id(), key);
            } catch (Exception e) {
                throw fileFailure(e, false);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * JCKF v1 또는 v2 파일을 복호화한다. 헤더의 Key ID로 키를 고르며, 인증이 끝까지 성공한 경우에만 출력 파일이 생긴다.
     *
     * @param in  암호화 파일
     * @param out 출력 파일(없어야 한다)
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void decryptFile(Path in, Path out) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                FileCipher.checkPaths(in, out);
                // 헤더의 Key ID를 먼저 확인해 등록되지 않은 Key ID 파일에는 키를 꺼내지 않는다.
                String id = FileCipher.readKeyId(in);
                if (settings.profiles().isEmpty()) throw missingKey();
                KeyProfile profile = settings.profile(id);
                if (profile == null) {
                    throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
                }
                key = key(profile);
                FileCipher.decryptFile(in, out, profile.id(), key);
            } catch (Exception e) {
                throw fileFailure(e, true);
            } finally {
                wipe(key);
            }
        }
    }

    /** CLI {@code info}·{@code doctor}·{@code fingerprint}·공개 API {@code keys()}용 키 확인 결과(키 값은 들어 있지 않다). */
    public static final class KeyCheck {
        private final KeyProfile profile;
        private final boolean available;
        private final boolean publicDefaultKey;
        private final String fingerprint;
        private final CredentialCryptoException failure;

        private KeyCheck(KeyProfile profile, boolean available, boolean publicDefaultKey, String fingerprint,
                         CredentialCryptoException failure) {
            this.profile = profile;
            this.available = available;
            this.publicDefaultKey = publicDefaultKey;
            this.fingerprint = fingerprint;
            this.failure = failure;
        }

        /** @return 확인한 키 프로필 */
        public KeyProfile profile() { return profile; }

        /** @return 키를 정상적으로 읽었으면 true */
        public boolean available() { return available; }

        /** @return 공개 기본 키와 같으면 true */
        public boolean publicDefaultKey() { return publicDefaultKey; }

        /** @return 키 지문(SHA-256 v1, 16진수 64자). 실패면 null */
        public String fingerprint() { return fingerprint; }

        /** @return 실패 사유(정제된 문구: 원인 + 조치). 성공이면 null */
        public String failure() { return failure == null ? null : failure.getMessage(); }

        /** @return 실패 사유 코드(공개 API Reason). 성공이면 null */
        public CredentialCryptoException.Reason failureReason() { return failure == null ? null : failure.getReason(); }

        /**
         * @return 실패를 알린 정제된 예외 그대로(성공이면 null). 다시 감싸지 않고 던지면 원인·조치가 한 번만 나온다.
         */
        public CredentialCryptoException failureException() { return failure; }
    }

    /** 기본 키(유형·Key ID 미지정 새 암호화가 쓰는 키)를 확인한다. */
    public KeyCheck checkKey() {
        return checkKey(defaultProfile());
    }

    /**
     * 프로필의 키를 실제로 읽어 보고 공개 기본 키인지·지문을 확인한다. 키는 확인 직후 지운다.
     * 경고 정책과 관계없이 결과를 돌려주는 명시적 진단 기능이다.
     *
     * @param profile 확인할 프로필
     * @return 확인 결과
     */
    public KeyCheck checkKey(KeyProfile profile) {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                key = key(profile);
                return new KeyCheck(profile, true, DefaultKeyWarning.isPublicDefaultKey(key), KeyResolver.fingerprint(key), null);
            } catch (Exception e) {
                return new KeyCheck(profile, false, false, null, translate(e));
            } finally {
                wipe(key);
            }
        }
    }

    /** @return 등록된 모든 키의 확인 결과(레거시 AES 슬롯이 먼저, 그다음 Key ID 순서) */
    public List<KeyCheck> checkKeys() {
        List<KeyCheck> checks = new ArrayList<>();
        for (KeyProfile profile : settings.profiles()) checks.add(checkKey(profile));
        return Collections.unmodifiableList(checks);
    }

    /**
     * 기본 키의 지문을 돌려준다. 키 원문은 돌려주지 않는다.
     *
     * @return 키 지문(SHA-256 v1, 16진수 64자)
     * @throws CredentialCryptoException 키를 읽지 못한 경우(KEY_SOURCE 등)
     */
    public String keyFingerprint() throws CredentialCryptoException {
        return keyFingerprint(defaultProfile());
    }

    /**
     * 프로필의 키 지문을 돌려준다({@code fingerprint}·{@code rekey}). 키 원문은 돌려주지 않는다.
     *
     * @throws CredentialCryptoException 키를 읽지 못한 경우(KEY_SOURCE 등)
     */
    public String keyFingerprint(KeyProfile profile) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                key = key(profile);
                return KeyResolver.fingerprint(key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /** @return 기본 키의 위치 설명 */
    public String describeKeyLocation() {
        return describeKeyLocation(defaultProfile());
    }

    /** @return 프로필의 키 위치 설명(비밀값 없음: 파일은 이름만, 환경변수·Vault·KMS는 이름·경로만) */
    public String describeKeyLocation(KeyProfile profile) {
        try (Messages.Scope ignored = scope()) {
            if (profile == null) return Messages.get("key.err.unconfigured");
            return KeyResolver.provider(profile.source()).describe(settings, profile);
        }
    }

    /** @return 기본 키가 원격 공급원(vault·aws-kms)이면 true */
    public boolean remoteKeySource() {
        return remoteKeySource(defaultProfile());
    }

    /** @return 프로필이 원격 공급원(vault·aws-kms)이면 true */
    public boolean remoteKeySource(KeyProfile profile) {
        return profile != null && KeyResolver.provider(profile.source()).remote();
    }

    /** @return 기본 키의 네트워크 없는 공급원 점검 결과({@code doctor}) */
    public List<Diagnostic> offlineKeyChecks() {
        return offlineKeyChecks(defaultProfile());
    }

    /** @return 프로필의 네트워크 없는 공급원 점검 결과({@code doctor}) */
    public List<Diagnostic> offlineKeyChecks(KeyProfile profile) {
        try (Messages.Scope ignored = scope()) {
            if (profile == null) return Collections.singletonList(Diagnostic.fail(Messages.get("key.err.unconfigured"), null));
            return KeyResolver.provider(profile.source()).offlineChecks(settings, profile);
        }
    }

    /** 봉투의 형식을 검사하고 Key ID로 등록된 프로필을 찾는다(없으면 KEY_ID_MISMATCH, 다른 키로 시도하지 않음). */
    private KeyProfile profileOf(String envelope) throws CredentialCryptoException {
        String id = CredentialCipher.keyIdOf(envelope);
        if (settings.profiles().isEmpty()) throw missingKey();
        KeyProfile profile = settings.profile(id);
        if (profile == null) throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
        CredentialCipher.checkEnvelope(envelope, profile.id());
        return profile;
    }

    /**
     * 프로필의 키를 얻는다. 로컬 공급원은 매번 읽고, 원격 공급원은 프로필마다 처음 한 번만 조회해 보관한 키의 복사본을 준다.
     *
     * @return 32바이트 키 복사본(호출자가 지운다)
     */
    private byte[] key(KeyProfile profile) throws IOException {
        // 직접 준 키: 설정·공급원을 거치지 않고 이 객체의 복사본을 준다(그 키 하나만 등록되어 있으므로 다른 키는 오지 않음).
        if (profile == null) throw new SafeMessageException(Messages.get("key.err.unconfigured"));
        if (directKey != null) return directKey.clone();
        if (!KeyResolver.provider(profile.source()).remote()) return KeyResolver.resolve(settings, profile);
        synchronized (keyLock) {
            byte[] cached = remoteKeys.get(profile.id());
            if (cached == null) {
                cached = KeyResolver.resolve(settings, profile);
                remoteKeys.put(profile.id(), cached);
            }
            return cached.clone();
        }
    }

    private static CredentialCryptoException missingKey() {
        return new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, Messages.get("key.err.unconfigured"));
    }

    private static void wipe(byte[] key) {
        if (key != null) Arrays.fill(key, (byte) 0);
    }

    /**
     * 복호화 실패를 정제한다. 직접 준 키 객체는 사유 코드는 그대로 두고 확인할 값(그 Key ID, 키·Passphrase·Salt·반복 횟수)을
     * 덧붙인다(다른 키로 바꿔 시도하지 않음). 설정 기반 서비스는 {@link #translate}와 같다.
     */
    private CredentialCryptoException decryptFailure(Exception e) {
        CredentialCryptoException failure = translate(e);
        if (directKey == null) return failure;
        if (failure.getReason() == CredentialCryptoException.Reason.INTEGRITY) {
            return new CredentialCryptoException(failure.getReason(), Messages.get("service.direct.integrity"));
        }
        if (failure.getReason() == CredentialCryptoException.Reason.KEY_ID_MISMATCH) {
            return new CredentialCryptoException(failure.getReason(),
                    Messages.get("service.direct.keyId", settings.profiles().get(0).id()));
        }
        return failure;
    }

    /** 파일 작업의 최초 오류와 정제된 추가 정리 오류를 함께 전달한다. */
    private CredentialCryptoException fileFailure(Exception original, boolean decrypt) {
        // 정리 오류가 겹쳤을 때는 직접 키 안내로 최초 파일 오류를 바꾸지 않는다.
        if (original instanceof CredentialCryptoException && original.getSuppressed().length != 0) {
            return (CredentialCryptoException) original;
        }
        CredentialCryptoException result = decrypt ? decryptFailure(original) : translate(original);
        if (result != original) {
            for (Throwable additional : original.getSuppressed()) {
                if (additional instanceof CredentialCryptoException) result.addSuppressed(additional);
            }
        }
        return result;
    }

    /** 빈 입력 예외. */
    private static CredentialCryptoException emptyInput() {
        return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get("service.err.empty"));
    }

    /**
     * 내부 예외를 정제된 공개 예외로 바꾼다. 원래 예외 객체·메시지는 버리고 종류만 남긴다(이 라이브러리의 고정 문구 제외).
     *
     * @param e 내부에서 발생한 예외
     * @return 정제된 예외
     */
    static CredentialCryptoException translate(Exception e) {
        if (e instanceof CredentialCryptoException) return (CredentialCryptoException) e;
        if (e instanceof SafeMessageException) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        }
        if (e instanceof CharacterCodingException) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                    Messages.get("cipher.err.notEncodable"));
        }
        if (e instanceof IOException || e instanceof IllegalArgumentException) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, Messages.get("service.err.keyRead"), e);
        }
        return new CredentialCryptoException(CredentialCryptoException.Reason.CRYPTO_PROVIDER, null, e);
    }
}
