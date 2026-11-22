package io.javacryptokit.core;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.file.FileCipher;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.Diagnostic;
import io.javacryptokit.key.KeyProvider;
import io.javacryptokit.key.KeyResolver;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 설정·키 공급·토큰 Codec·암호 엔진을 하나로 묶은 공통 서비스다.
 *
 * <p>공개 API {@code io.javacryptokit.CredentialCrypto}, CLI, Tomcat 연동 어댑터가 모두 이 클래스를 거치므로 설정 해석·키 공급·
 * 출력 형식·실패 정제·메시지 언어 규칙이 한 곳에만 존재한다(중복 구현 금지). 객체는 만든 뒤 설정이 바뀌지 않아 여러 스레드가
 * 공유해도 된다.</p>
 *
 * <p><b>키를 읽는 시점</b>: 로컬 공급원(embedded·file·env)은 호출할 때마다 읽고 사용 직후 지운다. 원격 공급원(vault·aws-kms)은
 * 이 객체에서 처음 필요할 때 한 번만 조회해 객체 안에 보관하고 재사용한다(JDBC 연결·호출마다 원격 요청을 보내지 않기 위함).
 * 조회에 실패하면 보관하지 않고 다음 호출에서 다시 시도하며, 다른 키로 바꾸지 않는다. 키·설정을 바꾸려면 객체를 새로 만든다
 * (WAS는 재시작).</p>
 *
 * <p><b>메시지 언어</b>: 모든 공개 동작은 설정 {@code crypto.lang}의 언어 범위 안에서 실행되므로, 여기서 나오는 예외·경고는
 * CLI·Java API·WAS 어디서든 같은 언어다.</p>
 *
 * <p><b>실패 정제</b>: 모든 메서드는 실패하면 {@link CredentialCryptoException}을 던진다. JDK 예외 객체와 메시지는 버리고 예외 종류만
 * 남기며(이 라이브러리의 고정 문구 제외), 평문·키·암호문·경로·토큰은 예외에 들어가지 않는다.</p>
 */
public final class CryptoService {
    /** 검증된 설정(불변). */
    private final CryptoSettings settings;
    /** 설정이 고른 키 공급원(고정 등록표에서 선택). */
    private final KeyProvider provider;
    /** 원격 공급원 키 보관 잠금. */
    private final Object keyLock = new Object();
    /** 원격 공급원에서 한 번 조회한 키(로컬 공급원은 보관하지 않음). */
    private byte[] remoteKey;

    private CryptoService(CryptoSettings settings) {
        this.settings = settings;
        try (Messages.Scope ignored = Messages.use(settings.language())) {
            this.provider = KeyResolver.provider(settings.keySource());
        }
    }

    /**
     * 설정을 읽어 서비스를 만든다.
     *
     * @param explicitConfigPath 직접 지정한 외부 설정 경로(CLI {@code --config}, 공개 API {@code fromConfigFile}).
     *                           null이면 JVM 속성 → 환경변수 → JAR 내부 설정 순서(WAS와 같은 규칙)
     * @return 서비스
     * @throws CredentialCryptoException CONFIGURATION: 외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님, 허용되지 않은 값,
     *                                   설정 경로 문제, 모호한 키 설정
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
     * 텍스트(char[])를 암호화해 설정한 출력 형식의 토큰을 만든다. 전달받은 배열은 지우지 않는다(호출자 책임).
     *
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptText(char[] plainText) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            if (plainText == null || plainText.length == 0) throw emptyInput();
            byte[] key = null;
            try {
                key = key();
                return TokenCodec.format(CredentialCipher.encryptChars(plainText, settings.keyId(), key), settings.outputFormat());
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰({@code ENC[v1:...]} 또는 {@code B64[...]})을 복호화해 텍스트로 돌려준다.
     *
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String decryptText(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                String envelope = TokenCodec.toEnvelope(token);
                // 형식·키ID 검사를 먼저 해서 잘못된 입력에는 키를 꺼내지도 않는다.
                CredentialCipher.checkEnvelope(envelope, settings.keyId());
                key = key();
                return CredentialCipher.decryptText(envelope, settings.keyId(), key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 바이트를 변환 없이 암호화한다.
     *
     * @throws CredentialCryptoException INVALID_INPUT, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public String encryptBytes(byte[] data) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            if (data == null || data.length == 0) throw emptyInput();
            byte[] key = null;
            try {
                key = key();
                return TokenCodec.format(CredentialCipher.encryptBytes(data, settings.keyId(), key), settings.outputFormat());
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰을 복호화해 원본 바이트를 돌려준다(호출자가 사용 후 지운다).
     *
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, KEY_SOURCE, CRYPTO_PROVIDER
     */
    public byte[] decryptBytes(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                String envelope = TokenCodec.toEnvelope(token);
                CredentialCipher.checkEnvelope(envelope, settings.keyId());
                key = key();
                return CredentialCipher.decryptToBytes(envelope, settings.keyId(), key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 토큰을 현재 키로 복호화할 수 있는지 확인한다. 평문은 돌려주지 않고 내부에서 바로 지운다.
     *
     * @return 복호화되면 true, 토큰 자체의 문제(형식·키ID·무결성)면 false
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
     * 토큰에 기록된 키ID를 돌려준다(형식만 검사, 키를 읽지 않음). {@code rekey}가 이전 키ID를 안내할 때 쓴다.
     *
     * @param token 토큰
     * @return 키ID
     * @throws CredentialCryptoException INVALID_TOKEN
     */
    public String keyIdOf(String token) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            return CredentialCipher.keyIdOf(TokenCodec.toEnvelope(token));
        }
    }

    /**
     * 파일을 JCKF v1 형식으로 암호화한다. 원본을 바꾸지 않고, 출력 파일이 있으면 덮어쓰지 않는다.
     *
     * @param in  입력 파일
     * @param out 출력 파일(없어야 한다)
     * @throws CredentialCryptoException INVALID_INPUT(경로·입출력), KEY_SOURCE, CRYPTO_PROVIDER
     */
    public void encryptFile(Path in, Path out) throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                FileCipher.checkPaths(in, out);
                key = key();
                FileCipher.encryptFile(in, out, settings.keyId(), key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * JCKF v1 파일을 복호화한다. 인증이 끝까지 성공한 경우에만 출력 파일이 생긴다.
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
                // 헤더의 키ID를 먼저 확인해 다른 키ID 파일에는 키를 꺼내지 않는다.
                if (!settings.keyId().equals(FileCipher.readKeyId(in))) {
                    throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
                }
                key = key();
                FileCipher.decryptFile(in, out, settings.keyId(), key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /** CLI {@code info}·{@code doctor}·{@code fingerprint}용 키 확인 결과(키 값은 들어 있지 않다). */
    public static final class KeyCheck {
        private final boolean available;
        private final boolean publicDefaultKey;
        private final String fingerprint;
        private final String failure;

        private KeyCheck(boolean available, boolean publicDefaultKey, String fingerprint, String failure) {
            this.available = available;
            this.publicDefaultKey = publicDefaultKey;
            this.fingerprint = fingerprint;
            this.failure = failure;
        }

        /** @return 키를 정상적으로 읽었으면 true */
        public boolean available() { return available; }

        /** @return 공개 기본 키와 같으면 true */
        public boolean publicDefaultKey() { return publicDefaultKey; }

        /** @return 키 지문(SHA-256 v1, 16진수 64자). 실패면 null */
        public String fingerprint() { return fingerprint; }

        /** @return 실패 사유(정제된 문구). 성공이면 null */
        public String failure() { return failure; }
    }

    /**
     * 설정된 공급원에서 키를 실제로 읽어 보고 공개 기본 키인지·지문을 확인한다. 키는 확인 직후 지운다.
     * 경고 정책과 관계없이 결과를 돌려주는 명시적 진단 기능이다.
     */
    public KeyCheck checkKey() {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                key = key();
                return new KeyCheck(true, DefaultKeyWarning.isPublicDefaultKey(key), KeyResolver.fingerprint(key), null);
            } catch (Exception e) {
                return new KeyCheck(false, false, null, translate(e).getMessage());
            } finally {
                wipe(key);
            }
        }
    }

    /**
     * 실제 적용 키의 지문을 돌려준다({@code fingerprint}·{@code rekey}). 키 원문은 돌려주지 않는다.
     *
     * @return 키 지문(SHA-256 v1, 16진수 64자)
     * @throws CredentialCryptoException 키를 읽지 못한 경우(KEY_SOURCE 등)
     */
    public String keyFingerprint() throws CredentialCryptoException {
        try (Messages.Scope ignored = scope()) {
            byte[] key = null;
            try {
                key = key();
                return KeyResolver.fingerprint(key);
            } catch (Exception e) {
                throw translate(e);
            } finally {
                wipe(key);
            }
        }
    }

    /** @return 키 위치 설명(비밀값 없음: 파일은 이름만, 환경변수·Vault·KMS는 이름·경로만) */
    public String describeKeyLocation() {
        try (Messages.Scope ignored = scope()) {
            return provider.describe(settings);
        }
    }

    /** @return 원격 공급원(vault·aws-kms)이면 true */
    public boolean remoteKeySource() {
        return provider.remote();
    }

    /** @return 네트워크 없이 확인할 수 있는 키 공급원 점검 결과({@code doctor}) */
    public List<Diagnostic> offlineKeyChecks() {
        try (Messages.Scope ignored = scope()) {
            return provider.offlineChecks(settings);
        }
    }

    /**
     * 키를 얻는다. 로컬 공급원은 매번 읽고, 원격 공급원은 처음 한 번만 조회해 보관한 키의 복사본을 준다.
     *
     * @return 32바이트 키 복사본(호출자가 지운다)
     */
    private byte[] key() throws IOException {
        if (!provider.remote()) return KeyResolver.resolve(settings);
        synchronized (keyLock) {
            if (remoteKey == null) remoteKey = KeyResolver.resolve(settings);
            return remoteKey.clone();
        }
    }

    private static void wipe(byte[] key) {
        if (key != null) Arrays.fill(key, (byte) 0);
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
