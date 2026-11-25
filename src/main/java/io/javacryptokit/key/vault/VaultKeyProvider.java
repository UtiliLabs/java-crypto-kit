package io.javacryptokit.key.vault;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.json.StrictJson;
import io.javacryptokit.key.Diagnostic;
import io.javacryptokit.key.KeyProvider;
import io.javacryptokit.key.SecretFiles;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: HashiCorp Vault <b>KV v2</b> Secret의 필드 값을 키 재료로 읽는 키 공급원
 * ({@code source=vault})이다. key 유형은 표준 Base64 AES-256 키, pass 유형은 Passphrase를 필드에 둔다. 연결 정보(주소·마운트·토큰·CA·
 * 제한 시간)는 공통 설정 {@code crypto.vault.*}, Secret 경로·필드·버전은 키 프로필마다 정한다(레거시 슬롯은 {@code crypto.vault.path}
 * 등 기존 이름). JDK 표준 {@link HttpsURLConnection}만 사용하므로 추가 의존성이 없다.
 * (Vault Transit처럼 Vault 안에서 암복호화하는 방식은 별개 기능이며 구현하지 않았다.)
 *
 * <p><b>요청</b>: {@code GET <crypto.vault.url>/v1/<crypto.vault.mount>/data/<crypto.vault.path>[?version=<crypto.vault.ver>]},
 * 헤더 {@code X-Vault-Token}. 응답의 {@code data.data.<crypto.vault.field>} 값을 키로 쓴다. {@code crypto.vault.ver}를 비우면 최신
 * 버전을 읽는다(새 버전이 쓰이면 다음 재시작부터 다른 키가 적용되므로 운영에서는 버전 고정을 권장한다).</p>
 *
 * <p><b>보안 판단</b></p>
 * <ul>
 *   <li>토큰은 설정에 두지 않는다: 토큰 파일({@code crypto.vault.token.file}, 지정하면 우선) 또는 환경변수
 *       ({@code crypto.vault.token.env}, 기본 {@code VAULT_TOKEN})에서 읽는다. 토큰·키는 로그·예외에 넣지 않는다.</li>
 *   <li>HTTPS만 사용하고 인증서·서버 이름 검증을 끌 수 없다. 사설 CA는 {@code crypto.vault.ca.file}(PEM)로 지정하며, 지정하면
 *       그 CA만 신뢰한다(JVM 전체 신뢰 저장소를 바꾸지 않음).</li>
 *   <li>리다이렉트를 따르지 않는다(토큰 헤더가 다른 서버로 전달되는 것을 막음).</li>
 *   <li>일시 장애(연결 실패·시간 초과·HTTP 429/500/502/503/504)만 최대 3회까지(대기 0.5초·1초) 다시 시도한다. TLS 오류·
 *       인증·권한·Secret 없음은 다시 시도하지 않는다. 한 시도의 연결·응답 대기는 각각 {@code crypto.vault.timeout.ms}를 넘지 않는다.</li>
 *   <li>403이면 {@code auth/token/lookup-self}로 토큰 자체가 유효한지 확인해 "인증 실패(토큰 만료·폐기)"와 "권한 부족(정책)"을
 *       구분해 알린다.</li>
 *   <li>실패하면 다른 키(내장 키 등)로 바꾸지 않는다(Fail Closed). WAS에서는 DataSource 생성이 실패하므로 원인을 고친 뒤
 *       WAS를 다시 시작한다.</li>
 * </ul>
 * <p>키는 {@code CryptoService} 인스턴스마다 처음 한 번 조회해 재사용하므로 JDBC 연결마다 Vault에 요청하지 않는다.</p>
 */
public final class VaultKeyProvider implements KeyProvider {
    /** 응답 최대 크기(바이트). */
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    /** 토큰 파일 최대 크기(바이트). */
    private static final int MAX_TOKEN_FILE_BYTES = 8192;
    /** CA 파일 최대 크기(바이트). */
    private static final int MAX_CA_FILE_BYTES = 1024 * 1024;
    /** 일시 장애 시 최대 시도 횟수. */
    static final int MAX_ATTEMPTS = 3;
    /** 기본 제한 시간(설정 항목이 없는 이전 설정 대비). */
    private static final int DEFAULT_TIMEOUT_MS = 5000;

    @Override
    public String source() {
        return "vault";
    }

    @Override
    public boolean remote() {
        return true;
    }

    @Override
    public String describe(CryptoSettings settings, KeyProfile profile) {
        String version = profile.value(KeyProfile.VAULT_VER);
        return Messages.get("key.describe.vault", settings.get(CryptoSettings.VAULT_MOUNT),
                profile.value(KeyProfile.VAULT_PATH), field(settings, profile),
                version.isEmpty() ? Messages.get("key.vault.latest") : version, tokenSourceDescription(settings));
    }

    /** 프로필의 필드 이름. 템플릿 프로필이 비워 두면 공통 {@code crypto.vault.field}를 쓴다. */
    private static String field(CryptoSettings settings, KeyProfile profile) {
        String field = profile.value(KeyProfile.VAULT_FIELD);
        return field.isEmpty() ? settings.get(CryptoSettings.VAULT_FIELD) : field;
    }

    /** 필수 설정이 비어 있으면 그 설정 이름, 모두 있으면 null. */
    private static String missingSetting(CryptoSettings settings, KeyProfile profile) {
        if (settings.get(CryptoSettings.VAULT_URL).isEmpty()) return CryptoSettings.VAULT_URL;
        if (settings.get(CryptoSettings.VAULT_MOUNT).isEmpty()) return CryptoSettings.VAULT_MOUNT;
        if (profile.value(KeyProfile.VAULT_PATH).isEmpty()) return profile.settingName(KeyProfile.VAULT_PATH);
        if (field(settings, profile).isEmpty()) return profile.settingName(KeyProfile.VAULT_FIELD);
        return null;
    }

    /** 토큰 공급 방법 설명(파일은 이름만, 환경변수는 이름만). */
    private static String tokenSourceDescription(CryptoSettings settings) {
        String file = settings.get(CryptoSettings.VAULT_TOKEN_FILE);
        return file.isEmpty() ? Messages.get("key.vault.tokenFromEnv", settings.get(CryptoSettings.VAULT_TOKEN_ENV))
                : Messages.get("key.vault.tokenFromFile", SecretFiles.fileName(file));
    }

    @Override
    public List<Diagnostic> offlineChecks(CryptoSettings settings, KeyProfile profile) {
        List<Diagnostic> results = new ArrayList<>();
        String missing = missingSetting(settings, profile);
        if (missing != null) {
            results.add(Diagnostic.fail(Messages.get("config.err.required", "vault", missing),
                    Messages.get("key.action.vaultSettings")));
        }
        String file = settings.get(CryptoSettings.VAULT_TOKEN_FILE);
        if (!file.isEmpty()) {
            results.addAll(SecretFiles.check(CryptoSettings.VAULT_TOKEN_FILE, file));
        } else {
            String env = settings.get(CryptoSettings.VAULT_TOKEN_ENV);
            String value = env.isEmpty() ? null : System.getenv(env);
            if (env.isEmpty()) {
                results.add(Diagnostic.fail(Messages.get("config.err.vaultToken"), Messages.get("key.action.vaultSettings")));
            } else if (value == null || value.trim().isEmpty()) {
                results.add(Diagnostic.fail(Messages.get("key.vault.err.tokenEnvMissing", env),
                        Messages.get("key.action.envExport", env)));
            } else {
                results.add(Diagnostic.pass(Messages.get("key.check.vaultTokenEnv", env)));
            }
        }
        String ca = settings.get(CryptoSettings.VAULT_CA_FILE);
        if (!ca.isEmpty()) {
            results.addAll(SecretFiles.check(CryptoSettings.VAULT_CA_FILE, ca));
        } else {
            results.add(Diagnostic.info(Messages.get("key.check.vaultDefaultTrust")));
        }
        // 읽을 Secret 버전(crypto.vault.ver)은 키 위치 설명에 사실로만 표시한다(버전 고정 여부는 운영 판단).
        return results;
    }

    @Override
    public boolean textMaterial() {
        return true;
    }

    @Override
    public byte[] loadMaterial(CryptoSettings settings, KeyProfile profile) throws IOException {
        String missing = missingSetting(settings, profile);
        if (missing != null) throw new SafeMessageException(Messages.get("config.err.required", "vault", missing));
        String token = readToken(settings);
        SSLSocketFactory tls = tlsFactory(settings);
        int timeout = settings.intValue(CryptoSettings.VAULT_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
        String base = stripSlash(settings.get(CryptoSettings.VAULT_URL));
        String version = profile.value(KeyProfile.VAULT_VER);
        String url = base + "/v1/" + settings.get(CryptoSettings.VAULT_MOUNT) + "/data/" + profile.value(KeyProfile.VAULT_PATH)
                + (version.isEmpty() ? "" : "?version=" + version);

        Reply reply = getWithRetry(url, token, tls, timeout);
        if (reply.status == 403 || reply.status == 401) {
            // 토큰 자체가 유효한지 확인해 인증 실패와 권한 부족을 구분한다(lookup-self는 기본 정책에서 허용된다).
            Reply self = getWithRetry(base + "/v1/auth/token/lookup-self", token, tls, timeout);
            throw new SafeMessageException(Messages.get(self.status == 200 ? "key.vault.err.permission" : "key.vault.err.auth"));
        }
        if (reply.status == 404) throw new SafeMessageException(Messages.get("key.vault.err.notFound"));
        if (reply.status >= 300 && reply.status < 400) throw new SafeMessageException(Messages.get("key.vault.err.redirect"));
        if (reply.status == 400) throw new SafeMessageException(Messages.get("key.vault.err.notFound"));
        if (retryable(reply.status)) {
            throw new SafeMessageException(Messages.get("key.vault.err.unavailable", reply.status));
        }
        if (reply.status != 200) throw new SafeMessageException(Messages.get("key.vault.err.status", reply.status));

        Object json;
        try {
            json = StrictJson.parse(reply.body);
        } catch (IllegalArgumentException e) {
            throw new SafeMessageException(Messages.get("key.vault.err.response"));
        }
        Object deletion = StrictJson.path(json, "data", "metadata", "deletion_time");
        Object destroyed = StrictJson.path(json, "data", "metadata", "destroyed");
        if (Boolean.TRUE.equals(destroyed) || (deletion instanceof String && !((String) deletion).isEmpty())) {
            throw new SafeMessageException(Messages.get("key.vault.err.deleted"));
        }
        Object data = StrictJson.path(json, "data", "data");
        if (!(data instanceof java.util.Map)) throw new SafeMessageException(Messages.get("key.vault.err.response"));
        String fieldName = field(settings, profile);
        Object field = StrictJson.path(data, fieldName);
        if (!(field instanceof String)) {
            throw new SafeMessageException(Messages.get("key.vault.err.field", fieldName));
        }
        // 해석(key: Base64, pass: Passphrase 파생)은 KeyResolver가 프로필 유형에 맞게 한다.
        return ((String) field).getBytes(StandardCharsets.UTF_8);
    }

    /** 토큰을 읽는다: 토큰 파일이 지정되면 파일, 아니면 환경변수. 값은 메시지에 넣지 않는다. */
    private static String readToken(CryptoSettings settings) throws IOException {
        String file = settings.get(CryptoSettings.VAULT_TOKEN_FILE);
        String token;
        String origin;
        if (!file.isEmpty()) {
            token = SecretFiles.readText(Paths.get(file), MAX_TOKEN_FILE_BYTES, CryptoSettings.VAULT_TOKEN_FILE);
            origin = CryptoSettings.VAULT_TOKEN_FILE;
        } else {
            String env = settings.get(CryptoSettings.VAULT_TOKEN_ENV);
            if (env.isEmpty()) throw new SafeMessageException(Messages.get("config.err.vaultToken"));
            token = System.getenv(env);
            if (token == null || token.trim().isEmpty()) {
                throw new SafeMessageException(Messages.get("key.vault.err.tokenEnvMissing", env));
            }
            token = token.trim();
            origin = CryptoSettings.VAULT_TOKEN_ENV;
        }
        // HTTP 헤더에 넣을 값이므로 공백·줄바꿈·제어문자가 없는 ASCII 한 줄만 허용한다(헤더 주입 방지).
        if (!token.matches("[\\x21-\\x7e]{1,4096}")) {
            throw new SafeMessageException(Messages.get("key.vault.err.tokenFormat", origin));
        }
        return token;
    }

    /** CA 파일이 있으면 그 CA만 신뢰하는 TLS 소켓 공장을 만든다(없으면 null = JVM 기본 신뢰 저장소). */
    private static SSLSocketFactory tlsFactory(CryptoSettings settings) throws IOException {
        String ca = settings.get(CryptoSettings.VAULT_CA_FILE);
        if (ca.isEmpty()) return null;
        Path path = Paths.get(ca);
        if (Files.exists(path) && !Files.isRegularFile(path)) {
            throw new SafeMessageException(Messages.get("key.err.notRegular", CryptoSettings.VAULT_CA_FILE));
        }
        byte[] pem = SecretFiles.readAtMost(path, MAX_CA_FILE_BYTES + 1);
        if (pem.length > MAX_CA_FILE_BYTES) {
            throw new SafeMessageException(Messages.get("key.err.tooLarge", CryptoSettings.VAULT_CA_FILE, MAX_CA_FILE_BYTES));
        }
        try {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new java.io.ByteArrayInputStream(pem));
            if (certificates.isEmpty()) throw new CertificateException("empty");
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            int i = 0;
            for (Certificate certificate : certificates) trust.setCertificateEntry("vault-ca-" + (i++), certificate);
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context.getSocketFactory();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new SafeMessageException(Messages.get("key.vault.err.ca"));
        }
    }

    /** 응답 상태와 본문. */
    private static final class Reply {
        final int status;
        final String body;

        Reply(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }

    /** 일시 장애만 정해진 횟수까지 다시 시도한다. */
    private static Reply getWithRetry(String url, String token, SSLSocketFactory tls, int timeout) throws IOException {
        int attempt = 0;
        while (true) {
            attempt++;
            try {
                Reply reply = get(url, token, tls, timeout);
                if (!retryable(reply.status) || attempt >= MAX_ATTEMPTS) return reply;
            } catch (SocketTimeoutException e) {
                if (attempt >= MAX_ATTEMPTS) throw new SafeMessageException(Messages.get("key.vault.err.timeout", attempt));
            } catch (SSLException e) {
                throw new SafeMessageException(Messages.get("key.vault.err.tls"));
            } catch (ConnectException | NoRouteToHostException | UnknownHostException e) {
                if (attempt >= MAX_ATTEMPTS) throw new SafeMessageException(Messages.get("key.vault.err.network", attempt));
            } catch (IOException e) {
                // JDK 8은 서버 이름 불일치를 일반 IOException("HTTPS hostname wrong")으로 알린다. 메시지는 출력하지 않고 분류에만 쓴다.
                String message = e.getMessage();
                if (message != null && message.startsWith("HTTPS hostname wrong")) {
                    throw new SafeMessageException(Messages.get("key.vault.err.tls"));
                }
                if (attempt >= MAX_ATTEMPTS) throw new SafeMessageException(Messages.get("key.vault.err.network", attempt));
            }
            sleep(500L * attempt);
        }
    }

    private static boolean retryable(int status) {
        return status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
    }

    /** HTTPS GET 한 번. */
    private static Reply get(String url, String token, SSLSocketFactory tls, int timeout) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        if (!(connection instanceof HttpsURLConnection)) {
            // 설정 검증에서 https만 허용하지만, 만약을 대비해 평문 HTTP로는 토큰을 보내지 않는다.
            throw new SafeMessageException(Messages.get("config.err.format." + CryptoSettings.VAULT_URL));
        }
        if (tls != null) ((HttpsURLConnection) connection).setSSLSocketFactory(tls);
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("X-Vault-Token", token);
            connection.setRequestProperty("Accept", "application/json");
            int status = connection.getResponseCode();
            InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            return new Reply(status, stream == null ? "" : readLimited(stream));
        } finally {
            connection.disconnect();
        }
    }

    private static String readLimited(InputStream stream) throws IOException {
        try (InputStream in = stream) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                if (out.size() > MAX_RESPONSE_BYTES) throw new SafeMessageException(Messages.get("key.vault.err.response"));
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
