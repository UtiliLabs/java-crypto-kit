package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.security.Bytes;
import io.javacryptokit.security.Encoding;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpRetryException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

/**
 * 패키지 내부: 인증 서버 HTTPS 호출의 공통 경계(Introspection·Client Credentials). HTTPS 전용·리다이렉트 안 따라감·JDK 기본 인증서·
 * 호스트명 검증(신뢰 설정만 {@link SSLContext}로 주입)·시간 제한·응답 크기 상한·form-urlencoding·client_secret_basic 헤더를 한 곳에
 * 둔다. 응답의 의미 해석(활성 여부·토큰 필드)은 각 API가 한다. 토큰·비밀·응답 본문을 기록하지 않는다.
 */
final class OAuthHttp {
    static final int MAX_RESPONSE_LIMIT = 1024 * 1024;
    /** 시간 제한의 최솟값(1ms). 더 짧으면 URLConnection에 0(무제한)으로 전달되므로 거부한다. */
    static final Duration MIN_TIMEOUT = Duration.ofMillis(1);

    private OAuthHttp() { }

    /** 연결 설정(빌더가 검증해 채운 뒤 바꾸지 않는다). */
    static final class Settings {
        final URL endpoint;
        Duration connectTimeout = Duration.ofSeconds(5);
        Duration readTimeout = Duration.ofSeconds(10);
        int maxResponseBytes = 64 * 1024;
        SSLContext sslContext;

        Settings(URI endpoint) {
            if (endpoint == null || !"https".equalsIgnoreCase(endpoint.getScheme()) || endpoint.getHost() == null
                    || endpoint.getRawUserInfo() != null || endpoint.getRawFragment() != null) {
                throw OAuthText.invalid("oauth.err.endpoint");
            }
            try {
                this.endpoint = endpoint.toURL();
            } catch (IOException | IllegalArgumentException e) {
                throw OAuthText.invalid("oauth.err.endpoint");
            }
        }

        private Settings(Settings other) {
            this.endpoint = other.endpoint;
            this.connectTimeout = other.connectTimeout;
            this.readTimeout = other.readTimeout;
            this.maxResponseBytes = other.maxResponseBytes;
            this.sslContext = other.sslContext;
        }

        /** @return 빌더가 나중에 바꿔도 영향받지 않는 사본(만든 객체는 불변) */
        Settings copy() {
            return new Settings(this);
        }

        void connectTimeout(Duration value) {
            connectTimeout = checkDuration(value, Duration.ofSeconds(60));
        }

        void readTimeout(Duration value) {
            readTimeout = checkDuration(value, Duration.ofSeconds(120));
        }

        void maxResponseBytes(int bytes) {
            if (bytes < 1024 || bytes > MAX_RESPONSE_LIMIT) throw OAuthText.invalid("oauth.err.limit");
            maxResponseBytes = bytes;
        }

        void sslContext(SSLContext context) {
            if (context == null) throw OAuthText.invalid("oauth.err.required", "sslContext");
            sslContext = context;
        }

        private static Duration checkDuration(Duration value, Duration max) {
            // URLConnection은 밀리초 단위이고 0은 "무제한 대기"이므로, 1ms 미만(0으로 잘리는 값)은 입력 오류로 거부한다.
            if (value == null || value.compareTo(MIN_TIMEOUT) < 0 || value.compareTo(max) > 0) throw OAuthText.invalid("oauth.err.limit");
            return value;
        }
    }

    /** 받은 응답(상태·형식·본문). 3xx는 본문 없이 돌려준다. */
    static final class Response {
        final int status;
        final String contentType;
        final byte[] body;

        Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }

        boolean isJson() {
            return contentType != null && contentType.toLowerCase(Locale.ROOT).split(";")[0].trim().equals("application/json");
        }

        /** 엄격한 UTF-8·JSON 객체(중복 멤버 거부). @throws IllegalArgumentException 형식 오류 */
        JwtClaims json() {
            return JwtClaims.parse(Bytes.utf8String(body));
        }
    }

    /** 응답을 받지 못한 통신 실패. */
    static final class Failure extends Exception {
        private static final long serialVersionUID = 1L;
        final OAuthClientException.Reason reason;
        final int status;

        Failure(OAuthClientException.Reason reason, int status) {
            super(null, null, false, false);
            this.reason = reason;
            this.status = status;
        }

        String messageKey() {
            switch (reason) {
                case TIMEOUT: return "oauth.err.timeout";
                case TLS: return "oauth.err.tls";
                case RESPONSE_TOO_LARGE: return "oauth.err.tooLarge";
                default: return "oauth.err.network";
            }
        }
    }

    /**
     * form 본문을 POST한다.
     *
     * @param settings      연결 설정
     * @param form          {@code application/x-www-form-urlencoded} 본문(호출 뒤 지운다)
     * @param authorization Authorization 헤더 값(없으면 null)
     * @return 응답(오류 상태 포함)
     * @throws Failure 시간 초과·TLS·네트워크·응답 크기 초과
     */
    static Response post(Settings settings, byte[] form, String authorization) throws Failure {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) settings.endpoint.openConnection();
            if (!(connection instanceof HttpsURLConnection)) throw new Failure(OAuthClientException.Reason.NETWORK, -1);
            if (settings.sslContext != null) ((HttpsURLConnection) connection).setSSLSocketFactory(settings.sslContext.getSocketFactory());
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setConnectTimeout((int) settings.connectTimeout.toMillis());
            connection.setReadTimeout((int) settings.readTimeout.toMillis());
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Accept", "application/json");
            if (authorization != null) connection.setRequestProperty("Authorization", authorization);
            connection.setFixedLengthStreamingMode(form.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(form);
            }
            int status = connection.getResponseCode();
            if (status >= 300 && status < 400) return new Response(status, null, new byte[0]);
            InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
            return new Response(status, connection.getContentType(), read(stream, settings.maxResponseBytes, status));
        } catch (HttpRetryException e) {
            // 고정 길이 스트리밍 요청에 인증 요구(401 등)가 오면 JDK가 재시도 대신 이 예외를 던진다(본문 없음).
            return new Response(e.responseCode(), null, new byte[0]);
        } catch (SocketTimeoutException e) {
            throw new Failure(OAuthClientException.Reason.TIMEOUT, -1);
        } catch (SSLException e) {
            throw new Failure(OAuthClientException.Reason.TLS, -1);
        } catch (IOException e) {
            throw new Failure(OAuthClientException.Reason.NETWORK, -1);
        } finally {
            Arrays.fill(form, (byte) 0);
            if (connection != null) connection.disconnect();
        }
    }

    /** RFC 6749 2.3.1: ID·비밀을 각각 form-urlencoding한 뒤 Basic으로 묶는다. */
    static String basic(String clientId, char[] secret) {
        return "Basic " + Encoding.BASE64.encode(Bytes.utf8(form(clientId) + ":" + form(new String(secret))));
    }

    static String form(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8");
        }
    }

    private static byte[] read(InputStream input, int limit, int status) throws IOException, Failure {
        if (input == null) return new byte[0];
        try (InputStream in = input) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                if (out.size() > limit) throw new Failure(OAuthClientException.Reason.RESPONSE_TOO_LARGE, status);
            }
            return out.toByteArray();
        }
    }
}
