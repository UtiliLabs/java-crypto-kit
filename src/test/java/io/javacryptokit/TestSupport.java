package io.javacryptokit;

import io.javacryptokit.config.CryptoSettings;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * JUnit 테스트 공용 도우미(여러 테스트 패키지에서 쓰므로 public). 테스트 값은 모두 더미이며 실제 키·비밀번호를 쓰지 않는다.
 */
public final class TestSupport {
    /** build.gradle이 test JVM에 넣어 주는 env 모드용 더미 난수 키 환경변수 이름. */
    public static final String ENV_TEST_KEY = "JAVA_CRYPTO_KIT_TEST_KEY";
    /** build.gradle이 test JVM에 넣어 주는 "공개 기본 키" 환경변수 이름(공개 값, 비밀 아님). */
    public static final String ENV_PUBLIC_KEY = "JAVA_CRYPTO_KIT_TEST_PUBLIC_KEY";

    private TestSupport() { }

    /** 지정한 줄로 UTF-8 외부 설정 파일을 만든다. */
    public static Path writeConfig(Path dir, String name, String... lines) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, (String.join("\n", lines) + "\n").getBytes(StandardCharsets.UTF_8));
        return file;
    }

    /** 32바이트 난수 키 파일(keygen과 같은 형식)을 만든다. */
    public static Path writeRandomKeyFile(Path dir, String name) throws IOException {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return writeKeyFile(dir, name, Base64.getEncoder().encodeToString(key));
    }

    /** 지정한 Base64 키로 키 파일을 만든다. */
    public static Path writeKeyFile(Path dir, String name, String base64) throws IOException {
        Path file = dir.resolve(name);
        Files.write(file, (base64 + "\n").getBytes(StandardCharsets.US_ASCII));
        return file;
    }

    /** Properties 파일에 쓸 경로. 역슬래시는 이스케이프 문자이므로 '/'로 바꾼다. */
    public static String propertiesPath(Path path) {
        return path.toAbsolutePath().toString().replace(File.separatorChar, '/');
    }

    /** JAR 기본 설정에 들어 있는 공개 기본 키(Base64). 공개 값이며 비밀이 아니다. */
    public static String publicKeyBase64() throws IOException {
        Properties defaults = new Properties();
        try (InputStream in = TestSupport.class.getResourceAsStream("/java-crypto-kit.properties");
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            defaults.load(reader);
        }
        return defaults.getProperty("crypto.key.embedded").trim();
    }

    /** 실제 JVM 속성·환경변수의 설정 경로를 무시하고 지정한 파일만으로 설정을 읽는다(null이면 JAR 기본값만). */
    public static CryptoSettings isolatedSettings(Path config) throws IOException {
        return CryptoSettings.load(config == null ? null : config.toString(), name -> null, name -> null);
    }

    /**
     * JAR 기본값(공개 내장 키, 키ID default)으로 동작하는 공개 API 객체. 빈 외부 설정 파일을 지정해 실제 환경의
     * 설정 경로(JVM 속성·환경변수)에 영향을 받지 않게 한다.
     */
    public static CredentialCrypto jarDefaults() throws IOException, CredentialCryptoException {
        Path empty = Files.createTempFile("java-crypto-kit-empty", ".properties");
        empty.toFile().deleteOnExit();
        return CredentialCrypto.fromConfigFile(empty);
    }

    /** 테스트를 실행하는 환경에 설정 경로 환경변수(CRYPTO_CONFIG_FILE)가 없을 때만 기본 탐색 시험을 의미 있게 수행할 수 있다. */
    public static boolean noConfigEnvironmentVariables() {
        return System.getenv(CryptoSettings.CONFIG_FILE_ENV) == null;
    }

    /**
     * 설정 경로 JVM 속성(-Dcrypto.config.file)을 잠시 지우고, 닫을 때 원래 값으로 되돌린다. 설정 경로 이름은 하나뿐이다
     * (최초 공개 전에 별칭을 정리함).
     */
    public static AutoCloseable clearOtherConfigProperties() {
        return systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
    }

    /**
     * JVM 개별 설정 속성(-Dcrypto.*)을 잠시 지정하고, 닫을 때 원래 값으로 되돌린다. 지정하지 않은 허용 목록 항목·정책 항목·
     * 키 원문 항목은 모두 지워 두어, 개발자 PC나 IDE 실행 옵션에 남아 있는 값이 시험 결과에 섞이지 않게 한다.
     *
     * @param pairs "이름=값" 형식(값이 빈 문자열이면 빈 값으로 지정). 아무것도 주지 않으면 모두 지운 상태로 만든다.
     * @return 닫으면 원래 상태로 되돌리는 객체
     */
    public static AutoCloseable jvmSettings(String... pairs) {
        java.util.Map<String, String> wanted = new java.util.LinkedHashMap<>();
        for (String pair : pairs) {
            int separator = pair.indexOf('=');
            wanted.put(pair.substring(0, separator), pair.substring(separator + 1));
        }
        java.util.Set<String> names = new java.util.LinkedHashSet<>(CryptoSettings.JVM_OVERRIDABLE_KEYS);
        names.add(CryptoSettings.JVM_OVERRIDE_ENABLED);
        names.add(CryptoSettings.KEY_EMBEDDED);
        names.addAll(wanted.keySet());
        final List<AutoCloseable> restores = new ArrayList<>();
        for (String name : names) restores.add(systemProperty(name, wanted.get(name)));
        return () -> {
            for (int i = restores.size() - 1; i >= 0; i--) restores.get(i).close();
        };
    }

    /** 시스템 속성을 잠시 바꾸고 닫을 때 원래 값으로 되돌린다. null을 주면 속성을 지운다. */
    public static AutoCloseable systemProperty(String name, String value) {
        final String previous = System.getProperty(name);
        if (value == null) System.clearProperty(name); else System.setProperty(name, value);
        return () -> {
            if (previous == null) System.clearProperty(name); else System.setProperty(name, previous);
        };
    }

    /**
     * 이 라이브러리 로거(io.javacryptokit 하위)로 기록되는 로그를 모두 붙잡는다.
     * 전역 로깅 설정은 바꾸지 않고 핸들러만 잠시 추가했다가 제거한다.
     */
    public static final class LogCapture implements AutoCloseable {
        private final Logger logger = Logger.getLogger("io.javacryptokit");
        private final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() { }

            @Override
            public void close() { }
        };

        public LogCapture() {
            handler.setLevel(Level.ALL);
            logger.addHandler(handler);
        }

        /** @return WARNING 이상 기록의 메시지 */
        public List<String> warnings() {
            List<String> messages = new ArrayList<>();
            for (LogRecord record : records) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) messages.add(record.getMessage());
            }
            return messages;
        }

        /** @return 모든 기록의 메시지를 이어 붙인 문자열(비밀값 누출 검사용) */
        public String allText() {
            StringBuilder text = new StringBuilder();
            for (LogRecord record : records) text.append(record.getMessage()).append('\n');
            return text.toString();
        }

        @Override
        public void close() {
            logger.removeHandler(handler);
        }
    }
}
