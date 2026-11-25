package io.javacryptokit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCryptoException.Reason;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

/**
 * 개발자가 직접 준 키로 암복호화하는 공개 API({@link CredentialCrypto#fromRawKey}·{@link CredentialCrypto#fromPassphrase}):
 * 왕복·재시작 후 복호화, 입력 검사, 잘못된 키·Passphrase·Salt·반복 횟수·Key ID의 실패, 호출자 배열 보존·복사, 객체 간 격리(직접 주입
 * 객체끼리·설정 기반 객체와), 멀티스레드, 기존 형식(ENC v1·JCKF v1)과 같은 키의 설정 기반 객체와 상호 복호화, JAR·설정·이력·JVM 속성
 * 무변경과 로그 미출력을 확인한다.
 */
class DirectKeyApiTest {
    /** 시험 속도를 위한 반복 횟수(허용 최솟값). 기본값(600,000)은 한 시험에서 따로 확인한다. */
    private static final int ITERATIONS = 100_000;

    @TempDir
    Path dir;

    // ===================================================================================================
    // 왕복과 재시작
    // ===================================================================================================

    @Test
    void rawKeyEncryptsAndANewObjectWithTheSameKeyDecrypts() throws Exception {
        byte[] key = randomBytes(32);
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("app-key-01", key);
        String token = crypto.encryptText("dummy-secret");
        assertTrue(token.startsWith("ENC[v1:app-key-01:"), token);
        assertEquals("dummy-secret", crypto.decryptText(token));
        assertEquals("dummy-chars", crypto.decryptText(crypto.encryptText("dummy-chars".toCharArray())));
        assertArrayEquals(new byte[] {0, 1, 2, (byte) 0xFF}, crypto.decryptBytes(crypto.encryptBytes(new byte[] {0, 1, 2, (byte) 0xFF})));
        assertTrue(crypto.verify(token));
        // 애플리케이션 재시작: 같은 Key ID·같은 키로 다시 만든 객체가 이전 암호문을 복호화한다
        CredentialCrypto restarted = CredentialCrypto.fromRawKey("app-key-01", key.clone());
        assertEquals("dummy-secret", restarted.decryptText(token));
        // 조회: 이 키 하나만(유형 key, 공급 방식 direct)
        assertEquals("app-key-01", crypto.keyId());
        assertEquals(KeyType.KEY, crypto.keyType());
        assertEquals("direct", crypto.keySource());
        List<KeyInfo> keys = crypto.keys();
        assertEquals(1, keys.size());
        assertEquals("app-key-01", keys.get(0).keyId());
        assertTrue(keys.get(0).isAvailable());
        // withKeyId: 자기 Key ID만, 다른 Key ID는 등록되지 않은 키로 실패(다른 키를 고르지 않음)
        assertEquals("dummy-secret", crypto.decryptText(crypto.withKeyId("app-key-01").encryptText("dummy-secret")));
        assertEquals(Reason.CONFIGURATION, assertThrows(CredentialCryptoException.class, () -> crypto.withKeyId("other")).getReason());
        assertEquals(Reason.CONFIGURATION, assertThrows(CredentialCryptoException.class,
                () -> crypto.encryptText("x", KeyType.PASS)).getReason(), "이 객체에는 pass 키가 없다");
        // 파일(JCKF v1)
        Path plain = Files.write(dir.resolve("report.csv"), "id,name\n1,example\n".getBytes(StandardCharsets.UTF_8));
        crypto.encryptFile(plain, dir.resolve("report.jck"));
        restarted.decryptFile(dir.resolve("report.jck"), dir.resolve("report-out.csv"));
        assertArrayEquals(Files.readAllBytes(plain), Files.readAllBytes(dir.resolve("report-out.csv")));
    }

    @Test
    void passphraseUsesTheSamePbkdf2RulesAndANewObjectWithTheSameValuesDecrypts() throws Exception {
        byte[] salt = randomBytes(16);
        CredentialCrypto crypto = CredentialCrypto.fromPassphrase("app-pass-01", "dummy-앱-Passphrase".toCharArray(), salt,
                600_000);
        String token = crypto.encryptText("dummy-secret");
        assertTrue(token.startsWith("ENC[v1:app-pass-01:"), token);
        assertEquals(KeyType.PASS, crypto.keyType());
        assertEquals("direct", crypto.keySource());
        // 재시작: 같은 Key ID·Passphrase·Salt·반복 횟수
        CredentialCrypto restarted = CredentialCrypto.fromPassphrase("app-pass-01", "dummy-앱-Passphrase".toCharArray(), salt.clone(),
                600_000);
        assertEquals("dummy-secret", restarted.decryptText(token));
        // 같은 키 = 기존 pass 유형의 파생 규칙(NFC 정규화·UTF-8·PBKDF2-HMAC-SHA256·32바이트)
        byte[] derived = PassKdf.derive(PassKdf.normalize("dummy-앱-Passphrase".toCharArray()), salt, 600_000);
        assertEquals("dummy-secret", CredentialCrypto.fromRawKey("app-pass-01", derived).decryptText(token));
        // NFC: 조합형·완성형 한글은 같은 Passphrase
        String decomposed = java.text.Normalizer.normalize("dummy-앱-Passphrase", java.text.Normalizer.Form.NFD);
        assertEquals("dummy-secret", CredentialCrypto.fromPassphrase("app-pass-01", decomposed.toCharArray(), salt, 600_000)
                .decryptText(token));
    }

    // ===================================================================================================
    // 입력 검사와 잘못된 키
    // ===================================================================================================

    @Test
    void invalidInputsAreRejectedWithoutRevealingValues() throws Exception {
        byte[] key = randomBytes(32);
        byte[] salt = randomBytes(16);
        char[] pass = "dummy-input-pass".toCharArray();
        assertInvalid(() -> CredentialCrypto.fromRawKey("k1", null));
        assertInvalid(() -> CredentialCrypto.fromRawKey("k1", new byte[31]));
        assertInvalid(() -> CredentialCrypto.fromRawKey("k1", new byte[33]));
        assertInvalid(() -> CredentialCrypto.fromRawKey("k1", new byte[16]), "AES-128 키는 받지 않는다");
        for (String id : new String[] {null, "", "bad id", "한글키", "a/b", repeat('a', 65)}) {
            assertInvalid(() -> CredentialCrypto.fromRawKey(id, key));
            assertInvalid(() -> CredentialCrypto.fromPassphrase(id, pass, salt, ITERATIONS));
        }
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", pass, null, ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", pass, new byte[15], ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", pass, new byte[17], ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", pass, salt, 99_999));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", pass, salt, 5_000_001));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", null, salt, ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", new char[0], salt, ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", "   ".toCharArray(), salt, ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", "dummy\u0000pass".toCharArray(), salt, ITERATIONS));
        assertInvalid(() -> CredentialCrypto.fromPassphrase("p1", repeat('가', 342).toCharArray(), salt, ITERATIONS),
                "UTF-8 1KiB를 넘는 Passphrase(한글 342자 = 1026바이트)");
        // 경계: 정확히 32바이트 키, 1024바이트 Passphrase, 허용 반복 횟수 양 끝은 통과
        CredentialCrypto.fromRawKey(repeat('a', 64), key);
        CredentialCryptoException e = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromPassphrase("p1", "dummy-visible-secret-777".toCharArray(), new byte[3], ITERATIONS));
        assertFalse(e.getMessage().contains("dummy-visible-secret-777"), "Passphrase를 오류에 넣지 않는다: " + e.getMessage());
    }

    @Test
    void wrongKeyPassphraseSaltIterationsOrKeyIdFailWithoutTryingOtherKeys() throws Exception {
        byte[] salt = randomBytes(16);
        char[] pass = "dummy-right-pass".toCharArray();
        CredentialCrypto right = CredentialCrypto.fromPassphrase("p1", pass, salt, ITERATIONS);
        String token = right.encryptText("dummy-secret");
        List<CredentialCrypto> wrong = Arrays.asList(
                CredentialCrypto.fromPassphrase("p1", "dummy-wrong-pass".toCharArray(), salt, ITERATIONS),
                CredentialCrypto.fromPassphrase("p1", pass, randomBytes(16), ITERATIONS),
                CredentialCrypto.fromPassphrase("p1", pass, salt, ITERATIONS + 1),
                CredentialCrypto.fromRawKey("p1", randomBytes(32)));
        for (CredentialCrypto other : wrong) {
            CredentialCryptoException e = assertThrows(CredentialCryptoException.class, () -> other.decryptText(token));
            assertEquals(Reason.INTEGRITY, e.getReason());
            assertTrue(e.getMessage().contains("Salt"), "직접 준 키의 확인 항목을 안내: " + e.getMessage());
            assertFalse(e.getMessage().contains("dummy-secret") || e.getMessage().contains("dummy-right-pass"), e.getMessage());
            assertFalse(other.verify(token), "verify는 평문 없이 false");
        }
        // 다른 Key ID의 암호문: 다른 키로 바꿔 시도하지 않고 KEY_ID_MISMATCH(이 객체의 Key ID 안내)
        CredentialCryptoException mismatch = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromPassphrase("p2", pass, salt, ITERATIONS).decryptText(token));
        assertEquals(Reason.KEY_ID_MISMATCH, mismatch.getReason());
        assertTrue(mismatch.getMessage().contains("p2"), mismatch.getMessage());
        // 위조·형식 오류
        assertEquals(Reason.INVALID_TOKEN, assertThrows(CredentialCryptoException.class, () -> right.decryptText("ENC[v1:p1:bad]"))
                .getReason());
    }

    @Test
    void callerArraysAreCopiedAndNeverChanged() throws Exception {
        byte[] key = randomBytes(32);
        byte[] keyCopy = key.clone();
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("k1", key);
        assertArrayEquals(keyCopy, key, "호출자 키 배열을 바꾸지 않는다");
        String token = crypto.encryptText("dummy-secret");
        Arrays.fill(key, (byte) 0); // 호출자가 원본을 지워도 객체의 키는 그대로
        assertEquals("dummy-secret", crypto.decryptText(token));
        assertEquals("dummy-secret", CredentialCrypto.fromRawKey("k1", keyCopy).decryptText(crypto.encryptText("dummy-secret")));

        char[] pass = "dummy-caller-pass".toCharArray();
        char[] passCopy = pass.clone();
        byte[] salt = randomBytes(16);
        byte[] saltCopy = salt.clone();
        CredentialCrypto passCrypto = CredentialCrypto.fromPassphrase("p1", pass, salt, ITERATIONS);
        assertArrayEquals(passCopy, pass, "Passphrase 배열을 바꾸지 않는다");
        assertArrayEquals(saltCopy, salt, "Salt 배열을 바꾸지 않는다");
        String passToken = passCrypto.encryptText("dummy-secret");
        Arrays.fill(pass, '\0');
        Arrays.fill(salt, (byte) 0);
        assertEquals("dummy-secret", passCrypto.decryptText(passToken));
    }

    // ===================================================================================================
    // 격리: 직접 주입 객체끼리, 설정 기반 객체와, 멀티스레드
    // ===================================================================================================

    @Test
    void directObjectsAndManagedObjectsDoNotAffectEachOther() throws Exception {
        CredentialCrypto managed = TestSupport.jarDefaults();
        List<KeyInfo> managedKeysBefore = managed.keys();
        String managedToken = managed.encryptText("dummy-managed");
        String managedKeyToken = managed.encryptText("dummy-managed-key", KeyType.KEY); // Key ID default

        CredentialCrypto a = CredentialCrypto.fromRawKey("app-a", randomBytes(32));
        CredentialCrypto b = CredentialCrypto.fromPassphrase("app-b", "dummy-b-pass".toCharArray(), randomBytes(16), ITERATIONS);
        // 설정 기반 키와 같은 Key ID(default)를 쓰는 다른 키: 저장소를 합치지 않는다
        CredentialCrypto sameId = CredentialCrypto.fromRawKey("default", randomBytes(32));
        String tokenA = a.encryptText("dummy-a");
        String tokenB = b.encryptText("dummy-b");
        String tokenSame = sameId.encryptText("dummy-same-id");

        assertEquals("dummy-a", a.decryptText(tokenA));
        assertEquals("dummy-b", b.decryptText(tokenB));
        assertEquals(Reason.KEY_ID_MISMATCH, failure(() -> a.decryptText(tokenB)));
        assertEquals(Reason.KEY_ID_MISMATCH, failure(() -> b.decryptText(tokenA)));
        // 설정 기반 ↔ 직접 주입: 서로의 암호문을 다른 키로 바꿔 풀지 않는다
        assertEquals(Reason.KEY_ID_MISMATCH, failure(() -> a.decryptText(managedToken)));
        assertEquals(Reason.KEY_ID_MISMATCH, failure(() -> managed.decryptText(tokenA)));
        assertEquals(Reason.INTEGRITY, failure(() -> sameId.decryptText(managedKeyToken)), "같은 Key ID라도 설정 기반 키로 바꾸지 않는다");
        assertEquals(Reason.INTEGRITY, failure(() -> managed.decryptText(tokenSame)), "같은 Key ID라도 직접 준 키를 쓰지 않는다");
        // 설정 기반 객체는 그대로(키 목록·기본 키·복호화)
        assertEquals("dummy-managed", managed.decryptText(managedToken));
        assertEquals("dummy-managed-key", managed.decryptText(managedKeyToken));
        assertEquals(summary(managedKeysBefore), summary(managed.keys()));
        assertEquals(summary(managedKeysBefore), summary(TestSupport.jarDefaults().keys()), "새로 만든 설정 기반 객체도 같은 키 목록");
        assertEquals("pass-default", managed.keyId());
    }

    @Test
    void concurrentUseKeepsEveryObjectsOwnKey() throws Exception {
        CredentialCrypto a = CredentialCrypto.fromRawKey("thread-a", randomBytes(32));
        CredentialCrypto b = CredentialCrypto.fromPassphrase("thread-b", "dummy-thread-pass".toCharArray(), randomBytes(16), ITERATIONS);
        CredentialCrypto managed = TestSupport.jarDefaults();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                final int thread = t;
                results.add(pool.submit((Callable<Boolean>) () -> {
                    for (int i = 0; i < 40; i++) {
                        String value = "dummy-" + thread + "-" + i;
                        CredentialCrypto crypto = i % 3 == 0 ? a : (i % 3 == 1 ? b : managed);
                        String token = crypto.encryptText(value);
                        if (!value.equals(crypto.decryptText(token))) return false;
                        if (crypto != managed && managed.verify(token)) return false;
                    }
                    return true;
                }));
            }
            for (Future<Boolean> result : results) assertTrue(result.get());
        } finally {
            pool.shutdownNow();
        }
    }

    // ===================================================================================================
    // 기존 형식 호환: 같은 키를 등록한 설정 기반 객체와 서로 복호화
    // ===================================================================================================

    @Test
    void tokensAndFilesAreTheSameFormatAsManagedKeysWithTheSameKey() throws Exception {
        // key: 같은 32바이트 키를 키 파일로 둔 설정(crypto.key.* AES 슬롯)과 서로 복호화
        byte[] key = randomBytes(32);
        Path keyFile = TestSupport.writeKeyFile(dir, "shared.key", Base64.getEncoder().encodeToString(key));
        Path keyConfig = TestSupport.writeConfig(dir, "shared-key.properties", "crypto.key.source=file", "crypto.key.id=shared01",
                "crypto.key.file=" + TestSupport.propertiesPath(keyFile));
        CredentialCrypto managedKey = CredentialCrypto.fromConfigFile(keyConfig);
        CredentialCrypto direct = CredentialCrypto.fromRawKey("shared01", key);
        assertEquals("dummy-direct", managedKey.decryptText(direct.encryptText("dummy-direct")));
        assertEquals("dummy-managed", direct.decryptText(managedKey.encryptText("dummy-managed", KeyType.KEY)));
        Path plain = Files.write(dir.resolve("data.bin"), new byte[] {9, 8, 7});
        direct.encryptFile(plain, dir.resolve("data.jck"));
        managedKey.decryptFile(dir.resolve("data.jck"), dir.resolve("data.out"));
        assertArrayEquals(new byte[] {9, 8, 7}, Files.readAllBytes(dir.resolve("data.out")));

        // pass: 같은 Passphrase·Salt·반복 횟수·Key ID의 설정 기반 pass 키(파일 공급원, 지문 고정)와 서로 복호화
        byte[] salt = randomBytes(16);
        Path passFile = Files.write(dir.resolve("app.pass"), "dummy-shared-pass\n".getBytes(StandardCharsets.UTF_8));
        String p = "crypto.keys.shared-pass.";
        Path passConfig = TestSupport.writeConfig(dir, "shared-pass.properties", p + "type=pass", p + "source=file",
                p + "file=" + TestSupport.propertiesPath(passFile), p + "kdf=pbkdf2-sha256", p + "kdf.iterations=" + ITERATIONS,
                p + "salt=" + Base64.getEncoder().encodeToString(salt),
                p + "fingerprint=" + KeyResolver.fingerprint(PassKdf.derive(PassKdf.normalize("dummy-shared-pass".toCharArray()), salt,
                        ITERATIONS)));
        CredentialCrypto managedPass = CredentialCrypto.fromConfigFile(passConfig);
        CredentialCrypto directPass = CredentialCrypto.fromPassphrase("shared-pass", "dummy-shared-pass".toCharArray(), salt,
                ITERATIONS);
        assertEquals("dummy-direct-pass", managedPass.decryptText(directPass.encryptText("dummy-direct-pass")));
        assertEquals("dummy-managed-pass", directPass.decryptText(managedPass.withKeyId("shared-pass").encryptText("dummy-managed-pass")));
    }

    // ===================================================================================================
    // 저장소·설정·이력·JVM 속성 무변경, 로그 미출력
    // ===================================================================================================

    @Test
    void directKeysNeverTouchTheJarSettingsHistorySystemPropertiesOrLogs() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        // 관리자 비밀번호 미설정 JAR에서 별도 클래스로더로 실행: JAR 파일·항목·폴더가 그대로여야 한다
        Path jar = TestJars.build(dir.resolve("java-crypto-kit-0.1.0.jar"));
        byte[] before = sha256(jar);
        List<String> entriesBefore = entries(jar);
        List<String> filesBefore = files();
        Map<String, String> propertiesBefore = systemProperties();
        List<String> logs = new ArrayList<>();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                logs.add(String.valueOf(record.getMessage()));
            }

            @Override
            public void flush() { }

            @Override
            public void close() { }
        };
        Logger root = Logger.getLogger("");
        root.addHandler(handler);
        java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        java.io.PrintStream previousErr = System.err;
        System.setErr(new java.io.PrintStream(err, true, "UTF-8"));
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jar.toUri().toURL()}, null)) {
            Class<?> api = loader.loadClass("io.javacryptokit.CredentialCrypto");
            Object raw = api.getMethod("fromRawKey", String.class, byte[].class).invoke(null, "isolated-key", randomBytes(32));
            Object pass = api.getMethod("fromPassphrase", String.class, char[].class, byte[].class, int.class)
                    .invoke(null, "isolated-pass", "dummy-isolated-pass".toCharArray(), randomBytes(16), ITERATIONS);
            Method encrypt = api.getMethod("encryptText", String.class);
            Method decrypt = api.getMethod("decryptText", String.class);
            for (Object crypto : new Object[] {raw, pass}) {
                String token = (String) encrypt.invoke(crypto, "dummy-isolated-secret");
                assertEquals("dummy-isolated-secret", decrypt.invoke(crypto, token));
            }
        } finally {
            System.setErr(previousErr);
            root.removeHandler(handler);
        }
        assertArrayEquals(before, sha256(jar), "JAR 파일(내장 키·키 목록·이력·관리자 항목)은 그대로");
        assertEquals(entriesBefore, entries(jar));
        assertEquals(filesBefore, files(), "설정·이력·감사 파일을 만들지 않는다");
        assertEquals(propertiesBefore, systemProperties(), "JVM 시스템 속성을 바꾸지 않는다");
        String output = String.join("\n", logs) + err.toString("UTF-8");
        assertFalse(output.contains("dummy-isolated"), "키·Passphrase·평문을 로그·표준 오류에 쓰지 않는다: " + output);
        assertTrue(logs.isEmpty() && err.size() == 0, "직접 준 키는 경고·로그를 남기지 않는다: " + output);
    }

    // ===================================================================================================
    // 도우미
    // ===================================================================================================

    private static void assertInvalid(Executable call) {
        assertInvalid(call, "INVALID_INPUT");
    }

    private static void assertInvalid(Executable call, String message) {
        CredentialCryptoException e = assertThrows(CredentialCryptoException.class, call, message);
        assertEquals(Reason.INVALID_INPUT, e.getReason(), message + ": " + e.getMessage());
    }

    private static Reason failure(Executable call) {
        return assertThrows(CredentialCryptoException.class, call).getReason();
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }

    private static List<String> summary(List<KeyInfo> keys) {
        List<String> lines = new ArrayList<>();
        for (KeyInfo key : keys) lines.add(key.keyId() + "|" + key.type() + "|" + key.source() + "|" + key.fingerprint());
        return lines;
    }

    private static byte[] sha256(Path file) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file));
    }

    private static List<String> entries(Path jar) throws Exception {
        try (JarFile file = new JarFile(jar.toFile())) {
            return Collections.list(file.entries()).stream().map(e -> e.getName() + ":" + e.getCrc()).sorted()
                    .collect(Collectors.toList());
        }
    }

    private List<String> files() throws Exception {
        try (Stream<Path> list = Files.walk(dir)) {
            return list.map(p -> dir.relativize(p).toString()).sorted().collect(Collectors.toList());
        }
    }

    private static Map<String, String> systemProperties() {
        Map<String, String> properties = new TreeMap<>();
        for (String name : System.getProperties().stringPropertyNames()) properties.put(name, System.getProperty(name));
        return properties;
    }
}
