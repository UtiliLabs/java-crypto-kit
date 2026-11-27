package io.javacryptokit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * pass(Passphrase)·key(AES 키) 두 유형의 키 목록(Keyring): 기본 선택 규칙, Key ID 자동 선택 복호화, 공개 API, 외부 키 지문 고정
 * (Fail Closed), 설정 검증, 한 JAR 안의 동시·독립 동작, 이전 형식 설정·암호문 호환.
 */
class KeyringTest {
    /** 시험용 Passphrase 반복 횟수(허용 최솟값, 빠른 시험용). */
    private static final int ITERATIONS = 100_000;

    @TempDir
    Path dir;
    private AutoCloseable isolation;

    @BeforeEach
    void isolate() {
        isolation = TestSupport.jvmSettings();
        DefaultKeyWarning.resetForTests();
    }

    @AfterEach
    void restore() throws Exception {
        isolation.close();
    }

    // ===== 공식 JAR 기본값: 공개 기본 키 두 개, 유형 미지정 = pass =====

    @Test
    void distributionHasNoKeysAndConfiguredKeysAreIndependent() throws Exception {
        CredentialCrypto empty = CredentialCrypto.fromDefaultConfiguration();
        assertTrue(empty.keys().isEmpty());
        assertNull(empty.keyId());
        assertNull(empty.keyType());
        assertNull(empty.keySource());
        for (KeyType type : KeyType.values()) {
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION,
                    assertThrows(CredentialCryptoException.class, () -> empty.encryptText("dummy", type)).getReason());
        }
        CredentialCrypto managed = TestSupport.managedCrypto();
        assertEquals(2, managed.keys().size());
        assertEquals(KeyType.PASS, managed.keyType());
        for (KeyInfo key : managed.keys()) {
            assertTrue(key.isAvailable() && key.isTypeDefault());
            assertFalse(key.isPublicDefault());
            assertEquals(key.type() == KeyType.PASS, key.isEncryptionDefault());
        }
    }

    @Test
    void managedKeySelectionDistinguishesMissingIdAndTypeInBothLanguages() throws Exception {
        for (String lang : new String[] {"ko", "en"}) {
            Path config = TestSupport.writeConfig(dir, "empty-" + lang + ".properties", "crypto.lang=" + lang);
            CredentialCrypto empty = CredentialCrypto.fromConfigFile(config);
            CredentialCryptoException unspecified = assertThrows(CredentialCryptoException.class, () -> empty.encryptText("dummy"));
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, unspecified.getReason());
            assertTrue(unspecified.getMessage().contains("PASS (Passphrase)") && unspecified.getMessage().contains("KEY (AES Key)")
                    && unspecified.getMessage().contains("admin setup"), unspecified.getMessage());
            CredentialCryptoException missingId = assertThrows(CredentialCryptoException.class, () -> empty.withKeyId("missing-id"));
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, missingId.getReason());
            assertTrue(missingId.getMessage().contains("missing-id"), missingId.getMessage());
            for (KeyType type : KeyType.values()) {
                CredentialCryptoException missingType = assertThrows(CredentialCryptoException.class,
                        () -> empty.encryptText("dummy", type));
                assertEquals(CredentialCryptoException.Reason.CONFIGURATION, missingType.getReason());
                assertTrue(missingType.getMessage().contains(type == KeyType.PASS ? "PASS (Passphrase)" : "KEY (AES Key)"));
                assertTrue(missingType.getMessage().contains("admin setup"), missingType.getMessage());
            }
            Path keyFile = TestSupport.writeRandomKeyFile(dir, "managed-" + lang + ".key");
            Path external = TestSupport.writeConfig(dir, "one-key-" + lang + ".properties", "crypto.lang=" + lang,
                    "crypto.key.id=example-key", "crypto.key.source=file",
                    "crypto.key.file=" + TestSupport.propertiesPath(keyFile));
            CredentialCrypto oneKey = CredentialCrypto.fromConfigFile(external);
            CredentialCryptoException noPass = assertThrows(CredentialCryptoException.class,
                    () -> oneKey.encryptText("dummy", KeyType.PASS));
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, noPass.getReason());
            assertTrue(noPass.getMessage().contains("PASS (Passphrase)") && noPass.getMessage().contains("crypto.key.active.pass"),
                    noPass.getMessage());
            CredentialCryptoException otherId = assertThrows(CredentialCryptoException.class,
                    () -> oneKey.withKeyId("other-id"));
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, otherId.getReason());
            assertTrue(otherId.getMessage().contains("other-id"), otherId.getMessage());
            CredentialCryptoException mismatch = assertThrows(CredentialCryptoException.class,
                    () -> oneKey.encryptText("dummy", KeyType.PASS, "example-key"));
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, mismatch.getReason());
            assertTrue(mismatch.getMessage().contains("example-key") && mismatch.getMessage().contains("pass"), mismatch.getMessage());
            assertTrue(oneKey.encryptText("dummy", KeyType.KEY).startsWith("ENC[v1:example-key:"));
        }
    }

    @Test
    void keyIdSelectsTheKeyWithItsOwnTypeAndTypeIsCheckedWhenGiven() throws Exception {
        CredentialCrypto crypto = TestSupport.managedCrypto();
        CredentialCrypto aes = crypto.withKeyId("default");
        assertEquals("default", aes.keyId());
        assertEquals(KeyType.KEY, aes.keyType());
        assertTrue(aes.encryptText("x").startsWith("ENC[v1:default:"));
        assertTrue(aes.encryptText("x".toCharArray()).startsWith("ENC[v1:default:"));
        assertTrue(aes.encryptBytes(new byte[] {1}).startsWith("ENC[v1:default:"));
        assertTrue(aes.encryptText("x", KeyType.KEY).startsWith("ENC[v1:default:"), "유형이 같으면 사용");
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION,
                assertThrows(CredentialCryptoException.class, () -> aes.encryptText("x", KeyType.PASS)).getReason());
        assertTrue(crypto.encryptText("x", KeyType.PASS, "test-pass").startsWith("ENC[v1:test-pass:"));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, assertThrows(CredentialCryptoException.class,
                () -> crypto.encryptText("x", KeyType.KEY, "test-pass")).getReason());
        // 원래 객체는 바뀌지 않는다. 미등록·빈 Key ID와 빈 유형은 다른 키로 바꾸지 않고 실패한다.
        assertEquals("test-pass", crypto.keyId());
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION,
                assertThrows(CredentialCryptoException.class, () -> crypto.withKeyId("no-such-key")).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.withKeyId("")).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("x", (KeyType) null)).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("x", KeyType.KEY, null)).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("", KeyType.KEY)).getReason());
        // 파일도 같은 규칙(헤더의 Key ID로 자동 복호화)
        Path in = Files.write(dir.resolve("in.bin"), new byte[] {1, 2, 3});
        crypto.encryptFile(in, dir.resolve("pass.jck"));
        aes.encryptFile(in, dir.resolve("aes.jck"));
        crypto.encryptFile(in, dir.resolve("typed.jck"), KeyType.KEY);
        for (String name : new String[] {"pass", "aes", "typed"}) {
            crypto.decryptFile(dir.resolve(name + ".jck"), dir.resolve(name + ".out"));
            assertTrue(Arrays.equals(new byte[] {1, 2, 3}, Files.readAllBytes(dir.resolve(name + ".out"))), name);
        }
    }

    // ===== 키 선택 실패 안내: 상황마다 원인·조치가 다르고 공개 사유(Reason)는 그대로 =====

    @Test
    void selectionFailuresNameTheSituationAndKeepTheirReasons() throws Exception {
        CredentialCryptoException.Reason configuration = CredentialCryptoException.Reason.CONFIGURATION;
        // 키 프로필이 하나도 없는 상태(최초 설정 전): 유형·Key ID 미지정, 유형만 지정, Key ID 지정, 복호화
        CredentialCrypto empty = CredentialCrypto.fromDefaultConfiguration();
        assertFailure(configuration, Messages.get("key.err.unconfigured"), () -> empty.encryptText("x"));
        assertFailure(configuration, Messages.get("config.err.noActiveKey.initial", "KEY (AES Key)",
                CryptoSettings.KEY_ACTIVE_KEY, "key"), () -> empty.encryptText("x", KeyType.KEY));
        assertFailure(configuration, Messages.get("config.err.noActiveKey.initial", "PASS (Passphrase)",
                CryptoSettings.KEY_ACTIVE_PASS, "pass"), () -> empty.encryptText("x", KeyType.PASS));
        assertFailure(configuration, Messages.get("config.err.keyIdUnknown", "corp01"),
                () -> empty.encryptText("x", KeyType.KEY, "corp01"));
        String aesToken = TestSupport.managedCrypto().encryptText("x", KeyType.KEY);
        assertFailure(configuration, Messages.get("key.err.unconfigured"), () -> empty.decryptText(aesToken));
        // pass 키만 있는 상태: 없는 유형은 등록·선택 안내, 유형 불일치·미등록 Key ID는 각자의 안내, 미등록 Key ID 암호문은 KEY_ID_MISMATCH
        Path passOnly = TestSupport.writeConfig(dir, "pass-only.properties",
                without(Arrays.asList(TestSupport.managedSettings()), "crypto.key.embedded=").toArray(new String[0]));
        CredentialCrypto pass = CredentialCrypto.fromConfigFile(passOnly);
        assertTrue(pass.encryptText("x").startsWith("ENC[v1:test-pass:"));
        assertFailure(configuration, Messages.get("config.err.noActiveKey", "KEY (AES Key)", CryptoSettings.KEY_ACTIVE_KEY,
                "key"), () -> pass.encryptText("x", KeyType.KEY));
        assertFailure(configuration, Messages.get("config.err.keyTypeMismatch", "test-pass", "pass", "key"),
                () -> pass.encryptText("x", KeyType.KEY, "test-pass"));
        assertFailure(configuration, Messages.get("config.err.keyIdUnknown", "no-such-key"),
                () -> pass.encryptText("x", KeyType.PASS, "no-such-key"));
        assertEquals(CredentialCryptoException.Reason.KEY_ID_MISMATCH,
                assertThrows(CredentialCryptoException.class, () -> pass.decryptText(aesToken)).getReason());
    }

    private static void assertFailure(CredentialCryptoException.Reason reason, String message,
            org.junit.jupiter.api.function.Executable call) {
        CredentialCryptoException failure = assertThrows(CredentialCryptoException.class, call);
        assertEquals(reason, failure.getReason());
        assertTrue(failure.getMessage().contains(message), failure.getMessage());
    }

    // ===== 외부 공급원 pass 키: 지문 고정과 Fail Closed =====

    @Test
    void passKeyFromAFileIsPinnedAndAChangedPassphraseFailsClosed() throws Exception {
        Path passFile = Files.write(dir.resolve("app.pass"), "dummy-app-passphrase\n".getBytes(StandardCharsets.UTF_8));
        byte[] salt = PassKdf.newSalt();
        Path config = TestSupport.writeManagedConfig(dir, "pass-file.properties", profileLines("app-pass", "file",
                "file=" + TestSupport.propertiesPath(passFile), salt, pin("dummy-app-passphrase", salt)).toArray(new String[0]));
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        String token = crypto.withKeyId("app-pass").encryptText("dummy-db-pw");
        assertTrue(token.startsWith("ENC[v1:app-pass:"));
        assertEquals("dummy-db-pw", crypto.decryptText(token));
        assertEquals("test-pass", crypto.keyId(), "키를 추가해도 기본 키는 바뀌지 않는다");

        // 같은 Key ID로 Passphrase가 바뀌면 다른 키로 조용히 동작하지 않고 실패한다(값을 바꾸려면 새 Key ID로 회전).
        Files.write(passFile, "dummy-changed-passphrase\n".getBytes(StandardCharsets.UTF_8));
        CredentialCrypto reloaded = CredentialCrypto.fromConfigFile(config);
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> reloaded.decryptText(token));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
        assertTrue(ex.getMessage().contains("app-pass"), ex.getMessage());
        assertFalse(ex.getMessage().contains("dummy-changed-passphrase") || ex.getMessage().contains(passFile.toString()));
        KeyInfo info = reloaded.keys().stream().filter(k -> "app-pass".equals(k.keyId())).findFirst().orElse(null);
        assertNotNull(info);
        assertFalse(info.isAvailable());
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, info.failureReason());
        assertNull(info.fingerprint(), "읽지 못한 키는 지문을 만들지 않는다");
        // 다른 키(공개 기본 키)는 그대로 쓸 수 있다(한 키의 실패가 다른 유형에 영향을 주지 않음).
        assertEquals("x", reloaded.decryptText(reloaded.encryptText("x")));
    }

    @Test
    void passKeyFromAnEnvironmentVariableDerivesAtRuntime() throws Exception {
        String value = System.getenv(TestSupport.ENV_TEST_KEY);
        org.junit.jupiter.api.Assumptions.assumeTrue(value != null, "Gradle test 태스크가 넣는 테스트용 환경변수가 필요하다");
        byte[] salt = PassKdf.newSalt();
        Path config = TestSupport.writeConfig(dir, "pass-env.properties", profileLines("env-pass", "env",
                "env=" + TestSupport.ENV_TEST_KEY, salt, pin(value, salt)).toArray(new String[0]));
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        assertEquals("dummy", crypto.decryptText(crypto.withKeyId("env-pass").encryptText("dummy")));
        KeyProfile profile = TestSupport.isolatedSettings(config).profile("env-pass");
        assertTrue(profile.derivesAtRuntime());
    }

    @Test
    void publicPassphraseIsRejectedRegardlessOfKdfSettings() throws Exception {
        String publicPassphrase = "java-crypto-kit-public-passphrase-v1";
        Path passFile = Files.write(dir.resolve("public.pass"), publicPassphrase.getBytes(StandardCharsets.UTF_8));
        byte[] originalSalt = Base64.getDecoder().decode("Bt9HhTFtDOVUgGsvFtnzMw==");
        byte[] changedSalt = originalSalt.clone();
        changedSalt[0] ^= 1;
        char[] passphrase = publicPassphrase.toCharArray();
        try {
            for (byte[] salt : new byte[][] {originalSalt, changedSalt}) {
                for (int iterations : new int[] {600_000, ITERATIONS}) {
                    byte[] key = PassKdf.derive(passphrase, salt, iterations);
                    List<String> lines;
                    try {
                        lines = profileLines("moved", "file", "file=" + TestSupport.propertiesPath(passFile),
                                salt, KeyResolver.fingerprint(key));
                    } finally {
                        Arrays.fill(key, (byte) 0);
                    }
                    lines.replaceAll(line -> line.replace("kdf.iterations=" + ITERATIONS, "kdf.iterations=" + iterations));
                    lines.add("crypto.warning.enabled=false");
                    Path config = TestSupport.writeConfig(dir, "moved.properties", lines.toArray(new String[0]));
                    CredentialCrypto managed = CredentialCrypto.fromConfigFile(config).withKeyId("moved");
                    CredentialCryptoException failure = assertThrows(CredentialCryptoException.class,
                            () -> managed.encryptText("x"));
                    assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, failure.getReason());
                    assertTrue(failure.getMessage().contains(Messages.get("key.err.publicPassphrase")));
                    assertFalse(failure.getMessage().contains(publicPassphrase));
                    assertFalse(failure.getMessage().contains(passFile.toString()));
                }
            }

            CredentialCrypto independent = CredentialCrypto.fromPassphrase("caller-key", passphrase, changedSalt, ITERATIONS);
            assertEquals("x", independent.decryptText(independent.encryptText("x")));
        } finally {
            Arrays.fill(passphrase, '\0');
        }
    }

    // ===== 설정 검증 =====

    @Test
    void invalidProfilesFailAtLoadingWithoutEchoingValues() throws Exception {
        byte[] salt = PassKdf.newSalt();
        String path = "file=" + TestSupport.propertiesPath(dir.resolve("x.pass"));
        String fp = pin("x", salt);
        assertInvalid("no-type", "crypto.keys.k1.source=embedded");
        assertInvalid("bad-type", "crypto.keys.k1.type=aes", "crypto.keys.k1.source=embedded");
        assertInvalid("no-pin", without(profileLines("k1", "file", path, salt, fp), ".fingerprint="));
        assertInvalid("no-salt", without(profileLines("k1", "file", path, salt, fp), ".salt="));
        List<String> lowIterations = profileLines("k1", "file", path, salt, fp);
        lowIterations.replaceAll(line -> line.replace("kdf.iterations=" + ITERATIONS, "kdf.iterations=99999"));
        assertInvalid("low-iterations", lowIterations);
        List<String> shortSalt = profileLines("k1", "file", path, salt, fp);
        shortSalt.replaceAll(line -> line.startsWith("crypto.keys.k1.salt=") ? "crypto.keys.k1.salt=AAAA" : line);
        assertInvalid("short-salt", shortSalt);
        assertInvalid("kdf-on-key", "crypto.keys.k1.type=key", "crypto.keys.k1.source=embedded",
                "crypto.keys.k1.embedded=" + Base64.getEncoder().encodeToString(new byte[32]), "crypto.keys.k1.kdf=pbkdf2-sha256");
        assertInvalid("wrong-location-item", "crypto.keys.k1.type=key", "crypto.keys.k1.source=file",
                "crypto.keys.k1.env=SOME_ENV", "crypto.keys.k1.fingerprint=" + fp);
        // 템플릿 Key ID가 crypto.key.*의 Key ID와 같으면 같은 Key ID가 두 키를 가리키게 되므로 거부한다.
        assertInvalid("id-conflict", "crypto.key.embedded=" + TestSupport.publicKeyBase64(), "crypto.keys.default.type=key", "crypto.keys.default.source=embedded",
                "crypto.keys.default.embedded=" + Base64.getEncoder().encodeToString(new byte[32]));
        // 기본 키 지정: 없는 Key ID, 다른 유형
        assertInvalid("active-missing", "crypto.key.active.pass=nope");
        assertInvalid("active-type", "crypto.key.active.pass=default");
        assertInvalid("active-key-type", "crypto.key.active.key=pass-default");
        // JAR에 등록된 키의 정체 항목(Salt 등)은 외부 설정이 바꿀 수 없다(위치 항목만 바꿀 수 있음).
        assertInvalid("immutable", "crypto.keys.pass-default.salt=" + Base64.getEncoder().encodeToString(salt));
        assertInvalid("bad-default-type", "crypto.key.type=aes");
    }

    @Test
    void jvmPropertiesMayMoveARegisteredKeyButNeverChangeItsIdentity() throws Exception {
        Path passFile = Files.write(dir.resolve("a.pass"), "dummy-a\n".getBytes(StandardCharsets.UTF_8));
        Path moved = Files.write(dir.resolve("moved.pass"), "dummy-a\n".getBytes(StandardCharsets.UTF_8));
        byte[] salt = PassKdf.newSalt();
        Path config = TestSupport.writeConfig(dir, "jvm.properties", profileLines("app", "file",
                "file=" + TestSupport.propertiesPath(passFile), salt, pin("dummy-a", salt)).toArray(new String[0]));
        Map<String, String> jvm = new HashMap<>();
        jvm.put("crypto.keys.app.file", TestSupport.propertiesPath(moved));
        CryptoSettings settings = CryptoSettings.load(config.toString(), jvm::get, name -> null, jvm.keySet());
        assertEquals(TestSupport.propertiesPath(moved), settings.profile("app").value(KeyProfile.FILE));
        assertEquals(CryptoSettings.ValueOrigin.JVM_PROPERTY, settings.valueOrigin("crypto.keys.app.file"));
        assertEquals("x", CryptoService.of(settings).decryptText(CryptoService.of(settings).encryptText("x".toCharArray(), null, "app")));
        // 정체 항목·미등록 Key ID·오타는 -D로 받지 않는다(정책과 관계없이 오류).
        for (String name : new String[] {"crypto.keys.app.salt", "crypto.keys.app.type", "crypto.keys.app.fingerprint",
                "crypto.keys.pass-default.embedded", "crypto.keys.nope.file", "crypto.keys.app.fiel"}) {
            Map<String, String> bad = new HashMap<>();
            bad.put(name, "dummy-value-123");
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> CryptoSettings.load(config.toString(), bad::get, n -> null, bad.keySet()), name);
            assertFalse(ex.getMessage().contains("dummy-value-123"), "값은 출력하지 않는다: " + ex.getMessage());
        }
        // 기본 유형·유형별 기본 키는 -D로 바꿀 수 있다.
        Map<String, String> active = new HashMap<>();
        active.put("crypto.key.type", "key");
        active.put("crypto.key.active.pass", "app");
        CryptoSettings switched = CryptoSettings.load(config.toString(), active::get, n -> null, active.keySet());
        assertEquals(KeyType.KEY, switched.defaultType());
        assertEquals("app", switched.activeProfile(KeyType.PASS).id());
        assertNull(switched.activeProfile(KeyType.KEY));
    }

    // ===== 한 JAR 안의 pass·key 동시·독립 동작 =====

    @Test
    void passAndKeyRunConcurrentlyAndIndependentlyInOneJar() throws Exception {
        Path aesKey = TestSupport.writeRandomKeyFile(dir, "biz.key");
        Path passFile = Files.write(dir.resolve("biz.pass"), "dummy-biz-pass\n".getBytes(StandardCharsets.UTF_8));
        byte[] salt = PassKdf.newSalt();
        List<String> lines = new ArrayList<>(profileLines("biz-pass", "file", "file=" + TestSupport.propertiesPath(passFile),
                salt, pin("dummy-biz-pass", salt)));
        lines.add("crypto.key.source=file");
        lines.add("crypto.key.id=biz-aes");
        lines.add("crypto.key.file=" + TestSupport.propertiesPath(aesKey));
        lines.add("crypto.key.active.pass=biz-pass");
        lines.add("crypto.warning.enabled=false");
        Path config = TestSupport.writeManagedConfig(dir, "both.properties", lines.toArray(new String[0]));
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        assertEquals("biz-pass", crypto.keyId(), "유형 미지정 = pass 기본 키");
        assertEquals("file", crypto.keySource());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                final int thread = t;
                results.add(pool.submit((Callable<Boolean>) () -> {
                    for (int i = 0; i < 40; i++) {
                        String value = "dummy-" + thread + "-" + i;
                        KeyType type = (i + thread) % 2 == 0 ? KeyType.PASS : KeyType.KEY;
                        String token = crypto.encryptText(value, type);
                        String expectedId = type == KeyType.PASS ? "biz-pass" : "biz-aes";
                        if (!token.startsWith("ENC[v1:" + expectedId + ":")) return false;
                        if (!value.equals(crypto.decryptText(token))) return false;
                    }
                    return true;
                }));
            }
            for (Future<Boolean> result : results) assertTrue(result.get(), "모든 스레드에서 유형별 키가 섞이지 않아야 한다");
        } finally {
            pool.shutdownNow();
        }
        // 한 유형의 기본 키를 바꿔도 다른 유형은 그대로다.
        lines.set(lines.indexOf("crypto.key.active.pass=biz-pass"), "crypto.key.active.pass=test-pass");
        CredentialCrypto changed = CredentialCrypto.fromConfigFile(
                TestSupport.writeManagedConfig(dir, "both2.properties", lines.toArray(new String[0])));
        assertEquals("test-pass", changed.keyId());
        assertTrue(changed.encryptText("x", KeyType.KEY).startsWith("ENC[v1:biz-aes:"), "key 유형 기본은 그대로");
    }

    // ===== 이전 형식 설정·JAR·암호문 호환(회귀) =====

    @Test
    void legacyConfigurationDecryptsOldCiphertextWithoutExtraSettings() throws Exception {
        // 이전 형식에서 만든 회사 AES 키 설정(crypto.key.*만, crypto.key.type 없음)과 그 설정으로 만든 기존 암호문
        Path key = TestSupport.writeRandomKeyFile(dir, "key01.key");
        Path legacy = TestSupport.writeConfig(dir, "legacy.properties", "crypto.key.source=file", "crypto.key.id=key01",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.warning.enabled=false");
        String oldToken = CryptoService.of(TestSupport.isolatedSettings(legacy))
                .encryptText("dummy-old-pw".toCharArray(), KeyType.KEY, null);
        assertTrue(oldToken.startsWith("ENC[v1:key01:"));
        // 추가 설정 없이 그대로 복호화된다(암호문의 Key ID로 자동 선택).
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(legacy);
        assertEquals("dummy-old-pw", crypto.decryptText(oldToken));
        assertTrue(crypto.verify(oldToken));
        // --type key(KEY)는 공개 키가 아니라 사용자 지정 AES 키(key01)를 쓴다.
        String newAes = crypto.encryptText("dummy-new", KeyType.KEY);
        assertTrue(newAes.startsWith("ENC[v1:key01:"), newAes);
        assertFalse(crypto.keys().get(0).isPublicDefault(), "crypto.key.* 키는 사용자 지정 키");
        // 유형 미지정 기본은 pass(승인된 기본값). 이전처럼 AES 키를 기본으로 쓰려면 crypto.key.type=key.
        assertNull(crypto.keyId());
        Path migrated = TestSupport.writeConfig(dir, "migrated.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.id=key01", "crypto.key.file=" + TestSupport.propertiesPath(key));
        assertEquals("key01", CredentialCrypto.fromConfigFile(migrated).keyId());
        assertEquals("file", CredentialCrypto.fromConfigFile(migrated).keySource());
    }

    @Test
    void legacyJarSettingsWithoutKeyringKeepKeyAsTheDefaultType() throws Exception {
        // 이전 형식 JAR의 내장 설정(키 목록 항목 없음): crypto.key.type이 없으면 key가 기본이다.
        Properties jar = new Properties();
        try (java.io.Reader reader = new java.io.InputStreamReader(
                KeyringTest.class.getResourceAsStream("/java-crypto-kit.properties"), StandardCharsets.UTF_8)) {
            jar.load(reader);
        }
        for (String name : new ArrayList<>(jar.stringPropertyNames())) {
            if (name.startsWith("crypto.keys.") || name.startsWith("crypto.key.active.") || name.equals("crypto.key.type")) {
                jar.remove(name);
            }
        }
        jar.setProperty("crypto.key.embedded", TestSupport.managedSettings()[0].split("=", 2)[1]);
        CryptoSettings settings = CryptoSettings.fromEmbeddedDefaults(jar);
        assertEquals(KeyType.KEY, settings.defaultType());
        assertEquals(1, settings.profiles().size());
        assertNull(settings.activeProfile(KeyType.PASS));
        CryptoService service = CryptoService.of(settings);
        assertTrue(service.encryptText("x".toCharArray()).startsWith("ENC[v1:default:"), "이전 형식와 같은 키·Key ID");
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> service.encryptText("x".toCharArray(), KeyType.PASS, null));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason(), "pass 키가 없으면 다른 키로 바꾸지 않는다");
    }

    // (이전 형식 공개 AES 키의 고정 v1 암호문 회귀 벡터는 TokenCodecTest가 JAR 기본값으로 계속 확인한다.)

    // ===== 도우미 =====

    /** pass 유형 외부 키 프로필 설정 줄(시험용 반복 횟수). */
    private static List<String> profileLines(String id, String source, String location, byte[] salt, String fingerprint) {
        String p = "crypto.keys." + id + ".";
        return new ArrayList<>(Arrays.asList(p + "type=pass", p + "source=" + source, p + location,
                p + "kdf=pbkdf2-sha256", p + "kdf.iterations=" + ITERATIONS,
                p + "salt=" + Base64.getEncoder().encodeToString(salt), p + "fingerprint=" + fingerprint));
    }

    /** Passphrase로 파생한 키의 지문(등록할 때 고정하는 값). */
    private static String pin(String passphrase, byte[] salt) {
        return KeyResolver.fingerprint(PassKdf.derive(PassKdf.normalize(passphrase.toCharArray()), salt, ITERATIONS));
    }

    private static List<String> without(List<String> lines, String marker) {
        List<String> kept = new ArrayList<>();
        for (String line : lines) if (!line.contains(marker)) kept.add(line);
        return kept;
    }

    private void assertInvalid(String name, String... lines) throws IOException {
        assertInvalid(name, Arrays.asList(lines));
    }

    private void assertInvalid(String name, List<String> lines) throws IOException {
        Path config = TestSupport.writeConfig(dir, name + ".properties", lines.toArray(new String[0]));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> CredentialCrypto.fromConfigFile(config),
                name);
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason(), name);
        assertFalse(ex.getMessage().contains(dir.toString()), "경로를 출력하지 않는다: " + ex.getMessage());
    }
}
