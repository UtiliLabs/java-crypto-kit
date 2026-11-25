package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestKeytool;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.jwt.JwtVerifier;
import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ADD-KS-01(N08·N09): keytool로 만든 PKCS12·JKS(별도 엔트리 비밀번호 포함)의 별칭·엔트리 종류·개인키·인증서·체인 읽기, 틀린
 * 비밀번호·없는 별칭·엔트리 종류·형식 불일치·손상 거부, 입력 파일 불변, 스트림 소유권, 꺼낸 키를 서명·RSA-OAEP·Hybrid·JWT에 연결.
 * 환경변수 {@code JCK_OTHER_JAVA_HOME}(다른 JDK)이 있으면 그 JDK로 만든 저장소를 읽는 교차 시험도 한다(없으면 건너뜀).
 */
class KeyStoreReaderTest {
    private static final char[] PASS = TestKeytool.STORE_PASS.toCharArray();
    private static final char[] KEY_PASS = "dummy-entry-pass".toCharArray();

    @TempDir
    Path dir;

    private void stores(String javaHome, Path target) throws Exception {
        String[] p12 = {"-storetype", "PKCS12", "-storepass", TestKeytool.STORE_PASS, "-keypass", TestKeytool.STORE_PASS, "-keystore", "store.p12"};
        TestKeytool.runWith(javaHome, target, concat(new String[] {"-genkeypair", "-alias", "signer", "-keyalg", "RSA", "-keysize", "2048",
            "-sigalg", "SHA256withRSA", "-dname", "CN=signer", "-validity", "30"}, p12));
        TestKeytool.runWith(javaHome, target, concat(new String[] {"-genkeypair", "-alias", "ec-signer", "-keyalg", "EC", "-keysize", "256",
            "-sigalg", "SHA256withECDSA", "-dname", "CN=ec-signer", "-validity", "30"}, p12));
        TestKeytool.runWith(javaHome, target, concat(new String[] {"-exportcert", "-alias", "signer", "-rfc", "-file", "signer.pem"}, p12));
        TestKeytool.runWith(javaHome, target, concat(new String[] {"-importcert", "-alias", "trusted", "-file", "signer.pem", "-noprompt"},
            new String[] {"-storetype", "PKCS12", "-storepass", TestKeytool.STORE_PASS, "-keystore", "trust.p12"}));
        TestKeytool.runWith(javaHome, target, "-genkeypair", "-alias", "signer", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
            "-dname", "CN=jks-signer", "-validity", "30", "-storetype", "JKS", "-storepass", TestKeytool.STORE_PASS,
            "-keypass", new String(KEY_PASS), "-keystore", "store.jks");
    }

    private static String[] concat(String[] a, String[] b) {
        String[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String reason(ThrowingRunnable action) {
        try {
            action.run();
        } catch (KeyStoreException e) {
            return e.getMessage();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        throw new AssertionError("KeyStoreException이 나야 한다");
    }

    interface ThrowingRunnable {
        void run() throws Exception;
    }

    @Test
    void readsEntriesAndConnectsKeysToSignaturesEncryptionAndJwt() throws Exception {
        stores(System.getProperty("java.home"), dir);
        Path p12 = dir.resolve("store.p12");
        byte[] before = Files.readAllBytes(p12);
        KeyStoreReader store = KeyStoreReader.load(p12, KeyStoreType.PKCS12, PASS);
        assertEquals(Arrays.asList("ec-signer", "signer"), store.aliases());
        assertTrue(store.isPrivateKeyEntry("signer"));
        assertFalse(store.isCertificateEntry("signer"));
        PrivateKey rsa = store.privateKey("signer", PASS);
        assertEquals("RSA", rsa.getAlgorithm());
        assertEquals("CN=signer", store.certificate("signer").getSubjectX500Principal().getName());
        assertEquals(1, store.certificateChain("signer").size());
        byte[] sig = Signatures.sign(SignatureAlgorithm.RSA_SHA256, rsa, "msg");
        assertTrue(Signatures.verify(SignatureAlgorithm.RSA_SHA256, store.publicKey("signer"), "msg".getBytes(StandardCharsets.UTF_8), sig));
        assertArrayEquals("dummy".getBytes(StandardCharsets.UTF_8), RsaOaep.decrypt(rsa, RsaOaep.encrypt(store.publicKey("signer"), "dummy".getBytes(StandardCharsets.UTF_8))));
        assertEquals("hybrid", HybridEncryption.decryptText(rsa, HybridEncryption.encryptText(store.publicKey("signer"), "hybrid", Encoding.BASE64), Encoding.BASE64));
        PrivateKey ec = store.privateKey("ec-signer", PASS);
        String jwt = Jwt.builder().audience("api").expiresIn(Duration.ofMinutes(1)).sign(JwtKey.es256(ec));
        assertEquals("api", JwtVerifier.builder().key(JwtKey.es256(store.publicKey("ec-signer"))).audience("api").build().verify(jwt).claims().audience().get(0));
        KeyStoreReader trust = KeyStoreReader.load(dir.resolve("trust.p12"), KeyStoreType.PKCS12, PASS);
        assertTrue(trust.isCertificateEntry("trusted"));
        assertTrue(reason(() -> trust.privateKey("trusted", PASS)).contains("개인키 엔트리가 아닙니다"));
        assertEquals(store.certificate("signer"), trust.certificate("trusted"));
        assertArrayEquals(before, Files.readAllBytes(p12), "저장소 파일 불변");
    }

    @Test
    void jksWithSeparateEntryPasswordAndChains() throws Exception {
        stores(System.getProperty("java.home"), dir);
        KeyStoreReader jks = KeyStoreReader.load(dir.resolve("store.jks"), KeyStoreType.JKS, PASS);
        assertTrue(reason(() -> jks.privateKey("signer", PASS)).contains("키 엔트리 비밀번호가 틀렸습니다"));
        assertEquals("RSA", jks.privateKey("signer", KEY_PASS).getAlgorithm());
        TestKeytool.caAndServer(dir, "dns:localhost");
        KeyStoreReader server = KeyStoreReader.load(dir.resolve("server.p12"), KeyStoreType.PKCS12, PASS);
        List<X509Certificate> chain = server.certificateChain("server");
        assertEquals(2, chain.size(), "서버 + CA");
        assertEquals("CN=JCK Test Root", chain.get(1).getSubjectX500Principal().getName());
    }

    @Test
    void rejectsWrongPasswordsTypesAliasesAndDamage() throws Exception {
        stores(System.getProperty("java.home"), dir);
        Path p12 = dir.resolve("store.p12");
        Path jks = dir.resolve("store.jks");
        assertTrue(reason(() -> KeyStoreReader.load(p12, KeyStoreType.PKCS12, "wrong-pass".toCharArray())).contains("비밀번호가 틀렸습니다"));
        assertTrue(reason(() -> KeyStoreReader.load(jks, KeyStoreType.JKS, "wrong-pass".toCharArray())).contains("비밀번호가 틀렸습니다"));
        assertTrue(reason(() -> KeyStoreReader.load(jks, KeyStoreType.PKCS12, PASS)).contains("읽을 수 없습니다"), "형식 지정이 다르면 거부");
        assertTrue(reason(() -> KeyStoreReader.load(p12, KeyStoreType.JKS, PASS)).contains("읽을 수 없습니다"));
        byte[] content = Files.readAllBytes(p12);
        assertTrue(reason(() -> KeyStoreReader.load(Arrays.copyOf(content, content.length / 2), KeyStoreType.PKCS12, PASS)).contains("읽을 수 없습니다"));
        KeyStoreReader store = KeyStoreReader.load(content, KeyStoreType.PKCS12, PASS);
        assertTrue(reason(() -> store.privateKey("none", PASS)).contains("별칭이 없습니다"));
        assertTrue(reason(() -> store.certificate("none")).contains("별칭이 없습니다"));
        assertThrows(IllegalArgumentException.class, () -> KeyStoreReader.load(p12, KeyStoreType.PKCS12, null), "null 비밀번호 거부");
        assertThrows(IllegalArgumentException.class, () -> store.privateKey("signer", null));
        assertThrows(java.nio.file.NoSuchFileException.class, () -> KeyStoreReader.load(dir.resolve("missing.p12"), KeyStoreType.PKCS12, PASS));
        // 스트림은 닫지 않는다(호출자 소유)
        boolean[] closed = {false};
        InputStream tracked = new FilterInputStream(new ByteArrayInputStream(content)) {
            @Override
            public void close() {
                closed[0] = true;
            }
        };
        KeyStoreReader.load(tracked, KeyStoreType.PKCS12, PASS);
        assertFalse(closed[0]);
        String message = reason(() -> KeyStoreReader.load(p12, KeyStoreType.PKCS12, "wrong-pass".toCharArray()));
        assertFalse(message.contains(p12.toString()) || message.contains(TestKeytool.STORE_PASS), "경로·비밀번호 비노출");
        assertArrayEquals(TestKeytool.STORE_PASS.toCharArray(), PASS, "호출자 비밀번호 배열 불변");
    }

    /**
     * 오래된 Java 8 업데이트(예: 8u202)는 최신 JDK 기본 PKCS12의 PBES2 매개변수를 해석하지 못하고 형식 오류처럼 IOException을 던진다.
     * 그 Java에서 PBES2 저장소는 "손상"이 아니라 "지원하지 않는 보호 알고리즘"으로, PBES2를 읽는 Java에서는 그대로 형식 오류로 알린다.
     */
    @Test
    void unparsablePbes2OnOldJavaIsReportedAsUnsupportedNotCorrupted() {
        byte[] pbes2Oid = {0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x05, 0x0D};
        byte[] pbes2Store = concatBytes(new byte[] {0x30, 0x10, 0x02, 0x01, 0x03}, pbes2Oid);
        byte[] otherStore = {0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x0A, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03};
        java.io.IOException parse = new java.io.IOException("parseAlgParameters failed", new java.io.IOException("not an object ID"));
        assertEquals("sec.err.ksUnsupported", KeyStoreReader.classify(parse, KeyStoreType.PKCS12, pbes2Store, false));
        assertEquals("sec.err.ksFormat", KeyStoreReader.classify(parse, KeyStoreType.PKCS12, pbes2Store, true), "PBES2를 읽는 Java에서는 형식 오류");
        assertEquals("sec.err.ksFormat", KeyStoreReader.classify(parse, KeyStoreType.PKCS12, otherStore, false), "PBES2가 아니면 형식 오류");
        assertEquals("sec.err.ksFormat", KeyStoreReader.classify(parse, KeyStoreType.JKS, pbes2Store, false));
        assertEquals("sec.err.ksPassword", KeyStoreReader.classify(new java.io.IOException("x",
                new java.security.UnrecoverableKeyException("p")), KeyStoreType.PKCS12, pbes2Store, false));
        assertEquals("sec.err.ksUnsupported", KeyStoreReader.classify(new java.io.IOException("x",
                new java.security.NoSuchAlgorithmException("m")), KeyStoreType.PKCS12, otherStore, true));
    }

    private static byte[] concatBytes(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void storesCreatedByAnotherJdkAreReadOrRejectedClearly() throws Exception {
        String other = System.getenv("JCK_OTHER_JAVA_HOME");
        assumeTrue(other != null && !other.isEmpty(), "JCK_OTHER_JAVA_HOME이 없으면 건너뜀");
        stores(other, dir);
        // 최신 JDK 기본 PKCS12(PBES2·HmacPBESHA256)를 오래된 Java 8이 못 읽는 경우의 표준 해결: 만들 때 이전 호환 알고리즘 선택
        TestKeytool.runWith(other, dir, "-J-Dkeystore.pkcs12.legacy", "-genkeypair", "-alias", "signer", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", "CN=legacy", "-validity", "30", "-storetype", "PKCS12", "-storepass", TestKeytool.STORE_PASS,
                "-keypass", TestKeytool.STORE_PASS, "-keystore", "legacy.p12");
        for (String[] spec : new String[][] {{"store.p12", "PKCS12"}, {"store.jks", "JKS"}, {"legacy.p12", "PKCS12"}}) {
            KeyStoreType type = KeyStoreType.valueOf(spec[1]);
            String result;
            try {
                KeyStoreReader store = KeyStoreReader.load(dir.resolve(spec[0]), type, PASS);
                PrivateKey key = store.privateKey("signer", type == KeyStoreType.JKS ? KEY_PASS : PASS);
                byte[] sig = Signatures.sign(SignatureAlgorithm.RSA_SHA256, key, "x");
                result = Signatures.verify(SignatureAlgorithm.RSA_SHA256, store.publicKey("signer"), "x".getBytes(StandardCharsets.UTF_8), sig) ? "READ" : "BAD";
            } catch (KeyStoreException e) {
                assertTrue(e.getMessage().contains("지원하지 않는 키 저장소 보호 알고리즘"), e.getMessage());
                result = "UNSUPPORTED";
            }
            System.out.println("KS-CROSS creator=" + other + " reader=" + System.getProperty("java.version") + " " + spec[1] + " " + result);
            assertFalse("BAD".equals(result));
            if (spec[0].equals("legacy.p12") || spec[0].equals("store.jks")) assertEquals("READ", result, spec[0] + "는 두 JDK 모두 읽어야 한다");
        }
    }
}
