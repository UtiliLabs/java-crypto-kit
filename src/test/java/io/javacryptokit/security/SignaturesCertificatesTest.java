package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.TestKeytool;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * SIG-01·CERT-01: 독립 구현(Python cryptography)이 만든 RSA·ECDSA 서명 검증, DER ↔ R‖S 경계(r·s 범위, 비정규 DER), 키 종류·길이·
 * 곡선 거부, PKCS#8·SPKI PEM/DER 읽기·쓰기와 미지원 형식 거부, keytool로 만든 CA·서버 인증서의 분석과 PKIX 체인 검증.
 */
class SignaturesCertificatesTest {
    @TempDir
    Path dir;

    static Properties vectors() throws IOException {
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(SignaturesCertificatesTest.class.getResourceAsStream(
                "/io/javacryptokit/jwt/independent-vectors.properties"), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    static String pem(Properties p, String key) {
        return p.getProperty(key).replace('|', '\n');
    }

    @Test
    void verifiesSignaturesMadeByAnIndependentImplementation() throws Exception {
        Properties p = vectors();
        PublicKey rsa = PemKeys.readPublicKey(pem(p, "py.rsa.spki"));
        PublicKey ec = PemKeys.readPublicKey(pem(p, "py.ec.spki"));
        String message = "dummy-서명-원문";
        assertTrue(Signatures.verify(SignatureAlgorithm.RSA_SHA256, rsa, message, p.getProperty("py.rsa.msg.sig"), Encoding.BASE64));
        assertTrue(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, ec, message, p.getProperty("py.ec.msg.sig.der"), Encoding.BASE64));
        assertFalse(Signatures.verify(SignatureAlgorithm.RSA_SHA256, rsa, message + "!", p.getProperty("py.rsa.msg.sig"), Encoding.BASE64));
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, ec, message + "!", p.getProperty("py.ec.msg.sig.der"), Encoding.BASE64));
        // DER 서명을 R‖S 형식으로 검증하면 실패(형식을 추측해 바꾸지 않음)
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, ec, message, p.getProperty("py.ec.msg.sig.der"), Encoding.BASE64));
        assertThrows(IllegalArgumentException.class, () -> Signatures.verify(SignatureAlgorithm.RSA_SHA256, ec, message, "AA", Encoding.BASE64),
                "키 종류가 알고리즘과 다름");
    }

    @Test
    void signAndVerifyAllAlgorithmsIncludingFilesAndFormats() throws Exception {
        byte[] data = "dummy-전문-데이터".getBytes(StandardCharsets.UTF_8);
        byte[] big = new byte[150_000];
        Arrays.fill(big, (byte) 7);
        Path file = Files.write(dir.resolve("doc.bin"), big);
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            KeyPair pair = algorithm == SignatureAlgorithm.RSA_SHA256 ? Signatures.generateRsaKeyPair(2048) : Signatures.generateKeyPair(algorithm);
            byte[] sig = Signatures.sign(algorithm, pair.getPrivate(), data);
            assertTrue(Signatures.verify(algorithm, pair.getPublic(), data, sig), algorithm.name());
            byte[] tampered = data.clone();
            tampered[0] ^= 1;
            assertFalse(Signatures.verify(algorithm, pair.getPublic(), tampered, sig));
            for (Encoding encoding : new Encoding[] {Encoding.HEX, Encoding.BASE64, Encoding.BASE64_URL}) {
                assertTrue(Signatures.verify(algorithm, pair.getPublic(), "텍스트", Signatures.sign(algorithm, pair.getPrivate(), "텍스트", encoding), encoding));
            }
            byte[] fileSig = Signatures.signFile(algorithm, pair.getPrivate(), file);
            assertTrue(Signatures.verifyFile(algorithm, pair.getPublic(), file, fileSig));
            assertTrue(Signatures.verify(algorithm, pair.getPublic(), big, fileSig), "파일 서명 = 같은 바이트 서명");
            assertFalse(Signatures.verifyFile(algorithm, pair.getPublic(), file, sig));
            assertFalse(Signatures.verify(algorithm, pair.getPublic(), data, (byte[]) null));
            assertFalse(Signatures.verify(algorithm, pair.getPublic(), data, new byte[0]));
            if (algorithm == SignatureAlgorithm.ECDSA_P256_SHA256_P1363) assertEquals(64, sig.length);
        }
        assertArrayEquals(big, Files.readAllBytes(file), "파일은 바뀌지 않는다");
    }

    @Test
    void ecdsaSignatureEdgeCasesAreRejected() {
        KeyPair pair = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        byte[] data = "x".getBytes(StandardCharsets.US_ASCII);
        // r = s = 0(R‖S) — 'psychic signature' 유형
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, pair.getPublic(), data, new byte[64]));
        // r = n(범위 밖)
        byte[] n = Signatures.P256_N.toByteArray();
        byte[] rsN = new byte[64];
        System.arraycopy(n, n.length - 32, rsN, 0, 32);
        rsN[63] = 1;
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, pair.getPublic(), data, rsN));
        // DER r = 0
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, pair.getPublic(), data, new byte[] {0x30, 6, 2, 1, 0, 2, 1, 1}));
        // 비정규 DER(불필요한 0 패딩) — 같은 값이라도 거부(서명 문자열 변형 방지)
        byte[] der = Signatures.sign(SignatureAlgorithm.ECDSA_P256_SHA256, pair.getPrivate(), data);
        assertTrue(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, pair.getPublic(), data, der));
        byte[] padded = padFirstInteger(der);
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, pair.getPublic(), data, padded));
        byte[] trailing = Arrays.copyOf(der, der.length + 1);
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256, pair.getPublic(), data, trailing));
        assertFalse(Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, pair.getPublic(), data, new byte[63]));
    }

    private static byte[] padFirstInteger(byte[] der) {
        int rLength = der[3];
        byte[] out = new byte[der.length + 1];
        out[0] = 0x30;
        out[1] = (byte) (der[1] + 1);
        out[2] = 0x02;
        out[3] = (byte) (rLength + 1);
        out[4] = 0;
        System.arraycopy(der, 4, out, 5, der.length - 4);
        return out;
    }

    @Test
    void weakOrForeignKeysAreRejected() throws Exception {
        KeyPairGenerator rsa1024 = KeyPairGenerator.getInstance("RSA");
        rsa1024.initialize(1024);
        KeyPair weak = rsa1024.generateKeyPair();
        assertThrows(IllegalArgumentException.class, () -> Signatures.sign(SignatureAlgorithm.RSA_SHA256, weak.getPrivate(), new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(PemKeys.toPem(weak.getPublic())));
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = ec.generateKeyPair();
        assertThrows(IllegalArgumentException.class, () -> Signatures.sign(SignatureAlgorithm.ECDSA_P256_SHA256, p384.getPrivate(), new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(PemKeys.toPem(p384.getPublic())));
        KeyPair rsa = Signatures.generateRsaKeyPair(2048);
        assertThrows(IllegalArgumentException.class, () -> Signatures.sign(SignatureAlgorithm.ECDSA_P256_SHA256, rsa.getPrivate(), new byte[1]));
        assertThrows(IllegalArgumentException.class, () -> Signatures.generateRsaKeyPair(1024));
        assertEquals(3072, ((java.security.interfaces.RSAKey) Signatures.generateKeyPair(SignatureAlgorithm.RSA_SHA256).getPublic()).getModulus().bitLength());
    }

    @Test
    void pemAndDerRoundTripAndUnsupportedFormatsAreExplained() throws Exception {
        for (SignatureAlgorithm algorithm : new SignatureAlgorithm[] {SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.ECDSA_P256_SHA256}) {
            KeyPair pair = algorithm == SignatureAlgorithm.RSA_SHA256 ? Signatures.generateRsaKeyPair(2048) : Signatures.generateKeyPair(algorithm);
            String privatePem = PemKeys.toPem(pair.getPrivate());
            String publicPem = PemKeys.toPem(pair.getPublic());
            assertTrue(privatePem.startsWith("-----BEGIN PRIVATE KEY-----\n") && privatePem.endsWith("-----END PRIVATE KEY-----\n"));
            assertTrue(publicPem.startsWith("-----BEGIN PUBLIC KEY-----\n"));
            assertArrayEquals(pair.getPrivate().getEncoded(), PemKeys.readPrivateKey(privatePem).getEncoded());
            assertArrayEquals(pair.getPublic().getEncoded(), PemKeys.readPublicKey(publicPem).getEncoded());
            assertArrayEquals(pair.getPrivate().getEncoded(), PemKeys.readPrivateKey(PemKeys.toDer(pair.getPrivate())).getEncoded());
            Path pemFile = Files.write(dir.resolve(algorithm + ".pem"), ("설명 텍스트\r\n" + privatePem).getBytes(StandardCharsets.UTF_8));
            Path derFile = Files.write(dir.resolve(algorithm + ".der"), PemKeys.toDer(pair.getPublic()));
            assertArrayEquals(pair.getPrivate().getEncoded(), PemKeys.readPrivateKeyFile(pemFile).getEncoded());
            assertArrayEquals(pair.getPublic().getEncoded(), PemKeys.readPublicKeyFile(derFile).getEncoded());
            assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(privatePem), "개인키 PEM을 공개키로 읽지 않음");
            assertThrows(IllegalArgumentException.class, () -> PemKeys.readPrivateKey(publicPem + privatePem + privatePem), "같은 블록 둘");
        }
        String body = "\nMIIBOgIBAAJBAK\n";
        for (String label : new String[] {"RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> PemKeys.readPrivateKey("-----BEGIN " + label + "-----" + body + "-----END " + label + "-----\n"));
            assertTrue(e.getMessage().contains("openssl pkcs8"), e.getMessage());
            assertFalse(e.getMessage().contains("MIIBOgIBAAJBAK"), "키 내용은 문구에 넣지 않는다");
        }
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----"));
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey("not a pem"));
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(new byte[] {1, 2, 3}));
        byte[] tooBig = new byte[70_000];
        Arrays.fill(tooBig, (byte) 'A');
        Path big = Files.write(dir.resolve("big.pem"), tooBig);
        assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKeyFile(big));
        // RFC 7515 A.3의 P-256 공개키(SPKI)를 읽는다
        assertEquals("EC", PemKeys.readPublicKey(pem(vectors(), "rfc7515.a3.spki")).getAlgorithm());
    }

    @Test
    void certificateAnalysisAndPkixChainValidation() throws Exception {
        TestKeytool.caAndServer(dir, "dns:jck-test.example,ip:127.0.0.1");
        X509Certificate ca = Certificates.readFile(dir.resolve("ca.pem"));
        X509Certificate server = Certificates.readFile(dir.resolve("server.pem"));
        CertificateInfo info = Certificates.info(server);
        assertEquals("CN=jck-test-server", info.subject());
        assertEquals("CN=JCK Test Root", info.issuer());
        assertEquals("RSA", info.publicKeyAlgorithm());
        assertEquals(2048, info.publicKeySize());
        assertEquals("SHA256withRSA", info.signatureAlgorithm());
        assertTrue(info.subjectAlternativeNames().containsAll(Arrays.asList("DNS:jck-test.example", "IP:127.0.0.1")), info.subjectAlternativeNames().toString());
        assertTrue(info.sha256Fingerprint().matches("([0-9A-F]{2}:){31}[0-9A-F]{2}"));
        assertTrue(info.isValidAt(Instant.now()));
        assertFalse(info.isValidAt(Instant.now().plus(400, ChronoUnit.DAYS)));
        assertTrue(info.daysUntilExpiry(Instant.now()) >= 363);
        // 신뢰 체인: 호출자가 준 루트로만 판단
        Certificates.validateChain(Collections.singletonList(server), Collections.singletonList(ca), Instant.now());
        Certificates.validateChain(Arrays.asList(server, ca), Collections.singletonList(ca), Instant.now());
        Path other = Files.createDirectory(dir.resolve("other"));
        TestKeytool.caAndServer(other, "dns:other.example");
        X509Certificate otherCa = Certificates.readFile(other.resolve("ca.pem"));
        assertThrows(CertPathValidatorException.class,
                () -> Certificates.validateChain(Collections.singletonList(server), Collections.singletonList(otherCa), Instant.now()));
        assertThrows(CertPathValidatorException.class,
                () -> Certificates.validateChain(Collections.singletonList(server), Collections.singletonList(ca), Instant.now().plus(400, ChronoUnit.DAYS)));
        // 읽기 규칙: 하나만 받는 read는 둘이면 거부, readChain은 순서대로
        String both = new String(Files.readAllBytes(dir.resolve("server.pem")), StandardCharsets.US_ASCII)
                + new String(Files.readAllBytes(dir.resolve("ca.pem")), StandardCharsets.US_ASCII);
        List<X509Certificate> chain = Certificates.readChain(both);
        assertEquals(Arrays.asList(server, ca), chain);
        assertThrows(IllegalArgumentException.class, () -> Certificates.read(both));
        assertThrows(IllegalArgumentException.class, () -> Certificates.read("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        assertEquals(server, Certificates.read(server.getEncoded()), "DER");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PemKeys.readPublicKey(new String(Files.readAllBytes(dir.resolve("ca.pem")), StandardCharsets.US_ASCII)));
        assertTrue(e.getMessage().contains("Certificates.read"), "인증서는 Certificates로 읽으라고 안내");
    }
}
