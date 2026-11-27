package io.javacryptokit.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.config.SafeMessageException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Passphrase(pass 유형) 키 파생: PBKDF2-HMAC-SHA256, NFC 정규화 후 UTF-8, 32바이트 결과. 고정 벡터는 JDK 8·JDK 21과 Python
 * {@code hashlib.pbkdf2_hmac}이 같은 값을 낸 것(설계 스파이크)이며, OS·JDK와 관계없이 같아야 한다.
 */
class PassKdfTest {
    /** 벡터용 Salt(16바이트, 시험 전용 값). */
    private static final byte[] SALT = "java-crypto-kit!".getBytes(StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "ascii|password|3038161dcdda16f31bf91779a731dc81881d8b5c4a8b83a7545518045ff8b3d6",
            "korean-nfc|한글 비밀번호|921e3a92f067d90e9fdf7d218dd91340f3c39ffa243e1f3fe97f8340f2d4e860",
            "korean-nfd|한글 비밀번호"
                    + "|921e3a92f067d90e9fdf7d218dd91340f3c39ffa243e1f3fe97f8340f2d4e860",
            "emoji|🔐🗝️👩‍💻"
                    + "|afe34630cb27998dee4fcb7fbd9a7460c20a75fc097e81d086cb21b213c1844d",
            "mixed|Pass-한글-🔐-#1|f74f8d0ddadb0c0aeaec51ed0ef854617984c32829c2ec6486dba8eab11d2876",
            "fullwidth|ＡＢＣ|d8ca2ef72f721a41359bcaec31df6b1108e67f2d108c5b62b2cf567ada119a79"})
    void fixedUnicodeVectorsMatchAcrossJdks(String name, String passphrase, String expectedHex) {
        assertEquals(expectedHex, hex(PassKdf.derive(PassKdf.normalize(passphrase.toCharArray()), SALT, 1000)), name);
    }

    @Test
    void symbolsVectorAndNfdInputDeriveTheSameKeyAsNfc() {
        String symbols = "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~\\";
        assertEquals("66e1569a4ca5de1a892a817fa7d1bab9ece28425a1338d6a6090f31de8fafbb9",
                hex(PassKdf.derive(PassKdf.normalize(symbols.toCharArray()), SALT, 1000)));
        // 같은 글자를 다른 정규화 형식(NFD)으로 입력해도 NFC로 바꿔 같은 키가 된다(입력기·OS 차이 흡수).
        String nfc = "한글 비밀번호";
        String nfd = Normalizer.normalize(nfc, Normalizer.Form.NFD);
        assertNotEquals(nfc, nfd);
        assertArrayEquals(PassKdf.derive(PassKdf.normalize(nfc.toCharArray()), SALT, 1000),
                PassKdf.derive(PassKdf.normalize(nfd.toCharArray()), SALT, 1000));
    }

    @Test
    void legacyPublicPassVectorMatchesItsPublishedFingerprint() throws Exception {
        // 공개 Salt = SHA-256("java-crypto-kit/pass-default/salt/v1")의 앞 16바이트(누구나 다시 계산할 수 있는 공개 값).
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest("java-crypto-kit/pass-default/salt/v1".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(Arrays.copyOf(digest, 16), Base64.getDecoder().decode("Bt9HhTFtDOVUgGsvFtnzMw=="));
        Properties jar = jarDefaults();
        assertEquals(Base64.getEncoder().encodeToString(Base64.getDecoder().decode("Bt9HhTFtDOVUgGsvFtnzMw==")), jar.getProperty("crypto.keys.pass-default.salt"));
        assertEquals("600000", jar.getProperty("crypto.keys.pass-default.kdf.iterations"));
        assertEquals("pbkdf2-sha256", jar.getProperty("crypto.keys.pass-default.kdf"));
        // JAR에는 공개 예제 Passphrase로 파생한 키만 들어 있다(원문은 없다). 같은 계산을 다시 하면 같은 키가 나온다.
        // 값은 obf1(경량 난독화) 표현으로 저장되어 있고, 되돌린 키 바이트가 파생 결과와 같다.
        byte[] derived = PassKdf.derive(PassKdf.normalize("java-crypto-kit-public-passphrase-v1".toCharArray()), Base64.getDecoder().decode("Bt9HhTFtDOVUgGsvFtnzMw=="), 600_000);
        String stored = jar.getProperty("crypto.keys.pass-default.embedded");
        assertTrue(stored.startsWith("obf1:"), "공개 pass 키도 같은 obf1 표현으로 저장한다: " + stored);
        assertArrayEquals(derived, KeyResolver.decodeEmbedded(stored));
        assertEquals("3dca588c78a17aad886e9403e8743990d79d479bbe610664adc3ff7e94453656", KeyResolver.fingerprint(derived));
        assertTrue(DefaultKeyWarning.isPublicDefaultKey(derived), "공개 pass 키도 공개 기본 키로 판정");
        assertFalse(jar.toString().contains("java-crypto-kit-public-passphrase-v1"), "JAR 설정에 Passphrase 원문은 없다");
    }

    @Test
    void onlyRealInputErrorsAreRejectedWithoutALengthPolicy() {
        for (String bad : new String[] {"", "   ", "\t 　", "a\u0000b", "line\nbreak", "\uD83D", "x\uDC00y"}) {
            assertThrows(SafeMessageException.class, () -> PassKdf.normalize(bad.toCharArray()), "거부해야 함: " + bad.length());
        }
        // 길이·문자 종류 정책은 없다(짧은 값·공백 포함 값도 실제 오류가 아니므로 받는다).
        for (String ok : new String[] {"a", "pass word", " 앞뒤 공백도 그대로 ", "🔐"}) {
            assertTrue(PassKdf.normalize(ok.toCharArray()).length > 0, ok);
        }
        assertArrayEquals(" 앞뒤 공백도 그대로 ".toCharArray(), PassKdf.normalize(" 앞뒤 공백도 그대로 ".toCharArray()),
                "앞뒤 공백을 잘라 다른 키를 만들지 않는다");
    }

    @Test
    void fileMaterialIsStrictUtf8AndOnlyOneTrailingLineEndIsRemoved() {
        assertArrayEquals("secret".toCharArray(), PassKdf.decodeUtf8("secret\n".getBytes(StandardCharsets.UTF_8), true));
        assertArrayEquals("secret".toCharArray(), PassKdf.decodeUtf8("secret\r\n".getBytes(StandardCharsets.UTF_8), true));
        assertArrayEquals("secret\n".toCharArray(), PassKdf.decodeUtf8("secret\n\n".getBytes(StandardCharsets.UTF_8), true),
                "줄바꿈은 하나만 뗀다");
        assertArrayEquals("secret\n".toCharArray(), PassKdf.decodeUtf8("secret\n".getBytes(StandardCharsets.UTF_8), false),
                "환경변수·Vault 값은 그대로");
        assertThrows(SafeMessageException.class, () -> PassKdf.decodeUtf8(new byte[] {'a', (byte) 0xC3, 0x28}, true));
        // 파일 앞의 UTF-8 BOM 하나는 뗀다(Windows PowerShell 5.1 Set-Content -Encoding UTF8). 환경변수·Vault 값은 그대로.
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 's', 'e', 'c', 'r', 'e', 't', '\r', '\n'};
        assertArrayEquals("secret".toCharArray(), PassKdf.decodeUtf8(bom, true));
        assertArrayEquals("﻿secret\r\n".toCharArray(), PassKdf.decodeUtf8(bom, false));
        assertArrayEquals(new char[0], PassKdf.decodeUtf8(new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, '\n'}, true));
    }

    @Test
    void publicPassphraseIsRecognizedAndGeneratedPassphrasesAreRandom() {
        assertTrue(PassKdf.isPublicPassphrase(PassKdf.normalize("java-crypto-kit-public-passphrase-v1".toCharArray())));
        assertFalse(PassKdf.isPublicPassphrase("java-crypto-kit-public-passphrase-v2".toCharArray()));
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 20; i++) {
            char[] generated = PassKdf.generate();
            assertEquals(32, generated.length);
            assertTrue(new String(generated).matches("[A-Za-z0-9]{32}"));
            assertTrue(seen.add(new String(generated)), "생성할 때마다 다른 값");
        }
        assertNotEquals(hex(PassKdf.newSalt()), hex(PassKdf.newSalt()), "키마다 다른 난수 Salt");
        assertEquals(16, PassKdf.newSalt().length);
    }

    private static Properties jarDefaults() throws Exception {
        Properties properties = new Properties();
        try (InputStream in = PassKdfTest.class.getResourceAsStream("/legacy-public.properties");
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) text.append(String.format("%02x", b & 0xff));
        return text.toString();
    }
}
