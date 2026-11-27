package io.javacryptokit.core;

import io.javacryptokit.CredentialCrypto;

import io.javacryptokit.CredentialCryptoException;

import io.javacryptokit.TestSupport;

import io.javacryptokit.config.CryptoSettings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * 출력 형식(crypto.output.encoding)과 토큰 읽기 규칙 검증: ENC 기본, B64 선택 포장, 양쪽 자동 인식, 손상·공격 입력 거부,
 * 그리고 이전에 만든 v1 암호문의 하위 호환(고정 회귀 벡터).
 */
class TokenCodecTest {
    /** 공개 기본 키·키ID default로 만든 고정 v1 암호문(더미 평문). 이 값이 복호화되지 않으면 하위 호환이 깨진 것이다. */
    static final String V1_VECTOR =
            "ENC[v1:default:fiwaaeeeILgco85o:-uFGHK3H0eqZKIfj3MZhRG3cr9gLeQCjYJ7UHFdWCg4f4982fNx8]";
    /** 위 암호문을 B64 포장한 값. */
    static final String V1_VECTOR_B64 = "B64[RU5DW3YxOmRlZmF1bHQ6Zml3YWFlZWVJTGdjbzg1bzotdUZHSEszSDBlcVpLSWZqM01a"
            + "aFJHM2NyOWdMZVFDallKN1VIRmRXQ2c0ZjQ5ODJmTng4XQ]";
    /** 위 암호문의 평문(더미). */
    static final String V1_PLAIN = "v1-regression-dummy-값";

    @TempDir
    Path dir;

    private CredentialCrypto jarDefaults;

    private static CredentialCrypto legacyDirect() throws Exception {
        return CredentialCrypto.fromRawKey("default", Base64.getDecoder().decode(TestSupport.publicKeyBase64()));
    }

    @BeforeEach
    void setUp() throws Exception {
        jarDefaults = TestSupport.managedCrypto();
    }

    @Test
    void fixedV1VectorStillDecrypts() throws Exception {
        assertEquals(V1_PLAIN, legacyDirect().decryptText(V1_VECTOR));
        assertTrue(legacyDirect().verify(V1_VECTOR));
    }

    @Test
    void fixedB64VectorStillDecryptsAndWrapsTheSameEnvelope() throws Exception {
        assertEquals(V1_PLAIN, legacyDirect().decryptText(V1_VECTOR_B64));
        assertEquals(V1_VECTOR, TokenCodec.toEnvelope(V1_VECTOR_B64));
        assertEquals(V1_VECTOR_B64, TokenCodec.format(V1_VECTOR, CryptoSettings.OutputFormat.BASE64));
    }

    @Test
    void defaultOutputIsUnchangedEncFormat() throws Exception {
        // 유형 미지정 기본은 pass(pass-default), key 유형은 기존 공개 AES 키(default). 두 유형 모두 같은 ENC v1 형식이다.
        assertTrue(jarDefaults.encryptText("dummy").startsWith("ENC[v1:test-pass:"), "기본 출력은 기존 ENC 형식 그대로여야 한다");
        assertTrue(jarDefaults.encryptText("dummy", io.javacryptokit.KeyType.KEY).startsWith("ENC[v1:default:"),
                "key 유형도 같은 ENC 형식");
    }

    @Test
    void base64OutputWrapsTheSameV1EnvelopeAndBothFormatsAreRead() throws Exception {
        Path config = TestSupport.writeManagedConfig(dir, "b64.properties", "crypto.output.encoding=base64");
        CredentialCrypto b64 = CredentialCrypto.fromConfigFile(config);
        String token = b64.encryptText("dummy-포장");
        assertTrue(token.startsWith("B64[") && token.endsWith("]"));
        assertTrue(TokenCodec.toEnvelope(token).startsWith("ENC[v1:test-pass:"), "포장 안은 항상 v1 봉투");
        // 출력 형식 설정과 관계없이 두 형식을 모두 읽는다.
        assertEquals("dummy-포장", jarDefaults.decryptText(token));
        assertEquals(V1_PLAIN, legacyDirect().decryptText(V1_VECTOR));
        assertEquals(V1_PLAIN, legacyDirect().decryptText(V1_VECTOR_B64));
    }

    static Stream<String> malformedTokens() {
        String body = V1_VECTOR_B64.substring(4, V1_VECTOR_B64.length() - 1);
        // 마지막 문자의 "남는 비트"만 바꾸면 같은 바이트로 디코딩되지만 정규 표기가 아니다.
        String nonCanonical = "B64[" + body.substring(0, body.length() - 1)
                + (body.charAt(body.length() - 1) == 'Q' ? 'R' : 'Q') + "]";
        StringBuilder oversized = new StringBuilder("B64[");
        while (oversized.length() <= TokenCodec.MAX_B64_LENGTH) oversized.append('A');
        oversized.append(']');
        return Stream.of(
                "B64[",                                      // 닫는 괄호 없음
                "B64[]",                                     // 빈 본문
                "B64[" + body,                               // 닫는 괄호 없음
                "B64[" + body + "==]",                       // 패딩 문자
                "B64[a+b/]",                                 // 표준 Base64 문자
                "B64[A]",                                    // 불가능한 길이(나머지 1)
                nonCanonical,                                // 비정규 표기
                "B64[" + b64(new byte[]{(byte) 0xC3, 0x28}) + "]",          // 잘못된 UTF-8
                "B64[" + b64("hello world".getBytes(StandardCharsets.UTF_8)) + "]", // 안에 ENC 없음
                "B64[" + b64(V1_VECTOR_B64.getBytes(StandardCharsets.US_ASCII)) + "]", // 중첩 포장
                oversized.toString(),                        // 최대 길이 초과
                "b64[" + body + "]",                         // 접두어 대소문자 다름(토큰 아님)
                "ENC[v2:default:AAAA:AAAA]",                 // 지원하지 않는 버전
                "plain-password");                           // 평문
    }

    @ParameterizedTest(name = "손상·공격 입력 거부 #{index}")
    @MethodSource("malformedTokens")
    void malformedTokensFailClosed(String token) {
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> jarDefaults.decryptText(token));
        assertEquals(CredentialCryptoException.Reason.INVALID_TOKEN, ex.getReason());
        assertFalse(ex.getMessage().contains(token), "입력값을 메시지에 넣으면 안 된다");
    }

    @Test
    void tamperedEnvelopeInsideB64FailsIntegrity() throws Exception {
        String[] parts = V1_VECTOR.substring(4, V1_VECTOR.length() - 1).split(":", -1);
        byte[] cipher = Base64.getUrlDecoder().decode(parts[3]);
        cipher[0] ^= 0x01;
        String tampered = "ENC[" + parts[0] + ":" + parts[1] + ":" + parts[2] + ":"
                + Base64.getUrlEncoder().withoutPadding().encodeToString(cipher) + "]";
        String wrapped = TokenCodec.format(tampered, CryptoSettings.OutputFormat.BASE64);
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> jarDefaults.decryptText(wrapped));
        assertEquals(CredentialCryptoException.Reason.INTEGRITY, ex.getReason());
    }

    @Test
    void tokenDetectionDoesNotGuessPlainOrGenericBase64() {
        assertTrue(CredentialCrypto.isToken(V1_VECTOR));
        assertTrue(CredentialCrypto.isToken(V1_VECTOR_B64));
        assertFalse(CredentialCrypto.isToken(null));
        assertFalse(CredentialCrypto.isToken("password"));
        assertFalse(CredentialCrypto.isToken(b64(V1_VECTOR.getBytes(StandardCharsets.US_ASCII))), "접두어 없는 Base64는 토큰이 아니다");
    }

    private static String b64(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }
}
