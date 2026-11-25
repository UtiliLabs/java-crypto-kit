package io.javacryptokit.ha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.PemKeys;
import io.javacryptokit.security.Signatures;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 다중 서버(G09·N03): 같은 프로세스의 객체가 아니라 <b>독립 JVM 3개</b>(서버 A 발급·암호화, 서버 B·C 검증·복호화)로 확인한다.
 * <ul>
 *   <li>A가 배포받은 키로 발급한 RS256·HS256 JWT와 RFC 9068 Access Token을 B·C가 공개키·공유 키만으로 검증(키 교체 기간의 이전 kid 포함).</li>
 *   <li>이전 키를 뺀 검증기는 이전 키 토큰을 거부, 다른 대상·토큰 종류 혼동(일반 JWT ↔ Access Token) 거부.</li>
 *   <li>A가 수신자 공개키로 만든 Hybrid 봉투·RSA-OAEP 암호문을 B·C가 각자의 JVM에서 수신자 개인키로 복호화(AAD가 다르면 실패).</li>
 *   <li>서버별 난수 토큰 3,000개가 JVM 사이에서 겹치지 않음(확률적 성질이며 절대 유일성 증명은 아니다).</li>
 * </ul>
 */
class MultiJvmTest {
    @TempDir
    Path dir;

    @Test
    void independentJvmsIssueVerifyAndDecrypt() throws Exception {
        KeyPair current = Signatures.generateRsaKeyPair(2048);
        KeyPair previous = Signatures.generateRsaKeyPair(2048);
        KeyPair receiver = Signatures.generateRsaKeyPair(2048);
        write("issuer-current.pem", PemKeys.toPem(current.getPrivate()));
        write("issuer-previous.pem", PemKeys.toPem(previous.getPrivate()));
        write("issuer-current.pub.pem", PemKeys.toPem(current.getPublic()));
        write("issuer-previous.pub.pem", PemKeys.toPem(previous.getPublic()));
        write("receiver.pem", PemKeys.toPem(receiver.getPrivate()));
        write("receiver.pub.pem", PemKeys.toPem(receiver.getPublic()));
        write("shared-hs256.key", Encoding.BASE64.encode(Hmac.generateKey()));

        Map<String, String> a = finish(start("issue", "serverA"));
        assertEquals("7", a.get("issued"));
        Process b = start("verify", "serverB");
        Process c = start("verify", "serverC");
        List<Map<String, String>> verifiers = new ArrayList<>();
        verifiers.add(finish(b));
        verifiers.add(finish(c));
        for (Map<String, String> r : verifiers) {
            assertEquals("VALID", r.get("rs-current"), r.toString());
            assertEquals("VALID", r.get("rs-previous"), "키 교체 기간: 이전 kid도 검증");
            assertEquals("KEY_NOT_FOUND", r.get("rs-previous-after-rotation"), "이전 키를 빼면 거부");
            assertEquals("AUDIENCE", r.get("rs-other-audience"));
            assertEquals("VALID", r.get("hs"));
            assertEquals("TYPE", r.get("access-as-jwt"), "일반 JWT 검증기는 Access Token(at+jwt)을 받지 않음");
            assertEquals("VALID", r.get("access"));
            assertEquals("TYPE", r.get("jwt-as-access"), "Access Token 검증기는 일반 JWT를 받지 않음");
            assertEquals("OK", r.get("hybrid"), "다른 JVM에서 같은 수신자 키로 Hybrid 복호화");
            assertEquals("INTEGRITY", r.get("hybrid-wrong-aad"));
            assertEquals("OK", r.get("oaep"), "다른 JVM에서 RSA-OAEP 복호화");
        }
        Set<String> tokens = new HashSet<>();
        for (String node : new String[] {"serverA", "serverB", "serverC"}) {
            for (String token : Files.readAllLines(dir.resolve(node + ".tokens"), StandardCharsets.UTF_8)) assertTrue(tokens.add(token));
        }
        assertEquals(3000, tokens.size());
    }

    private void write(String name, String content) throws IOException {
        Files.write(dir.resolve(name), content.getBytes(StandardCharsets.US_ASCII));
    }

    private Process start(String role, String node) throws IOException {
        String java = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
        List<String> command = new ArrayList<>();
        command.add(java);
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(MultiJvmNode.class.getName());
        command.add(role);
        command.add(dir.toString());
        command.add(node);
        return new ProcessBuilder(command).redirectErrorStream(true).start();
    }

    private static Map<String, String> finish(Process process) throws Exception {
        byte[] output = readAll(process.getInputStream());
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "JVM 시간 초과");
        String text = new String(output, StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), text);
        Map<String, String> results = new HashMap<>();
        for (String line : text.split("\\r?\\n")) {
            if (line.startsWith("RESULT ")) {
                String[] pair = line.substring(7).split("=", 2);
                results.put(pair[0], pair[1]);
            }
        }
        return results;
    }

    private static byte[] readAll(InputStream input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) != -1) out.write(buffer, 0, read);
        return out.toByteArray();
    }
}
