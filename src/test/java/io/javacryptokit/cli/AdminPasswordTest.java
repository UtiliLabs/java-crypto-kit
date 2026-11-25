package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CLI 관리자 비밀번호의 규칙(10~128자, 영문자·숫자·ASCII 특수문자 각 1자 이상, 그 밖의 문자 불가)과 JAR 안 검증값(단방향 PBKDF2,
 * 형식·버전 확인, 손상 Fail Closed), 비대화형 비밀번호 파일 읽기 규칙을 확인한다.
 */
class AdminPasswordTest {
    @TempDir
    Path dir;

    private static List<String> rules(String password) {
        return AdminPassword.violations(password.toCharArray());
    }

    @Test
    void finalPolicyExamplesAndBoundaries() {
        // Steering의 검증 예제
        assertEquals(Collections.emptyList(), rules("admin@12345"));
        assertEquals(Collections.emptyList(), rules("ADMIN@12345"), "대문자만으로도 영문자 조건 충족");
        assertEquals(Collections.singletonList("admin.rule.special"), rules("Admin12345"), "특수문자 없음");
        assertEquals(Collections.singletonList("admin.rule.digit"), rules("admin@@@@@"), "숫자 없음");
        assertEquals(Collections.singletonList("admin.rule.letter"), rules("12345@6789"), "영문자 없음");
        assertEquals(Collections.singletonList("admin.rule.short"), rules("admin@123"), "9자: 10자 미만");
        assertEquals(Collections.singletonList("admin.rule.short"), rules("ADMIN@123"), "9자: 10자 미만");
        assertEquals(Collections.emptyList(), rules("admin@1234"), "10자 경계: 허용");
        // 길이 경계 128 / 129
        char[] max = new char[128];
        Arrays.fill(max, 'a');
        max[0] = '1';
        max[1] = '#';
        assertEquals(Collections.emptyList(), AdminPassword.violations(max), "128자 허용");
        char[] over = Arrays.copyOf(max, 129);
        over[128] = 'b';
        assertEquals(Collections.singletonList("admin.rule.long"), AdminPassword.violations(over), "129자 거부");
        // 대문자만·소문자만 조합 모두 허용, 공백·한글·비ASCII·제어문자는 거부(공백은 특수문자로 세지 않음)
        assertEquals(Collections.emptyList(), rules("abcdefgh1!"));
        assertEquals(Collections.emptyList(), rules("ABCDEFGH1!"));
        assertEquals(Arrays.asList("admin.rule.chars", "admin.rule.special"), rules("admin 12345"), "공백은 특수문자가 아니다");
        assertEquals(Collections.singletonList("admin.rule.chars"), rules("admin@1234가"));
        assertEquals(Collections.singletonList("admin.rule.chars"), rules("admin@1234é"));
        assertEquals(Collections.singletonList("admin.rule.chars"), rules("admin@1234\t"));
        // 특수문자 32개 모두 인정
        for (char c : AdminPassword.SPECIALS.toCharArray()) {
            assertEquals(Collections.emptyList(), rules("abcdefgh1" + c), "특수문자: " + c);
        }
        assertEquals(32, AdminPassword.SPECIALS.length());
        // 여러 위반은 고정 순서로 모두 알린다(구체적인 오류 메시지).
        assertEquals(Arrays.asList("admin.rule.short", "admin.rule.digit", "admin.rule.special"), rules("abc"));
        try (AutoCloseable ignored = language(Messages.Language.KO)) {
            assertEquals("10자 미만, 숫자 없음, 특수문자 없음", AdminPassword.describe(rules("abc")));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void verifierIsOneWayAndMatchesOnlyTheSamePassword() {
        byte[] entry = AdminPassword.create("admin@12345".toCharArray(), AdminPassword.MIN_ITERATIONS);
        String text = new String(entry, StandardCharsets.US_ASCII);
        assertFalse(text.contains("admin@12345"), "원문을 저장하지 않는다");
        assertTrue(text.contains("format.version=1") && text.contains("kdf=PBKDF2WithHmacSHA256")
                && text.contains("kdf.iterations=100000"), text);
        AdminPassword.Verifier verifier = AdminPassword.parse(entry);
        assertTrue(verifier.matches("admin@12345".toCharArray()));
        assertFalse(verifier.matches("admin@12346".toCharArray()));
        assertFalse(verifier.matches("ADMIN@12345".toCharArray()), "대소문자 구분");
        assertFalse(verifier.matches(new char[0]));
        // 저장된 값(검증값·Salt)을 비밀번호처럼 넣어도 통과하지 않는다(늘 다시 파생해 비교).
        String stored = text.replaceAll("(?s).*verifier=([^\n]+).*", "$1");
        String salt = text.replaceAll("(?s).*salt=([^\n]+).*", "$1");
        assertFalse(verifier.matches(stored.toCharArray()), "검증값으로 우회 인증 불가");
        assertFalse(verifier.matches(salt.toCharArray()));
        // 같은 비밀번호라도 Salt가 달라 검증값이 다르다(키마다 독립 Salt).
        assertNotEquals(text, new String(AdminPassword.create("admin@12345".toCharArray(), AdminPassword.MIN_ITERATIONS),
                StandardCharsets.US_ASCII));
        // 새로 만드는 검증값은 600,000회
        assertTrue(new String(AdminPassword.create("admin@12345".toCharArray()), StandardCharsets.US_ASCII)
                .contains("kdf.iterations=600000"));
        assertTrue(AdminPassword.same("abc".toCharArray(), "abc".toCharArray()));
        assertFalse(AdminPassword.same("abc".toCharArray(), "abd".toCharArray()));
        assertFalse(AdminPassword.same("abc".toCharArray(), "abcd".toCharArray()));
    }

    @Test
    void damagedUnknownOrWeakenedVerifiersFailClosed() {
        String good = new String(AdminPassword.create("admin@12345".toCharArray(), AdminPassword.MIN_ITERATIONS),
                StandardCharsets.US_ASCII);
        String[] bad = {
                "",
                good.replace("format.version=1", "format.version=2"),
                good.replace("kdf=PBKDF2WithHmacSHA256", "kdf=PBKDF2WithHmacSHA1"),
                good.replace("kdf.iterations=100000", "kdf.iterations=1000"),
                good.replace("kdf.iterations=100000", "kdf.iterations=abc"),
                good.replaceAll("salt=[^\n]+", "salt=AAAA"),
                good.replaceAll("verifier=[^\n]+", "verifier=!!!"),
                good.replaceAll("(?m)^verifier=.*\n", ""),
                good + "verifier=AAAA\n",
                good + "extra=1\n",
                good + "# é\n",
        };
        for (String text : bad) {
            assertThrows(SafeMessageException.class, () -> AdminPassword.parse(text.getBytes(StandardCharsets.ISO_8859_1)), text);
        }
        SafeMessageException version = assertThrows(SafeMessageException.class,
                () -> AdminPassword.parse(bad[1].getBytes(StandardCharsets.US_ASCII)));
        assertTrue(version.getMessage().contains("버전") || version.getMessage().contains("version"), version.getMessage());
        byte[] huge = new byte[AdminPassword.MAX_ENTRY_BYTES + 1];
        Arrays.fill(huge, (byte) '#');
        assertThrows(SafeMessageException.class, () -> AdminPassword.parse(huge));
    }

    @Test
    void passwordFileIsOneUtf8LineWithOptionalBomAndLineEnd() throws Exception {
        assertArrayEquals("admin@12345".toCharArray(), read(("admin@12345\r\n").getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals("admin@12345".toCharArray(), read(("admin@12345").getBytes(StandardCharsets.UTF_8)));
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 'a', 'd', 'm', 'i', 'n', '@', '1', '2', '3', '4', '5', '\n'};
        assertArrayEquals("admin@12345".toCharArray(), read(bom), "PowerShell 5.1 BOM 하나는 뗀다");
        assertArrayEquals(" admin@12345 ".toCharArray(), read(" admin@12345 \n".getBytes(StandardCharsets.UTF_8)),
                "앞뒤 공백을 몰래 지우지 않는다(규칙 검사가 거부)");
        for (byte[] bad : new byte[][]{"a\nb\n".getBytes(StandardCharsets.UTF_8), "\n".getBytes(StandardCharsets.UTF_8),
                new byte[0], {(byte) 0xC3, (byte) 0x28}}) {
            Path file = CliHarness.writeSecret(dir.resolve("bad.pw"), bad);
            CryptoCli.CliException e = assertThrows(CryptoCli.CliException.class,
                    () -> AdminPassword.readFile(file.toString(), "ADMIN_AUTH"));
            assertEquals("ADMIN_AUTH", e.code);
            assertFalse(e.getMessage().contains(dir.toString()), "경로를 오류에 넣지 않는다: " + e.getMessage());
        }
        byte[] large = new byte[AdminPassword.MAX_FILE_BYTES + 1];
        Arrays.fill(large, (byte) 'a');
        Path big = CliHarness.writeSecret(dir.resolve("big.pw"), large);
        assertThrows(CryptoCli.CliException.class, () -> AdminPassword.readFile(big.toString(), "ADMIN_AUTH"));
        CryptoCli.CliException missing = assertThrows(CryptoCli.CliException.class,
                () -> AdminPassword.readFile(dir.resolve("none.pw").toString(), "ADMIN_PASSWORD"));
        assertEquals("ADMIN_PASSWORD", missing.code);
        assertThrows(CryptoCli.CliException.class, () -> AdminPassword.readFile(dir.toString(), "ADMIN_AUTH"), "폴더는 거부");
    }

    @Test
    void passwordFileOpenToOtherUsersIsRejectedByPermissionRule() {
        // 권한 판단(모든 OS에서 확인): 다른 사용자(other)의 읽기·쓰기가 있으면 거부, 소유자·그룹 권한만이면 허용
        assertTrue(AdminPassword.othersCanAccess(PosixFilePermissions.fromString("rw-r--r--")));
        assertTrue(AdminPassword.othersCanAccess(PosixFilePermissions.fromString("rw-----w-")));
        assertFalse(AdminPassword.othersCanAccess(PosixFilePermissions.fromString("rw-------")));
        assertFalse(AdminPassword.othersCanAccess(PosixFilePermissions.fromString("r--------")));
        assertFalse(AdminPassword.othersCanAccess(PosixFilePermissions.fromString("rw-r-----")));
    }

    @Test
    void posixPasswordFileMustNotBeReadableByOthersAndLinksUseTheTargetPermissions() throws Exception {
        assumeTrue(JarConfigEditor.posix(), "실제 파일 권한은 POSIX(Linux·macOS)에서 확인한다(Windows는 폴더 ACL, 사용자 가이드 1.4)");
        byte[] line = "admin@12345\n".getBytes(StandardCharsets.UTF_8);
        Path open = CliHarness.writeSecret(dir.resolve("open.pw"), line);
        Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rw-r--r--"));
        CryptoCli.CliException e = assertThrows(CryptoCli.CliException.class, () -> AdminPassword.readFile(open.toString(), "ADMIN_AUTH"));
        assertEquals("ADMIN_AUTH", e.code);
        assertTrue(e.getMessage().contains("rw-r--r--") && e.getMessage().contains("chmod 600"), e.getMessage());
        assertFalse(e.getMessage().contains("admin@12345") || e.getMessage().contains(dir.toString()), e.getMessage());
        Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rw-r-----"));
        assertArrayEquals("admin@12345".toCharArray(), AdminPassword.readFile(open.toString(), "ADMIN_AUTH"), "그룹 읽기(통제된 그룹) 허용");
        // 심볼릭 링크(Kubernetes Secret 볼륨 등)는 최종 대상의 권한을 본다. 끊긴 링크는 없는 파일과 같다.
        Path link = Files.createSymbolicLink(dir.resolve("link.pw"), open);
        assertArrayEquals("admin@12345".toCharArray(), AdminPassword.readFile(link.toString(), "ADMIN_AUTH"));
        Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rw-rw-rw-"));
        assertThrows(CryptoCli.CliException.class, () -> AdminPassword.readFile(link.toString(), "ADMIN_AUTH"));
        Path dangling = Files.createSymbolicLink(dir.resolve("dangling.pw"), dir.resolve("none.pw"));
        assertThrows(CryptoCli.CliException.class, () -> AdminPassword.readFile(dangling.toString(), "ADMIN_PASSWORD"));
    }

    private char[] read(byte[] content) throws Exception {
        Path file = CliHarness.writeSecret(dir.resolve("admin.pw"), content);
        return AdminPassword.readFile(file.toString(), "ADMIN_AUTH");
    }

    private static AutoCloseable language(Messages.Language language) {
        Messages.Language previous = Messages.processLanguage();
        Messages.setProcessLanguage(language);
        return () -> Messages.setProcessLanguage(previous);
    }
}
