package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * JAR 내부 설정 관리(config show / history / set / embed-key) 회귀 테스트. 실제 배포 JAR와 같은 구조의 JAR를 만들어 검증한다.
 * 최종 QA 필수 항목: 전체 이력(시각·수정자·설정·이전/변경 값, 비밀값 미기록, 새 JAR·교체 후 유지), CLI만으로 회사 키·키ID 내장,
 * 키ID 재사용 거부·재암호화 안내, 바뀐 JAR 재실행 시 show/history 정확성.
 */
class ConfigJarTest {
    @TempDir
    Path dir;
    private CliHarness cli;
    private Path jar;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
        jar = TestJars.build(dir.resolve("java-crypto-kit-0.1.0.jar"));
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    private String historyText(Path target) throws Exception {
        try (JarFile file = new JarFile(target.toFile())) {
            JarEntry entry = file.getJarEntry(ConfigHistory.ENTRY);
            if (entry == null) return null;
            try (InputStream in = file.getInputStream(entry)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    private List<Path> leftovers() throws Exception {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> list = Files.list(dir)) {
            list.filter(p -> p.getFileName().toString().endsWith(".tmp") || p.getFileName().toString().endsWith(".lock"))
                    .forEach(files::add);
        }
        return files;
    }

    @Test
    void repeatedChangesGetNumberedResultNamesAndNeverTouchEarlierJars() throws Exception {
        // 기본 결과 이름 규칙: 접미사를 겹치지 않고 순번을 올린다(대소문자 무시, 다른 이름은 그대로 뒤에 붙임).
        assertEquals("a-configured.jar", ConfigCommand.defaultOutputName("a.jar"));
        assertEquals("a-configured-2.jar", ConfigCommand.defaultOutputName("a-configured.jar"));
        assertEquals("a-configured-3.jar", ConfigCommand.defaultOutputName("a-configured-2.jar"));
        assertEquals("A-configured-2.jar", ConfigCommand.defaultOutputName("A-CONFIGURED.jar"));
        assertEquals("app-configured-old-configured.jar", ConfigCommand.defaultOutputName("app-configured-old.jar"));

        // 실제 사용 순서: 공개 JAR → embed-key → 결과 JAR로 config set → 그 결과 JAR로 다시 config set
        Path work = Files.createDirectories(dir.resolve("chain"));
        Path original = Files.copy(jar, work.resolve("java-crypto-kit-0.1.0.jar"));
        byte[] originalBytes = Files.readAllBytes(original);
        Path keyFile = work.resolve("company.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString()));
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--yes", "--jar", original.toString()), cli.err());
        Path first = work.resolve("java-crypto-kit-0.1.0-configured.jar");
        assertTrue(cli.out().contains(first.toAbsolutePath().toString()) && cli.out().contains("다음 작업:"),
                "결과 JAR의 절대 경로와 다음에 쓸 JAR를 안내한다: " + cli.out());
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", first.toString()), cli.err());
        Path second = work.resolve("java-crypto-kit-0.1.0-configured-2.jar");
        assertTrue(Files.exists(second), cli.out());
        assertFalse(Files.exists(work.resolve("java-crypto-kit-0.1.0-configured-configured.jar")), "접미사가 겹치면 안 된다");
        assertEquals(0, cli.run("config", "set", "crypto.warning.enabled=false", "--operator", "123456",
                "--jar", second.toString()), cli.err());
        Path third = work.resolve("java-crypto-kit-0.1.0-configured-3.jar");
        assertTrue(Files.exists(third), cli.out());
        assertEquals(0, cli.run("config", "set", "crypto.output.encoding=base64", "--operator", "123456",
                "--jar", third.toString()), cli.err());
        Path fourth = work.resolve("java-crypto-kit-0.1.0-configured-4.jar");
        assertTrue(Files.exists(fourth), cli.out());
        try (Stream<Path> list = Files.list(work)) {
            assertFalse(list.anyMatch(p -> p.getFileName().toString().matches(".*configured.*configured.*")),
                    "접미사가 누적된 이름(-configured-2-configured.jar 등)이 생기면 안 된다");
        }

        // 원본은 그대로, 이력은 1 → 2 → 3 → 4건으로 이어지고, 마지막 JAR에는 네 변경이 모두 들어 있다.
        assertTrue(Arrays.equals(originalBytes, Files.readAllBytes(original)), "원본 JAR는 바뀌지 않는다");
        assertTrue(historyText(first).contains("entry.1.") && !historyText(first).contains("entry.2."));
        assertTrue(historyText(third).contains("entry.3.command=set") && !historyText(third).contains("entry.4."));
        assertTrue(historyText(fourth).contains("entry.4.command=set"), historyText(fourth));
        assertEquals(0, cli.run("config", "show", "--jar", fourth.toString()), cli.err());
        assertTrue(cli.out().contains("crypto.key.id = prod01") && cli.out().contains("crypto.lang = en")
                && cli.out().contains("crypto.warning.enabled = false") && cli.out().contains("crypto.output.encoding = base64"),
                cli.out());

        // 같은 원본으로 다시 바꾸면 기본 결과가 이미 있으므로 확인 질문 전에 멈추고, 덮어쓰지 않으며, 쓸 수 있는 이름을 안내한다.
        byte[] firstBytes = Files.readAllBytes(first);
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "123456", "--jar", original.toString()));
        assertTrue(cli.err().contains("--out java-crypto-kit-0.1.0-configured-5.jar") && !cli.err().contains("CHANGE"), cli.err());
        assertTrue(Arrays.equals(firstBytes, Files.readAllBytes(first)), "기존 결과 JAR는 그대로");
        assertFalse(Files.exists(work.resolve("java-crypto-kit-0.1.0-configured-5.jar")), "안내만 하고 만들지 않는다");

        // --out·--replace(백업 후 교체)는 기존과 같이 동작한다.
        Path named = work.resolve("company-final.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=ko", "--operator", "123456", "--jar", fourth.toString(),
                "--out", named.toString()), cli.err());
        byte[] beforeReplace = Files.readAllBytes(named);
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", named.toString(),
                "--replace"), cli.err());
        Path backup;
        try (Stream<Path> list = Files.list(work)) {
            backup = list.filter(p -> p.getFileName().toString().startsWith("company-final.jar.bak-")).findFirst().orElse(null);
        }
        assertTrue(backup != null && Arrays.equals(beforeReplace, Files.readAllBytes(backup)), "교체 전 JAR가 그대로 백업된다");
        assertTrue(historyText(named).contains("entry.6."), "교체 후에도 이력 유지: " + historyText(named));
        try (Stream<Path> list = Files.list(work)) {
            assertFalse(list.anyMatch(p -> p.getFileName().toString().endsWith(".tmp") || p.getFileName().toString().endsWith(".lock")),
                    "임시·잠금 파일이 남지 않는다");
        }
    }

    @Test
    void initialJarShowsNoHistoryAndHidesTheKey() throws Exception {
        assertEquals(0, cli.run("config", "show", "--jar", jar.toString()), cli.err());
        String out = cli.out();
        assertTrue(out.contains("최초 빌드 상태(변경 이력 없음)"), out);
        assertTrue(out.contains("최초 빌드 일시: 2026-11-21T00:00:00Z"), out);
        assertTrue(out.contains("공개 기본 키"), out);
        assertFalse(out.contains(TestSupport.publicKeyBase64()), "내장 키 값을 출력하면 안 된다");
        assertTrue(out.contains("crypto.lang = ko"), out);
        assertEquals(0, cli.run("config", "history", "--jar", jar.toString()), cli.err());
        assertTrue(cli.out().contains("변경 이력 없음(최초 빌드 상태)"), cli.out());
    }

    @Test
    void setRecordsEveryChangeAndKeepsFullHistoryAcrossNewJars() throws Exception {
        Path first = dir.resolve("first.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "crypto.warning.enabled=false", "--operator", "123456",
                "--reason", "보안팀 승인", "--jar", jar.toString(), "--out", first.toString()), cli.err());
        assertTrue(cli.out().contains("변경 이력: 1번째 변경"), cli.out());
        Path second = dir.resolve("second.jar");
        assertEquals(0, cli.run("config", "set", "crypto.output.encoding=base64", "--operator", "a.kim@corp",
                "--jar", first.toString(), "--out", second.toString()), cli.err());
        // 바꾼 값이 없으면 실패하고 이력에도 남지 않는다.
        assertEquals(1, cli.run("config", "set", "crypto.output.encoding=base64", "--operator", "123456",
                "--jar", second.toString(), "--out", dir.resolve("same.jar").toString()));
        assertTrue(cli.err().contains("바꿀 내용이 없습니다"), cli.err());
        assertFalse(Files.exists(dir.resolve("same.jar")), "실패하면 결과 파일을 남기지 않는다");
        // 잘못된 값은 실패하고 이력에도 남지 않는다.
        assertEquals(1, cli.run("config", "set", "crypto.lang=jp", "--operator", "123456", "--jar", second.toString(),
                "--out", dir.resolve("bad.jar").toString()));
        assertTrue(cli.err().contains("[사유: CONFIGURATION]"), cli.err());

        assertEquals(0, cli.run("config", "history", "--jar", second.toString()), cli.err());
        String history = cli.out();
        assertTrue(history.contains("#1") && history.contains("수정자 123456") && history.contains("명령 config set"), history);
        assertTrue(history.contains("사유: 보안팀 승인"), history);
        assertTrue(history.contains("crypto.lang: ko -> en"), history);
        assertTrue(history.contains("crypto.warning.enabled: true -> false"), history);
        assertTrue(history.contains("#2") && history.contains("수정자 a.kim@corp"), history);
        assertTrue(history.contains("crypto.output.encoding: enc -> base64"), history);
        assertFalse(history.contains("#3"), "실패한 작업은 기록하지 않는다");
        assertTrue(history.contains("이력 검증: 정상"), history);
        assertTrue(history.contains("위변조 방지 감사 로그가 아닙니다"), history);

        assertEquals(0, cli.run("config", "show", "--jar", second.toString()), cli.err());
        assertTrue(cli.out().contains("총 변경 횟수: 2"), cli.out());
        assertTrue(cli.out().contains("마지막 수정자: a.kim@corp"), cli.out());
        assertTrue(leftovers().isEmpty(), "임시·잠금 파일이 남으면 안 된다: " + leftovers());
    }

    @Test
    void embedKeyWithCliOnlyMakesCompanyJarAndNeverRecordsTheKey() throws Exception {
        Path keyFile = dir.resolve("company.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString()), cli.err());
        String keyText = new String(Files.readAllBytes(keyFile), StandardCharsets.US_ASCII).trim();
        // 공개 키로 만든 기존 암호문
        String oldToken = TestSupport.jarDefaults().encryptText("dummy-db-password");

        Path company = dir.resolve("company.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--yes", "--jar", jar.toString(), "--out", company.toString()), cli.err());
        String out = cli.out();
        assertTrue(out.contains("rekey --from-jar"), "재암호화 절차를 안내해야 한다: " + out);
        assertFalse(out.contains(keyText), "키를 출력하면 안 된다");

        String history = historyText(company);
        assertFalse(history.contains(keyText), "이력에 키 원문이 들어가면 안 된다");
        assertFalse(history.contains(TestSupport.publicKeyBase64()), "이전 키 원문도 기록하면 안 된다");
        assertTrue(history.contains("after.crypto.key.embedded=[replaced]"), history);
        assertTrue(history.contains("before.crypto.key.id=default") && history.contains("after.crypto.key.id=prod01"), history);
        assertEquals(TestSupport.publicKeyBase64().length(), keyText.length());

        // 회사 JAR를 별도 JVM으로 다시 실행: config show/history, 기존 공개 키 암호문 거부, 새 키 암복호화
        TestJars.Run show = TestJars.run(company, Collections.singletonList("-Duser.language=ko"), "config", "show");
        assertEquals(0, show.exit, show.toString());
        assertTrue(show.out.contains("교체된 키") && show.out.contains("crypto.key.id = prod01"), show.toString());
        assertFalse(show.out.contains(keyText), "키를 출력하면 안 된다");
        TestJars.Run hist = TestJars.run(company, Collections.<String>emptyList(), "config", "history");
        assertEquals(0, hist.exit, hist.toString());
        assertTrue(hist.out.contains("crypto.key.embedded: (비공개) -> (교체됨)"), hist.toString());
        assertTrue(hist.out.contains("crypto.key.id: default -> prod01"), hist.toString());
        TestJars.Run verifyOld = TestJars.run(company, Collections.<String>emptyList(), "verify", "--value", oldToken);
        assertEquals(1, verifyOld.exit, "공개 키 암호문은 회사 JAR로 복호화되지 않아야 한다: " + verifyOld);
        assertTrue(verifyOld.err.contains("[사유: KEY_ID_MISMATCH]"), verifyOld.toString());
        TestJars.Run rekey = TestJars.run(company, Collections.<String>emptyList(), "rekey", "--from-jar", jar.toString(),
                "--value", oldToken);
        assertEquals(0, rekey.exit, rekey.toString());
        String newToken = rekey.out.trim();
        assertTrue(newToken.startsWith("ENC[v1:prod01:"), rekey.toString());
        assertFalse(rekey.out.contains("dummy-db-password") || rekey.err.contains("dummy-db-password"), "평문 미노출");
        TestJars.Run verifyNew = TestJars.run(company, Collections.<String>emptyList(), "verify", "--value", newToken);
        assertEquals(0, verifyNew.exit, verifyNew.toString());
        TestJars.Run fp = TestJars.run(company, Collections.<String>emptyList(), "fingerprint");
        TestJars.Run fpFile = TestJars.run(company, Collections.<String>emptyList(), "fingerprint", "--key-file", keyFile.toString());
        String line = fpLine(fp.out);
        assertEquals(line, fpLine(fpFile.out), "회사 JAR 키와 키 파일의 지문이 같아야 한다");
        // README 빠른 시작 2)의 doctor: 회사 JAR는 공개 키 WARN 없이 종료 코드 0(내장 키 추출 위험 안내는 남음), 키는 출력하지 않음
        TestJars.Run doctor = TestJars.run(company, Collections.<String>emptyList(), "doctor");
        assertEquals(0, doctor.exit, doctor.toString());
        assertFalse(doctor.out.contains("[WARN] 공개 기본 키"), doctor.toString());
        assertTrue(doctor.out.contains("FAIL 0"), doctor.toString());
        assertFalse(doctor.out.contains(keyText) || doctor.err.contains(keyText), "doctor가 키를 출력하면 안 된다");
    }

    private static String fpLine(String out) {
        for (String line : out.split("\\r?\\n")) {
            if (line.contains("SHA-256")) return line;
        }
        return "";
    }

    @Test
    void embedKeyRejectsKeyIdReuseThePublicKeyAndNonEmbeddedSourceWithoutOption() throws Exception {
        Path keyFile = dir.resolve("k.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString()));
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "default",
                "--operator", "123456", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("키ID 충돌") && cli.err().contains("rekey"), cli.err());
        Path publicKey = TestSupport.writeKeyFile(dir, "public.key", TestSupport.publicKeyBase64());
        assertEquals(1, cli.run("config", "embed-key", "--from-file", publicKey.toString(), "--key-id", "prod01",
                "--operator", "123456", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("공개 기본 키는 내장할 수 없습니다"), cli.err());
        Path fileSource = dir.resolve("file-source.jar");
        assertEquals(0, cli.run("config", "set", "crypto.key.source=file", "--operator", "123456", "--yes",
                "--jar", jar.toString(), "--out", fileSource.toString()), cli.err());
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--yes", "--jar", fileSource.toString()));
        assertTrue(cli.err().contains("--source=embedded"), cli.err());
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--source", "embedded", "--operator", "123456", "--yes", "--jar", fileSource.toString(),
                "--out", dir.resolve("embedded-again.jar").toString()), cli.err());
        assertTrue(historyText(dir.resolve("embedded-again.jar")).contains("after.crypto.key.source=embedded"));
    }

    @Test
    void embedKeyRejectsKeyIdsUsedEarlierInTheHistory() throws Exception {
        Path first = dir.resolve("first.key");
        Path second = dir.resolve("second.key");
        Path third = dir.resolve("third.key");
        for (Path key : new Path[] {first, second, third}) assertEquals(0, cli.run("keygen", "--out", key.toString()));
        Path v1 = dir.resolve("v1.jar");
        Path v2 = dir.resolve("v2.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", first.toString(), "--key-id", "prod01",
                "--operator", "123456", "--yes", "--jar", jar.toString(), "--out", v1.toString()), cli.err());
        assertEquals(0, cli.run("config", "embed-key", "--from-file", second.toString(), "--key-id", "prod02",
                "--operator", "123456", "--yes", "--jar", v1.toString(), "--out", v2.toString()), cli.err());
        // 이력에 남은 예전 키ID(prod01, 최초 값 default)는 다른 키에 다시 붙일 수 없다(예전 암호문과 혼동 방지).
        for (String reused : new String[] {"prod01", "default"}) {
            Path out = dir.resolve("reuse-" + reused + ".jar");
            assertEquals(1, cli.run("config", "embed-key", "--from-file", third.toString(), "--key-id", reused,
                    "--operator", "123456", "--yes", "--jar", v2.toString(), "--out", out.toString()));
            assertTrue(cli.err().contains("키ID 충돌") && cli.err().contains(reused) && cli.err().contains("config history")
                    && cli.err().contains("rekey"), cli.err());
            assertFalse(Files.exists(out), "거부하면 결과 JAR를 만들지 않는다");
        }
        // 한 번도 쓰지 않은 키ID는 허용한다.
        assertEquals(0, cli.run("config", "embed-key", "--from-file", third.toString(), "--key-id", "prod03",
                "--operator", "123456", "--yes", "--jar", v2.toString(), "--out", dir.resolve("v3.jar").toString()), cli.err());
    }

    @Test
    void keyRelatedChangeNeedsConfirmationAndOperatorIsRequired() throws Exception {
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--jar", jar.toString()));
        assertTrue(cli.err().contains("--operator"), cli.err());
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "bad id", "--jar", jar.toString()));
        assertTrue(cli.err().contains("수정자 ID 형식"), cli.err());
        // 터미널이 없고 --yes도 없으면 진행하지 않는다.
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "123456", "--jar", jar.toString()));
        assertTrue(cli.err().contains("CHANGE"), cli.err());
        // 대화형 확인에서 다른 값을 넣으면 취소
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("no");
        assertEquals(0, cli.run(terminal, "config", "set", "crypto.key.id=prod09", "--operator", "123456", "--jar", jar.toString()));
        assertTrue(cli.out().contains("취소했습니다"), cli.out());
        assertFalse(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")));
        terminal.lines.add("CHANGE");
        assertEquals(0, cli.run(terminal, "config", "set", "crypto.key.id=prod09", "--operator", "123456", "--jar", jar.toString()),
                cli.err());
        assertTrue(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")), "기본 결과 이름 <이름>-configured.jar");
        // 내장 키는 config set으로 바꿀 수 없다.
        assertEquals(1, cli.run("config", "set", "crypto.key.embedded=AAAA", "--operator", "123456", "--jar", jar.toString()));
        assertTrue(cli.err().contains("config embed-key"), cli.err());
        assertFalse(cli.err().contains("AAAA"));
    }

    @Test
    void unknownSettingNameGetsSuggestionAndNothingChanges() throws Exception {
        assertEquals(1, cli.run("config", "set", "crypto.warnning.enabled=false", "--operator", "123456", "--jar", jar.toString()));
        assertTrue(cli.err().contains("'crypto.warning.enabled'"), cli.err());
        assertFalse(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")));
    }

    @Test
    void replaceMakesBackupKeepsHistoryAndRefusesWhenLocked() throws Exception {
        Path target = Files.copy(jar, dir.resolve("app.jar"));
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", target.toString(),
                "--replace"), cli.err());
        assertTrue(cli.out().contains("Move-Item -Force") && cli.out().contains("mv "), cli.out());
        Path backup;
        try (Stream<Path> list = Files.list(dir)) {
            backup = list.filter(p -> p.getFileName().toString().startsWith("app.jar.bak-")).findFirst().orElse(null);
        }
        assertTrue(backup != null, "백업 파일이 있어야 한다");
        assertEquals(null, historyText(backup), "백업은 교체 전 원본이다");
        assertEquals(0, cli.run("config", "set", "crypto.warning.enabled=false", "--operator", "654321", "--jar", target.toString(),
                "--replace"), cli.err());
        String history = historyText(target);
        assertTrue(history.contains("entry.1.") && history.contains("entry.2."), "교체 후에도 전체 이력 유지: " + history);
        Files.createFile(dir.resolve("app.jar.lock"));
        assertEquals(1, cli.run("config", "set", "crypto.output.encoding=base64", "--operator", "123456", "--jar", target.toString(),
                "--replace"));
        assertTrue(cli.err().contains("잠금 파일"), cli.err());
        Files.delete(dir.resolve("app.jar.lock"));
        assertEquals(1, cli.run("config", "set", "crypto.lang=ko", "--operator", "123456", "--jar", target.toString(),
                "--replace", "--out", dir.resolve("x.jar").toString()));
        assertTrue(cli.err().contains("--out") && cli.err().contains("--replace"), cli.err());
    }

    @Test
    void existingOutputIsNeverOverwrittenAndSignedJarIsRefused() throws Exception {
        Path existing = Files.write(dir.resolve("exists.jar"), "keep".getBytes(StandardCharsets.US_ASCII));
        assertEquals(1, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", jar.toString(),
                "--out", existing.toString()));
        assertTrue(Arrays.equals("keep".getBytes(StandardCharsets.US_ASCII), Files.readAllBytes(existing)));
        Path signed = copyWithExtraEntry(jar, dir.resolve("signed.jar"), "META-INF/CORP.SF", "Signature-Version: 1.0\n");
        assertEquals(1, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", signed.toString(),
                "--out", dir.resolve("signed-out.jar").toString()));
        assertTrue(cli.err().contains("서명된 JAR"), cli.err());
        assertTrue(leftovers().isEmpty(), leftovers().toString());
    }

    @Test
    void tamperedHistoryOrSettingsChangedWithoutHistoryAreDetected() throws Exception {
        Path changed = dir.resolve("changed.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", jar.toString(),
                "--out", changed.toString()), cli.err());
        // 1) 이력의 수정자를 몰래 바꾼 JAR
        String history = historyText(changed);
        Path tampered = replaceEntry(changed, dir.resolve("tampered.jar"), ConfigHistory.ENTRY,
                history.replace("operator=123456", "operator=999999"));
        assertEquals(1, cli.run("config", "history", "--jar", tampered.toString()));
        assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
        assertFalse(cli.out().contains("999999"), "손상 이력을 정상 이력처럼 보여 주면 안 된다");
        assertEquals(1, cli.run("config", "set", "crypto.lang=ko", "--operator", "123456", "--jar", tampered.toString(),
                "--out", dir.resolve("t2.jar").toString()));
        assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
        // 2) 이력 없이 설정만 바꾼 JAR(직접 압축 수정)
        String settings = readEntry(jar, "java-crypto-kit.properties");
        Path silent = replaceEntry(jar, dir.resolve("silent.jar"), "java-crypto-kit.properties",
                settings.replace("crypto.warning.enabled=true", "crypto.warning.enabled=false"));
        assertEquals(1, cli.run("config", "show", "--jar", silent.toString()));
        assertTrue(cli.out().contains("이력 검증 실패"), cli.out());
        assertEquals(1, cli.run("config", "history", "--jar", silent.toString()));
        // 3) 설정은 그대로 두고 이력 파일만 지운 변경 JAR
        Path noHistory = removeEntry(changed, dir.resolve("nohistory.jar"), ConfigHistory.ENTRY);
        assertEquals(1, cli.run("config", "history", "--jar", noHistory.toString()));
    }

    @Test
    void changedJarAppliesSettingsAtRuntimeAndLanguagePersists() throws Exception {
        Path english = dir.resolve("english.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", jar.toString(),
                "--out", english.toString()), cli.err());
        TestJars.Run help = TestJars.run(english, Collections.singletonList("-Duser.language=ko"), "help");
        assertEquals(0, help.exit, help.toString());
        assertTrue(help.out.contains("Usage"), "JAR 설정 en이 Locale보다 우선: " + help);
        TestJars.Run info = TestJars.run(english, Collections.<String>emptyList(), "info");
        assertTrue(info.out.contains("Message language (crypto.lang): en -> en"), info.toString());
        TestJars.Run once = TestJars.run(english, Collections.<String>emptyList(), "info", "--lang", "ko");
        assertTrue(once.out.contains("메시지 언어(crypto.lang): en -> en"), "--lang은 이번 실행만: " + once);
        TestJars.Run again = TestJars.run(english, Collections.<String>emptyList(), "info");
        assertTrue(again.out.contains("Message language"), "--lang 뒤에도 영구 설정은 그대로: " + again);
        TestJars.Run jvm = TestJars.run(english, Collections.singletonList("-Dcrypto.lang=ko"), "info");
        assertTrue(jvm.out.contains("메시지 언어(crypto.lang): ko -> ko [출처: JVM 속성 -D]"), jvm.toString());
        TestJars.Run original = TestJars.run(jar, Collections.singletonList("-Duser.language=en"), "info");
        assertTrue(original.out.contains("메시지 언어(crypto.lang): ko -> ko"), "기본값 ko는 Locale과 무관: " + original);
    }

    @Test
    void basicJarWorksWithoutAwsSdkAndReportsMissingSdkOnlyForAwsKms() throws Exception {
        TestJars.Run info = TestJars.run(jar, Collections.<String>emptyList(), "info");
        assertEquals(0, info.exit, info.toString());
        Path dataKey = Files.write(dir.resolve("prod.datakey"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n".getBytes(StandardCharsets.US_ASCII));
        Path config = TestSupport.writeConfig(dir, "kms.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=ap-northeast-2", "crypto.aws.kms.key.id=alias/test",
                "crypto.aws.kms.data-key.file=" + TestSupport.propertiesPath(dataKey));
        TestJars.Run doctor = TestJars.run(jar, Collections.<String>emptyList(), "doctor", "--offline", "--config", config.toString());
        assertEquals(1, doctor.exit, doctor.toString());
        assertTrue(doctor.out.contains("[FAIL]") && doctor.out.contains("AWS SDK"), doctor.toString());
        TestJars.Run encrypt = TestJars.run(jar, Collections.<String>emptyList(), "verify", "--config", config.toString(),
                "--value", "ENC[v1:prod01:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA]");
        assertEquals(1, encrypt.exit);
        assertTrue(encrypt.err.contains("[사유: KEY_SOURCE]") && encrypt.err.contains("AWS SDK"), encrypt.toString());
    }

    // ---- 도우미 ----

    private static String readEntry(Path source, String name) throws Exception {
        try (JarFile file = new JarFile(source.toFile())) {
            try (InputStream in = file.getInputStream(file.getJarEntry(name))) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                return new String(out.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    private static Path replaceEntry(Path source, Path target, String name, String content) throws Exception {
        return rewrite(source, target, name, content.getBytes(StandardCharsets.UTF_8), null, null);
    }

    private static Path removeEntry(Path source, Path target, String name) throws Exception {
        return rewrite(source, target, name, null, null, null);
    }

    private static Path copyWithExtraEntry(Path source, Path target, String name, String content) throws Exception {
        return rewrite(source, target, null, null, name, content.getBytes(StandardCharsets.UTF_8));
    }

    /** JAR 항목 하나를 바꾸거나(내용 null이면 제거) 항목을 더한 사본을 만든다(이력 갱신 없이 = 직접 조작 재현). */
    private static Path rewrite(Path source, Path target, String name, byte[] content, String extraName, byte[] extra)
            throws Exception {
        try (JarFile in = new JarFile(source.toFile());
             OutputStream file = Files.newOutputStream(target);
             JarOutputStream out = new JarOutputStream(file, in.getManifest())) {
            for (Enumeration<JarEntry> entries = in.entries(); entries.hasMoreElements(); ) {
                JarEntry entry = entries.nextElement();
                if ("META-INF/MANIFEST.MF".equals(entry.getName())) continue;
                if (entry.getName().equals(name) && content == null) continue;
                out.putNextEntry(new JarEntry(entry.getName()));
                if (entry.getName().equals(name)) {
                    out.write(content);
                } else if (!entry.isDirectory()) {
                    try (InputStream data = in.getInputStream(entry)) {
                        byte[] buffer = new byte[8192];
                        int read;
                        while ((read = data.read(buffer)) != -1) out.write(buffer, 0, read);
                    }
                }
                out.closeEntry();
            }
            if (extraName != null) {
                out.putNextEntry(new JarEntry(extraName));
                out.write(extra);
                out.closeEntry();
            }
        }
        assertNotEquals(source, target);
        return target;
    }
}
