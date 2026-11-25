package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.LightObfuscation;
import io.javacryptokit.key.KeyResolver;
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
    /** 별도 JVM(java -jar)으로 민감 명령을 실행할 때 쓰는 관리자 비밀번호 파일. */
    private String adminFile;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
        // 관리자 비밀번호를 설정한 JAR(배포 JAR에 최초 설정을 마친 상태). 별도 JVM 실행이 실제 관리자 인증을 거친다.
        jar = CliHarness.configure(TestJars.build(dir.resolve("java-crypto-kit-0.1.0.jar")), CliHarness.ADMIN_PASSWORD);
        adminFile = CliHarness.passFile(dir, CliHarness.ADMIN_PASSWORD);
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    /** JAR 안 이력 본문(obf1 저장 표현을 되돌린 것). 이력이 없으면 null. */
    private String historyText(Path target) throws Exception {
        byte[] raw = rawEntry(target, ConfigHistory.ENTRY);
        return raw == null ? null : new String(LightObfuscation.decodeFile(raw), StandardCharsets.UTF_8);
    }

    /** JAR 항목의 원래 바이트(압축을 풀어 열었을 때 보이는 그대로). 없으면 null. */
    private static byte[] rawEntry(Path target, String name) throws Exception {
        try (JarFile file = new JarFile(target.toFile())) {
            JarEntry entry = file.getJarEntry(name);
            if (entry == null) return null;
            try (InputStream in = file.getInputStream(entry)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                return out.toByteArray();
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
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "시험"));
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "회사 키", "--yes", "--jar", original.toString()), cli.err());
        Path first = work.resolve("java-crypto-kit-0.1.0-configured.jar");
        assertTrue(cli.out().contains("생성 JAR  : " + first.toAbsolutePath()), "결과 JAR의 절대 경로: " + cli.out());
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

        // 원본은 그대로, 이력은 최초 설정 1건 뒤로 2 → 3 → 4 → 5건으로 이어지고, 마지막 JAR에는 네 변경이 모두 들어 있다.
        assertTrue(Arrays.equals(originalBytes, Files.readAllBytes(original)), "원본 JAR는 바뀌지 않는다");
        assertTrue(historyText(first).contains("entry.1.command=admin setup") && historyText(first).contains("entry.2.")
                && !historyText(first).contains("entry.3."), historyText(first));
        assertTrue(historyText(third).contains("entry.4.command=set") && !historyText(third).contains("entry.5."));
        assertTrue(historyText(fourth).contains("entry.5.command=set"), historyText(fourth));
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
        assertTrue(historyText(named).contains("entry.7."), "교체 후에도 이력 유지: " + historyText(named));
        try (Stream<Path> list = Files.list(work)) {
            assertFalse(list.anyMatch(p -> p.getFileName().toString().endsWith(".tmp") || p.getFileName().toString().endsWith(".lock")),
                    "임시·잠금 파일이 남지 않는다");
        }
    }

    @Test
    void initialJarShowsNoHistoryAndHidesTheKey() throws Exception {
        // 빌드 직후 JAR(관리자 비밀번호 미설정, 이력 없음): 최초 빌드 상태
        Path fresh = TestJars.build(dir.resolve("fresh.jar"));
        assertEquals(0, cli.run("config", "show", "--jar", fresh.toString()), cli.err());
        assertTrue(cli.out().contains("상태      : 최초 빌드 상태(변경 이력 없음)")
                && cli.out().contains("관리자    : 미설정(CLI를 처음 실행할 때 설정)"), cli.out());
        assertEquals(0, cli.run("config", "history", "--jar", fresh.toString()), cli.err());
        assertTrue(cli.out().contains("변경 이력 없음"), cli.out());
        // 최초 설정을 마친 JAR: 이력은 관리자 비밀번호 설정 기록 1건
        assertEquals(0, cli.run("config", "show", "--jar", jar.toString()), cli.err());
        String out = cli.out();
        assertTrue(out.startsWith("JAR 내부 설정 (외부 설정·-D 미반영"), "첫 줄에 JAR 내부 값임을 표시: " + out);
        assertTrue(out.contains("상태      : 변경 1회 - 마지막 ") && out.contains("수정자 test-setup"), out);
        assertTrue(out.contains("빌드 일시 : 2026-11-21T00:00:00Z"), out);
        // 관리자 인증 뒤 보는 관리정보: 관리자 비밀번호 상태, 기본 유형, 유형별 기본 키, 키마다 요약 한 줄과 전체 지문(64자),
        // pass는 KDF·반복 횟수·Salt·Salt SHA-256(마스킹 없음, 키 원문 없음)
        assertTrue(out.contains("관리자    : 비밀번호 설정됨(민감 명령은 관리자 인증 필요)"), out);
        assertTrue(out.contains("기본 유형 : pass"), out);
        assertTrue(out.contains("기본 키   : pass=pass-default, key=default"), out);
        String ls = System.lineSeparator();
        assertTrue(out.contains("키 목록   :" + ls + "  default: key, embedded, 공개 기본 키, crypto.key.*" + ls
                + "    키 지문: aac695cbd2498e97131ae49579a219c5e7f41e87e2738ba49199847c00e41a49" + ls), out);
        assertTrue(out.contains("  pass-default: pass, embedded, 공개 기본 키" + ls
                + "    키 지문: 3dca588c78a17aad886e9403e8743990d79d479bbe610664adc3ff7e94453656" + ls
                + "    KDF: pbkdf2-sha256, 600,000회" + ls + "    Salt: "), out);
        assertTrue(out.contains("    Salt SHA-256:" + ls + "      "), "80열을 넘는 항목은 이름 다음 줄에 값: " + out);
        for (String line : out.split("\\r?\\n")) assertTrue(CliHelp.width(line) <= 80 || line.contains(" = "), "80열: " + line);
        assertTrue(out.contains("crypto.keys.pass-default.embedded = (비공개)"), "키 프로필의 내장 값도 숨긴다: " + out);
        assertTrue(out.contains("설정 지문 : sha256:"), "설정 파일 지문은 키 지문과 다른 라벨: " + out);
        assertFalse(out.contains(TestSupport.publicKeyBase64()), "내장 키 값을 출력하면 안 된다");
        assertTrue(out.contains("crypto.key.embedded = (비공개)") && out.contains("crypto.lang = ko"), out);
        assertEquals(1, out.split("crypto\\.lang = ", -1).length - 1, "설정값은 한 번만 표시: " + out);
        assertEquals(0, cli.run("config", "history", "--jar", jar.toString()), cli.err());
        assertTrue(cli.out().contains("이력 검증 : 정상(1건") && cli.out().contains("표시 범위 : pass 관련 0건(전체 1건)"), cli.out());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", jar.toString()), cli.err());
        assertTrue(cli.out().contains("admin setup  [관리자]") && cli.out().contains("관리자 비밀번호: (없음) -> (설정됨)"), cli.out());
    }

    @Test
    void setRecordsEveryChangeAndKeepsFullHistoryAcrossNewJars() throws Exception {
        Path first = dir.resolve("first.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "crypto.warning.enabled=false", "--operator", "123456",
                "--reason", "보안팀 승인", "--jar", jar.toString(), "--out", first.toString()), cli.err());
        // 결과: 생성 JAR 한 줄과 변경 항목(한 줄에 하나씩, 값 열에 맞춤)뿐
        assertEquals("생성 JAR  : " + first.toAbsolutePath() + System.lineSeparator() + CliHarness.permissionLine()
                + "변경 항목 : crypto.lang (ko -> en)" + System.lineSeparator()
                + "            crypto.warning.enabled (true -> false)" + System.lineSeparator(),
                cli.out(), "결과는 생성 JAR와 항목별 변경 내용뿐");
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

        // 기본 보기는 pass 관련 변경만이다: 일반 설정만 바꾼 이력은 보이지 않고, 범위와 전체 건수를 표시한다(검증은 전체).
        assertEquals(0, cli.run("config", "history", "--jar", second.toString()), cli.err());
        assertTrue(cli.out().contains("이력 검증 : 정상(3건") && cli.out().contains("표시 범위 : pass 관련 0건(전체 3건)")
                && !cli.out().contains("#1") && !cli.out().contains("#2"), cli.out());
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", second.toString()), cli.err());
        assertTrue(cli.out().contains("표시 범위 : key 관련 0건(전체 3건)"), cli.out());
        assertEquals(1, cli.run("config", "history", "--all", "--type", "pass", "--jar", second.toString()));
        assertTrue(cli.err().contains("--type과 --all은 함께 쓸 수 없습니다"), cli.err());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", second.toString()), cli.err());
        String history = cli.out();
        assertTrue(history.contains("표시 범위 : 전체 3건"), history);
        assertTrue(history.contains("#1  ") && history.contains("admin setup  [관리자]"), history);
        assertTrue(history.contains("#2  ") && history.contains("수정자 123456") && history.contains("config set  [일반]"), history);
        assertTrue(history.contains("    사유: 보안팀 승인"), "사유·변경 줄은 4칸 들여 쓴다: " + history);
        assertTrue(history.contains("    crypto.lang: ko -> en"), history);
        assertTrue(history.contains("crypto.warning.enabled: true -> false"), history);
        assertTrue(history.contains("#3") && history.contains("수정자 a.kim@corp"), history);
        assertTrue(history.contains("crypto.output.encoding: enc -> base64"), history);
        assertFalse(history.contains("#4"), "실패한 작업은 기록하지 않는다");
        assertTrue(history.contains("이력 검증 : 정상(3건"), history);
        assertFalse(history.contains("감사 로그"), "이력 특성 설명은 사용자 가이드에만 둔다: " + history);

        assertEquals(0, cli.run("config", "show", "--jar", second.toString()), cli.err());
        assertTrue(cli.out().contains("상태      : 변경 3회 - 마지막 ") && cli.out().contains("수정자 a.kim@corp"), cli.out());

        // 긴 값: 80열을 넘으면 이름 다음과 -> 앞에서만 줄을 바꾸고 값은 자르지 않는다(결과·이력 모두).
        Path pool = dir.resolve("pool.jar");
        assertEquals(0, cli.run("config", "set", "crypto.pool.factory=org.apache.tomcat.jdbc.pool.DataSourceFactory",
                "--operator", "123456", "--jar", second.toString(), "--out", pool.toString()), cli.err());
        String[] result = CliHarness.withoutPermissionLine(cli.out()).split("\\r?\\n");
        assertEquals("변경 항목 : crypto.pool.factory", result[1], cli.out());
        assertEquals("              (org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory", result[2], cli.out());
        assertEquals("              -> org.apache.tomcat.jdbc.pool.DataSourceFactory)", result[3], cli.out());
        assertEquals(4, result.length, cli.out());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", pool.toString()), cli.err());
        assertTrue(cli.out().contains("    crypto.pool.factory: org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory"
                + System.lineSeparator() + "      -> org.apache.tomcat.jdbc.pool.DataSourceFactory"), cli.out());
        for (String line : cli.out().split("\\r?\\n")) {
            assertTrue(CliHelp.width(line) <= 80, "이력 80열 초과: " + line);
        }
        assertTrue(leftovers().isEmpty(), "임시·잠금 파일이 남으면 안 된다: " + leftovers());
    }

    @Test
    void embedKeyWithCliOnlyMakesCompanyJarAndNeverRecordsTheKey() throws Exception {
        Path keyFile = dir.resolve("company.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "회사 키 준비"), cli.err());
        String keyText = new String(Files.readAllBytes(keyFile), StandardCharsets.US_ASCII).trim();
        // 공개 AES 키(default)로 만든 기존 암호문
        String oldToken = TestSupport.jarDefaults().encryptText("dummy-db-password", io.javacryptokit.KeyType.KEY);

        Path company = dir.resolve("company.jar");
        // 실제 키 변경이므로 새 JAR를 만들 때도 확인이 필요하다: 터미널도 --yes도 없으면 아무것도 만들지 않는다.
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "회사 키", "--jar", jar.toString(), "--out", company.toString()));
        assertTrue(cli.err().contains("CHANGE") && cli.err().contains("--yes"), cli.err());
        assertFalse(Files.exists(company), "확인 없이 결과 JAR를 만들면 안 된다");
        // 대화형 확인 화면: 제목, 결과 JAR, 바뀌는 항목(이전 키를 같은 키 ID로 남기는 항목 포함)
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("회사 키로 교체");
        terminal.lines.add("CHANGE");
        assertEquals(0, cli.run(terminal, "config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--jar", jar.toString(), "--out", company.toString()), cli.err());
        // 사유 → 바꿀 내용 → CHANGE 확인 순서
        assertEquals(java.util.Arrays.asList("사유(비밀값 제외): ", "계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): "),
                terminal.prompts);
        String screen = String.join("\n", terminal.printed);
        assertTrue(screen.startsWith("AES 키(crypto.key.*)를 교체합니다(이전 키가 남아 기존 암호문은 그대로):"), screen);
        assertTrue(screen.contains("  사유: 회사 키로 교체"), screen);
        assertTrue(screen.contains("  결과: 새 JAR company.jar (원본은 그대로)"), screen);
        assertTrue(screen.contains("  crypto.keys.default.embedded (비공개)"), screen);
        String out = cli.out();
        assertTrue(out.contains("생성 JAR  : " + company.toAbsolutePath()), out);
        String ls = System.lineSeparator();
        assertTrue(out.contains("변경 항목 : crypto.key.embedded (비공개)" + ls
                + "            crypto.key.id (default -> prod01)" + ls
                + "            crypto.keys.default.type ((없음) -> key)" + ls
                + "            crypto.keys.default.source ((없음) -> embedded)" + ls
                + "            crypto.keys.default.embedded (비공개)" + ls), "변경 항목은 한 줄에 하나씩: " + out);
        assertTrue(java.util.regex.Pattern.compile("키 지문   : [0-9a-f]{12}\\.\\.\\.[0-9a-f]{8}").matcher(out).find(), out);
        assertEquals(7, CliHarness.withoutPermissionLine(out).trim().split("\\r?\\n").length,
                "결과는 JAR·(POSIX 권한 안내)·변경 항목·키 지문뿐(다음 단계 안내 없음): " + out);
        assertFalse(out.contains(keyText), "키를 출력하면 안 된다");

        String history = historyText(company);
        assertFalse(history.contains(keyText), "이력에 키 원문이 들어가면 안 된다");
        assertFalse(history.contains(TestSupport.publicKeyBase64()), "이전 키 원문도 기록하면 안 된다");
        assertTrue(history.contains("after.crypto.key.embedded=[replaced]"), history);
        assertTrue(history.contains("before.crypto.key.id=default") && history.contains("after.crypto.key.id=prod01"), history);
        assertTrue(history.contains("before.crypto.keys.default.embedded=[none]")
                && history.contains("after.crypto.keys.default.embedded=[secret]"), "옮긴 이전 키도 값 없이 표시만: " + history);
        assertTrue(history.contains("before.key.prod01=[none]")
                && history.contains("after.key.prod01=type=key;source=embedded;origin=file;slot=yes;fingerprint="), history);
        // 이전 슬롯 키(공개 AES 키 default)는 같은 키 ID로 키 목록에 옮긴다: 전후 지문이 같은 기록
        assertTrue(history.contains("before.key.default=type=key;source=embedded;slot=yes;public=yes;fingerprint=aac695cbd249")
                && history.contains("after.key.default=type=key;source=embedded;origin=moved;public=yes;fingerprint=aac695cbd249"),
                history);
        assertTrue(history.contains("entry.1.command=admin setup") && history.contains("entry.2.reason=회사 키로 교체"), history);
        assertEquals(TestSupport.publicKeyBase64().length(), keyText.length());

        // 회사 JAR를 별도 JVM으로 다시 실행: config show/history, 기존 공개 키 암호문 거부, 새 키 암복호화
        TestJars.Run show = TestJars.run(company, Collections.singletonList("-Duser.language=ko"), "config", "show",
                "--admin-pass-file", adminFile);
        assertEquals(0, show.exit, show.toString());
        assertTrue(show.out.contains("  prod01: key, embedded, 사용자 지정, ")
                && show.out.contains("crypto.key.id = prod01"), show.toString());
        assertTrue(show.out.contains("기본 키   : pass=pass-default, key=prod01"), "key 기본은 새 crypto.key.* 키: " + show);
        assertFalse(show.out.contains(keyText), "키를 출력하면 안 된다");
        TestJars.Run hist = TestJars.run(company, Collections.<String>emptyList(), "config", "history", "--type", "key",
                "--admin-pass-file", adminFile);
        assertEquals(0, hist.exit, hist.toString());
        assertTrue(hist.out.contains("표시 범위 : key 관련 1건(전체 2건)"), hist.toString());
        assertTrue(hist.out.contains("config embed-key  [key]") && hist.out.contains("    사유: 회사 키로 교체"), hist.toString());
        assertTrue(hist.out.contains("crypto.key.embedded: (비공개) -> (교체됨)"), hist.toString());
        assertTrue(hist.out.contains("crypto.key.id: default -> prod01"), hist.toString());
        // 키 기록: 요약 한 줄과 기록된 관리정보(전체 지문)를 마스킹 없이 보여 준다. 80열을 넘는 기록은 -> 앞에서 줄을 바꾼다.
        assertTrue(hist.out.contains("    키 prod01: (없음) -> key, embedded, crypto.key.*, 파일" + System.lineSeparator()
                + "      키 지문: " + KeyResolver.fingerprint(java.util.Base64.getDecoder().decode(keyText))), hist.toString());
        assertTrue(hist.out.contains("    키 default: key, embedded, crypto.key.*, 공개 기본 키" + System.lineSeparator()
                + "      -> key, embedded, 공개 기본 키, 옮김" + System.lineSeparator()
                + "      키 지문: aac695cbd2498e97131ae49579a219c5e7f41e87e2738ba49199847c00e41a49"), hist.toString());
        for (String line : hist.out.split("\\r?\\n")) assertTrue(CliHelp.width(line) <= 80, "이력 80열: " + line);
        // 기본 보기(pass)에는 이 변경이 없다.
        TestJars.Run passView = TestJars.run(company, Collections.<String>emptyList(), "config", "history",
                "--admin-pass-file", adminFile);
        assertTrue(passView.out.contains("표시 범위 : pass 관련 0건(전체 2건)") && !passView.out.contains("#1")
                && !passView.out.contains("#2"), passView.toString());
        // 이전 키(공개 AES 키 default)는 키 목록에 남으므로 기존 암호문은 계속 복호화된다(공개 키 사용 경고 1줄).
        TestJars.Run verifyOld = TestJars.run(company, Collections.<String>emptyList(), "verify", "--value", oldToken);
        assertEquals(0, verifyOld.exit, "이전 키는 남아 기존 암호문을 복호화한다: " + verifyOld);
        assertTrue(verifyOld.err.contains("[WARN]"), verifyOld.toString());
        TestJars.Run rekey = TestJars.run(company, Collections.<String>emptyList(), "rekey", "--from-jar", jar.toString(),
                "--value", oldToken, "--admin-pass-file", adminFile);
        assertEquals(0, rekey.exit, rekey.toString());
        String newToken = rekey.out.trim();
        assertTrue(newToken.startsWith("ENC[v1:prod01:"), rekey.toString());
        assertFalse(newToken.contains("\n"), "표준 출력은 새 암호문 한 줄만: " + rekey);
        // 이전 키(공개 키)로 푸는 것은 경고하지 않는다(새 암호문은 사용자 지정 키). 안내 문구도 없다.
        assertEquals("", rekey.err.trim(), "rekey 성공 시 표준 오류는 비어 있다: " + rekey);
        assertFalse(rekey.out.contains("dummy-db-password") || rekey.err.contains("dummy-db-password"), "평문 미노출");
        TestJars.Run verifyNew = TestJars.run(company, Collections.<String>emptyList(), "verify", "--value", newToken);
        assertEquals(0, verifyNew.exit, verifyNew.toString());
        TestJars.Run fp = TestJars.run(company, Collections.<String>emptyList(), "fingerprint", "--type", "key");
        TestJars.Run fpFile = TestJars.run(company, Collections.<String>emptyList(), "fingerprint", "--key-file", keyFile.toString());
        String line = fpLine(fp.out);
        assertFalse(line.isEmpty(), fp.toString());
        assertEquals(line, fpLine(fpFile.out), "회사 JAR 키와 키 파일의 지문(전체 64자)이 같아야 한다");
        // README 4장의 doctor: 회사 JAR는 경고 없이 종료 코드 0, 키 상태는 사용자 지정, 키는 출력하지 않음
        TestJars.Run doctor = TestJars.run(company, Collections.<String>emptyList(), "doctor");
        assertEquals(0, doctor.exit, doctor.toString());
        assertFalse(doctor.out.contains("[WARN]") || doctor.err.contains("[WARN]"), doctor.toString());
        assertTrue(doctor.out.contains("키 로딩 정상: prod01, 사용자 지정") && doctor.out.contains("결과: PASS"), doctor.toString());
        assertFalse(doctor.out.contains(keyText) || doctor.err.contains(keyText), "doctor가 키를 출력하면 안 된다");

        // 공개 키를 더 쓰지 않으려면 명시적으로 제거한다(자동 삭제 없음). 제거 후에는 그 키의 암호문이 KEY_ID_MISMATCH다.
        Path noPublic = dir.resolve("company-no-public.jar");
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "default", "--operator", "123456", "--yes",
                "--reason", "공개 키 제거", "--jar", company.toString(), "--out", noPublic.toString()), cli.err());
        TestJars.Run verifyRemoved = TestJars.run(noPublic, Collections.<String>emptyList(), "verify", "--value", oldToken);
        assertEquals(1, verifyRemoved.exit, verifyRemoved.toString());
        assertTrue(verifyRemoved.err.contains("[사유: KEY_ID_MISMATCH]"), verifyRemoved.toString());
        TestJars.Run verifyMoved = TestJars.run(noPublic, Collections.<String>emptyList(), "verify", "--value", newToken);
        assertEquals(0, verifyMoved.exit, "rekey한 암호문은 그대로 쓴다: " + verifyMoved);
    }

    @Test
    void cliPrintsThePublicKeyWarningOnceOnStandardErrorOnlyWhenTheKeyIsUsed() throws Exception {
        // 실제 JVM(java -jar)으로 실행: 공개 기본 키를 쓰는 명령은 표준 오류에 [WARN] 한 줄, 결과(표준 출력)와 섞이지 않는다.
        String token = TestSupport.jarDefaults().encryptText("dummy-warn-pw");
        TestJars.Run verify = TestJars.run(jar, Collections.<String>emptyList(), "verify", "--value", token);
        assertEquals(0, verify.exit, verify.toString());
        assertEquals("OK", verify.out.trim(), verify.toString());
        assertEquals("[WARN] 공개 기본 키 사용 중 (별도 키 설정 권장)", verify.err.trim(), verify.toString());
        // 경고를 끄면 0건, 결과는 그대로
        TestJars.Run quiet = TestJars.run(jar, Collections.singletonList("-Dcrypto.warning.enabled=false"),
                "verify", "--value", token);
        assertEquals(0, quiet.exit, quiet.toString());
        assertEquals("", quiet.err.trim(), quiet.toString());
        // 키 상태를 직접 보여 주는 조회(info·doctor·fingerprint)와 키를 쓰지 않는 조회(config show·help)는 경고하지 않는다.
        for (String[] args : new String[][]{{"info"}, {"doctor"}, {"fingerprint"},
                {"config", "show", "--admin-pass-file", adminFile}, {"help"}}) {
            TestJars.Run run = TestJars.run(jar, Collections.<String>emptyList(), args);
            assertEquals(0, run.exit, run.toString());
            assertFalse(run.err.contains("[WARN]") || run.out.contains("[WARN]"), String.join(" ", args) + ": " + run);
        }
    }

    /** fingerprint 출력에서 64자 키 지문 줄을 찾는다. */
    private static String fpLine(String out) {
        for (String line : out.split("\\r?\\n")) {
            if (line.matches(".*: [0-9a-f]{64}")) return line;
        }
        return "";
    }

    @Test
    void embedKeyRejectsKeyIdReuseThePublicKeyAndNonEmbeddedSourceWithoutOption() throws Exception {
        Path keyFile = dir.resolve("k.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "x"));
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "default",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("키 ID default") && cli.err().contains("--key-id"), cli.err());
        Path publicKey = TestSupport.writeKeyFile(dir, "public.key", TestSupport.publicKeyBase64());
        assertEquals(1, cli.run("config", "embed-key", "--from-file", publicKey.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("공개 기본 키는 내장할 수 없습니다"), cli.err());
        Path fileSource = dir.resolve("file-source.jar");
        assertEquals(0, cli.run("config", "set", "crypto.key.source=file", "--operator", "123456", "--reason", "외부 키",
                "--yes", "--jar", jar.toString(), "--out", fileSource.toString()), cli.err());
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", fileSource.toString()));
        assertTrue(cli.err().contains("--source embedded") && cli.err().contains("JAR는 바뀌지 않았습니다"), cli.err());
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--source", "embedded", "--operator", "123456", "--reason", "x", "--yes", "--jar", fileSource.toString(),
                "--out", dir.resolve("embedded-again.jar").toString()), cli.err());
        assertTrue(historyText(dir.resolve("embedded-again.jar")).contains("after.crypto.key.source=embedded"));
        // 이전 키(file, 위치는 실행 시 지정)는 지금 읽을 수 없으므로 키 목록에 남기지 않고 그 사실을 결과에 쓴다.
        assertTrue(cli.out().contains("이전 키 default(file)는 지금 읽을 수 없어 키 목록에 남기지 않습니다"), cli.out());
        assertFalse(cli.out().contains("crypto.keys.default."), cli.out());
        // 이전 키를 남길 수 없으면 확인 제목도 기존 암호문 영향(rekey 필요)을 그대로 알린다("남습니다"라고 하지 않음).
        CliHarness.FakeTerminal confirmTerminal = new CliHarness.FakeTerminal();
        confirmTerminal.lines.add("CANCEL");
        assertEquals(0, cli.run(confirmTerminal, "config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--source", "embedded", "--operator", "123456", "--reason", "x", "--jar", fileSource.toString(),
                "--out", dir.resolve("cancelled.jar").toString()), cli.err());
        String confirmScreen = String.join("\n", confirmTerminal.printed);
        assertTrue(confirmScreen.startsWith("내장 키를 교체합니다(기존 암호문은 rekey로 재암호화 필요):"), confirmScreen);
        assertTrue(confirmScreen.contains("이전 키 default(file)는 지금 읽을 수 없어 키 목록에 남기지 않습니다"), confirmScreen);
        assertFalse(Files.exists(dir.resolve("cancelled.jar")), "취소하면 결과 JAR를 만들지 않는다");
    }

    @Test
    void embedKeyRejectsKeyIdsUsedEarlierInTheHistory() throws Exception {
        Path first = dir.resolve("first.key");
        Path second = dir.resolve("second.key");
        Path third = dir.resolve("third.key");
        for (Path key : new Path[] {first, second, third}) {
            assertEquals(0, cli.run("keygen", "--out", key.toString(), "--reason", "x"));
        }
        Path v1 = dir.resolve("v1.jar");
        Path v2 = dir.resolve("v2.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", first.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString(), "--out", v1.toString()), cli.err());
        assertEquals(0, cli.run("config", "embed-key", "--from-file", second.toString(), "--key-id", "prod02",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", v1.toString(), "--out", v2.toString()), cli.err());
        // 이전 AES 키 prod01은 키 목록에 남아 있다(등록된 키 ID), default는 공개 기본 키 전용: 둘 다 다른 키에 붙일 수 없다.
        for (String reused : new String[] {"prod01", "default"}) {
            Path out = dir.resolve("reuse-" + reused + ".jar");
            assertEquals(1, cli.run("config", "embed-key", "--from-file", third.toString(), "--key-id", reused,
                    "--operator", "123456", "--reason", "x", "--yes", "--jar", v2.toString(), "--out", out.toString()));
            assertTrue(cli.err().contains("키 ID " + reused) && cli.err().contains("--key-id"), cli.err());
            assertFalse(Files.exists(out), "거부하면 결과 JAR를 만들지 않는다");
        }
        // 키 목록에서 뺀 뒤에도 이력에 남은 키 ID(prod01)는 다른 키에 다시 붙일 수 없다(예전 암호문과 혼동 방지).
        Path v2r = dir.resolve("v2-removed.jar");
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "prod01", "--operator", "123456", "--reason", "x",
                "--yes", "--jar", v2.toString(), "--out", v2r.toString()), cli.err());
        Path reuse = dir.resolve("reuse-removed.jar");
        assertEquals(1, cli.run("config", "embed-key", "--from-file", third.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", v2r.toString(), "--out", reuse.toString()));
        assertTrue(cli.err().contains("키 ID prod01") && cli.err().contains("config history") && cli.err().contains("--key-id")
                && cli.err().contains("다른 항목: 키 지문"), cli.err());
        assertFalse(Files.exists(reuse), "거부하면 결과 JAR를 만들지 않는다");
        // 같은 키(first)를 같은 키 ID로 되살리는 것은 허용한다: 이력의 전체 지문과 같다. 예전 prod01 암호문이 다시 복호화된다.
        String oldToken = io.javacryptokit.core.CryptoService.of(JarConfigEditor.read(v1).validated())
                .encryptText("dummy-prod01".toCharArray(), null, "prod01");
        Path back = dir.resolve("prod01-back.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", first.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "복구", "--yes", "--jar", v2r.toString(), "--out", back.toString()), cli.err());
        assertTrue(cli.out().contains("복원      : 이력에 기록된 이 키 ID의 키와 같음"), cli.out());
        assertEquals("dummy-prod01", io.javacryptokit.core.CryptoService.of(JarConfigEditor.read(back).validated())
                .decryptText(oldToken));
        // 한 번도 쓰지 않은 키ID는 허용한다.
        assertEquals(0, cli.run("config", "embed-key", "--from-file", third.toString(), "--key-id", "prod03",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", v2.toString(), "--out",
                dir.resolve("v3.jar").toString()), cli.err());
    }

    @Test
    void confirmationIsAskedForEveryKeyChangeButNotForOtherSettings() throws Exception {
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--jar", jar.toString()));
        assertTrue(cli.err().contains("--operator"), cli.err());
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "bad id", "--jar", jar.toString()));
        assertTrue(cli.err().contains("수정자 ID 형식"), cli.err());
        // 키 관련 설정은 사유가 필수다(비대화형이면 아무것도 만들기 전에 실패, --yes로도 생략할 수 없음).
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "123456", "--yes", "--jar",
                jar.toString()));
        assertTrue(cli.err().contains("--reason"), cli.err());
        assertFalse(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")), "사유 없이 만들면 안 된다");
        // 키 관련 설정은 새 JAR를 만들 때도 확인한다: 터미널도 --yes도 없으면 만들지 않는다.
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "123456", "--reason", "x",
                "--jar", jar.toString()));
        assertTrue(cli.err().contains("CHANGE") && cli.err().contains("--yes"), cli.err());
        assertFalse(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")), "확인 없이 만들면 안 된다");
        assertEquals(0, cli.run("config", "set", "crypto.key.id=prod09", "--operator", "123456", "--reason", "x", "--yes",
                "--jar", jar.toString()), cli.err());
        assertTrue(Files.exists(dir.resolve("java-crypto-kit-0.1.0-configured.jar")), "기본 결과 이름 <이름>-configured.jar");
        // 키와 무관한 설정은 새 JAR 생성에 확인이 없다.
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", jar.toString(),
                "--out", dir.resolve("lang.jar").toString()), cli.err());
        // 원본 교체(--replace) + 키 관련 설정: 터미널이 없고 --yes도 없으면 바꾸지 않고 실패한다.
        Path target = Files.copy(jar, dir.resolve("replace-me.jar"));
        byte[] before = Files.readAllBytes(target);
        assertEquals(1, cli.run("config", "set", "crypto.key.id=prod10", "--operator", "123456", "--reason", "x",
                "--jar", target.toString(), "--replace"));
        assertTrue(cli.err().contains("CHANGE") && cli.err().contains("--yes"), cli.err());
        assertTrue(Arrays.equals(before, Files.readAllBytes(target)), "확인 없이 원본을 바꾸면 안 된다");
        // 대화형 확인에서 다른 값을 넣으면 취소, CHANGE면 백업 후 교체
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("키 ID 정리");
        terminal.lines.add("no");
        assertEquals(0, cli.run(terminal, "config", "set", "crypto.key.id=prod10", "--operator", "123456",
                "--jar", target.toString(), "--replace"));
        assertEquals("사유(비밀값 제외): ", terminal.prompts.get(0), "사유를 먼저 묻는다");
        assertTrue(cli.out().contains("취소했습니다"), cli.out());
        assertTrue(Arrays.equals(before, Files.readAllBytes(target)), "취소하면 원본 그대로");
        assertTrue(String.join("\n", terminal.printed).contains("crypto.key.id (default -> prod10)"), terminal.printed.toString());
        assertTrue(terminal.printed.contains("  결과: 원본 JAR 교체(백업 생성)"), terminal.printed.toString());
        terminal.lines.add("CHANGE");
        assertEquals(0, cli.run(terminal, "config", "set", "crypto.key.id=prod10", "--operator", "123456",
                "--reason", "키 ID 정리", "--jar", target.toString(), "--replace"), cli.err());
        assertTrue(historyText(target).contains("after.crypto.key.id=prod10"), "확인 후 원본 자리에서 변경");
        // --yes면 묻지 않는다(무인 자동화). 키와 무관한 설정은 --replace여도 묻지 않는다.
        assertEquals(0, cli.run("config", "set", "crypto.key.id=prod11", "--operator", "123456", "--reason", "x",
                "--jar", target.toString(), "--replace", "--yes"), cli.err());
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", target.toString(),
                "--replace"), cli.err());
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
        String historyBefore = historyText(target);
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", target.toString(),
                "--replace"), cli.err());
        Path backup;
        try (Stream<Path> list = Files.list(dir)) {
            backup = list.filter(p -> p.getFileName().toString().startsWith("app.jar.bak-")).findFirst().orElse(null);
        }
        assertTrue(backup != null, "백업 파일이 있어야 한다");
        // 결과: 교체한 JAR, 백업 파일, 변경 항목(복구 명령 강의 없음)
        assertTrue(cli.out().contains("교체 JAR  : " + target.toAbsolutePath())
                && cli.out().contains("백업      : " + backup.toAbsolutePath())
                && cli.out().contains("변경 항목 : crypto.lang (ko -> en)"), cli.out());
        assertEquals(3, cli.out().trim().split("\\r?\\n").length, cli.out());
        assertEquals(historyBefore, historyText(backup), "백업은 교체 전 원본이다(이력 포함)");
        assertEquals(0, cli.run("config", "set", "crypto.warning.enabled=false", "--operator", "654321", "--jar", target.toString(),
                "--replace"), cli.err());
        String history = historyText(target);
        assertTrue(history.contains("entry.1.command=admin setup") && history.contains("entry.2.") && history.contains("entry.3."),
                "교체 후에도 전체 이력 유지: " + history);
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
        // JAR 안 이력은 obf1로 저장되어 압축을 풀어도 수정자 등이 글자 그대로 보이지 않는다.
        assertFalse(new String(rawEntry(changed, ConfigHistory.ENTRY), StandardCharsets.UTF_8).contains("123456"),
                "이력 본문은 obf1 표현");
        // 1) 이력의 수정자를 몰래 바꾼 JAR(obf1을 되돌려 고친 뒤 다시 저장해도 해시 체인 검증에 걸린다)
        String history = historyText(changed);
        Path tampered = replaceEntry(changed, dir.resolve("tampered.jar"), ConfigHistory.ENTRY,
                new String(ConfigHistory.store(history.replace("operator=123456", "operator=999999")
                        .getBytes(StandardCharsets.UTF_8)), StandardCharsets.US_ASCII));
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
        // 4) obf1 이력의 한 글자가 손상된 JAR(확인값 불일치): 다른 값으로 대체하지 않고 손상으로 판정한다
        String stored = new String(rawEntry(changed, ConfigHistory.ENTRY), StandardCharsets.US_ASCII).trim();
        int at = stored.length() / 2;
        String broken = stored.substring(0, at) + (stored.charAt(at) == 'A' ? 'B' : 'A') + stored.substring(at + 1);
        Path damaged = replaceEntry(changed, dir.resolve("damaged.jar"), ConfigHistory.ENTRY, broken + "\n");
        assertEquals(1, cli.run("config", "history", "--jar", damaged.toString()));
        assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
        // 5) 내장 키 obf1 값이 손상된 JAR: 키를 쓰는 작업은 다른 키로 대체하지 않고 실패한다(Fail Closed)
        String settings2 = readEntry(jar, "java-crypto-kit.properties");
        String keyLine = settings2.replaceAll("(?s).*\\n(crypto\\.key\\.embedded=obf1:[A-Za-z0-9_-]+).*", "$1");
        String damagedKey = keyLine.substring(0, keyLine.length() - 3) + (keyLine.endsWith("AAA") ? "BBB" : "AAA");
        Path badKey = replaceEntry(jar, dir.resolve("badkey.jar"), "java-crypto-kit.properties",
                settings2.replace(keyLine, damagedKey));
        assertEquals(1, cli.run("config", "show", "--jar", badKey.toString()));
        assertTrue(cli.out().contains("손상되었거나 이 버전이 모르는 형식"), cli.out());
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
        assertTrue(info.out.contains("Language   : en [JAR built-in value]"), info.toString());
        TestJars.Run once = TestJars.run(english, Collections.<String>emptyList(), "info", "--lang", "ko");
        assertTrue(once.out.contains("언어      : en [JAR 기본값]"), "--lang은 이번 실행만: " + once);
        TestJars.Run again = TestJars.run(english, Collections.<String>emptyList(), "info");
        assertTrue(again.out.contains("Language   : en"), "--lang 뒤에도 영구 설정은 그대로: " + again);
        TestJars.Run jvm = TestJars.run(english, Collections.singletonList("-Dcrypto.lang=ko"), "info");
        assertTrue(jvm.out.contains("언어      : ko [JVM 속성 -D]"), jvm.toString());
        TestJars.Run original = TestJars.run(jar, Collections.singletonList("-Duser.language=en"), "info");
        assertTrue(original.out.contains("언어      : ko [JAR 기본값]"), "기본값 ko는 Locale과 무관: " + original);
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

    @Test
    void keysAndHistoryInsideTheJarAreNotPlainTextYetEveryCommandReadsThem() throws Exception {
        Path keyFile = dir.resolve("unique.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "x"), cli.err());
        String keyText = new String(Files.readAllBytes(keyFile), StandardCharsets.US_ASCII).trim();
        String reason = "obf1-확인용-고유사유-7f3a";
        Path out = dir.resolve("obf.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "obf01",
                "--operator", "123456", "--reason", reason, "--yes", "--jar", jar.toString(), "--out", out.toString()), cli.err());
        // 압축을 풀어 일반 텍스트로 열었을 때: 설정 파일·이력 어디에도 키 Base64·사유·공개 키 Base64가 글자 그대로 없다.
        for (String entry : new String[] {"java-crypto-kit.properties", ConfigHistory.ENTRY}) {
            String raw = new String(rawEntry(out, entry), StandardCharsets.UTF_8);
            assertFalse(raw.contains(keyText), entry + "에 키 원문");
            assertFalse(raw.contains(reason), entry + "에 사유 원문");
            assertFalse(raw.contains(TestSupport.publicKeyBase64()), entry + "에 공개 키 원문");
        }
        String rawSettings = new String(rawEntry(out, "java-crypto-kit.properties"), StandardCharsets.UTF_8);
        assertTrue(rawSettings.contains("crypto.key.embedded=obf1:") && rawSettings.contains("crypto.keys.default.embedded=obf1:")
                && rawSettings.contains("crypto.keys.pass-default.embedded=obf1:"), "내장 값은 모두 같은 obf1 표현");
        assertTrue(new String(rawEntry(out, ConfigHistory.ENTRY), StandardCharsets.US_ASCII).startsWith("obf1:"), "이력 본문도 obf1");
        assertFalse(new String(Files.readAllBytes(out), StandardCharsets.ISO_8859_1).contains(keyText), "JAR 파일 전체에도 없다");
        // 제품 명령은 그대로 읽는다: 이력의 사유, 키 지문 = 키 파일, 암복호화
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", out.toString()), cli.err());
        assertTrue(cli.out().contains("    사유: " + reason), cli.out());
        assertFalse(cli.out().contains(keyText), "이력 화면에 키 원문 없음");
        CryptoSettings settings = JarConfigEditor.read(out).validated();
        assertNotNull(settings);
        byte[] fileKey = io.javacryptokit.key.KeyResolver.readKeyFile(keyFile, "k");
        assertEquals(io.javacryptokit.key.KeyResolver.fingerprint(fileKey),
                io.javacryptokit.core.CryptoService.of(settings).keyFingerprint(settings.profile("obf01")));
        io.javacryptokit.core.CryptoService service = io.javacryptokit.core.CryptoService.of(settings);
        assertEquals("dummy", service.decryptText(service.encryptText("dummy".toCharArray(), null, "obf01")));
    }

    @Test
    void olderJarsWithPlainBuiltInKeysAreReadAndAnyEditRewritesThemAsObf1() throws Exception {
        Path old = plainCopy(TestJars.build(dir.resolve("old-build.jar")), dir.resolve("old-plain.jar"));
        String oldSettings = readEntry(old, "java-crypto-kit.properties");
        assertTrue(oldSettings.contains("crypto.key.embedded=" + TestSupport.publicKeyBase64()), "구형 평문 표현으로 만든 사본");
        // 그대로 읽힌다(같은 키·지문, 이력 없음 정상).
        assertEquals(0, cli.run("config", "show", "--jar", old.toString()), cli.err());
        String ls = System.lineSeparator();
        assertTrue(cli.out().contains("  default: key, embedded, 공개 기본 키, crypto.key.*" + ls
                + "    키 지문: aac695cbd2498e97131ae49579a219c5e7f41e87e2738ba49199847c00e41a49" + ls), cli.out());
        assertTrue(cli.out().contains("  pass-default: pass, embedded, 공개 기본 키" + ls
                + "    키 지문: 3dca588c78a17aad886e9403e8743990d79d479bbe610664adc3ff7e94453656" + ls), cli.out());
        // 키와 무관한 설정 하나만 바꿔도 결과 JAR의 내장 값은 모두 obf1로 다시 쓴다(키 바이트 그대로라 변경 항목·이력에는 없음).
        Path edited = dir.resolve("old-edited.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", old.toString(),
                "--out", edited.toString()), cli.err());
        assertTrue(cli.out().contains("crypto.lang (ko -> en)") && !cli.out().contains("embedded"), cli.out());
        String newSettings = readEntry(edited, "java-crypto-kit.properties");
        assertFalse(newSettings.contains(TestSupport.publicKeyBase64()), "평문 내장 값이 남지 않는다");
        assertTrue(newSettings.contains("crypto.key.embedded=obf1:") && newSettings.contains("crypto.keys.pass-default.embedded=obf1:"),
                newSettings);
        assertEquals(0, cli.run("config", "history", "--all", "--jar", edited.toString()), cli.err());
        assertTrue(cli.out().contains("    crypto.lang: ko -> en") && !cli.out().contains("embedded"), cli.out());
        // 같은 키: 공개 키 암호문(pass·key)이 그대로 복호화되고 지문도 같다(암호문을 다시 만들지 않음).
        String keyToken = TestSupport.jarDefaults().encryptText("dummy-key", io.javacryptokit.KeyType.KEY);
        String passToken = TestSupport.jarDefaults().encryptText("dummy-pass");
        io.javacryptokit.core.CryptoService service = io.javacryptokit.core.CryptoService.of(JarConfigEditor.read(edited).validated());
        assertEquals("dummy-key", service.decryptText(keyToken));
        assertEquals("dummy-pass", service.decryptText(passToken));
    }

    @Test
    void historyIsVerifiedWholeButShownByTypeAndOldAesRecordsAreNeverCalledPass() throws Exception {
        // 이전 형식 JAR(키 목록 없음): AES 키 교체(crypto.key.*)와 일반 설정 변경만 있다.
        Path legacy = TestJars.buildLegacy(dir.resolve("java-crypto-kit-legacy.jar"));
        Path keyFile = dir.resolve("legacy.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "x"), cli.err());
        Path l1 = dir.resolve("l1.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01", "--operator",
                "123456", "--reason", "AES 교체", "--yes", "--jar", legacy.toString(), "--out", l1.toString()), cli.err());
        Path l2 = dir.resolve("l2.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "123456", "--jar", l1.toString(),
                "--out", l2.toString()), cli.err());
        assertEquals(0, cli.run("config", "history", "--jar", l2.toString()), cli.err());
        assertTrue(cli.out().contains("이력 검증 : 정상(2건") && cli.out().contains("표시 범위 : pass 관련 0건(전체 2건)")
                && !cli.out().contains("#1"), "이전 형식 AES 기록을 pass로 보여 주지 않는다: " + cli.out());
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", l2.toString()), cli.err());
        assertTrue(cli.out().contains("#1  ") && cli.out().contains("config embed-key  [key]") && !cli.out().contains("#2  "),
                cli.out());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", l2.toString()), cli.err());
        assertTrue(cli.out().contains("config embed-key  [key]") && cli.out().contains("config set  [일반]"), cli.out());
        // 기본 유형(crypto.key.type) 변경은 두 유형 모두에 영향이므로 pass·key 보기에 모두 나온다.
        Path t1 = dir.resolve("t1.jar");
        assertEquals(0, cli.run("config", "set", "crypto.key.type=key", "--operator", "123456", "--reason", "AES 기본",
                "--yes", "--jar", jar.toString(), "--out", t1.toString()), cli.err());
        for (String[] view : new String[][] {{"config", "history", "--jar", t1.toString()},
                {"config", "history", "--type", "key", "--jar", t1.toString()}}) {
            assertEquals(0, cli.run(view), cli.err());
            assertTrue(cli.out().contains("config set  [key, pass]") && cli.out().contains("crypto.key.type: pass -> key"), cli.out());
        }
        // 이력이 손상되면 어떤 보기도 정상 이력처럼 보여 주지 않는다(걸러 보더라도 전체를 검증).
        String history = historyText(t1);
        Path broken = replaceEntry(t1, dir.resolve("broken.jar"), ConfigHistory.ENTRY,
                new String(ConfigHistory.store(history.replace("after.crypto.key.type=key", "after.crypto.key.type=pass")
                        .getBytes(StandardCharsets.UTF_8)), StandardCharsets.US_ASCII));
        for (String option : new String[] {"--all", "--type"}) {
            String[] args = "--type".equals(option) ? new String[] {"config", "history", "--type", "key", "--jar", broken.toString()}
                    : new String[] {"config", "history", "--all", "--jar", broken.toString()};
            assertEquals(1, cli.run(args));
            assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
        }
    }

    /**
     * 구형 JAR 재현: 내장 키 값을 표준 Base64 평문으로 되돌리고 Manifest 설정 지문도 그 내용에 맞춘 사본(obf1 이전 공식 JAR와 같은
     * 구조, 이력 없음).
     */
    private static Path plainCopy(Path source, Path target) throws Exception {
        String settings = readEntry(source, "java-crypto-kit.properties");
        StringBuilder plain = new StringBuilder();
        for (String line : settings.split("\n", -1)) {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("^(crypto\\.(?:key|keys\\.[A-Za-z0-9_-]+)\\.embedded)=(obf1:.*)$")
                    .matcher(line);
            if (m.matches()) {
                line = m.group(1) + "=" + java.util.Base64.getEncoder().encodeToString(
                        io.javacryptokit.key.KeyResolver.decodeEmbedded(m.group(2)));
            }
            plain.append(line).append('\n');
        }
        byte[] bytes = plain.substring(0, plain.length() - 1).getBytes(StandardCharsets.UTF_8);
        try (JarFile in = new JarFile(source.toFile())) {
            java.util.jar.Manifest manifest = new java.util.jar.Manifest(in.getManifest());
            manifest.getMainAttributes().putValue(ConfigHistory.SETTINGS_FINGERPRINT, ConfigHistory.fingerprint(bytes));
            try (OutputStream file = Files.newOutputStream(target); JarOutputStream out = new JarOutputStream(file, manifest)) {
                for (Enumeration<JarEntry> entries = in.entries(); entries.hasMoreElements(); ) {
                    JarEntry entry = entries.nextElement();
                    if ("META-INF/MANIFEST.MF".equals(entry.getName())) continue;
                    out.putNextEntry(new JarEntry(entry.getName()));
                    if ("java-crypto-kit.properties".equals(entry.getName())) {
                        out.write(bytes);
                    } else if (!entry.isDirectory()) {
                        try (InputStream data = in.getInputStream(entry)) {
                            byte[] buffer = new byte[8192];
                            int read;
                            while ((read = data.read(buffer)) != -1) out.write(buffer, 0, read);
                        }
                    }
                    out.closeEntry();
                }
            }
        }
        return target;
    }

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
