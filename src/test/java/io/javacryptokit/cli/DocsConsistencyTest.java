package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * 저장소 문서(README·예제 설정·예제 XML 2종·웹 페이지 부재·통합 시험 JSP의 오류 태그·LICENSE)가 실제 구현과 맞는지 자동으로 확인한다.
 * 도움말과 구현의 일치는 {@code DoctorAndHelpTest}가, 이 클래스는 저장소 파일 쪽을 맡는다(테스트는 프로젝트 폴더에서 실행).
 */
class DocsConsistencyTest {
    /** apache.org에서 받은 Apache License 2.0 원문(LF 줄바꿈)의 SHA-256. 내용을 바꾸면 안 된다. */
    private static final String APACHE_2_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
    private static final String FACTORY = "io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory";
    /** 저장소의 예제·시험 파일 위치(README·AGENTS·CI가 같은 경로를 쓴다). */
    static final String EXAMPLE_PROPERTIES = "docs/config/java-crypto-kit.example.properties";
    static final String DBCP2_XML = "docs/tomcat/dbcp2-context.xml";
    static final String JDBC_POOL_XML = "docs/tomcat/jdbc-pool-context.xml";
    static final String USER_GUIDE = "docs/user-guide.md";
    static final String HARNESS = "src/test/integration/run-tomcat-integration.sh";
    private static final Pattern OPTION = Pattern.compile("(?<![A-Za-z0-9-])--[a-z][a-z-]*[a-z]");
    /** 설정 이름(crypto.xxx). Java 예제의 {@code crypto.encryptText(...)} 같은 메서드 호출은 제외한다. */
    private static final Pattern SETTING = Pattern.compile("crypto\\.[a-z0-9.-]*[a-z0-9](?![A-Za-z0-9(])");
    /** 예제 명령 줄: "-jar <jar 파일>" 또는 "... io.javacryptokit.cli.CryptoCli" 다음의 명령과 나머지 인자. */
    private static final Pattern EXAMPLE = Pattern.compile(
            "java .*?(?:-jar \\S*\\.jar|io\\.javacryptokit\\.cli\\.CryptoCli) ((?:config|file|kms) \\S+|\\S+)(.*)");

    @TempDir
    Path dir;

    private static String read(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }

    @Test
    void readmeCommandExamplesUseRealCommandsAndValidOptions() throws IOException {
        // README: 바로 해 보기(encrypt·decrypt·verify)와 운영용 키 준비 명령
        int checked = checkExampleCommands("README.md");
        assertTrue(checked >= 8, "README에서 검사한 예제 명령 수: " + checked);
    }

    @Test
    void userGuideCommandExamplesUseRealCommandsAndValidOptions() throws IOException {
        // 사용자 가이드의 모든 예제 명령(코드 블록·인라인 코드)이 실제 명령과 그 명령의 옵션만 쓰는지 확인한다.
        int checked = checkExampleCommands(USER_GUIDE);
        assertTrue(checked >= 40, "사용자 가이드에서 검사한 예제 명령 수: " + checked);
    }

    /** 문서의 "java ... -jar X.jar 명령 ..." 예제가 실제 명령·옵션만 쓰는지 검사하고, 검사한 예제 수를 돌려준다. */
    private static int checkExampleCommands(String document) throws IOException {
        int checked = 0;
        for (String line : read(document).split("\\r?\\n")) {
            // 코드 블록 줄은 그대로, 본문의 인라인 코드는 백틱 사이 조각만 본다. 셸 주석(#)은 제외한다.
            for (String segment : line.split("`")) {
                int comment = segment.indexOf(" #");
                String code = comment >= 0 ? segment.substring(0, comment) : segment;
                Matcher m = EXAMPLE.matcher(code);
                if (!m.find()) continue;
                String name = m.group(1).trim();
                // help·config help는 명령이 아니라 도움말 주제다(DoctorAndHelpTest가 따로 검사).
                if (name.startsWith("<") || name.equals("help") || name.equals("config help")) continue;
                CliCommands.Spec spec = CliCommands.find(name);
                assertNotNull(spec, document + " 예제의 없는 명령: " + line);
                for (String option : tokens(OPTION, m.group(2))) {
                    if (option.equals("--help") || option.equals("--lang")) continue;
                    assertTrue(spec.options().contains(option), document + " 예제의 잘못된 옵션 " + option + ": " + line);
                }
                checked++;
            }
        }
        return checked;
    }

    @Test
    void readmeMentionsEveryCliCommandAndOnlyRealSettings() throws IOException {
        String readme = read("README.md");
        assertTrue(readme.indexOf("## 1. 암호화·복호화") >= 0, "README 첫 장은 기본 암복호화");
        assertTrue(readme.indexOf("encrypt") < readme.indexOf("keygen"), "README 기본 암호화가 키 생성보다 먼저");
        for (CliCommands.Spec spec : CliCommands.ALL) {
            assertTrue(readme.contains("`" + spec.name + "`"), "README CLI 안내에 없는 명령: " + spec.name);
        }
        Set<String> known = new LinkedHashSet<>(SettingCatalog.keys());
        known.add(CryptoSettings.CONFIG_FILE_PROPERTY);
        for (String setting : tokens(SETTING, readme)) {
            if (known.contains(setting)) continue;
            // "crypto.vault.*"처럼 묶어서 적은 경우: 그 접두사로 시작하는 실제 설정이 있어야 한다.
            boolean group = readme.contains(setting + ".*");
            boolean prefix = false;
            for (String key : known) prefix |= key.startsWith(setting + ".");
            assertTrue(group && prefix, "README의 없는 설정 이름: " + setting);
        }
    }

    @Test
    void readmeIsTheSingleKoreanReadme() throws IOException {
        String readme = read("README.md");
        int hangul = 0;
        for (char c : readme.toCharArray()) {
            if (c >= '가' && c <= '힣') hangul++;
        }
        assertTrue(hangul > 1000, "README.md는 한국어 문서여야 한다(한글 " + hangul + "자)");
        try (DirectoryStream<Path> files = Files.newDirectoryStream(Paths.get("."), "README*")) {
            for (Path file : files) {
                assertEquals("README.md", file.getFileName().toString(), "README는 하나만 둔다: " + file);
            }
        }
    }

    @Test
    void examplePropertiesFileAndEachCommentedExampleLoadWithTheRealRules() throws Exception {
        Path example = Paths.get(EXAMPLE_PROPERTIES);
        // 1) 파일 그대로(예 1이 켜져 있음)
        assertEquals("file", load(example).keySource());
        // 2) 주석으로 둔 예 2~4와 공통 블록도 하나씩 켜서 같은 규칙으로 검증한다(오타·잘못된 값이 문서에 남지 않게).
        List<List<String>> blocks = new ArrayList<>();
        List<String> current = null;
        for (String line : read(example.toString()).split("\\r?\\n")) {
            if (line.startsWith("# ---- ")) {
                current = new ArrayList<>();
                blocks.add(current);
            } else if (current != null && line.matches("#?crypto\\.[a-z0-9.-]+=.*")) {
                current.add(line.startsWith("#") ? line.substring(1) : line);
            }
        }
        assertTrue(blocks.size() >= 5, "예제 블록 수: " + blocks.size());
        int index = 0;
        for (List<String> block : blocks) {
            assertFalse(block.isEmpty(), "비어 있는 예제 블록 " + index);
            Path file = dir.resolve("block-" + (index++) + ".properties");
            Files.write(file, String.join("\n", block).getBytes(StandardCharsets.UTF_8));
            assertNotNull(load(file), "예제 블록 " + block);
        }
    }

    private static CryptoSettings load(Path config) throws IOException {
        // 실제 JVM 속성·환경변수와 무관하게 파일 내용만으로 검증한다.
        return CryptoSettings.load(config.toString(), name -> null, name -> null);
    }

    @Test
    void tomcatExampleResourcesUseTheFactoryAndAnEncryptedPassword() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        for (String path : new String[] {DBCP2_XML, JDBC_POOL_XML}) {
            NodeList resources = builder.parse(Paths.get(path).toFile()).getElementsByTagName("Resource");
            assertTrue(resources.getLength() > 0, path);
            for (int i = 0; i < resources.getLength(); i++) {
                Element resource = (Element) resources.item(i);
                assertEquals(FACTORY, resource.getAttribute("factory"), path);
                assertEquals("javax.sql.DataSource", resource.getAttribute("type"), path);
                assertEquals("Container", resource.getAttribute("auth"), path + ": 기본 JNDI 인증 주체");
                assertTrue(resource.getAttribute("password").startsWith("ENC[v1:"), path + ": password는 암호문 형식 자리표시자");
                assertFalse(resource.getAttribute("driverClassName").isEmpty(), path);
            }
        }
        String dbcp = read(DBCP2_XML);
        String tomcatJdbc = read(JDBC_POOL_XML);
        assertTrue(dbcp.contains("maxTotal") && dbcp.contains("validationQuery=\"SELECT 1\"") && dbcp.contains("testOnBorrow=\"true\""),
                "DBCP2 예제는 그 Pool의 속성 이름과 연결 검사 옵션을 보여 줘야 한다");
        // Pool 종류는 Resource 속성이 아니라 JVM 공통 설정 crypto.pool.factory로 고른다(Resource별 선택 기능 없음).
        assertTrue(tomcatJdbc.contains("maxActive") && tomcatJdbc.contains(CryptoSettings.TOMCAT_JDBC_FACTORY)
                        && tomcatJdbc.contains("validationQuery=\"SELECT 1\"") && tomcatJdbc.contains("testOnBorrow=\"true\""),
                "Tomcat JDBC Pool 예제는 그 Pool의 속성과 crypto.pool.factory 값을 안내해야 한다");
        for (String xml : new String[] {dbcp, tomcatJdbc}) {
            // 예제 파일 이름과 Tomcat이 실제로 읽는 Context 파일을 구분해 안내한다.
            assertTrue(xml.contains("Tomcat은 이 파일을 직접 읽지 않는다") && xml.contains("META-INF/context.xml"),
                    "예제 XML은 실제 Context 파일에 Resource만 붙여 넣는다고 안내해야 한다");
        }
    }

    @Test
    void productAndExamplesContainNoWebPages() throws IOException {
        // 이 제품은 Tomcat Factory JAR다. 오배포되면 DB·Pool 정보가 웹으로 드러날 수 있는 진단 페이지는 예제·제품 소스에 두지 않는다.
        for (String root : new String[] {"docs", "src/main"}) {
            try (Stream<Path> files = Files.walk(Paths.get(root))) {
                List<String> pages = files.map(p -> p.toString().replace('\\', '/'))
                        .filter(p -> p.matches("(?i).*\\.(jsp|jspx|war)$") || p.contains("/WEB-INF"))
                        .collect(Collectors.toList());
                assertTrue(pages.isEmpty(), root + "에 웹 페이지가 있으면 안 된다: " + pages);
            }
        }
        // 실서버 시험용 웹앱은 하니스가 실행 중에만 컨테이너 안에 만든다. 그 JSP는 라이브러리의 정제된 오류를 태그로 알아보므로,
        // 태그가 바뀌면 오류 내용이 시험 결과에서 사라지지 않게 같이 확인한다(이전 점검 JSP 검사를 옮긴 것).
        String harness = read(HARNESS);
        assertTrue(harness.contains("startsWith(\"" + Messages.TAG + "\")"), "통합 시험 JSP의 오류 태그가 Messages.TAG와 다름");
        assertTrue(harness.contains("--internal") && !harness.matches("(?s).*docker (run|create)[^\\n]* -p .*"),
                "통합 시험은 격리 네트워크를 쓰고 호스트 포트를 공개하지 않는다");
    }

    @Test
    void repositoryLayoutLinksAndPathsAreCurrent() throws IOException {
        // docs/에는 예제 3개 + 한국어 통합 상세 가이드 1개만 둔다(중복 문서 난립 방지).
        try (Stream<Path> files = Files.walk(Paths.get("docs"))) {
            List<String> others = files.filter(Files::isRegularFile).map(p -> p.toString().replace('\\', '/'))
                    .filter(p -> !p.equals(USER_GUIDE) && !p.endsWith(".properties") && !p.endsWith(".xml"))
                    .collect(Collectors.toList());
            assertTrue(others.isEmpty(), "docs/에는 상세 가이드 하나와 예제 설정·Tomcat 예제만 둔다: " + others);
        }
        for (String path : new String[] {EXAMPLE_PROPERTIES, DBCP2_XML, JDBC_POOL_XML, USER_GUIDE, HARNESS}) {
            assertTrue(Files.isRegularFile(Paths.get(path)), "파일이 없음: " + path);
        }
        String guide = read(USER_GUIDE);
        assertFalse(guide.contains("## 2. 처음 설치해 연결하기"), "상세 가이드에 README 빠른 시작이 중복되면 안 된다");
        assertFalse(guide.contains("DBA — 회사 키"), "상세 가이드는 특정 조직의 역할을 전제하지 않는다");
        // 체험용 내장 키와 운영용 사용자 지정 키를 구분하고, keygen이 필수 단계가 아님을 안내한다.
        assertTrue(guide.contains("체험용 내장 키와 운영용 사용자 지정 키") && guide.contains("필수 선행 단계가 아닙니다"),
                "체험용 키·운영용 키 구분과 keygen 선택 안내 누락");
        // Pool은 JVM 공통 설정 crypto.pool.factory 하나로 고른다(Resource별 선택 기능 없음).
        assertTrue(guide.contains(CryptoSettings.TOMCAT_JDBC_FACTORY) && guide.contains("JVM의 모든 Resource"),
                "Pool 선택 방법(crypto.pool.factory, JVM 공통) 안내 누락");
        assertTrue(guide.contains("키 파일을 매번 만들거나") && guide.contains("비밀번호 + Salt")
                && guide.contains("미지원"), "암호화 키 공급 방식과 Salt·PBE 지원 범위 설명 누락");
        // 운영자가 자주 묻는 JNDI·WAS·API 차이가 문서에서 누락되지 않게 한다.
        assertTrue(guide.contains("`auth`") && guide.contains("auth=\"Container\"") && guide.contains("auth=\"Application\""), "auth 허용값 설명 누락");
        assertTrue(guide.contains("WebLogic") && guide.contains("Tomcat JNDI 전용"), "타 WAS 적용 범위 설명 누락");
        assertTrue(guide.contains("javac -cp") && guide.contains("java -cp"), "Java API 직접 실행 예제 누락");
        for (String key : SettingCatalog.keys()) {
            assertTrue(guide.contains("`" + key + "`"), "상세 가이드에 빠진 실제 설정 키: " + key);
        }
        for (String api : new String[] {"encryptText", "decryptText", "encryptBytes", "decryptBytes",
                "encryptFile", "decryptFile", "verify"}) {
            assertTrue(guide.contains(api), "상세 가이드에 빠진 공개 Java API: " + api);
        }
        assertTrue(read("README.md").contains("docs/user-guide.md"));
        // README·AGENTS·상세 가이드의 상대 링크가 실제 파일로 이어지고, 제목 링크도 정확한지 확인한다.
        for (String doc : new String[] {"README.md", "AGENTS.md", USER_GUIDE}) {
            String text = read(doc);
            Set<String> anchors = new LinkedHashSet<>();
            for (String line : text.split("\\r?\\n")) {
                if (line.startsWith("#")) anchors.add(slug(line.replaceFirst("^#+\\s*", "")));
            }
            Matcher link = Pattern.compile("\\]\\(([^)\\s]+)\\)").matcher(text);
            int checked = 0;
            while (link.find()) {
                String target = link.group(1);
                if (target.startsWith("http://") || target.startsWith("https://") || target.startsWith("mailto:")) continue;
                if (target.startsWith("#")) {
                    assertTrue(anchors.contains(target.substring(1)), doc + "의 없는 제목 링크: " + target);
                } else {
                    String file = target.contains("#") ? target.substring(0, target.indexOf('#')) : target;
                    Path parent = Paths.get(doc).getParent();
                    Path resolved = (parent == null ? Paths.get(file) : parent.resolve(file)).normalize();
                    assertTrue(Files.exists(resolved), doc + "의 깨진 링크: " + target);
                    if (target.contains("#") && file.endsWith(".md")) {
                        String targetHeading = target.substring(target.indexOf('#') + 1);
                        Set<String> targetAnchors = new LinkedHashSet<>();
                        for (String line : read(resolved.toString()).split("\\r?\\n")) {
                            if (line.startsWith("#")) targetAnchors.add(slug(line.replaceFirst("^#+\\s*", "")));
                        }
                        assertTrue(targetAnchors.contains(targetHeading), doc + "의 대상 제목 링크가 없음: " + target);
                    }
                }
                checked++;
            }
            if (doc.equals("README.md")) assertTrue(checked >= 5, "README에서 검사한 링크 수: " + checked);
        }
        // 옮기기 전 경로가 문서·도움말·CI·하니스·예제에 남아 있으면 안 된다.
        List<Path> sources = new ArrayList<>();
        for (String file : new String[] {"README.md", "AGENTS.md", ".gitignore", ".github/workflows/ci.yml", HARNESS}) {
            sources.add(Paths.get(file));
        }
        for (String root : new String[] {"src/main/resources/io/javacryptokit/i18n/help", "docs"}) {
            try (Stream<Path> files = Files.walk(Paths.get(root))) {
                files.filter(Files::isRegularFile).forEach(sources::add);
            }
        }
        // 마지막 세 개는 승인 없이 들어왔다가 사용자 결정으로 원복한 기능(Resource별 Pool 선택, 호출별 출력 형식 API)이다.
        String[] stale = {"examples/", "config/java-crypto-kit.properties.example", "qa/integration", "context-dbcp2.xml",
            "context-tomcat-jdbc.xml", "tomcat-smoke-test", "cryptoPool", "OutputFormat", "POOL_CONFIGURATION"};
        for (Path source : sources) {
            String text = new String(Files.readAllBytes(source), StandardCharsets.UTF_8);
            for (String old : stale) {
                assertFalse(text.contains(old), source + "에 이전 경로가 남아 있음: " + old);
            }
        }
    }

    /** GitHub Markdown 제목 링크 규칙(소문자, 문자·숫자·공백·하이픈만 남기고 공백은 하이픈). */
    private static String slug(String heading) {
        return heading.trim().toLowerCase(java.util.Locale.ROOT).replaceAll("[^\\p{L}\\p{N}\\s-]", "").replace(' ', '-');
    }

    /** 신규 개발자가 CLI Help를 별도로 열지 않고도 모든 명령·옵션을 상세 가이드에서 찾는지 확인한다. */
    @Test
    void userGuideCoversEveryCliCommandAndItsOptions() throws IOException {
        String guide = read(USER_GUIDE);
        int start = guide.indexOf("## 2. CLI 명령");
        int end = guide.indexOf("## 3. Tomcat JNDI 연동", start);
        assertTrue(start >= 0 && end > start, "사용 가이드에 CLI 전체 설명 장이 없음");
        String chapter = guide.substring(start, end);
        for (CliCommands.Spec spec : CliCommands.ALL) {
            Pattern header = Pattern.compile("(?m)^### 2\\.\\d+ `" + Pattern.quote(spec.name) + "`.*$");
            Matcher found = header.matcher(chapter);
            assertTrue(found.find(), "CLI 상세 가이드에 명령 설명 누락: " + spec.name);
            int next = chapter.indexOf("\n### 2.", found.end());
            String details = chapter.substring(found.start(), next < 0 ? chapter.length() : next);
            assertTrue(details.contains("```"), "CLI 명령별 실제 실행 예제가 없음: " + spec.name);
            for (String option : spec.options()) {
                assertTrue(details.contains(option), "CLI 명령별 실제 옵션 누락: " + spec.name + " " + option);
            }
        }
    }

    @Test
    void licenseIsTheUnmodifiedApacheLicense20() throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get("LICENSE"));
        String text = new String(bytes, StandardCharsets.UTF_8).replace("\r\n", "\n"); // Windows 체크아웃(CRLF) 대비
        assertTrue(text.trim().startsWith("Apache License"), "LICENSE 첫 줄");
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) hex.append(String.format("%02x", b));
        assertEquals(APACHE_2_SHA256, hex.toString(), "LICENSE는 Apache License 2.0 원문 그대로여야 한다");
    }

    private static Set<String> tokens(Pattern pattern, String text) {
        Set<String> found = new LinkedHashSet<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) found.add(m.group());
        return found;
    }
}
