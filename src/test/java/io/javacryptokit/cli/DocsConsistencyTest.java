package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.Properties;
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
            "java .*?(?:-jar \\S*\\.jar|io\\.javacryptokit\\.cli\\.CryptoCli) ((?:config key|config|file|kms|admin password|admin) \\S+|\\S+)(.*)");

    @TempDir
    Path dir;

    private static String read(String path) throws IOException {
        return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
    }

    private static List<String> guideFiles() throws IOException {
        try (Stream<Path> paths = Files.walk(Paths.get("docs"))) {
            return paths.filter(Files::isRegularFile).map(p -> p.toString().replace('\\', '/'))
                    .filter(p -> p.endsWith(".md")).sorted().collect(Collectors.toList());
        }
    }

    private static String guideText() throws IOException {
        StringBuilder text = new StringBuilder();
        for (String path : guideFiles()) text.append(read(path)).append('\n');
        return text.toString().replace("\r\n", "\n");
    }

    @Test
    void readmeCommandExamplesUseRealCommandsAndValidOptions() throws IOException {
        // README에 예제를 싣는 경우에만 문법을 검사한다. 실행 절차와 옵션의 완전성은 업무 가이드에서 검사한다.
        checkExampleCommands("README.md");
    }

    @Test
    void userGuideCommandExamplesUseRealCommandsAndValidOptions() throws IOException {
        // 사용자 가이드의 모든 예제 명령(코드 블록·인라인 코드)이 실제 명령과 그 명령의 옵션만 쓰는지 확인한다.
        int checked = 0;
        for (String path : guideFiles()) checked += checkExampleCommands(path);
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
                if (name.equals("file encrypt") || name.equals("file decrypt")) {
                    assertTrue(tokens(OPTION, m.group(2)).contains("--out"), document + ": " + line);
                }
                checked++;
            }
        }
        return checked;
    }

    @Test
    void readmeMentionsEveryCliCommandAndOnlyRealSettings() throws IOException {
        String readme = read("README.md").replace("\r\n", "\n");
        for (String guide : Arrays.asList("guide/cli", "guide/tomcat-jdbc", "guide/java-encryption", "guide/key-management",
                "reference/java-api-reference", "reference/getting-started")) {
            assertTrue(readme.contains("](docs/" + guide + ".md"), "README에서 찾을 수 없는 가이드: " + guide);
        }
        String index = read("docs/guide/cli.md");
        for (CliCommands.Spec spec : CliCommands.ALL) {
            assertTrue(index.contains("[`" + spec.name + "`]("), "README에서 여는 CLI 색인에 빠진 명령: " + spec.name);
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
        assertTrue(hangul > 0, "한국어 README 설명이 필요하다");
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
                boolean dbcp2 = DBCP2_XML.equals(path);
                assertEquals(dbcp2 ? "dbcp2" : "tomcat-jdbc", resource.getAttribute("cryptoPool"), path);
                assertTrue(resource.hasAttribute(dbcp2 ? "maxTotal" : "maxActive"), path);
                assertTrue(resource.hasAttribute(dbcp2 ? "maxWaitMillis" : "maxWait"), path);
                assertFalse(resource.hasAttribute(dbcp2 ? "maxActive" : "maxTotal"), path);
                assertFalse(resource.hasAttribute(dbcp2 ? "maxWait" : "maxWaitMillis"), path);
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
        assertTrue(tomcatJdbc.contains("maxActive") && tomcatJdbc.contains("cryptoPool=\"tomcat-jdbc\"")
                        && tomcatJdbc.contains("validationQuery=\"SELECT 1\"") && tomcatJdbc.contains("testOnBorrow=\"true\""),
                "Tomcat JDBC Pool 예제는 명시 선택값과 그 Pool의 속성을 안내해야 한다");
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
        Set<String> allowed = new LinkedHashSet<>(Arrays.asList(USER_GUIDE, EXAMPLE_PROPERTIES, DBCP2_XML, JDBC_POOL_XML));
        String index = read(USER_GUIDE);
        for (String doc : guideFiles()) {
            if (doc.equals(USER_GUIDE)) continue;
            assertTrue(doc.matches("docs/(guide|reference)/[a-z-]+\\.md"), doc);
            assertTrue(index.contains("](" + doc.substring(5) + ")"), "허브에서 찾을 수 없는 문서: " + doc);
            allowed.add(doc);
        }
        try (Stream<Path> paths = Files.walk(Paths.get("docs"))) {
            paths.filter(Files::isRegularFile).forEach(p -> assertTrue(allowed.contains(p.toString().replace('\\', '/')), p.toString()));
        }
        for (String path : new String[] {EXAMPLE_PROPERTIES, DBCP2_XML, JDBC_POOL_XML, USER_GUIDE, HARNESS}) {
            assertTrue(Files.isRegularFile(Paths.get(path)), "파일이 없음: " + path);
        }
        String guide = guideText();
        assertFalse(guide.contains("## 2. 처음 설치해 연결하기"), "상세 가이드에 README 빠른 시작이 중복되면 안 된다");
        assertFalse(guide.contains("DBA — 회사 키"), "상세 가이드는 특정 조직의 역할을 전제하지 않는다");
        // 체험용 내장 키와 운영용 사용자 지정 키를 구분하고, keygen이 필수 단계가 아님을 안내한다.
        assertTrue(guide.contains("체험용 내장 키와 운영용 사용자 지정 키") && guide.contains("필수 선행 단계가 아닙니다"),
                "체험용 키·운영용 키 구분과 keygen 선택 안내 누락");
        String tomcat = read("docs/guide/tomcat-jdbc.md");
        assertTrue(tomcat.contains("cryptoPool=\"dbcp2\"") && tomcat.contains("cryptoPool=\"tomcat-jdbc\"")
                && tomcat.contains("Resource의 `cryptoPool` > 유효한 공통 `crypto.pool.factory`"));
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
        List<String> docs = guideFiles();
        docs.add("README.md");
        docs.add("AGENTS.md");
        Map<Path, Set<String>> targets = new LinkedHashMap<>();
        for (String doc : docs) {
            String prose = withoutFences(read(doc));
            Set<String> anchors = new LinkedHashSet<>();
            Matcher explicit = Pattern.compile("<a (?:name|id)=\"([^\"]+)\"").matcher(prose);
            while (explicit.find()) anchors.add(explicit.group(1));
            Set<String> headings = new LinkedHashSet<>();
            Matcher heading = Pattern.compile("(?m)^#{1,6} +(.+)$").matcher(prose);
            while (heading.find()) {
                String base = slug(heading.group(1).replaceAll("\\[([^]]+)\\]\\([^)]+\\)", "$1"));
                String id = base;
                int sequence = 0;
                while (!headings.add(id)) id = base + "-" + (++sequence);
                anchors.add(id);
            }
            targets.put(Paths.get(doc), anchors);
        }
        for (String doc : docs) {
            Path source = Paths.get(doc);
            Matcher link = Pattern.compile("\\]\\(([^)\\s]+)\\)").matcher(withoutFences(read(doc)));
            int checked = 0;
            while (link.find()) {
                String target = link.group(1);
                if (target.matches("^(https?://|mailto:).*")) continue;
                String[] parts = target.split("#", 2);
                Path file = parts[0].isEmpty() ? source : source.resolveSibling(parts[0]).normalize();
                assertTrue(Files.isRegularFile(file), doc + " → " + target);
                if (parts.length == 2) assertTrue(targets.containsKey(file) && targets.get(file).contains(parts[1]), doc + " → " + target);
                checked++;
            }
            if (doc.equals("README.md")) assertTrue(checked >= 5);
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
        // 현재 범위에서 제외한 호출별 출력 형식 API의 이전 이름은 금지한다.
        String[] stale = {"examples/", "config/java-crypto-kit.properties.example", "qa/integration", "context-dbcp2.xml",
            "context-tomcat-jdbc.xml", "tomcat-smoke-test", "OutputFormat", "POOL_CONFIGURATION"};
        for (Path source : sources) {
            String text = new String(Files.readAllBytes(source), StandardCharsets.UTF_8);
            for (String old : stale) {
                assertFalse(text.contains(old), source + "에 이전 경로가 남아 있음: " + old);
            }
        }
    }

    private static String withoutFences(String text) {
        return text.replace("\r\n", "\n").replaceAll("(?ms)^```[^\\n]*\\n.*?^```[ \\t]*$", "");
    }

    /** GitHub Markdown 제목 링크 규칙(소문자, 문자·숫자·공백·하이픈만 남기고 공백은 하이픈). */
    private static String slug(String heading) {
        return heading.trim().toLowerCase(java.util.Locale.ROOT).replaceAll("[^\\p{L}\\p{N}\\s-]", "").replace(' ', '-');
    }

    /** 신규 개발자가 CLI Help를 별도로 열지 않고도 모든 명령·옵션을 상세 가이드에서 찾는지 확인한다. */
    @Test
    void userGuideCoversEveryCliCommandAndItsOptions() throws IOException {
        String guide = guideText();
        for (CliCommands.Spec spec : CliCommands.ALL) {
            Pattern section = Pattern.compile("(?ms)^### `" + Pattern.quote(spec.name) + "`[^\\n]*\\n(.*?)(?=^#{2,3} |\\z)");
            Matcher found = section.matcher(guide);
            assertTrue(found.find(), "명령별 상세 설명 누락: " + spec.name);
            String details = found.group(1);
            assertFalse(found.find(), "명령별 상세 설명 중복: " + spec.name);
            Matcher examples = EXAMPLE.matcher(details);
            boolean hasExample = false;
            while (examples.find()) hasExample |= spec.name.equals(examples.group(1));
            assertTrue(hasExample, "CLI 명령별 실제 실행 예제가 없음: " + spec.name);
            for (String option : spec.options()) {
                assertTrue(Pattern.compile("(?m)^\\| `" + Pattern.quote(option) + "(?: |`)").matcher(details).find(), "CLI 명령별 실제 옵션 누락: " + spec.name + " " + option);
            }
        }
    }

    /**
     * 가이드 13장의 {@code // 예제: 클래스.메서드} 블록이 컴파일·실행 시험하는 예제 소스(src/test/java/example)의 그 메서드와
     * 글자 그대로 같고, 예제 소스의 예제가 모두 가이드에 한 번씩 있는지 확인한다. 블록 = 표시 줄 + 메서드 선언·본문(표시 줄 제외, 클래스
     * 들여쓰기 4칸 제거).
     */
    @Test
    void userGuideJavaSnippetsMatchTheTestedExampleSources() throws IOException {
        String guide = guideText();
        Matcher block = Pattern.compile("(?ms)^```java\\n// 예제: (\\w+)\\.(\\w+)\\n(.*?)^```$").matcher(guide);
        Set<String> documented = new LinkedHashSet<>();
        while (block.find()) {
            String name = block.group(1) + "." + block.group(2);
            assertTrue(documented.add(name), "같은 예제 블록이 두 번 있음: " + name);
            assertEquals(exampleSnippet(block.group(1), block.group(2)), block.group(3), "가이드 예제가 시험하는 예제 소스와 다름: " + name);
        }
        Set<String> sources = new LinkedHashSet<>();
        for (String cls : new String[] {"SecurityApiExample", "TokenApiExample"}) {
            Matcher marker = Pattern.compile("(?m)^ {8}// 예제: (" + cls + "\\.\\w+)$")
                    .matcher(read("src/test/java/example/" + cls + ".java").replace("\r\n", "\n"));
            while (marker.find()) sources.add(marker.group(1));
        }
        assertFalse(sources.isEmpty(), "예제 소스에 예제 표시가 없음");
        assertEquals(sources, documented, "예제 소스의 예제와 가이드의 예제 블록이 일대일로 같아야 한다");
    }

    private static String exampleSnippet(String cls, String method) throws IOException {
        List<String> lines = java.util.Arrays.asList(read("src/test/java/example/" + cls + ".java").replace("\r\n", "\n").split("\n", -1));
        int marker = lines.indexOf("        // 예제: " + cls + "." + method);
        assertTrue(marker > 0 && lines.lastIndexOf(lines.get(marker)) == marker, "예제 소스에 표시가 없거나 중복: " + cls + "." + method);
        int start = marker - 1;
        while (!lines.get(start).startsWith("    public static ")) start--;
        int end = marker + 1;
        while (!lines.get(end).equals("    }")) end++;
        StringBuilder out = new StringBuilder();
        for (int i = start; i <= end; i++) {
            if (i != marker) out.append(lines.get(i).isEmpty() ? "" : lines.get(i).substring(4)).append('\n');
        }
        return out.toString();
    }

    /** 공개 보안 API의 업무별 설명을 찾을 수 있고 README와 선택표에서 상세 절로 이동할 수 있는지 검사한다. */
    @Test
    void userGuideCoversEveryPublicSecurityApiClass() throws IOException {
        StringBuilder guide = new StringBuilder();
        for (String path : guideFiles()) {
            if (path.startsWith("docs/guide/")) guide.append(read(path)).append('\n');
        }
        String selection = read("docs/reference/api-selection.md");
        int classes = 0;
        for (String pkg : new String[] {"security", "jwt", "oauth"}) {
            try (DirectoryStream<Path> files = Files.newDirectoryStream(Paths.get("src/main/java/io/javacryptokit/" + pkg), "*.java")) {
                for (Path file : files) {
                    String name = file.getFileName().toString().replace(".java", "");
                    if (!Pattern.compile("(?m)^public (?:final |abstract )?(?:class|enum|interface) " + name + "\\b")
                            .matcher(read(file.toString())).find()) {
                        continue;
                    }
                    classes++;
                    assertTrue(Pattern.compile("\\b" + name + "\\b").matcher(guide).find(), "가이드에 빠진 공개 클래스: " + pkg + "." + name);
                }
            }
        }
        assertTrue(classes > 0, "범용 보안 API 공개 클래스를 찾지 못함");
        int sections = 0;
        for (String file : guideFiles()) {
            if (!file.startsWith("docs/guide/")) continue;
            String text = read(file).replace("\r\n", "\n");
            Matcher heading = Pattern.compile("(?m)^<a name=\"([^\"]+)\"></a>\\n### [^\\n]+ — [^\\n]+ \\(13\\.\\d+\\)").matcher(text);
            while (heading.find()) {
                sections++;
                assertTrue(selection.contains("../" + file.substring(5) + "#" + heading.group(1) + ")"), "선택표에 빠진 절: " + heading.group(1));
            }
        }
        assertTrue(sections > 0);
        String readme = read("README.md");
        assertTrue(readme.contains("](docs/reference/api-selection.md") && readme.contains("](docs/reference/java-api-reference.md"));

    }

    @Test
    void configurationTablesDescribeBundledDefaultsAndAllowedValues() throws Exception {
        String guide = read("docs/reference/configuration.md");
        Properties defaults = new Properties();
        try (java.io.Reader input = Files.newBufferedReader(Paths.get("src/main/resources/java-crypto-kit.properties"),
                StandardCharsets.UTF_8)) {
            defaults.load(input);
        }
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            String row = optionRow(guide, setting.key);
            String cell = row.split("\\|", -1)[2].trim();
            String value = defaults.getProperty(setting.key);
            assertNotNull(value, setting.key);
            if (setting.sensitive) {
                assertTrue(cell.startsWith("공개 예제 키"), setting.key);
            } else if (value.isEmpty()) {
                assertTrue(cell.startsWith("없음") || cell.startsWith("빈 값"), setting.key);
            } else if (setting.key.equals(CryptoSettings.POOL_FACTORY)) {
                assertTrue(cell.startsWith("DBCP2") && guide.contains("`" + value + "`(DBCP2, 기본)"), setting.key);
            } else {
                assertTrue(cell.startsWith("`" + value + "`"), setting.key);
            }
            for (String choice : setting.choices) {
                String location = setting.key.equals(CryptoSettings.POOL_FACTORY) ? guide : cell;
                assertTrue(location.contains("`" + choice + "`"), setting.key + " " + choice);
            }
            if (setting.max > 0) assertTrue(cell.contains(setting.min + "~" + setting.max), setting.key);
        }
        for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
            String row = optionRow(guide, item.name);
            assertTrue(row.contains(item.location ? "예(위치)" : "아니요"), item.name);
            for (String choice : item.choices) assertTrue(row.contains("`" + choice + "`"), item.name + " " + choice);
            if (item.max > 0) assertTrue(row.contains(item.min + "~" + item.max), item.name);
        }
    }

    private static String optionRow(String guide, String name) {
        Matcher row = Pattern.compile("(?m)^\\| `" + Pattern.quote(name) + "` \\|[^\\r\\n]*").matcher(guide);
        assertTrue(row.find(), "설정 표에 없는 항목: " + name);
        String text = row.group();
        assertFalse(row.find(), "설정 표에 중복된 항목: " + name);
        return text;
    }

    @Test
    void apiReferenceIncludesEveryPublicOverloadConstructorAndField() throws Exception {
        String guide = read("docs/reference/java-api-reference.md");
        Path root = Paths.get("src/main/java/io/javacryptokit");
        for (String pkg : Arrays.asList("", "security", "jwt", "oauth")) {
            try (DirectoryStream<Path> paths = Files.newDirectoryStream(root.resolve(pkg), "*.java")) {
                for (Path path : paths) {
                    String name = path.getFileName().toString().replace(".java", "");
                    if (name.equals("package-info")) continue;
                    String qualified = "io.javacryptokit." + (pkg.isEmpty() ? "" : pkg + ".") + name;
                    checkTypeDocumentation(Class.forName(qualified, false, getClass().getClassLoader()), guide);
                }
            }
        }
        checkTypeDocumentation(Class.forName(FACTORY), guide);
    }

    private static void checkTypeDocumentation(Class<?> type, String guide) {
        if (!Modifier.isPublic(type.getModifiers())) return;
        String name = type.getName().substring(type.getPackage().getName().length() + 1).replace('$', '.');
        Matcher section = Pattern.compile("(?s)<summary>" + Pattern.quote(name) + "</summary>(.*?)</details>").matcher(guide);
        assertTrue(section.find(), "호출 형식이 없는 타입: " + name);
        Set<String> documented = new LinkedHashSet<>();
        Matcher entries = Pattern.compile("(?m)^- `([^`]+)`").matcher(section.group(1));
        while (entries.find()) {
            String declaration = entries.group(1).replaceAll("<[^<>]*>", "").replace("...", "[]")
                    .replaceAll("(?:\\w+\\.)+(?=\\w)", "").replaceAll("\\s+\\w+(?=[,)])", "").replace(", ", ",");
            assertTrue(documented.add(declaration), name + ": " + declaration);
        }
        Set<String> members = new LinkedHashSet<>();
        for (Method method : type.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers()) || method.isSynthetic()) continue;
            if (type.isEnum() && (method.getName().equals("values") || method.getName().equals("valueOf"))) continue;
            members.add(signature(method.getName(), method.getParameterTypes()));
        }
        for (Constructor<?> ctor : type.getDeclaredConstructors()) {
            if (Modifier.isPublic(ctor.getModifiers())) members.add(signature(type.getSimpleName(), ctor.getParameterTypes()));
        }
        for (Field field : type.getDeclaredFields()) {
            if (Modifier.isPublic(field.getModifiers())) members.add(field.getName());
        }
        assertEquals(members, documented, name);
        for (Class<?> nested : type.getDeclaredClasses()) checkTypeDocumentation(nested, guide);
    }

    private static String signature(String name, Class<?>[] parameters) {
        return name + "(" + Arrays.stream(parameters).map(Class::getSimpleName).collect(Collectors.joining(",")) + ")";
    }

    /** 빌드 버전과 시험·README·가이드의 버전 표기(소스 버전 안내, 예제 JAR 이름)가 같은지 확인한다. */
    @Test
    void documentedVersionMatchesTheBuild() throws IOException {
        Matcher declared = Pattern.compile("(?m)^version = '(\\d+\\.\\d+\\.\\d+)'$").matcher(read("build.gradle"));
        assertTrue(declared.find(), "build.gradle의 version");
        String version = declared.group(1);
        assertEquals(version, io.javacryptokit.TestJars.VERSION, "시험용 JAR 버전이 빌드 버전과 다름");
        List<String> docs = guideFiles();
        docs.add("README.md");
        for (String doc : docs) {
            String text = read(doc);
            if (doc.equals("README.md") || doc.equals(USER_GUIDE)) assertTrue(Pattern.compile("(?<![0-9.])" + Pattern.quote(version) + "(?![0-9.])").matcher(text).find(), doc + "에 소스 버전 안내가 없음");
            Matcher jar = Pattern.compile("java-crypto-kit-(\\d+\\.\\d+\\.\\d+)").matcher(text);
            while (jar.find()) assertEquals(version, jar.group(1), doc + "의 JAR 이름 버전이 빌드 버전과 다름");
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
