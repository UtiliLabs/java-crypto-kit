package io.javacryptokit.cli;

import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * <b>내부 구현 클래스</b>: CLI 도움말. 실행 중에 명령을 빨리 찾고 바로 실행할 수 있게 짧게 보여 준다(명령 목록, 명령별 용도·실제
 * 옵션·예제). 배경 설명·운영 정책·설정별 상세는 사용자 가이드({@code docs/user-guide.md})에 둔다.
 *
 * <p><b>원본</b>: 명령별 문서는 {@code io/javacryptokit/i18n/help/<en|ko>/<주제>.txt}(UTF-8)에 있고, 두 언어는 같은 주제·같은
 * 옵션·같은 설정을 설명한다(테스트가 검사). {@code config help}의 설정 표는 {@link SettingCatalog}(이름·허용값·숫자 범위)와 JAR
 * 내장 기본값, 언어별 짧은 값 설명({@code setting.<이름>.values})으로 자동 생성하므로 실제 구현과 어긋나지 않는다. 표는 80열
 * 콘솔에서 가로 스크롤 없이 보이도록 맞추고(한글은 2칸), 넘치는 항목만 다음 줄로 넘긴다.</p>
 *
 * <p><b>안전</b>: 도움말은 키 파일·외부 설정·Vault·AWS·DB에 접근하지 않는다. 비밀 항목의 기본값은 표시하지 않는다.</p>
 */
final class CliHelp {
    private CliHelp() { }

    /**
     * {@code help [주제...]}. 주제가 없으면 전체 목차를 보여 준다.
     *
     * @param words 주제 단어(예: {@code config set} → config-set)
     * @return 종료 코드
     */
    static int help(String[] words, PrintStream out) throws CryptoCli.CliException {
        List<String> parts = new ArrayList<>();
        for (String word : words) {
            if (!word.startsWith("-")) parts.add(word);
        }
        String topic = parts.isEmpty() ? "overview" : String.join("-", parts);
        if ("help".equals(topic)) topic = "overview";
        if (!CliCommands.topics().contains(topic)) {
            throw new CryptoCli.CliException(Messages.get("cli.err.unknownTopic", String.join(", ", CliCommands.topics())));
        }
        topic(topic, out);
        return 0;
    }

    /**
     * 주제 문서를 현재 언어로 출력한다(없으면 영어).
     *
     * @param name 주제 이름
     */
    static void topic(String name, PrintStream out) {
        topic(name, out, jarName());
    }

    /**
     * {@link #topic(String, PrintStream)}와 같고 예제에 쓸 JAR 이름을 정한다(초기 설정 안내: 실행 중인 CLI JAR 이름과 설정 결과 이름).
     *
     * @param jar 예제의 {@code {jar}} 자리에 넣을 JAR 파일 이름
     */
    static void topic(String name, PrintStream out, String jar) {
        String text = Messages.text(Messages.current(), name);
        if (text == null) text = Messages.text(Messages.Language.EN, name);
        if (text == null) text = "!" + name + "!";
        text = text.replace("{jar}", jar).replace("{version}", version())
                .replace("{configured}", ConfigCommand.defaultOutputName(jar));
        if (text.contains("{settings}")) text = text.replace("{settings}", settingsSection());
        out.print(text.endsWith("\n") ? text : text + "\n");
    }

    /** 그룹 명령({@code file}, {@code kms})만 입력했을 때의 짧은 안내. */
    static void group(String group, PrintStream out) {
        out.println(Messages.get("help.group", group, CryptoCli.subNames(group)));
        for (CliCommands.Spec spec : CliCommands.ALL) {
            if (spec.name.startsWith(group + " ")) out.println("  java -jar " + jarName() + " " + spec.name + " --help");
        }
    }

    /** 설정 표의 들여쓰기·열 너비(콘솔 표시 칸 수). 2 + 29 + 33 + 기본값(최대 16) = 80열. */
    private static final int INDENT = 2;
    private static final int NAME_WIDTH = 29;
    private static final int VALUE_WIDTH = 33;
    /** 다음 줄로 넘긴 값의 들여쓰기. */
    private static final String WRAP_INDENT = "      ";

    /**
     * {@code config help}의 설정 표를 만든다: 묶음별로 설정 이름·허용값·기본값(이 JAR의 내부 값) 한 줄씩. 이름이나 값이 열보다 길면
     * 그 항목만 다음 줄로 넘긴다. 목적·예제·주의 같은 상세는 사용자 가이드 10장에 있다.
     */
    static String settingsSection() {
        Properties defaults = jarDefaults();
        StringBuilder text = new StringBuilder();
        text.append(spaces(INDENT)).append(pad(Messages.get("help.settings.column.name"), NAME_WIDTH))
                .append(pad(Messages.get("help.settings.column.values"), VALUE_WIDTH))
                .append(Messages.get("help.settings.column.default")).append('\n');
        SettingCatalog.Group current = null;
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            if (setting.group != current) {
                current = setting.group;
                text.append(Messages.get("help.settings.group." + current.name())).append('\n');
            }
            String fallback = defaultValue(setting, defaults);
            if (setting.type == SettingCatalog.Type.CHOICE && setting.choices.size() > 1
                    && width(String.join("|", setting.choices)) >= VALUE_WIDTH) {
                // 값이 긴 선택형(예: Pool Factory 클래스 이름): 선택지마다 한 줄, 기본값에 표시.
                text.append(spaces(INDENT)).append(setting.key).append('\n');
                for (String choice : setting.choices) {
                    text.append(WRAP_INDENT).append(choice);
                    if (choice.equals(fallback)) text.append(' ').append(Messages.get("help.settings.defaultMark"));
                    text.append('\n');
                }
                continue;
            }
            String values = values(setting);
            String shownDefault = isFixed(setting) ? "" : fallback;
            if (width(setting.key) >= NAME_WIDTH) {
                // 이름이 긴 항목: 이름만 한 줄, 값은 다음 줄의 같은 열에.
                text.append(spaces(INDENT)).append(setting.key).append('\n');
                text.append(spaces(INDENT + NAME_WIDTH));
            } else {
                text.append(spaces(INDENT)).append(pad(setting.key, NAME_WIDTH));
            }
            text.append(shownDefault.isEmpty() ? values : pad(values, VALUE_WIDTH) + shownDefault);
            text.append('\n');
        }
        return text.toString();
    }

    /** @return 허용값 요약: 선택형은 {@code a|b|c}, 하나뿐이면 {@code 값 (고정)}, 숫자는 {@code 최소~최대}, 그 밖은 짧은 설명 */
    private static String values(SettingCatalog.Setting setting) {
        if (isFixed(setting)) return setting.choices.get(0) + " " + Messages.get("help.settings.fixed");
        if (!setting.choices.isEmpty()) return String.join("|", setting.choices);
        if (setting.type == SettingCatalog.Type.NUMBER) return setting.min + "~" + setting.max;
        return Messages.get("setting." + setting.key + ".values");
    }

    /** @return 허용값이 하나뿐인 설정(예: crypto.algorithm, crypto.require.encrypted.password) */
    private static boolean isFixed(SettingCatalog.Setting setting) {
        return setting.choices.size() == 1;
    }

    /** JAR 기본값(비밀 항목은 표시하지 않음). */
    private static String defaultValue(SettingCatalog.Setting setting, Properties defaults) {
        if (setting.sensitive) return Messages.get("help.settings.hiddenDefault");
        String value = defaults.getProperty(setting.key);
        if (value == null) return "-";
        value = value.trim();
        return value.isEmpty() ? Messages.get("help.settings.emptyDefault") : value;
    }

    /** @return 오른쪽을 공백으로 채워 표시 폭을 맞춘 문자열(이미 길면 공백 하나만 붙임) */
    private static String pad(String text, int columns) {
        int fill = columns - width(text);
        return text + spaces(fill > 0 ? fill : 1);
    }

    /** @return 공백 count칸 */
    static String spaces(int count) {
        StringBuilder text = new StringBuilder(count);
        for (int i = 0; i < count; i++) text.append(' ');
        return text.toString();
    }

    /**
     * 조회·결과 화면에서 여러 항목을 한 줄에 하나씩 쓴다. 첫 항목은 라벨 줄에, 나머지는 값 열에 맞춰 아랫줄에 둔다.
     * 예) {@code 변경 항목 : crypto.lang (ko -> en)} 다음 줄 {@code             crypto.warning.enabled (true -> false)}
     *
     * @param prefix 라벨과 구분자까지의 앞부분(예: "변경 항목 : ")
     * @param items  항목(비어 있지 않아야 함). {@link #arrow}로 만든 여러 줄 항목도 그대로 쓴다.
     */
    static void printItems(PrintStream out, String prefix, List<String> items) {
        String indent = spaces(width(prefix));
        for (int i = 0; i < items.size(); i++) out.println((i == 0 ? prefix : indent) + items.get(i));
    }

    /**
     * "이전 값 -> 변경 값" 한 항목을 만든다. 줄 앞부분(lead)과 합쳐 80열을 넘으면 {@code ->} 앞에서 한 번만 줄을 바꾸고 다음 줄은
     * continuation으로 들여 쓴다. 값(경로·URL 등)은 자르지 않으므로 값 하나가 80열보다 길면 그 줄은 그대로 길다.
     *
     * @param lead         이 항목 앞에 오는 줄 앞부분(라벨 또는 들여쓰기). 결과에는 포함하지 않는다.
     * @param before       {@code ->} 앞부분(예: "crypto.lang (ko")
     * @param after        {@code ->} 뒷부분(예: "en)")
     * @param continuation 줄을 바꿀 때 다음 줄 앞에 붙일 들여쓰기
     * @return 한 줄 또는 줄 구분자로 이은 두 줄(lead 제외)
     */
    static String arrow(String lead, String before, String after, String continuation) {
        String line = before + " -> " + after;
        if (width(lead + line) <= LINE_WIDTH) return line;
        return before + System.lineSeparator() + continuation + "-> " + after;
    }

    /** 조회·결과 화면의 한 줄 목표 폭(80열 콘솔, 한글 2칸). 경로·URL·지문·암호문 같은 값은 넘어도 자르지 않는다. */
    static final int LINE_WIDTH = 80;

    /**
     * 콘솔 표시 폭: 한글·한자·전각 문자는 2칸, 그 밖은 1칸으로 센다(표 정렬용 근사치).
     *
     * @param text 문자열
     * @return 표시 칸 수
     */
    static int width(String text) {
        int columns = 0;
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            boolean wide = (cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3)
                    || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE4F) || (cp >= 0xFF00 && cp <= 0xFF60)
                    || (cp >= 0xFFE0 && cp <= 0xFFE6);
            columns += wide ? 2 : 1;
            i += Character.charCount(cp);
        }
        return columns;
    }

    /** 실행 중인 JAR(클래스패스)의 내부 기본값. 읽지 못하면 빈 값(도움말은 계속 동작). */
    private static Properties jarDefaults() {
        Properties properties = new Properties();
        try (InputStream in = CliHelp.class.getResourceAsStream(CryptoSettings.DEFAULT_CONFIG_RESOURCE)) {
            if (in != null) {
                try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                    properties.load(reader);
                }
            }
        } catch (IOException | IllegalArgumentException ignored) {
            // 기본값 표시만 생략한다.
        }
        return properties;
    }

    /** @return 예제에 쓸 JAR 파일 이름(실행 중인 JAR 이름, 없으면 java-crypto-kit-&lt;버전&gt;.jar) */
    static String jarName() {
        Path running = ConfigCommand.runningJar();
        if (running != null && running.getFileName() != null) return SecretFiles.fileName(running);
        return "java-crypto-kit-" + version() + ".jar";
    }

    /** @return JAR Manifest의 버전(클래스 폴더에서 실행 중이면 "&lt;version&gt;") */
    static String version() {
        Package pkg = CliHelp.class.getPackage();
        String version = pkg == null ? null : pkg.getImplementationVersion();
        return version == null ? "<version>" : version;
    }
}
