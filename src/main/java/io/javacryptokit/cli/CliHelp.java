package io.javacryptokit.cli;

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
 * <b>내부 구현 클래스</b>: CLI 도움말. 사용자가 JAR만 가지고(인터넷·별도 문서 없이) 모든 기능을 설정·사용할 수 있게 한다.
 *
 * <p><b>원본</b>: 명령별 문서는 {@code io/javacryptokit/i18n/help/<en|ko>/<주제>.txt}(UTF-8)에 있고, 두 언어는 같은 주제·같은
 * 옵션·같은 설정을 설명한다(테스트가 검사). {@code config help}의 설정 목록은 {@link SettingCatalog}(이름·자료형·허용값·{@code -D}
 * 규칙·적용 공급원)와 JAR 내장 기본값, 언어별 설명({@code setting.<이름>.*})으로 자동 생성하므로 실제 구현과 어긋나지 않는다.</p>
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
        String text = Messages.text(Messages.current(), name);
        if (text == null) text = Messages.text(Messages.Language.EN, name);
        if (text == null) text = "!" + name + "!";
        text = text.replace("{jar}", jarName()).replace("{version}", version());
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

    /**
     * {@code config help}의 설정 목록을 만든다: 묶음별로 이름, 설명, 자료형, JAR 기본값, 허용값, 설정 위치(JAR 내부·외부 Properties·
     * -D), 적용 공급원, 주의사항, 예제.
     */
    static String settingsSection() {
        Properties defaults = jarDefaults();
        StringBuilder text = new StringBuilder();
        SettingCatalog.Group current = null;
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            if (setting.group != current) {
                current = setting.group;
                text.append('\n').append(Messages.get("help.settings.group." + current.name())).append('\n');
            }
            text.append('\n').append("  ").append(setting.key).append('\n');
            item(text, "help.settings.purpose", Messages.get("setting." + setting.key + ".purpose"));
            item(text, "help.settings.type", Messages.get("help.settings.type." + setting.type.name()));
            item(text, "help.settings.default", defaultValue(setting, defaults));
            item(text, "help.settings.allowed", Messages.get("setting." + setting.key + ".allowed"));
            item(text, "help.settings.where", where(setting));
            item(text, "help.settings.sources", setting.sources.isEmpty() ? Messages.get("help.settings.allSources")
                    : String.join(", ", setting.sources));
            String notes = "setting." + setting.key + ".notes";
            if (Messages.has(Messages.current(), notes)) item(text, "help.settings.notes", Messages.get(notes));
            item(text, "help.settings.example", Messages.get("setting." + setting.key + ".example"));
        }
        return text.toString();
    }

    private static void item(StringBuilder text, String labelKey, String value) {
        text.append("      ").append(Messages.get(labelKey)).append(' ').append(value).append('\n');
    }

    /** JAR 기본값(비밀 항목은 표시하지 않음). */
    private static String defaultValue(SettingCatalog.Setting setting, Properties defaults) {
        if (setting.sensitive) return Messages.get("help.settings.hiddenDefault");
        String value = defaults.getProperty(setting.key);
        if (value == null) return "-";
        value = value.trim();
        return value.isEmpty() ? Messages.get("help.settings.emptyDefault") : value;
    }

    /** 설정할 수 있는 위치와 -D 규칙. */
    private static String where(SettingCatalog.Setting setting) {
        String jar = Messages.get(setting.sensitive ? "help.settings.where.jarEmbed" : "help.settings.where.jar");
        String jvm;
        switch (setting.jvmRule) {
            case ALLOWED:
                jvm = Messages.get("help.settings.where.jvmAllowed", setting.key);
                break;
            case IGNORED:
                jvm = Messages.get("help.settings.where.jvmIgnored");
                break;
            default:
                jvm = Messages.get("help.settings.where.jvmRejected");
                break;
        }
        return jar + ", " + Messages.get("help.settings.where.external") + ", " + jvm;
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
        if (running != null && running.getFileName() != null) return running.getFileName().toString();
        return "java-crypto-kit-" + version() + ".jar";
    }

    /** @return JAR Manifest의 버전(클래스 폴더에서 실행 중이면 "&lt;version&gt;") */
    static String version() {
        Package pkg = CliHelp.class.getPackage();
        String version = pkg == null ? null : pkg.getImplementationVersion();
        return version == null ? "<version>" : version;
    }
}
