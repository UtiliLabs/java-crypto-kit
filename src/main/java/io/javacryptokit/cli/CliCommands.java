package io.javacryptokit.cli;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.i18n.Messages;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>내부 구현 클래스</b>: CLI 명령과 옵션의 "정의"를 한 곳에 모은 목록이다. 인자 해석({@link #parse})과 도움말·테스트가 이 정의를
 * 같이 쓰므로 도움말에 적힌 옵션과 실제로 받는 옵션이 어긋나지 않는다(테스트가 영어·한국어 도움말이 이 목록의 옵션을 빠짐없이
 * 설명하는지 검사한다).
 *
 * <p><b>공통 옵션</b>: {@code --lang en|ko}(이번 실행에만 적용하는 메시지 언어, 영구 설정은 {@code crypto.lang}),
 * {@code --help}/{@code -h}. 모든 명령에서 같은 위치 규칙으로 쓴다.</p>
 *
 * <p><b>보안</b>: 평문 비밀번호·원시 키·토큰을 값으로 받는 옵션은 없다. {@code --value}는 암호문(verify·rekey)만 받는다.
 * {@code -D...}를 {@code -jar} 뒤에 두면 JVM 속성이 아니라 프로그램 인자가 되므로 거부하고 올바른 위치를 안내한다.</p>
 */
final class CliCommands {
    /** 명령 하나의 정의. */
    static final class Spec {
        /** 명령 이름(하위 명령은 공백으로 구분, 예: "config set"). */
        final String name;
        /** 도움말 문서 이름(io/javacryptokit/i18n/help/&lt;언어&gt;/&lt;topic&gt;.txt). */
        final String topic;
        /** 값을 받는 옵션. */
        final List<String> values;
        /** 값 없이 쓰는 옵션. */
        final List<String> flags;
        /** {@code 이름=값} 형식의 설정 인자를 받는지(config set). */
        final boolean settingArgs;

        Spec(String name, String topic, List<String> values, List<String> flags, boolean settingArgs) {
            this.name = name;
            this.topic = topic;
            this.values = Collections.unmodifiableList(values);
            this.flags = Collections.unmodifiableList(flags);
            this.settingArgs = settingArgs;
        }

        /** @return 이 명령이 받는 모든 옵션 이름(공통 옵션 제외) */
        List<String> options() {
            List<String> all = new ArrayList<>(values);
            all.addAll(flags);
            return all;
        }
    }

    /** 해석한 인자. */
    static final class Parsed {
        final Spec spec;
        final Map<String, String> values = new LinkedHashMap<>();
        final Set<String> flags = new LinkedHashSet<>();
        /** config set의 이름=값(입력 순서). */
        final Map<String, String> settings = new LinkedHashMap<>();
        boolean help;

        Parsed(Spec spec) {
            this.spec = spec;
        }

        String value(String option) {
            return values.get(option);
        }

        boolean flag(String option) {
            return flags.contains(option);
        }
    }

    /** 공통 언어 옵션. */
    static final String LANG_OPTION = "--lang";

    /** 전체 명령 정의(도움말 목차 순서). */
    static final List<Spec> ALL = Collections.unmodifiableList(Arrays.asList(
            spec("encrypt", "encrypt", list("--config"), list()),
            spec("verify", "verify", list("--config", "--value"), list()),
            spec("decrypt", "decrypt", list("--config"), list()),
            spec("file encrypt", "file-encrypt", list("--in", "--out", "--config"), list()),
            spec("file decrypt", "file-decrypt", list("--in", "--out", "--config"), list()),
            spec("keygen", "keygen", list("--out"), list()),
            spec("fingerprint", "fingerprint", list("--config", "--key-file"), list()),
            spec("rekey", "rekey", list("--from-config", "--from-jar", "--to-config", "--to-jar", "--value"), list()),
            spec("info", "info", list("--config"), list()),
            spec("doctor", "doctor", list("--config"), list("--offline")),
            spec("config show", "config-show", list("--jar"), list()),
            spec("config history", "config-history", list("--jar"), list()),
            new Spec("config set", "config-set", list("--jar", "--out", "--operator", "--reason"),
                    list("--replace", "--yes"), true),
            spec("config embed-key", "config-embed-key",
                    list("--from-file", "--key-id", "--operator", "--reason", "--source", "--jar", "--out"),
                    list("--replace", "--yes")),
            spec("kms datakey", "kms-datakey", list("--out", "--from-file", "--config"), list())));

    /** 명령이 아닌 도움말 주제(설정 묶음 안내). */
    static final List<String> EXTRA_TOPICS = Collections.unmodifiableList(Arrays.asList("config", "tomcat", "vault", "aws-kms"));

    /** 하위 명령을 가진 그룹 명령. */
    static final List<String> GROUPS = Collections.unmodifiableList(Arrays.asList("config", "file", "kms"));

    private CliCommands() { }

    private static Spec spec(String name, String topic, List<String> values, List<String> flags) {
        return new Spec(name, topic, values, flags, false);
    }

    private static List<String> list(String... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

    /**
     * @param name 명령 이름(예: "config set")
     * @return 정의(없으면 null)
     */
    static Spec find(String name) {
        for (Spec spec : ALL) {
            if (spec.name.equals(name)) return spec;
        }
        return null;
    }

    /** @return 최상위 명령 이름(help 포함, 그룹은 그룹 이름으로) */
    static Set<String> topLevelNames() {
        Set<String> names = new LinkedHashSet<>();
        names.add("help");
        for (Spec spec : ALL) names.add(spec.name.split(" ")[0]);
        return names;
    }

    /** @return 도움말 주제 전체(명령 주제 + 설정 안내 주제) */
    static List<String> topics() {
        List<String> topics = new ArrayList<>();
        topics.add("overview");
        for (Spec spec : ALL) topics.add(spec.topic);
        topics.addAll(EXTRA_TOPICS);
        return topics;
    }

    /**
     * 명령 인자를 해석한다. 옵션은 {@code --이름 값}과 {@code --이름=값}을 모두 받는다. 모르는 옵션·인자는 값을 출력하지 않고
     * 거부한다(실수로 비밀번호·키를 넣었을 수 있음).
     *
     * @param spec  명령 정의
     * @param args  전체 인자({@code --lang}은 이미 제거됨)
     * @param start 옵션이 시작하는 위치
     * @return 해석 결과
     * @throws CryptoCli.CliException 사용법 오류(USAGE)
     */
    static Parsed parse(Spec spec, String[] args, int start) throws CryptoCli.CliException {
        Parsed parsed = new Parsed(spec);
        for (int i = start; i < args.length; i++) {
            String arg = args[i];
            if ("--help".equals(arg) || "-h".equals(arg)) {
                parsed.help = true;
                return parsed;
            }
            if (arg.startsWith("-D")) {
                throw new CryptoCli.CliException(Messages.get("cli.err.jvmAfterJar", spec.name));
            }
            if (arg.startsWith("--")) {
                String name = arg;
                String value = null;
                int eq = arg.indexOf('=');
                if (eq > 0) {
                    name = arg.substring(0, eq);
                    value = arg.substring(eq + 1);
                }
                if (spec.flags.contains(name) && value == null) {
                    parsed.flags.add(name);
                } else if (spec.values.contains(name)) {
                    if (value == null) {
                        if (++i >= args.length) {
                            throw new CryptoCli.CliException(Messages.get("cli.err.missingValue", name, spec.name));
                        }
                        value = args[i];
                    }
                    if (parsed.values.containsKey(name)) {
                        throw new CryptoCli.CliException(Messages.get("cli.err.duplicate", name, spec.name));
                    }
                    parsed.values.put(name, value);
                } else {
                    String shown = name.matches("--[a-z-]{1,30}") ? name : "?";
                    String suggestion = CryptoSettings.suggest(name, spec.options());
                    throw new CryptoCli.CliException(Messages.get("cli.err.unknownOption", shown, spec.name,
                            spec.options().isEmpty() ? "-" : String.join(", ", spec.options()))
                            + (suggestion != null ? " " + Messages.get("config.hint.didYouMean", suggestion) : ""));
                }
            } else if (spec.settingArgs && arg.indexOf('=') > 0) {
                String key = arg.substring(0, arg.indexOf('='));
                if (parsed.settings.containsKey(key)) {
                    throw new CryptoCli.CliException(Messages.get("cli.err.duplicate", key, spec.name));
                }
                parsed.settings.put(key, arg.substring(arg.indexOf('=') + 1));
            } else {
                // 값 자체를 출력하지 않는다(실수로 키·비밀번호를 넣었을 수 있음).
                throw new CryptoCli.CliException(Messages.get("cli.err.unknownArg", spec.name));
            }
        }
        return parsed;
    }
}
