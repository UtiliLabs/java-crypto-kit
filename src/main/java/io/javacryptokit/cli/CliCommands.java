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
 * <p><b>보안</b>: 평문 비밀번호·원시 키·Passphrase·토큰·관리자 비밀번호를 값으로 받는 옵션은 없다. {@code --value}는 암호문
 * (verify·rekey)만 받고, 키 재료는 파일({@code --from-file})·입력(화면 비표시)·생성({@code --generate})으로만, 관리자 비밀번호는
 * 입력(화면 비표시)·파일({@code --admin-pass-file})로만 받는다.
 * {@code -D...}를 {@code -jar} 뒤에 두면 JVM 속성이 아니라 프로그램 인자가 되므로 거부하고 올바른 위치를 안내한다.</p>
 */
final class CliCommands {
    /**
     * 명령의 CLI 관리자 비밀번호 정책. 명령 정의마다 반드시 하나를 정하며(생성자 인자), 인증은 이 값만 보고 {@link CryptoCli}가 명령
     * 본 처리 전에 한 곳에서 한다(명령별 인증 호출 없음).
     */
    enum Access {
        /** 최초 설정만 마치면 묻지 않는다(평문·키 원문을 보여 주지 않는 명령: encrypt·verify·file encrypt·fingerprint·info·doctor). */
        OPEN,
        /** 미설정 JAR에서만 쓰는 최초 설정({@code admin setup}). 인증 대상이 아니다. */
        SETUP,
        /**
         * 실행할 때마다 관리자 비밀번호를 확인한다(복호화·키 생성/등록/변경/삭제·키 조회·JAR 설정 조회/변경·비밀번호 변경). 입력 없이
         * 하는 사전 검사 → 실행 중인 JAR와 {@code --jar}·{@code --from-jar} JAR의 인증({@code --to-jar}는 무결성만) → 본 처리 순서다.
         */
        ADMIN
    }

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
        /** 관리자 비밀번호 정책(단일 정본). */
        final Access access;

        Spec(String name, String topic, List<String> values, List<String> flags, boolean settingArgs, Access access) {
            if (access == null) throw new IllegalArgumentException("access");
            this.name = name;
            this.topic = topic;
            this.values = Collections.unmodifiableList(values);
            this.flags = Collections.unmodifiableList(flags);
            this.settingArgs = settingArgs;
            this.access = access;
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
        /** 이번 실행의 관리자 비밀번호 확인 창구({@link CryptoCli}가 명령 실행 전에 채운다). */
        AdminGate admin;

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
    /** {@code config} 아래의 키 목록 묶음 이름({@code config key add|use|remove}). */
    static final String KEY_GROUP = "key";

    /** 관리자 비밀번호 파일 옵션(비대화형 인증·최초 설정). */
    static final String ADMIN_FILE = AdminPassword.FILE_OPTION;

    /**
     * 전체 명령 정의(도움말 목차 순서). 명령마다 관리자 비밀번호 정책({@link Access})을 함께 정한다: 평문·키 원문을 보여 주지 않는
     * 명령만 {@link Access#OPEN}이고, 복호화·키 생성/등록/변경/삭제·키 조회·JAR 설정 조회/변경·비밀번호 변경은 {@link Access#ADMIN}.
     */
    static final List<Spec> ALL = Collections.unmodifiableList(Arrays.asList(
            spec("encrypt", "encrypt", list("--type", "--key-id", "--config"), list(), Access.OPEN),
            spec("verify", "verify", list("--config", "--value"), list(), Access.OPEN),
            spec("decrypt", "decrypt", list("--config", ADMIN_FILE), list(), Access.ADMIN),
            spec("file encrypt", "file-encrypt", list("--in", "--out", "--type", "--key-id", "--config"), list(), Access.OPEN),
            spec("file decrypt", "file-decrypt", list("--in", "--out", "--config", ADMIN_FILE), list(), Access.ADMIN),
            spec("keygen", "keygen", list("--out", "--reason", "--operator", ADMIN_FILE), list(), Access.ADMIN),
            spec("fingerprint", "fingerprint", list("--type", "--key-id", "--config", "--key-file"), list(), Access.OPEN),
            spec("rekey", "rekey", list("--type", "--key-id", "--from-config", "--from-jar", "--to-config", "--to-jar",
                    "--value", ADMIN_FILE), list(), Access.ADMIN),
            spec("info", "info", list("--config"), list(), Access.OPEN),
            spec("doctor", "doctor", list("--config"), list("--offline"), Access.OPEN),
            spec("config show", "config-show", list("--jar", ADMIN_FILE), list(), Access.ADMIN),
            spec("config history", "config-history", list("--type", "--jar", ADMIN_FILE), list("--all"), Access.ADMIN),
            new Spec("config set", "config-set", list("--jar", "--out", "--operator", "--reason", ADMIN_FILE),
                    list("--replace", "--yes"), true, Access.ADMIN),
            spec("config embed-key", "config-embed-key",
                    list("--from-file", "--key-id", "--operator", "--reason", "--source", "--jar", "--out", ADMIN_FILE),
                    list("--replace", "--yes"), Access.ADMIN),
            spec("config key add", "config-key-add",
                    list("--key-id", "--type", "--from-file", "--from-jar", "--source", "--location", "--export",
                            "--operator", "--reason", "--jar", "--out", ADMIN_FILE),
                    list("--generate", "--active", "--replace", "--yes"), Access.ADMIN),
            spec("config key use", "config-key-use",
                    list("--key-id", "--type", "--operator", "--reason", "--jar", "--out", ADMIN_FILE),
                    list("--replace", "--yes"), Access.ADMIN),
            spec("config key remove", "config-key-remove",
                    list("--key-id", "--operator", "--reason", "--jar", "--out", ADMIN_FILE), list("--replace", "--yes"),
                    Access.ADMIN),
            spec("config key show", "config-key-show", list("--key-id", "--jar", "--export", ADMIN_FILE), list("--show"),
                    Access.ADMIN),
            spec("kms datakey", "kms-datakey", list("--out", "--from-file", "--config", "--reason", "--operator", ADMIN_FILE),
                    list(), Access.ADMIN),
            spec("admin setup", "admin-setup", list("--operator", "--out", ADMIN_FILE), list(), Access.SETUP),
            spec("admin password change", "admin-password-change", list("--operator", "--reason", "--out"), list(),
                    Access.ADMIN)));

    /** 명령이 아닌 도움말 주제(설정 묶음 안내, config key 묶음 안내, 미설정 JAR의 초기 설정 안내). */
    static final List<String> EXTRA_TOPICS = Collections.unmodifiableList(Arrays.asList("config", "config-key", "tomcat", "vault",
            "aws-kms", "admin-required"));

    /** 하위 명령을 가진 그룹 명령. */
    static final List<String> GROUPS = Collections.unmodifiableList(Arrays.asList("config", "file", "kms", "admin"));

    /** 3단계 명령의 묶음(예: {@code config key add}) → 묶음만 입력했을 때 보여 줄 도움말 주제. */
    static final Map<String, String> NESTED_GROUPS;

    static {
        Map<String, String> nested = new LinkedHashMap<>();
        nested.put("config " + KEY_GROUP, "config-key");
        nested.put("admin password", "admin-password-change");
        NESTED_GROUPS = Collections.unmodifiableMap(nested);
    }

    // Keys are the exact short spellings. Only command segments and option names are normalized.
    private static final Map<String, String> GROUP_ALIASES = aliasMap(
            "sig", "signature", "cert", "certificate", "rand", "random", "req-auth", "request-auth");
    private static final Map<String, String> PATH_ALIASES = pathAliases();
    private static final Map<String, String> OPTION_ALIASES = aliasMap(
            "--alg", "--algorithm", "--enc", "--encoding", "--in-enc", "--input-encoding",
            "--key-enc", "--key-encoding", "--fmt", "--format", "--pub-key", "--public-key",
            "--priv-key", "--private-key", "--len", "--length", "--iter", "--iterations",
            "--sig-file", "--signature-file", "--iss", "--issuer", "--sub", "--subject",
            "--aud", "--audience", "--jti", "--jwt-id", "--iat", "--issued-at",
            "--nbf", "--not-before", "--ttl", "--expires-in");

    private static Map<String, String> aliasMap(String... pairs) {
        Map<String, String> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            if (result.put(pairs[i], pairs[i + 1]) != null) throw new IllegalStateException("duplicate CLI alias");
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<String, String> pathAliases() {
        Map<String, String> result = new LinkedHashMap<>();
        for (String prefix : Arrays.asList("", "file ", "api aes ", "api rsa ", "api hybrid ")) {
            result.put(prefix + "enc", prefix + "encrypt");
            result.put(prefix + "dec", prefix + "decrypt");
        }
        result.put("api keyconv", "api keyconvert");
        result.put("api hash gen", "api hash generate");
        result.put("api otp gen", "api otp generate");
        return Collections.unmodifiableMap(result);
    }

    static String canonicalPath(String path) {
        if (path.startsWith("api ")) {
            int end = path.indexOf(' ', 4);
            if (end < 0) end = path.length();
            String group = path.substring(4, end);
            String resolved = GROUP_ALIASES.get(group);
            if (resolved != null) path = "api " + resolved + path.substring(end);
        }
        return PATH_ALIASES.getOrDefault(path, path);
    }

    static String commandAlias(String path) {
        for (Map.Entry<String, String> alias : PATH_ALIASES.entrySet()) {
            if (alias.getValue().equals(path)) return alias.getKey();
        }
        for (Map.Entry<String, String> alias : GROUP_ALIASES.entrySet()) {
            String group = "api " + alias.getValue();
            if (path.equals(group) || path.startsWith(group + " ")) {
                return "api " + alias.getKey() + path.substring(group.length());
            }
        }
        return null;
    }

    private static boolean apiAliasesAllowed(Spec spec, String option) {
        return spec.name.startsWith("api ") && (!"--issuer".equals(option)
                || spec.name.startsWith("api jwt ") || spec.name.startsWith("api oauth "));
    }

    static String canonicalOption(Spec spec, String name) {
        String target = OPTION_ALIASES.get(name);
        return target != null && apiAliasesAllowed(spec, target) && spec.values.contains(target) ? target : name;
    }

    static String optionAlias(Spec spec, String canonical) {
        if (!apiAliasesAllowed(spec, canonical) || !spec.values.contains(canonical)) return null;
        for (Map.Entry<String, String> alias : OPTION_ALIASES.entrySet()) {
            if (alias.getValue().equals(canonical)) return alias.getKey();
        }
        return null;
    }

    /** @return 실행할 때마다 관리자 비밀번호를 확인하는 명령이면 true */
    static boolean needsAdmin(Spec spec) {
        return spec.access == Access.ADMIN;
    }

    private CliCommands() { }

    private static Spec spec(String name, String topic, List<String> values, List<String> flags, Access access) {
        return new Spec(name, topic, values, flags, false, access);
    }

    private static List<String> list(String... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

    /**
     * @param name 명령 이름(예: "config set")
     * @return 정의(없으면 null)
     */
    static Spec find(String name) {
        name = canonicalPath(name);
        for (Spec spec : ALL) {
            if (spec.name.equals(name)) return spec;
        }
        if (name.startsWith("api ")) {
            for (Spec spec : ApiCommands.ALL) if (spec.name.equals(name)) return spec;
        }
        return null;
    }

    /** @return 최상위 명령 이름(help 포함, 그룹은 그룹 이름으로) */
    static Set<String> topLevelNames() {
        Set<String> names = new LinkedHashSet<>();
        names.add("help");
        names.add("api");
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
                name = canonicalOption(spec, name);
                if (spec.flags.contains(name) && value == null) {
                    if (!parsed.flags.add(name) && spec.name.startsWith("api ")) {
                        throw new CryptoCli.CliException(Messages.get("cli.err.duplicate", name, spec.name));
                    }
                } else if (spec.values.contains(name)) {
                    if (value == null) {
                        if (++i >= args.length || (spec.name.startsWith("api ") && args[i].startsWith("--"))) {
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
