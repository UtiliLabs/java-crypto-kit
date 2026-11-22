package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: {@code config show / history / set / embed-key}의 확인 절차·출력을 맡는다. JAR 읽기·쓰기·검증은
 * {@link JarConfigEditor}, 이력은 {@link ConfigHistory}가 한다.
 *
 * <p><b>역할 구분</b>: {@code config show}는 JAR 파일 안의 현재 설정값과 최종 변경 요약, {@code config history}는 최초 변경부터
 * 전체 변경 내역을 보여 준다. 둘 다 외부 Properties·JVM {@code -D}·환경변수를 읽지 않는다(설정 로더를 거치지 않으므로 잘못된
 * 외부 설정이 있어도 동작). 실행 시 최종 적용값은 {@code info}, 실제 동작 점검은 {@code doctor}가 맡는다.</p>
 *
 * <p><b>보안</b>: 내장 키 값은 출력하지 않는다(키 지문만). 키 원문은 명령행 인자로 받지 않고 키 파일로만 받는다. 키·키ID처럼
 * 기존 암호문에 영향을 주는 변경은 영향을 안내한 뒤 대화형 확인({@code CHANGE}) 또는 명시적 승인({@code --yes})을 요구한다.
 * 수정자 ID는 기록용이며 본인 인증이 아니다(별도 관리자 비밀번호 없음, 실제 통제는 OS 파일 권한과 배포 승인 절차).</p>
 */
final class ConfigCommand {
    /** 키 관련 변경을 진행하기 위해 사용자가 직접 입력해야 하는 확인 문구(번역하지 않음). */
    static final String CONFIRM_WORD = "CHANGE";
    /** 결과 JAR 기본 이름에 붙이는 표시(원본과 쉽게 구분). */
    static final String DEFAULT_SUFFIX = "-configured.jar";

    private ConfigCommand() { }

    /**
     * {@code config show / history / set / embed-key}를 실행한다.
     *
     * @param parsed 해석한 인자
     * @return 종료 코드
     */
    static int run(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        switch (parsed.spec.name) {
            case "config show":
                return show(sourceJar(parsed), out);
            case "config history":
                return history(sourceJar(parsed), out);
            case "config set":
                return set(parsed, terminals, out);
            default:
                return embedKey(parsed, terminals, out);
        }
    }

    // ===================================================================================================
    // config show
    // ===================================================================================================

    private static int show(Path jar, PrintStream out) throws CryptoCli.CliException {
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        ConfigHistory.Log log = snap.history;
        out.println(Messages.get("cfg.show.header1"));
        out.println(Messages.get("cfg.show.header2"));
        out.println(Messages.get("cfg.show.project", orDefault(snap.title, "java-crypto-kit")));
        out.println(Messages.get("cfg.show.version", orDefault(snap.version, "-")));
        out.println(Messages.get("cfg.show.file", JarConfigEditor.name(jar), snap.signed ? Messages.get("cfg.show.signed") : ""));
        out.println(Messages.get("cfg.show.buildTime", orDefault(snap.buildTime, Messages.get("cfg.value.unknown"))));
        if (log.problem != null) {
            out.println(Messages.get("cfg.show.state.invalid", log.problem));
        } else if (!log.present) {
            out.println(Messages.get("cfg.show.state.initial"));
            out.println(Messages.get("cfg.show.lastModified", Messages.get("cfg.show.noHistory")));
            out.println(Messages.get("cfg.show.count", 0));
        } else {
            ConfigHistory.Entry last = log.last();
            out.println(Messages.get("cfg.show.state.changed"));
            out.println(Messages.get("cfg.show.lastModified", last.time));
            out.println(Messages.get("cfg.show.lastOperator", last.operator));
            out.println(Messages.get("cfg.show.count", log.entries.size()));
            List<String> keys = new ArrayList<>();
            for (ConfigHistory.Change change : last.changes) keys.add(change.key);
            out.println(Messages.get("cfg.show.lastKeys", String.join(", ", keys), last.command));
            if (!last.reason.isEmpty()) out.println(Messages.get("cfg.show.lastReason", last.reason));
        }
        out.println(Messages.get("cfg.show.fingerprint", ConfigHistory.fingerprint(snap.settingsBytes)));
        out.println();
        out.println(Messages.get("cfg.show.values"));
        for (String key : keysInFileOrder(snap)) {
            String value = snap.settings.getProperty(key).trim();
            String shown = SettingCatalog.sensitiveKeys().contains(key) ? Messages.get("cfg.value.hidden", keyStatus(snap))
                    : (value.isEmpty() ? Messages.get("history.value.empty") : value);
            out.println(key + " = " + shown);
        }
        out.println();
        out.println(Messages.get("cfg.show.summary"));
        String source = setting(snap, CryptoSettings.KEY_SOURCE);
        out.println(Messages.get("cfg.show.summary.source", source, describeSource(source)));
        out.println(Messages.get("cfg.show.summary.keyId", setting(snap, CryptoSettings.KEY_ID)));
        out.println(Messages.get("cfg.show.summary.keyStatus", keyStatus(snap)));
        out.println(Messages.get("cfg.show.summary.lang", orDefault(setting(snap, CryptoSettings.LANG), SettingCatalog.DEFAULT_LANGUAGE)));
        out.println(Messages.get("cfg.show.summary.warning", onOff(setting(snap, CryptoSettings.WARNING_ENABLED))));
        out.println(Messages.get("cfg.show.summary.jvm", onOff(setting(snap, CryptoSettings.JVM_OVERRIDE_ENABLED))));
        out.println(Messages.get("cfg.show.summary.algorithm", setting(snap, CryptoSettings.ALGORITHM)));
        out.println(Messages.get("cfg.show.summary.output", setting(snap, CryptoSettings.OUTPUT_ENCODING)));
        out.println(Messages.get("cfg.show.summary.pool", setting(snap, CryptoSettings.POOL_FACTORY)));
        out.println(Messages.get("cfg.show.summary.validation", snap.validationError == null ? Messages.get("cfg.ok")
                : Messages.get("cfg.show.validationError", snap.validationError)));
        out.println();
        out.println(Messages.get("cfg.show.historyHint"));
        out.println(Messages.get("cfg.notAudit"));
        return snap.validationError == null && log.problem == null ? 0 : 1;
    }

    // ===================================================================================================
    // config history
    // ===================================================================================================

    private static int history(Path jar, PrintStream out) throws CryptoCli.CliException {
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        ConfigHistory.Log log = snap.history;
        if (log.problem != null) {
            // 손상·변조가 의심되는 이력은 정상 이력처럼 보여 주지 않는다.
            throw new CryptoCli.CliException("INTEGRITY", Messages.get("cfg.history.invalid", log.problem));
        }
        out.println(Messages.get("cfg.history.header"));
        out.println(Messages.get("cfg.history.file", JarConfigEditor.name(jar), orDefault(snap.version, "-")));
        out.println(Messages.get("cfg.show.buildTime", orDefault(snap.buildTime, Messages.get("cfg.value.unknown"))));
        if (!log.present) {
            out.println(Messages.get("cfg.history.none"));
            out.println(Messages.get("cfg.notAudit"));
            return 0;
        }
        out.println(Messages.get("cfg.show.lastModified", log.last().time));
        out.println(Messages.get("cfg.show.count", log.entries.size()));
        out.println(Messages.get("cfg.history.verified"));
        out.println();
        for (ConfigHistory.Entry entry : log.entries) {
            out.println(Messages.get("cfg.history.entry", entry.number, entry.time, entry.operator, entry.command));
            if (!entry.reason.isEmpty()) out.println(Messages.get("cfg.history.reason", entry.reason));
            boolean secret = false;
            for (ConfigHistory.Change change : entry.changes) {
                out.println(Messages.get("cfg.history.change", change.key, ConfigHistory.display(change.before),
                        ConfigHistory.display(change.after)));
                if (ConfigHistory.SECRET_AFTER.equals(change.after)) secret = true;
            }
            if (secret) out.println(Messages.get("cfg.history.secretNote"));
        }
        out.println();
        out.println(Messages.get("cfg.notAudit"));
        return 0;
    }

    /** 내장 키 상태(값은 출력하지 않고, 교체된 키는 지문만). */
    private static String keyStatus(JarConfigEditor.Snapshot snap) {
        byte[] key = null;
        try {
            key = KeyResolver.decodeKey(snap.settings.getProperty(CryptoSettings.KEY_EMBEDDED));
            return DefaultKeyWarning.isPublicDefaultKey(key) ? Messages.get("cfg.key.public")
                    : Messages.get("cfg.key.custom", KeyResolver.fingerprint(key));
        } catch (IllegalArgumentException e) {
            return Messages.get("cfg.key.invalid", e.getMessage());
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    private static String describeSource(String source) {
        String key = "cfg.source." + source;
        return Messages.has(Messages.current(), key) ? Messages.get(key) : "";
    }

    private static String onOff(String value) {
        return "true".equals(value) ? "ON" : "false".equals(value) ? "OFF" : Messages.get("cfg.value.badBoolean");
    }

    private static String setting(JarConfigEditor.Snapshot snap, String key) {
        return snap.settings.getProperty(key, "").trim();
    }

    /** 설정 파일에 적힌 순서대로 항목 이름을 돌려준다. */
    private static List<String> keysInFileOrder(JarConfigEditor.Snapshot snap) {
        List<String> keys = new ArrayList<>();
        Matcher m = Pattern.compile("(?m)^\\s*([A-Za-z0-9._-]+)\\s*[=:]").matcher(snap.settingsText());
        while (m.find()) {
            if (snap.settings.containsKey(m.group(1)) && !keys.contains(m.group(1))) keys.add(m.group(1));
        }
        for (String key : snap.settings.stringPropertyNames()) if (!keys.contains(key)) keys.add(key);
        return keys;
    }

    // ===================================================================================================
    // config set
    // ===================================================================================================

    private static int set(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        if (parsed.settings.isEmpty()) throw new CryptoCli.CliException(Messages.get("cfg.err.setNone"));
        checkOutputOptions(parsed);
        JarConfigEditor.checkOperator(parsed.value("--operator"));
        JarConfigEditor.checkReason(parsed.value("--reason"));
        if (parsed.settings.containsKey(CryptoSettings.KEY_EMBEDDED)) {
            throw new CryptoCli.CliException(Messages.get("jar.err.sensitiveSet", CryptoSettings.KEY_EMBEDDED));
        }
        Path source = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(source);
        // 결과 경로는 확인 질문(CHANGE) 전에 정한다: 결과 파일이 이미 있으면 입력을 받기 전에 바로 안내한다.
        Path output = outputJar(parsed, source);
        List<String> keyChanges = new ArrayList<>();
        for (Map.Entry<String, String> item : parsed.settings.entrySet()) {
            String current = snap.settings.getProperty(item.getKey());
            if (SettingCatalog.keyAffectingKeys().contains(item.getKey()) && current != null
                    && !current.trim().equals(item.getValue())) {
                keyChanges.add(item.getKey() + " (" + display(current) + " -> " + display(item.getValue()) + ")");
            }
        }
        if (!keyChanges.isEmpty()) {
            printKeyImpact(out, Messages.get("cfg.impact.set", String.join(", ", keyChanges)), false);
            if (!confirm(parsed, terminals, out)) return 0;
        }
        noteIncompleteKeySource(snap, parsed.settings, out);
        JarConfigEditor.Change change = new JarConfigEditor.Change("set", parsed.settings, parsed.value("--operator"),
                parsed.value("--reason"));
        JarConfigEditor.Result result = JarConfigEditor.apply(source, output, parsed.flag("--replace"),
                runningJar(), change, Instant.now());
        printResult(result, out);
        return 0;
    }

    /** file 방식인데 경로가 비어 있는 등, 실행 때 외부 설정이 꼭 필요해지는 조합을 미리 알린다(차단하지는 않음: 실행 시 Fail Closed). */
    private static void noteIncompleteKeySource(JarConfigEditor.Snapshot snap, Map<String, String> changes, PrintStream out) {
        String source = changes.containsKey(CryptoSettings.KEY_SOURCE) ? changes.get(CryptoSettings.KEY_SOURCE)
                : snap.settings.getProperty(CryptoSettings.KEY_SOURCE, "").trim();
        String path = changes.containsKey(CryptoSettings.KEY_FILE) ? changes.get(CryptoSettings.KEY_FILE)
                : snap.settings.getProperty(CryptoSettings.KEY_FILE, "").trim();
        if ("file".equals(source) && path.isEmpty()) out.println(Messages.get("cfg.note.filePathEmpty"));
    }

    // ===================================================================================================
    // config embed-key
    // ===================================================================================================

    private static int embedKey(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out)
            throws Exception {
        String keyFile = parsed.value("--from-file");
        String keyId = parsed.value("--key-id");
        if (keyFile == null || keyId == null) throw new CryptoCli.CliException(Messages.get("cfg.err.embedNeeds"));
        checkOutputOptions(parsed);
        JarConfigEditor.checkOperator(parsed.value("--operator"));
        JarConfigEditor.checkReason(parsed.value("--reason"));
        if (!keyId.matches("[A-Za-z0-9_-]{1,64}")) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdFormat"));
        String sourceOption = parsed.value("--source");
        if (sourceOption != null && !"embedded".equals(sourceOption)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.sourceValue"));
        }
        Path jar = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        String currentId = setting(snap, CryptoSettings.KEY_ID);
        String currentSource = setting(snap, CryptoSettings.KEY_SOURCE);
        if (keyId.equals(currentId)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdConflict", currentId));
        // 예전에 쓴 키ID(이력의 이전·변경 후 값)도 새 키에 다시 쓸 수 없다. 같은 키ID가 다른 키를 가리키면 예전 암호문이
        // "키ID 불일치"가 아니라 무결성 오류로 실패해 원인을 구분할 수 없게 된다.
        if (snap.history.recordedValues(CryptoSettings.KEY_ID).contains(keyId)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdUsedBefore", keyId));
        }
        if (!"embedded".equals(currentSource) && sourceOption == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.notEmbedded", currentSource));
        }
        byte[] key = readKeyFile(keyFile);
        byte[] current = null;
        String encoded;
        String fingerprint;
        try {
            if (DefaultKeyWarning.isPublicDefaultKey(key)) throw new CryptoCli.CliException(Messages.get("cfg.err.publicKey"));
            try {
                current = KeyResolver.decodeKey(snap.settings.getProperty(CryptoSettings.KEY_EMBEDDED));
            } catch (IllegalArgumentException ignored) {
                current = null; // 현재 내장 키 형식이 깨져 있어도 새 키로 교체는 가능
            }
            if (current != null && Arrays.equals(current, key)) throw new CryptoCli.CliException(Messages.get("cfg.err.sameKey"));
            encoded = Base64.getEncoder().encodeToString(key);
            fingerprint = KeyResolver.fingerprint(key);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (current != null) Arrays.fill(current, (byte) 0);
        }
        Map<String, String> values = new LinkedHashMap<>();
        values.put(CryptoSettings.KEY_EMBEDDED, encoded);
        values.put(CryptoSettings.KEY_ID, keyId);
        if (!"embedded".equals(currentSource)) values.put(CryptoSettings.KEY_SOURCE, "embedded");

        Path output = outputJar(parsed, jar); // 확인 질문 전에 결과 경로 충돌을 안내한다
        printKeyImpact(out, Messages.get("cfg.impact.embed", JarConfigEditor.name(Paths.get(keyFile)), currentId, keyId,
                currentSource, fingerprint), true);
        if (!confirm(parsed, terminals, out)) return 0;
        JarConfigEditor.Change change = new JarConfigEditor.Change("embed-key", values, parsed.value("--operator"),
                parsed.value("--reason"));
        JarConfigEditor.Result result = JarConfigEditor.apply(jar, output, parsed.flag("--replace"),
                runningJar(), change, Instant.now());
        printResult(result, out);
        String newJar = result.output.toAbsolutePath().toString();
        out.println(Messages.get("cfg.next.title"));
        // 처음 적용하는 운영자는 기존 암호문이 없으므로 encrypt가 먼저다. 기존 암호문이 있을 때만 rekey를 쓴다.
        out.println(Messages.get("cfg.next.encrypt", newJar));
        out.println(Messages.get("cfg.next.rekey", newJar, (result.replaced ? result.backup : result.source).toAbsolutePath()));
        out.println(Messages.get("cfg.next.jndi"));
        out.println(Messages.get("cfg.next.restart"));
        out.println(Messages.get("cfg.next.protect"));
        return 0;
    }

    /** 키 파일을 읽는다. 문제는 KEY_SOURCE 사유로 알리며 경로 전체·키 내용은 메시지에 넣지 않는다. */
    private static byte[] readKeyFile(String keyFile) throws CredentialCryptoException {
        Path path;
        try {
            path = Paths.get(keyFile);
        } catch (InvalidPathException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, Messages.get("cfg.err.keyFilePath"));
        }
        try {
            return KeyResolver.readKeyFile(path, "--from-file");
        } catch (NoSuchFileException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("cfg.err.keyFileMissing", JarConfigEditor.name(path)));
        } catch (IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        } catch (IOException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("cfg.err.keyFileRead", JarConfigEditor.name(path)), e);
        }
    }

    // ===================================================================================================
    // 공통
    // ===================================================================================================

    /** 키 관련 변경의 기존 암호문 영향을 안내한다. */
    private static void printKeyImpact(PrintStream out, String what, boolean embed) {
        out.println(Messages.get("cfg.impact.title", what));
        out.println(Messages.get("cfg.impact.line1"));
        out.println(Messages.get("cfg.impact.line2"));
        out.println(Messages.get("cfg.impact.line3"));
        out.println(Messages.get("cfg.impact.line4"));
        if (embed) out.println(Messages.get("cfg.impact.line5"));
    }

    /** 확인 절차: --yes면 생략(무인 자동화), 아니면 대화형 터미널에서 CHANGE 입력을 받는다. */
    private static boolean confirm(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out)
            throws CryptoCli.CliException {
        if (parsed.flag("--yes")) {
            out.println(Messages.get("cfg.confirm.yes"));
            return true;
        }
        CryptoCli.Terminal terminal;
        try {
            terminal = terminals.open();
        } catch (CryptoCli.CliException e) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.confirmNeeded", CONFIRM_WORD, parsed.spec.name));
        }
        String answer = terminal.readLine(Messages.get("cfg.confirm.prompt", CONFIRM_WORD) + " ");
        if (answer == null || !CONFIRM_WORD.equals(answer.trim())) {
            out.println(Messages.get("cfg.confirm.cancel"));
            return false;
        }
        return true;
    }

    /** 결과를 출력한다: 어떤 파일이 바뀐 결과물인지, 원본·백업·복구 방법. */
    private static void printResult(JarConfigEditor.Result result, PrintStream out) {
        ConfigHistory.Entry last = result.after.history.last();
        String output = result.output.toAbsolutePath().toString();
        if (result.replaced) {
            String backup = result.backup.toAbsolutePath().toString();
            out.println(Messages.get("cfg.result.replaced"));
            out.println(Messages.get("cfg.result.target", output));
            out.println(Messages.get("cfg.result.backup", backup));
            out.println(Messages.get("cfg.result.restoreLinux", backup, output));
            out.println(Messages.get("cfg.result.restoreWindows", backup, output));
        } else {
            out.println(Messages.get("cfg.result.created"));
            out.println(Messages.get("cfg.result.original", result.source.toAbsolutePath()));
            out.println(Messages.get("cfg.result.output", output));
            out.println(Messages.get("cfg.result.useOutput"));
        }
        StringBuilder changes = new StringBuilder();
        for (String key : result.changedKeys) {
            if (changes.length() > 0) changes.append(", ");
            if (SettingCatalog.sensitiveKeys().contains(key)) {
                changes.append(key).append(' ').append(Messages.get("cfg.result.secret"));
            } else {
                changes.append(key).append(" (").append(display(result.before.get(key))).append(" -> ")
                        .append(display(result.after.settings.getProperty(key))).append(')');
            }
        }
        out.println(Messages.get("cfg.result.changes", changes));
        out.println(Messages.get("cfg.result.history", last.number, last.time, last.operator));
        out.println(Messages.get("cfg.result.check", output));
        out.println(Messages.get("cfg.result.deploy"));
        out.println(Messages.get("cfg.result.note"));
    }

    private static String display(String value) {
        if (value == null) return Messages.get("cfg.value.none");
        return value.trim().isEmpty() ? Messages.get("history.value.empty") : value.trim();
    }

    /** --out과 --replace는 함께 쓸 수 없다. */
    private static void checkOutputOptions(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        if (parsed.flag("--replace") && parsed.value("--out") != null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.outAndReplace"));
        }
    }

    /** 대상 JAR: --jar가 있으면 그 파일, 없으면 지금 실행 중인 JAR. */
    static Path sourceJar(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        String jar = parsed.value("--jar");
        if (jar != null) {
            try {
                return Paths.get(jar);
            } catch (InvalidPathException e) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.jarPath"));
            }
        }
        Path running = runningJar();
        if (running == null) throw new CryptoCli.CliException(Messages.get("cfg.err.noRunningJar"));
        return running;
    }

    /**
     * 결과 JAR: --out이 있으면 그 경로, 교체 모드면 null, 아니면 원본 옆의 기본 이름({@link #defaultOutputName}).
     * 기본 이름의 파일이 이미 있으면 덮어쓰지 않고 오류로 멈추며(기존 동작), 쓸 수 있는 다음 이름을 --out 예로 안내한다.
     */
    private static Path outputJar(CliCommands.Parsed parsed, Path source) throws CryptoCli.CliException {
        if (parsed.flag("--replace")) return null;
        String out = parsed.value("--out");
        if (out != null) {
            try {
                return Paths.get(out);
            } catch (InvalidPathException e) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.outPath"));
            }
        }
        Path parent = source.toAbsolutePath().getParent();
        Path target = parent.resolve(defaultOutputName(JarConfigEditor.name(source)));
        if (java.nio.file.Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.defaultOutExists",
                    JarConfigEditor.name(target), nextFreeName(parent, JarConfigEditor.name(target))));
        }
        return target;
    }

    /** "-configured" 또는 "-configured-숫자"로 끝나는 이름(대소문자 무시). 그룹 1: 앞부분, 그룹 2: 순번. */
    private static final java.util.regex.Pattern CONFIGURED_STEM =
            java.util.regex.Pattern.compile("(?i)(.+)-configured(?:-(\\d{1,6}))?");

    /**
     * 기본 결과 JAR 이름. 처음 바꾸는 JAR는 {@code <이름>-configured.jar}, 이미 바꾼 JAR는 접미사를 겹치지 않고 순번을 올린다
     * ({@code x-configured.jar → x-configured-2.jar → x-configured-3.jar}).
     *
     * @param fileName 원본 JAR 파일 이름
     * @return 원본 옆에 만들 결과 파일 이름
     */
    static String defaultOutputName(String fileName) {
        String stem = fileName.toLowerCase(java.util.Locale.ROOT).endsWith(".jar")
                ? fileName.substring(0, fileName.length() - 4) : fileName;
        java.util.regex.Matcher m = CONFIGURED_STEM.matcher(stem);
        if (!m.matches()) return stem + DEFAULT_SUFFIX;
        long next = m.group(2) == null ? 2 : Long.parseLong(m.group(2)) + 1;
        return m.group(1) + "-configured-" + next + ".jar";
    }

    /** 안내용: 같은 폴더에서 아직 없는 다음 순번 이름(찾지 못하면 기본 형식의 예). */
    private static String nextFreeName(Path parent, String taken) {
        String candidate = taken;
        for (int i = 0; i < 100; i++) {
            candidate = defaultOutputName(candidate);
            if (!java.nio.file.Files.exists(parent.resolve(candidate), java.nio.file.LinkOption.NOFOLLOW_LINKS)) return candidate;
        }
        return candidate;
    }

    /** @return 지금 실행 중인 JAR 파일(클래스 폴더에서 실행 중이면 null) */
    static Path runningJar() {
        try {
            CodeSource code = ConfigCommand.class.getProtectionDomain().getCodeSource();
            if (code == null || code.getLocation() == null) return null;
            Path path = Paths.get(code.getLocation().toURI());
            return java.nio.file.Files.isRegularFile(path) ? path : null;
        } catch (URISyntaxException | IllegalArgumentException | SecurityException | java.nio.file.FileSystemNotFoundException e) {
            return null;
        }
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }
}
