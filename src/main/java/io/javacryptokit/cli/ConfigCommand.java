package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: {@code config show / history / set / embed-key}의 확인 절차·출력을 맡는다. JAR 읽기·쓰기·검증은
 * {@link JarConfigEditor}, 이력은 {@link ConfigHistory}, 키 목록 변경({@code config key add|use|remove})은 {@link KeyringCommand}가
 * 한다.
 *
 * <p><b>역할 구분</b>: {@code config show}는 JAR 파일 안의 현재 설정값과 최종 변경 요약, {@code config history}는 최초 변경부터
 * 전체 변경 내역을 보여 준다. 둘 다 외부 Properties·JVM {@code -D}·환경변수를 읽지 않는다(설정 로더를 거치지 않으므로 잘못된
 * 외부 설정이 있어도 동작). 실행 시 최종 적용값은 {@code info}, 실제 동작 점검은 {@code doctor}가 맡는다.</p>
 *
 * <p><b>확인 절차</b>: 실제로 키를 바꾸는 변경(AES 키 교체, 키 추가·제거·기본 키 변경, 키에 영향을 주는 {@code config set})은 새 JAR를
 * 만들 때도 원본을 교체할 때도 대화형 확인({@code CHANGE}) 또는 {@code --yes}를 요구한다. 키와 무관한 {@code config set}은 확인하지
 * 않는다. 취소·실패하면 원본은 그대로다(백업·잠금·원자적 교체·결과 재검증은 그대로).</p>
 *
 * <p><b>보안</b>: 내장 키 값은 출력하지 않는다(짧은 키 지문만). 키 원문은 명령행 인자로 받지 않고 키 파일로만 받는다. 수정자 ID는
 * 기록용 식별자다.</p>
 */
final class ConfigCommand {
    /** 원본 JAR의 키 관련 설정을 그 자리에서 바꿀 때(--replace) 사용자가 직접 입력해야 하는 확인 문구(번역하지 않음). */
    static final String CONFIRM_WORD = "CHANGE";
    /** 확인 질문에서 바뀌는 설정 한 줄의 들여쓰기. */
    private static final String CONFIRM_INDENT = "  ";
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
                return show(parsed, out);
            case "config history":
                return history(parsed, out);
            case "config set":
                return set(parsed, terminals, out);
            case "config embed-key":
                return embedKey(parsed, terminals, out);
            default:
                return KeyringCommand.run(parsed, terminals, out);
        }
    }

    // ===================================================================================================
    // config show
    // ===================================================================================================

    /**
     * config show: 관리자 인증 뒤 JAR 파일 안의 상태(파일·버전·이력 상태·관리자 비밀번호 상태·빌드 일시·키 목록·설정 파일 지문·설정
     * 검증)를 한 번, 이어서 내장 설정값 전체를 한 번만 보여 준다. 키 목록은 키마다 전체 지문(64자), pass는 KDF·반복 횟수·Salt·Salt
     * SHA-256까지 마스킹 없이 보여 준다(키 원문은 보여 주지 않음: {@code config key show --show}). 외부 Properties·-D·환경변수는
     * 반영하지 않는다(실행 시 적용값은 info).
     *
     * <p>이력·관리자 검증값이 손상된 JAR는 {@link CryptoCli}가 인증 전에 거부하므로(INTEGRITY, 원인 안내) 관리정보를 보여 주지 않는다.
     * 아래의 이력 손상 표시는 그 판단이 바뀌어도 손상된 이력을 정상처럼 보이지 않게 남긴 방어 코드다.</p>
     *
     * @return 0: 정상, 1: 설정 검증 실패 또는 이력 손상
     */
    private static int show(CliCommands.Parsed parsed, PrintStream out) throws CryptoCli.CliException {
        Path jar = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        ConfigHistory.Log log = snap.history;
        out.println(Messages.get("cfg.show.title"));
        out.println(Messages.get("cfg.show.file", JarConfigEditor.name(jar), orDefault(snap.version, "-"),
                snap.signed ? Messages.get("cfg.show.signed") : ""));
        if (log.problem != null) {
            out.println(Messages.get("cfg.show.state.invalid", log.problem));
        } else if (!log.present) {
            out.println(Messages.get("cfg.show.state.initial"));
        } else {
            ConfigHistory.Entry last = log.last();
            out.println(Messages.get("cfg.show.state.changed", log.entries.size(), last.time, last.operator));
        }
        out.println(Messages.get("cfg.show.admin", Messages.get("cfg.show.admin."
                + AdminPassword.statusOf(snap).state.name().toLowerCase(java.util.Locale.ROOT))));
        out.println(Messages.get("cfg.show.buildTime", orDefault(snap.buildTime, Messages.get("cfg.value.unknown"))));
        printKeyring(snap, out);
        // 설정 파일 지문은 JAR 내부 설정 파일 내용의 식별값이다(키 지문과 다름).
        out.println(Messages.get("cfg.show.fingerprint", ConfigHistory.fingerprint(snap.settingsBytes)));
        out.println(Messages.get("cfg.show.validation", snap.validationError == null ? Messages.get("cfg.ok")
                : Messages.get("cfg.show.validationError", snap.validationError)));
        out.println();
        for (String key : keysInFileOrder(snap)) {
            String value = snap.settings.getProperty(key).trim();
            String shown = SettingCatalog.isSensitive(key) ? Messages.get("cfg.value.hidden")
                    : (value.isEmpty() ? Messages.get("history.value.empty") : value);
            out.println(key + " = " + shown);
        }
        return snap.validationError == null && log.problem == null ? 0 : 1;
    }

    // ===================================================================================================
    // config history
    // ===================================================================================================

    /**
     * config history: 관리자 인증 뒤 이력 전체를 검증하고(해시 체인·설정 지문, 걸러 보더라도 전체를 확인) 고른 범위만 보여 준다. 기본은
     * pass 관련 변경, {@code --type key}는 key 관련, {@code --all}은 키와 무관한 설정·관리자 비밀번호 기록까지 전체다. 순번은 원래
     * 번호를 그대로 쓴다. 기록된 관리정보(전체 지문·KDF·반복 횟수·Salt·Salt SHA-256·작업자·사유)는 마스킹 없이 보여 주고, 기록에
     * 없는 값(이전 형식의 Salt 줄 등)은 "기록 없음"으로 구분한다. 키 원문·관리자 비밀번호는 이력에 없다.
     */
    /** config history 사전 검사(관리자 인증 전): {@code --all}과 {@code --type}을 함께 쓰지 않았는지, 유형 값. */
    static void checkHistory(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        if (parsed.flag("--all") && parsed.value("--type") != null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.historyTypeAll"));
        }
        CryptoCli.typeOption(parsed);
    }

    private static int history(CliCommands.Parsed parsed, PrintStream out) throws CryptoCli.CliException {
        io.javacryptokit.KeyType type = CryptoCli.typeOption(parsed);
        String scope = parsed.flag("--all") ? null : (type == null ? ConfigHistory.TYPE_PASS : type.code());
        Path jar = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        ConfigHistory.Log log = snap.history;
        if (log.problem != null) {
            // 방어 코드: 손상·변조가 의심되는 이력은 정상 이력처럼 보여 주지 않는다(보통은 CryptoCli가 인증 전에 거부한다).
            throw new CryptoCli.CliException("INTEGRITY", Messages.get("cfg.history.invalid", log.problem));
        }
        out.println(Messages.get("cfg.history.title", JarConfigEditor.name(jar), orDefault(snap.version, "-")));
        out.println(Messages.get("cfg.show.buildTime", orDefault(snap.buildTime, Messages.get("cfg.value.unknown"))));
        if (!log.present) {
            out.println(Messages.get("cfg.history.none"));
            return 0;
        }
        out.println(Messages.get("cfg.history.verified", log.entries.size()));
        List<java.util.Set<String>> types = ConfigHistory.classify(log.entries);
        int shown = 0;
        for (java.util.Set<String> entryTypes : types) if (scope == null || entryTypes.contains(scope)) shown++;
        out.println(scope == null ? Messages.get("cfg.history.scopeAll", log.entries.size())
                : Messages.get("cfg.history.scope", scope, shown, log.entries.size()));
        for (int i = 0; i < log.entries.size(); i++) {
            if (scope != null && !types.get(i).contains(scope)) continue;
            ConfigHistory.Entry entry = log.entries.get(i);
            out.println();
            out.println(Messages.get("cfg.history.entry", entry.number, entry.time, entry.operator,
                    ConfigHistory.commandLabel(entry.command), typeTags(types.get(i))));
            if (!entry.reason.isEmpty()) out.println(Messages.get("cfg.history.reason", entry.reason));
            for (ConfigHistory.Change change : entry.changes) printHistoryChange(out, change);
        }
        return 0;
    }

    /** @return 이력 항목의 유형 꼬리표(예: {@code pass}, {@code pass, key}, {@code 일반}, {@code 관리자}) */
    private static String typeTags(java.util.Set<String> types) {
        List<String> tags = new ArrayList<>();
        for (String type : types) {
            if (ConfigHistory.TYPE_GENERAL.equals(type)) {
                tags.add(Messages.get("cfg.history.general"));
            } else if (ConfigHistory.TYPE_ADMIN.equals(type)) {
                tags.add(Messages.get("cfg.history.admin"));
            } else {
                tags.add(type);
            }
        }
        return String.join(", ", tags);
    }

    /**
     * 이력의 바뀐 항목 한 개: {@code    이름: 이전 -> 변경}. 80열을 넘으면 {@code ->} 앞에서 줄을 바꾸고, 이름과 이전 값만으로도 넘으면
     * 이름 다음에서도 바꾼다(값은 자르지 않음). 키 요약 기록은 {@code 키 <ID>}로 쓰고 유형·공급원·출처 요약 다음 줄에 기록된
     * 관리정보(전체 지문·KDF·반복 횟수·Salt SHA-256)를 그대로 보여 준다. 관리자 기록은 {@code 관리자 비밀번호: (없음) -> (설정됨)}처럼
     * 고정 표시만 보여 준다(비밀번호·검증값은 이력에 없음). 이전 형식의 Salt 줄처럼 값이 기록되지 않은 항목은 "기록 없음"으로 구분한다.
     */
    private static void printHistoryChange(PrintStream out, ConfigHistory.Change change) {
        boolean record = change.key.startsWith(ConfigHistory.KEY_SUMMARY_PREFIX);
        boolean admin = ConfigHistory.ADMIN_SUMMARY.equals(change.key);
        boolean salt = SettingCatalog.isSaltSetting(change.key);
        String label;
        if (record) {
            label = Messages.get("cfg.history.key", change.key.substring(ConfigHistory.KEY_SUMMARY_PREFIX.length()));
        } else if (admin) {
            label = Messages.get("cfg.history.adminPassword");
        } else {
            label = change.key;
        }
        String before = record ? KeyringView.displayRecord(change.before) : historyValue(change.before, admin, salt);
        String after = record ? KeyringView.displayRecord(change.after) : historyValue(change.after, admin, salt);
        String lead = "    " + label + ": ";
        if (CliHelp.width(lead + before) <= CliHelp.LINE_WIDTH) {
            out.println(lead + CliHelp.arrow(lead, before, after, "      "));
        } else {
            out.println("    " + label + ":");
            out.println("      " + CliHelp.arrow("      ", before, after, "      "));
        }
        if (record) {
            // 추가·교체 기록은 변경 후 값, 제거 기록은 이전 값이 그 키의 기록이다.
            ConfigHistory.KeyRecord detail = ConfigHistory.KeyRecord.parse(ConfigHistory.ABSENT.equals(change.after)
                    ? change.before : change.after);
            if (detail != null) for (String line : KeyringView.recordDetails(detail, "      ")) out.println(line);
        }
    }

    /** 이력 값 표시: 관리자 기록과 이전 형식 Salt 줄의 고정 표시는 뜻에 맞는 말로, 그 밖은 {@link ConfigHistory#display}. */
    private static String historyValue(String value, boolean admin, boolean salt) {
        if (admin) {
            if (ConfigHistory.SECRET_BEFORE.equals(value)) return Messages.get("history.value.adminSet");
            if (ConfigHistory.SECRET_AFTER.equals(value)) return Messages.get("history.value.adminChanged");
        }
        if (salt && (ConfigHistory.SECRET_BEFORE.equals(value) || ConfigHistory.SECRET_AFTER.equals(value))) {
            return Messages.get("history.value.notRecorded");
        }
        return ConfigHistory.display(value);
    }

    /**
     * JAR 안의 키 목록: 기본 유형, 유형별 기본 키, 키마다 유형·공급원·상태(공개 기본 키/사용자 지정, 외부 키) 한 줄과 그 아래 전체 지문,
     * pass는 KDF·반복 횟수·Salt·Salt SHA-256. 외부 키는 읽지 않는다(고정 지문이 있으면 그 값, 실제 적용 키는 info·fingerprint).
     * 키 원문은 출력하지 않는다.
     */
    private static void printKeyring(JarConfigEditor.Snapshot snap, PrintStream out) {
        CryptoSettings settings = snap.validated();
        if (settings == null) {
            out.println(Messages.get("cfg.show.keysInvalid"));
            return;
        }
        out.println(Messages.get("cfg.show.keyType", settings.defaultType().code()));
        out.println(Messages.get("cfg.show.active", KeyringView.actives(settings)));
        // 키 목록: 머리줄 아래 키마다 요약 한 줄(2칸 들여쓰기)과 관리정보 줄(4칸). 80열을 넘으면 키 ID·항목 이름 다음에서만 줄을
        // 바꾼다(값은 자르지 않음).
        out.println(Messages.get("cfg.show.keys"));
        for (KeyProfile profile : settings.profiles()) {
            out.println("  " + KeyringView.wrapAfter("  ", profile.id() + ":", KeyringView.jarSummary(settings, profile), "    "));
            for (String line : KeyringView.profileDetails(profile, "    ")) out.println(line);
        }
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

    /**
     * config set 사전 검사(관리자 인증 전): 바꿀 항목·결과 옵션·작업자·사유 형식, 내장 키·키 정체 항목을 바꾸려 하지 않는지, 결과 파일이
     * 이미 있지 않은지(JAR 내용은 읽지 않음).
     */
    static void checkSet(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        if (parsed.settings.isEmpty()) throw new CryptoCli.CliException(Messages.get("cfg.err.setNone"));
        checkOutputOptions(parsed);
        JarConfigEditor.checkOperator(parsed.value("--operator"));
        JarConfigEditor.checkReason(parsed.value("--reason"));
        if (parsed.settings.containsKey(CryptoSettings.KEY_EMBEDDED)) {
            throw new CryptoCli.CliException(Messages.get("jar.err.sensitiveSet", CryptoSettings.KEY_EMBEDDED));
        }
        for (String key : parsed.settings.keySet()) {
            // 키 프로필의 정체 항목(유형·공급원·내장 값·KDF·Salt·고정 지문)을 바꾸면 같은 Key ID가 다른 키가 된다. 위치 항목만 바꿀 수 있다.
            String[] profile = SettingCatalog.parseProfileName(key);
            SettingCatalog.ProfileItem item = profile == null ? null : SettingCatalog.profileItem(profile[1]);
            if (item != null && !item.location) throw new CryptoCli.CliException(Messages.get("cfg.err.profileIdentitySet", key));
        }
        outputJar(parsed, sourceJar(parsed));
    }

    private static int set(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        String reason = parsed.value("--reason");
        Path source = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(source);
        // 결과 경로(사전 검사에서 확인)는 확인 질문 전에 정한다.
        Path output = outputJar(parsed, source);
        // 키에 영향을 주는 설정을 실제로 바꾸면(새 JAR 생성 포함) 확인한다. 키와 무관한 설정은 묻지 않는다.
        List<String> keyChanges = new ArrayList<>();
        for (Map.Entry<String, String> item : parsed.settings.entrySet()) {
            String current = snap.settings.getProperty(item.getKey());
            if (SettingCatalog.isKeyAffecting(item.getKey()) && current != null && !current.trim().equals(item.getValue())) {
                keyChanges.add(change(item.getKey(), current, item.getValue()));
            }
        }
        // (관리자 인증 뒤) 키에 영향을 주는 변경이면 사유 → 바꿀 내용 → CHANGE 확인 순서. 키와 무관한 설정은 사유를 선택으로 둔다.
        if (!keyChanges.isEmpty()) reason = CryptoCli.reasonOption(parsed, terminals);
        if (!keyChanges.isEmpty() && !confirm(parsed, terminals, out, Messages.get("cfg.confirm.set"), output, keyChanges,
                reason)) {
            return 0;
        }
        // 키 공급 방식만 바꾸고 경로는 실행 시 -D·외부 Properties로 주는 구성도 정상이므로 막지 않는다(실행 시 없으면 Fail Closed).
        JarConfigEditor.Change change = new JarConfigEditor.Change("set", parsed.settings, parsed.value("--operator"), reason);
        JarConfigEditor.Result result = JarConfigEditor.apply(source, output, parsed.flag("--replace"),
                runningJar(), change, Instant.now());
        printResult(result, out);
        return 0;
    }

    // ===================================================================================================
    // config embed-key
    // ===================================================================================================

    /**
     * config embed-key 사전 검사(관리자 인증 전): 키 파일·Key ID 지정과 형식, 결과 옵션·작업자, {@code --source} 값, 결과 파일이 이미
     * 있지 않은지(JAR 내용·키 파일은 읽지 않음).
     */
    static void checkEmbedKey(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        String keyId = parsed.value("--key-id");
        if (parsed.value("--from-file") == null || keyId == null) throw new CryptoCli.CliException(Messages.get("cfg.err.embedNeeds"));
        checkOutputOptions(parsed);
        JarConfigEditor.checkOperator(parsed.value("--operator"));
        if (!keyId.matches("[A-Za-z0-9_-]{1,64}")) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdFormat"));
        String sourceOption = parsed.value("--source");
        if (sourceOption != null && !"embedded".equals(sourceOption)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.sourceValue"));
        }
        outputJar(parsed, sourceJar(parsed));
    }

    private static int embedKey(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out)
            throws Exception {
        String keyFile = parsed.value("--from-file");
        String keyId = parsed.value("--key-id");
        String sourceOption = parsed.value("--source");
        Path jar = sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        // 키 목록을 지원하는 JAR는 이전 AES 키를 같은 Key ID의 키 프로필로 남긴다(다른 유형·다른 Key ID 보존). 이전 버전 JAR는 그
        // 형식을 모르므로 이전 형식와 같이 crypto.key.*만 바꾼다(기존 암호문은 rekey 필요).
        boolean keyring = KeyringCommand.supportsKeyring(snap);
        CryptoSettings settings = keyring ? KeyringCommand.validated(snap) : null;
        String currentId = setting(snap, CryptoSettings.KEY_ID);
        String currentSource = setting(snap, CryptoSettings.KEY_SOURCE);
        if (keyId.equals(currentId)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdConflict", currentId));
        // 예전에 쓴 키ID(이력의 이전·변경 후 값)는 같은 키를 되살릴 때만(이력의 기록과 전체 지문·유형이 같을 때) 다시 쓸 수 있다.
        // 같은 키ID가 다른 키를 가리키면 예전 암호문이 "키ID 불일치"가 아니라 무결성 오류로 실패해 원인을 구분할 수 없게 된다.
        if (keyring) KeyringCommand.checkNewKeyId(keyId, settings, snap, true);
        if (!"embedded".equals(currentSource) && sourceOption == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.notEmbedded", currentSource));
        }
        // 키 파일은 관리자 인증 뒤에만 읽는다(인증 → 사유 → 바꿀 내용 → CHANGE).
        byte[] key = readKeyFile(keyFile);
        byte[] current = null;
        String encoded;
        String fingerprint;
        try {
            if (DefaultKeyWarning.isPublicDefaultKey(key)) throw new CryptoCli.CliException(Messages.get("cfg.err.publicKey"));
            try {
                current = KeyResolver.decodeEmbedded(snap.settings.getProperty(CryptoSettings.KEY_EMBEDDED));
            } catch (IllegalArgumentException ignored) {
                current = null; // 현재 내장 키 형식이 깨져 있어도 새 키로 교체는 가능
            }
            if (current != null && Arrays.equals(current, key)) throw new CryptoCli.CliException(Messages.get("cfg.err.sameKey"));
            encoded = KeyResolver.encodeEmbedded(key);
            fingerprint = KeyResolver.fingerprint(key);
        } finally {
            Arrays.fill(key, (byte) 0);
            if (current != null) Arrays.fill(current, (byte) 0);
        }
        ConfigHistory.KeyRecord newSlot = KeyringView.record(io.javacryptokit.KeyType.KEY, "embedded", "file", fingerprint, null,
                false, true);
        boolean restored = KeyringCommand.checkRestore(keyId, newSlot, snap);
        if (keyring) KeyringCommand.checkNotRegistered(settings, fingerprint);
        Path output = outputJar(parsed, jar); // 확인 질문·외부 키 읽기 전에 결과 경로 충돌을 알린다
        // 사유: 입력 없이 할 수 있는 검사를 마친 뒤, 이전 키 읽기·바꿀 내용·CHANGE 확인보다 먼저 받는다.
        String reason = CryptoCli.reasonOption(parsed, terminals);
        Map<String, String> values = new LinkedHashMap<>();
        values.put(CryptoSettings.KEY_EMBEDDED, encoded);
        values.put(CryptoSettings.KEY_ID, keyId);
        if (!"embedded".equals(currentSource)) values.put(CryptoSettings.KEY_SOURCE, "embedded");
        List<ConfigHistory.Change> summaries = new ArrayList<>();
        String notPreserved = null;
        if (keyring) {
            Map<String, String> preserved = KeyringCommand.preservedSlot(settings);
            KeyProfile slot = settings.legacyProfile();
            ConfigHistory.KeyRecord oldSlot = KeyringView.record(slot, null);
            String movedFingerprint = preserved.get(KeyProfile.PREFIX + currentId + "." + KeyProfile.FINGERPRINT);
            String fingerprintBefore = oldSlot.fingerprint != null ? oldSlot.fingerprint : movedFingerprint;
            // 이전 값: 이력에 남은 이 키의 마지막 기록을 그대로(없으면 지금 슬롯의 정보로 만든 기록).
            String recorded = snap.history.lastAfter(ConfigHistory.KEY_SUMMARY_PREFIX + currentId);
            String before = recorded != null ? recorded : new ConfigHistory.KeyRecord(oldSlot.type, oldSlot.source, null,
                    fingerprintBefore, null, null, null, oldSlot.publicKey, true).format();
            if (preserved.isEmpty()) {
                // 이전 외부 키를 지금 읽을 수 없어 키 목록에 남기지 못한다(이전 형식와 같이 그 키의 암호문은 rekey). 확인·결과에 보여 준다.
                notPreserved = Messages.get("cfg.embed.notPreserved", currentId, currentSource);
                summaries.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + currentId, before, ConfigHistory.ABSENT));
            } else {
                // 이전 키는 같은 Key ID로 키 목록에 옮긴다(전후 지문이 같다: 같은 키).
                ConfigHistory.KeyRecord moved = new ConfigHistory.KeyRecord(oldSlot.type, oldSlot.source, "moved",
                        fingerprintBefore, null, null, null, oldSlot.publicKey, false);
                summaries.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + currentId, before, moved.format()));
            }
            values.putAll(preserved);
            summaries.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + keyId, ConfigHistory.ABSENT,
                    KeyringView.record(io.javacryptokit.KeyType.KEY, "embedded", restored ? "restored" : "file", fingerprint, null,
                            false, true).format()));
        }

        // 실제 키 변경이므로 새 JAR를 만들 때도 확인한다(--yes면 묻지 않음).
        List<String> items = new ArrayList<>();
        for (Map.Entry<String, String> item : values.entrySet()) {
            items.add(change(item.getKey(), snap.settings.getProperty(item.getKey()), item.getValue()));
        }
        if (notPreserved != null) items.add(notPreserved);
        // 확인 제목은 기존 암호문에 주는 영향: 이전 키가 키 목록에 남으면 그대로, 남길 수 없으면(이전 버전 JAR, 지금 읽을 수 없는
        // 외부 키) rekey 필요.
        String header = keyring && notPreserved == null ? "cfg.confirm.embed" : "cfg.confirm.embedLegacy";
        if (!confirm(parsed, terminals, out, Messages.get(header), output, items, reason)) {
            return 0;
        }
        JarConfigEditor.Change change = new JarConfigEditor.Change("embed-key", values, java.util.Collections.<String>emptySet(),
                summaries, parsed.value("--operator"), reason);
        JarConfigEditor.Result result = JarConfigEditor.apply(jar, output, parsed.flag("--replace"),
                runningJar(), change, Instant.now());
        printResult(result, out);
        out.println(Messages.get("cfg.result.fingerprint", KeyResolver.shortFingerprint(fingerprint)));
        if (restored) out.println(Messages.get("cfg.result.restoredHistory"));
        if (notPreserved != null) out.println(notPreserved);
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

    /**
     * 키 변경 확인: {@code --yes}면 묻지 않고(무인 자동화), 아니면 바꿀 내용(제목 한 줄, 결과 JAR 한 줄, 사유 한 줄, 바뀌는 설정을
     * 한 줄에 하나씩)을 보여 준 뒤 대화형 터미널에서 {@code CHANGE} 입력을 받는다. 대화형 터미널이 아니고 {@code --yes}도 없으면
     * 아무것도 바꾸지 않고 실패한다.
     *
     * @param header 제목(무엇을 바꾸는지와 기존 암호문 영향)
     * @param output 결과 JAR(원본 교체면 null)
     * @param items  바뀌는 설정({@link #change} 결과)
     * @param reason 이번 변경의 사유
     * @return 진행하면 true, 취소하면 false
     */
    static boolean confirm(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out,
                           String header, Path output, List<String> items, String reason) throws CryptoCli.CliException {
        if (parsed.flag("--yes")) return true;
        CryptoCli.Terminal terminal;
        try {
            terminal = terminals.open();
        } catch (CryptoCli.CliException e) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.confirmNeeded", CONFIRM_WORD, parsed.spec.name));
        }
        terminal.println(header);
        terminal.println(CONFIRM_INDENT + (output == null ? Messages.get("cfg.confirm.replace")
                : Messages.get("cfg.confirm.newJar", JarConfigEditor.name(output))));
        if (reason != null) terminal.println(CONFIRM_INDENT + Messages.get("cfg.confirm.reason", reason));
        for (String item : items) terminal.println(CONFIRM_INDENT + item);
        String answer = terminal.readLine(Messages.get("cfg.confirm.prompt", CONFIRM_WORD) + " ");
        if (answer == null || !CONFIRM_WORD.equals(answer.trim())) {
            out.println(Messages.get("cfg.confirm.cancel"));
            return false;
        }
        return true;
    }

    /** 결과를 출력한다: 만든(또는 교체한) JAR, 백업(교체 시), 변경 항목(한 줄에 하나씩, 값 열에 맞춤). */
    static void printResult(JarConfigEditor.Result result, PrintStream out) {
        Path output = result.output.toAbsolutePath();
        if (result.replaced) {
            out.println(Messages.get("cfg.result.replaced", output));
            out.println(Messages.get("cfg.result.backup", result.backup.toAbsolutePath()));
        } else {
            out.println(Messages.get("cfg.result.created", output));
            if (JarConfigEditor.posix()) out.println(Messages.get("cfg.result.permission"));
        }
        String prefix = Messages.get("cfg.result.changes", "");
        String indent = CliHelp.spaces(CliHelp.width(prefix));
        List<String> items = new ArrayList<>();
        for (String key : result.changedKeys) {
            items.add(change(indent, key, result.before.get(key), result.after.settings.getProperty(key)));
        }
        if (items.isEmpty()) items.add(Messages.get("cfg.value.none"));
        CliHelp.printItems(out, prefix, items);
    }

    /** 확인 질문의 항목 한 줄(앞 들여쓰기 2칸 기준). */
    static String change(String key, String before, String after) {
        return change(CONFIRM_INDENT, key, before, after);
    }

    /**
     * 바뀌는 설정 한 항목: 비밀 항목은 {@code 이름 (비공개)}만, 그 밖은 {@code 이름 (이전 -> 변경)}. 줄 앞부분(lead)과 합쳐 80열을
     * 넘으면 {@code ->} 앞에서 줄을 바꾸고, 이름과 이전 값만으로도 넘으면 이름 다음에서도 바꾼다. 이어지는 줄은 2칸 더 들여 쓰며
     * 값 자체는 자르지 않는다.
     */
    private static String change(String lead, String key, String before, String after) {
        if (SettingCatalog.isSensitive(key)) return key + " " + Messages.get("cfg.result.secret");
        String next = lead + "  ";
        String head = key + " (" + display(before);
        String tail = display(after) + ")";
        if (CliHelp.width(lead + head) <= CliHelp.LINE_WIDTH) return CliHelp.arrow(lead, head, tail, next);
        return key + System.lineSeparator() + next + CliHelp.arrow(next, "(" + display(before), tail, next);
    }

    private static String display(String value) {
        if (value == null) return Messages.get("cfg.value.none");
        return value.trim().isEmpty() ? Messages.get("history.value.empty") : value.trim();
    }

    /** --out과 --replace는 함께 쓸 수 없다. */
    static void checkOutputOptions(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        if (parsed.flag("--replace") && parsed.value("--out") != null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.outAndReplace"));
        }
    }

    /** 대상 JAR: --jar가 있으면 그 파일, 없으면 지금 실행 중인 CLI JAR(관리자 확인 창구가 아는 JAR). */
    static Path sourceJar(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        String jar = parsed.value("--jar");
        if (jar != null) {
            try {
                return Paths.get(jar);
            } catch (InvalidPathException e) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.jarPath"));
            }
        }
        Path running = parsed.admin != null && parsed.admin.cliJar() != null ? parsed.admin.cliJar() : runningJar();
        if (running == null) throw new CryptoCli.CliException(Messages.get("cfg.err.noRunningJar"));
        return running;
    }

    /**
     * 결과 JAR: --out이 있으면 그 경로, 교체 모드면 null, 아니면 원본 옆의 기본 이름({@link #defaultOutputName}).
     * 기본 이름의 파일이 이미 있으면 덮어쓰지 않고 오류로 멈추며(기존 동작), 쓸 수 있는 다음 이름을 --out 예로 안내한다.
     */
    static Path outputJar(CliCommands.Parsed parsed, Path source) throws CryptoCli.CliException {
        if (parsed.flag("--replace")) return null;
        String out = parsed.value("--out");
        if (out != null) {
            try {
                return Paths.get(out);
            } catch (InvalidPathException e) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.outPath"));
            }
        }
        return defaultOutputJar(source);
    }

    /**
     * 원본 옆의 기본 결과 JAR({@link #defaultOutputName}). 이미 있으면 덮어쓰지 않고 오류로 멈추며 쓸 수 있는 다음 이름을 --out 예로
     * 안내한다.
     */
    static Path defaultOutputJar(Path source) throws CryptoCli.CliException {
        Path parent = source.toAbsolutePath().getParent();
        Path target = parent.resolve(defaultOutputName(source.getFileName().toString()));
        if (java.nio.file.Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.defaultOutExists",
                    JarConfigEditor.name(target), JarConfigEditor.name(parent.resolve(nextFreeName(parent, target.getFileName().toString())))));
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
