package io.javacryptokit.cli;

import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: JAR 내부 설정의 <b>전체 변경 이력</b>({@value #ENTRY})을 만들고 검증한다. {@code config set}·
 * {@code config embed-key}가 성공한 변경만 기록하고, {@code config history}가 처음부터 끝까지 보여 준다.
 *
 * <p><b>기록 내용</b>(변경 1건 = 항목 1개, 개수 제한 없음, 새 JAR·{@code --replace}에서도 이전 기록을 모두 옮긴다)</p>
 * <ul>
 *   <li>순번, UTC 수정 시각(초 단위 ISO 8601), 수정자({@code --operator}), 명령(set/embed-key), 사유(선택)</li>
 *   <li>바꾼 설정마다 이름·이전 값·변경 후 값. 비밀 항목({@code crypto.key.embedded})은 값 대신 고정 표시만 남긴다
 *       ({@value #SECRET_BEFORE} → {@value #SECRET_AFTER}, 즉 "키를 교체했다"는 사실과 함께 바뀐 키ID만 보인다).</li>
 *   <li>변경 후 전체 설정의 지문(SHA-256 앞 16자)과 이전 항목에 이어지는 해시(체인)</li>
 * </ul>
 *
 * <p><b>손상·변조 의심 검사</b>: 순번 연속성, 항목 형식, 해시 체인, 마지막 항목의 설정 지문 = 현재 JAR 설정, 빌드 때 Manifest에
 * 기록한 기본 설정 지문({@code Settings-Fingerprint}) = 이력의 시작점, 이전 값 = 직전 변경 후 값을 확인한다. 하나라도 어긋나면
 * 정상 이력으로 보여 주지 않고 오류로 처리한다. 이력이 없는데 설정이 빌드 때와 다르면(이력 없이 수정됨) 역시 오류다.</p>
 *
 * <p><b>한계</b>: 이 검사는 실수·손상·단순 수정 탐지용이다. 해시에는 비밀 키가 없으므로 JAR를 고칠 수 있는 사람은 이력을 다시
 * 계산해 꾸밀 수 있다. 위변조 방지 감사 로그가 아니며, 수정자 ID는 기록용(본인 인증 아님)이다. 실제 통제는 파일 권한과
 * 배포 승인 절차로 한다.</p>
 */
final class ConfigHistory {
    /** JAR 안의 이력 리소스 이름(최초 빌드 상태의 JAR에는 없다). */
    static final String ENTRY = "META-INF/java-crypto-kit/config-history.properties";
    /** 이력 형식 버전. */
    static final String FORMAT = "1";
    /** 비밀 항목의 이전 값 표시. */
    static final String SECRET_BEFORE = "[secret]";
    /** 비밀 항목의 변경 후 값 표시. */
    static final String SECRET_AFTER = "[replaced]";
    /** 이력 파일 최대 크기(바이트). */
    static final int MAX_BYTES = 1024 * 1024;
    /** Manifest의 빌드 시각 속성. */
    static final String BUILD_TIME = "Build-Time";
    /** Manifest의 기본 설정 지문 속성. */
    static final String SETTINGS_FINGERPRINT = "Settings-Fingerprint";
    /** 수정자 ID 형식(문자·숫자와 . _ @ -, 1~64자). */
    static final Pattern OPERATOR = Pattern.compile("[\\p{L}\\p{N}._@-]{1,64}");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]{1,80}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");

    private ConfigHistory() { }

    /** 바꾼 설정 하나. */
    static final class Change {
        final String key;
        final String before;
        final String after;

        Change(String key, String before, String after) {
            this.key = key;
            this.before = before;
            this.after = after;
        }
    }

    /** 이력 항목 하나. */
    static final class Entry {
        final int number;
        final String time;
        final String operator;
        final String command;
        final String reason;
        final List<Change> changes;
        final String settings;
        final String hash;

        Entry(int number, String time, String operator, String command, String reason, List<Change> changes,
              String settings, String hash) {
            this.number = number;
            this.time = time;
            this.operator = operator;
            this.command = command;
            this.reason = reason;
            this.changes = Collections.unmodifiableList(changes);
            this.settings = settings;
            this.hash = hash;
        }
    }

    /** 검증한 이력 전체. */
    static final class Log {
        /** 이력 파일이 있었는지(없으면 최초 빌드 상태). */
        final boolean present;
        final String buildTime;
        final String baseVersion;
        final String baseSettings;
        final List<Entry> entries;
        /** 검증 실패 사유(정상이면 null). 실패하면 entries를 정상 이력으로 보여 주지 않는다. */
        final String problem;

        Log(boolean present, String buildTime, String baseVersion, String baseSettings, List<Entry> entries, String problem) {
            this.present = present;
            this.buildTime = buildTime;
            this.baseVersion = baseVersion;
            this.baseSettings = baseSettings;
            this.entries = Collections.unmodifiableList(entries);
            this.problem = problem;
        }

        /** @return 마지막 항목(없으면 null) */
        Entry last() {
            return entries.isEmpty() ? null : entries.get(entries.size() - 1);
        }

        /**
         * 이력에 기록된 한 설정의 이전 값·변경 후 값을 모두 모은다(빈 값·비밀 표시 제외).
         * {@code config embed-key}가 예전에 쓴 키ID를 다른 키에 다시 붙이지 못하게 검사할 때 쓴다.
         *
         * @param key 설정 이름(예: {@code crypto.key.id})
         * @return 기록된 값(기록 순서 유지)
         */
        Set<String> recordedValues(String key) {
            Set<String> values = new LinkedHashSet<>();
            for (Entry entry : entries) {
                for (Change change : entry.changes) {
                    if (!change.key.equals(key)) continue;
                    for (String value : new String[] {change.before, change.after}) {
                        if (value != null && !value.isEmpty() && !SECRET_BEFORE.equals(value) && !SECRET_AFTER.equals(value)) {
                            values.add(value);
                        }
                    }
                }
            }
            return values;
        }
    }

    /**
     * 이력을 해석하고 검증한다.
     *
     * @param history          이력 Properties(파일이 없으면 null)
     * @param settingsBytes    현재 JAR의 설정 파일 내용
     * @param manifestFingerprint Manifest {@code Settings-Fingerprint}(없으면 null)
     * @param manifestBuildTime   Manifest {@code Build-Time}(없으면 null)
     * @param manifestVersion     Manifest {@code Implementation-Version}(없으면 null)
     * @return 검증 결과
     */
    static Log read(Properties history, byte[] settingsBytes, String manifestFingerprint, String manifestBuildTime,
                    String manifestVersion) {
        String current = fingerprint(settingsBytes);
        if (history == null) {
            // 최초 빌드 상태: 빌드 때 기록한 지문이 있으면 설정이 그대로인지 확인한다(이력 없이 수정된 JAR 탐지).
            String problem = manifestFingerprint != null && !manifestFingerprint.equals(current)
                    ? Messages.get("history.err.modifiedWithoutHistory") : null;
            return new Log(false, manifestBuildTime, manifestVersion, manifestFingerprint == null ? current : manifestFingerprint,
                    Collections.<Entry>emptyList(), problem);
        }
        List<Entry> entries = new ArrayList<>();
        String buildTime = history.getProperty("build.time", "");
        String baseVersion = history.getProperty("base.version", "");
        String baseSettings = history.getProperty("base.settings", "");
        try {
            if (!FORMAT.equals(history.getProperty("format.version"))) throw new IllegalStateException("format");
            if (manifestFingerprint != null && !manifestFingerprint.equals(baseSettings)) throw new IllegalStateException("base");
            int count = Integer.parseInt(history.getProperty("change.count", "x"));
            if (count < 1) throw new IllegalStateException("count");
            String previousHash = baseSettings;
            Map<String, String> lastAfter = new HashMap<>();
            for (int i = 1; i <= count; i++) {
                Entry entry = parseEntry(history, i, previousHash);
                for (Change change : entry.changes) {
                    String known = lastAfter.get(change.key);
                    if (known != null && !SECRET_BEFORE.equals(change.before) && !known.equals(change.before)) {
                        throw new IllegalStateException("chain-value");
                    }
                    lastAfter.put(change.key, change.after);
                }
                entries.add(entry);
                previousHash = entry.hash;
            }
            if (history.getProperty("entry." + (count + 1) + ".time") != null) throw new IllegalStateException("extra");
            Entry last = entries.get(entries.size() - 1);
            if (!last.hash.equals(history.getProperty("head.hash"))) throw new IllegalStateException("head");
            if (!last.time.equals(history.getProperty("last.modified"))
                    || !last.operator.equals(history.getProperty("last.operator"))) {
                throw new IllegalStateException("last");
            }
            if (!last.settings.equals(current)) throw new IllegalStateException("settings");
            return new Log(true, buildTime, baseVersion, baseSettings, entries, null);
        } catch (RuntimeException e) {
            // 어떤 항목이 어긋났는지는 내부 판단에만 쓰고, 사용자에게는 같은 안내를 보여 준다(손상·변조 의심).
            return new Log(true, buildTime, baseVersion, baseSettings, Collections.<Entry>emptyList(),
                    Messages.get("history.err.invalid"));
        }
    }

    /** 항목 하나를 읽고 형식·해시를 확인한다. */
    private static Entry parseEntry(Properties history, int number, String previousHash) {
        String prefix = "entry." + number + ".";
        String time = require(history, prefix + "time");
        try {
            Instant.parse(time);
        } catch (DateTimeParseException e) {
            throw new IllegalStateException("time");
        }
        String operator = require(history, prefix + "operator");
        if (!OPERATOR.matcher(operator).matches()) throw new IllegalStateException("operator");
        String command = require(history, prefix + "command");
        if (!"set".equals(command) && !"embed-key".equals(command)) throw new IllegalStateException("command");
        String reason = history.getProperty(prefix + "reason", "");
        String keys = require(history, prefix + "keys");
        List<Change> changes = new ArrayList<>();
        for (String key : keys.split(",")) {
            if (!NAME.matcher(key).matches()) throw new IllegalStateException("key");
            String before = history.getProperty(prefix + "before." + key);
            String after = history.getProperty(prefix + "after." + key);
            if (before == null || after == null) throw new IllegalStateException("change");
            if (SettingCatalog.sensitiveKeys().contains(key) && (!SECRET_BEFORE.equals(before) || !SECRET_AFTER.equals(after))) {
                throw new IllegalStateException("secret");
            }
            changes.add(new Change(key, before, after));
        }
        String settings = require(history, prefix + "settings");
        String hash = require(history, prefix + "hash");
        if (!HEX64.matcher(hash).matches() || !hash.equals(chain(previousHash, time, operator, command, reason, changes, settings))) {
            throw new IllegalStateException("hash");
        }
        return new Entry(number, time, operator, command, reason, changes, settings, hash);
    }

    private static String require(Properties history, String key) {
        String value = history.getProperty(key);
        if (value == null || value.isEmpty()) throw new IllegalStateException(key);
        return value;
    }

    /**
     * 기존 이력(검증된 것)에 성공한 변경 1건을 더한 새 이력 파일 내용을 만든다.
     *
     * @param log         검증된 기존 이력(문제가 있으면 호출하지 않는다)
     * @param version     JAR 버전(최초 기록용)
     * @param time        UTC 시각
     * @param operator    수정자 ID
     * @param command     set 또는 embed-key
     * @param reason      사유(없으면 빈 문자열)
     * @param changes     실제로 바뀐 설정(비밀 항목은 표시값으로 이미 바꾼 상태)
     * @param newSettings 변경 후 설정 파일 내용
     * @return UTF-8 이력 파일 내용
     */
    static byte[] append(Log log, String version, Instant time, String operator, String command, String reason,
                         List<Change> changes, byte[] newSettings) {
        String timeText = time.truncatedTo(ChronoUnit.SECONDS).toString();
        String settings = fingerprint(newSettings);
        String previousHash = log.entries.isEmpty() ? log.baseSettings : log.last().hash;
        String hash = chain(previousHash, timeText, operator, command, reason, changes, settings);
        List<Entry> all = new ArrayList<>(log.entries);
        all.add(new Entry(all.size() + 1, timeText, operator, command, reason, changes, settings, hash));

        StringBuilder text = new StringBuilder();
        text.append("# java-crypto-kit JAR internal settings change history (written by config set / config embed-key).\n");
        text.append("# Secret values are never recorded. This is not a tamper-proof audit log: anyone who can modify the JAR\n");
        text.append("# can modify this file. The operator ID is a record, not authentication.\n");
        text.append("# java-crypto-kit JAR 내부 설정 변경 이력(config set / config embed-key가 기록). 비밀값은 기록하지 않는다.\n");
        text.append("# 위변조 방지 감사 로그가 아니다(JAR를 수정할 수 있는 사람은 이 파일도 바꿀 수 있다). 수정자 ID는 기록용이다.\n");
        line(text, "format.version", FORMAT);
        line(text, "build.time", log.buildTime == null ? "" : log.buildTime);
        line(text, "base.version", log.present ? log.baseVersion : (version == null ? "" : version));
        line(text, "base.settings", log.baseSettings);
        line(text, "change.count", String.valueOf(all.size()));
        Entry last = all.get(all.size() - 1);
        line(text, "last.modified", last.time);
        line(text, "last.operator", last.operator);
        line(text, "last.command", last.command);
        line(text, "last.keys", keysOf(last));
        line(text, "head.hash", last.hash);
        for (Entry entry : all) {
            String prefix = "entry." + entry.number + ".";
            line(text, prefix + "time", entry.time);
            line(text, prefix + "operator", entry.operator);
            line(text, prefix + "command", entry.command);
            line(text, prefix + "reason", entry.reason);
            line(text, prefix + "keys", keysOf(entry));
            for (Change change : entry.changes) {
                line(text, prefix + "before." + change.key, change.before);
                line(text, prefix + "after." + change.key, change.after);
            }
            line(text, prefix + "settings", entry.settings);
            line(text, prefix + "hash", entry.hash);
        }
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String keysOf(Entry entry) {
        List<String> keys = new ArrayList<>();
        for (Change change : entry.changes) keys.add(change.key);
        return String.join(",", keys);
    }

    /** Properties 한 줄(값은 역슬래시·앞 공백·줄 시작 특수문자를 이스케이프). */
    private static void line(StringBuilder text, String key, String value) {
        String escaped = value.replace("\\", "\\\\");
        if (escaped.startsWith(" ")) escaped = "\\" + escaped;
        text.append(key).append('=').append(escaped).append('\n');
    }

    /** 해시 체인: SHA-256(이전 해시 | 항목 정규 표현). */
    private static String chain(String previous, String time, String operator, String command, String reason,
                                List<Change> changes, String settings) {
        StringBuilder canonical = new StringBuilder();
        canonical.append(previous).append('\n').append(time).append('\n').append(operator).append('\n')
                .append(command).append('\n').append(reason).append('\n');
        for (Change change : changes) {
            canonical.append(change.key).append('\u0000').append(change.before).append('\u0000').append(change.after).append('\n');
        }
        canonical.append(settings);
        return hex(sha256(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 설정 파일 전체 내용의 지문(SHA-256 앞 16자). 키 줄도 포함하므로 내장 키만 바꿔치기한 경우도 드러난다(지문에서 키를 알아낼
     * 수는 없다).
     *
     * @param settingsBytes 설정 파일 내용
     * @return {@code sha256:} + 16진수 16자
     */
    static String fingerprint(byte[] settingsBytes) {
        return "sha256:" + hex(sha256(settingsBytes)).substring(0, 16);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) text.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        return text.toString();
    }

    /**
     * 실행 중인 JAR의 이력 요약({@code info}용). 클래스패스의 설정·이력 리소스와(있으면) 실행 중인 JAR의 Manifest만 읽는다.
     *
     * @return 예: "최초 기본 상태(변경 이력 없음)" 또는 "변경됨 - 3회, 마지막 ... 수정자 ..."
     */
    static String describeRunningJar() {
        try {
            byte[] settings = resource("/java-crypto-kit.properties");
            if (settings == null) return Messages.get("history.summary.none");
            byte[] history = resource("/" + ENTRY);
            String manifestFingerprint = null;
            String buildTime = null;
            String version = null;
            Path running = ConfigCommand.runningJar();
            if (running != null) {
                try (JarFile jar = new JarFile(running.toFile(), false)) {
                    Manifest manifest = jar.getManifest();
                    if (manifest != null) {
                        Attributes main = manifest.getMainAttributes();
                        manifestFingerprint = main.getValue(SETTINGS_FINGERPRINT);
                        buildTime = main.getValue(BUILD_TIME);
                        version = main.getValue(Attributes.Name.IMPLEMENTATION_VERSION);
                    }
                }
            }
            Log log = read(history == null ? null : load(history), settings, manifestFingerprint, buildTime, version);
            if (log.problem != null) return Messages.get("history.summary.invalid");
            if (!log.present) return Messages.get("history.summary.none");
            Entry last = log.last();
            return Messages.get("history.summary.changed", log.entries.size(), last.time, last.operator);
        } catch (IOException | RuntimeException e) {
            return Messages.get("history.summary.unreadable", e.getClass().getSimpleName());
        }
    }

    /** 이력 바이트를 Properties로 읽는다(UTF-8). */
    static Properties load(byte[] bytes) throws IOException {
        Properties properties = new Properties();
        try (java.io.Reader reader = new java.io.InputStreamReader(new java.io.ByteArrayInputStream(bytes),
                StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static byte[] resource(String name) throws IOException {
        try (InputStream in = ConfigHistory.class.getResourceAsStream(name)) {
            if (in == null) return null;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                if (out.size() > MAX_BYTES) throw new IOException("too large");
            }
            return out.toByteArray();
        }
    }

    /** @return 표시용 값(비밀 표시는 현재 언어로 바꾸고, 빈 값은 "(비어 있음)") */
    static String display(String value) {
        if (SECRET_BEFORE.equals(value)) return Messages.get("history.value.secret");
        if (SECRET_AFTER.equals(value)) return Messages.get("history.value.replaced");
        return value == null || value.isEmpty() ? Messages.get("history.value.empty") : value;
    }

    /** 변경 목록(순서 유지) 도우미. */
    static Map<String, String> ordered() {
        return new LinkedHashMap<>();
    }
}
