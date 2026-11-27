package io.javacryptokit.cli;

import io.javacryptokit.config.LightObfuscation;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: JAR 내부 설정의 <b>전체 변경 이력</b>({@value #ENTRY})을 만들고 검증한다. {@code config set}·
 * {@code config embed-key}·{@code config key add|use|remove}와 {@code admin setup}·{@code admin password change}가 성공한 변경만
 * 기록하고, {@code config history}가 관리자 인증 뒤 처음부터 끝까지 보여 준다.
 *
 * <p><b>기록 내용</b>(변경 1건 = 항목 1개, 저장 용량 한도 내에서 이전 기록을 보존한다)</p>
 * <ul>
 *   <li>순번, UTC 수정 시각(초 단위 ISO 8601), 수정자({@code --operator}), 명령, 사유</li>
 *   <li>바꾼 설정마다 이름·이전 값·변경 후 값. 없던 항목·제거한 항목은 {@value #ABSENT}로 남긴다. 비밀 항목(내장 키)은 값 대신
 *       고정 표시만 남긴다(교체 {@value #SECRET_BEFORE} → {@value #SECRET_AFTER}, 추가 {@value #ABSENT} → {@value #SECRET_BEFORE},
 *       제거 {@value #SECRET_BEFORE} → {@value #ABSENT}). pass 키의 Salt는 비밀이 아닌 관리정보라 값 그대로 남긴다(이전 형식의
 *       이력에는 고정 표시로 남아 있으며 화면에 "기록 없음"으로 구분한다).</li>
 *   <li>키를 추가·제거·교체하면 키 요약 기록({@code key.<Key ID>}: 유형, 공급원, 출처, 전체 키 지문, pass는 KDF·반복 횟수·Salt의
 *       SHA-256)을 함께 남긴다(키 원문·Passphrase 없음). 화면에 모두 보여 주고, 같은 Key ID를 다시 등록할 때 같은 키인지 확인하는
 *       데 쓴다.</li>
 *   <li>관리자 비밀번호 설정·변경은 요약 줄 {@value #ADMIN_SUMMARY} 하나만 남긴다(고정 표시, 비밀번호·검증값·Salt 없음).</li>
 *   <li>변경 후 전체 설정의 지문(SHA-256 앞 16자)과 이전 항목에 이어지는 해시(체인)</li>
 * </ul>
 *
 * <p><b>손상·변조 의심 검사</b>: 순번 연속성, 항목 형식, 해시 체인, 마지막 항목의 설정 지문 = 현재 JAR 설정, 빌드 때 Manifest에
 * 기록한 기본 설정 지문({@code Settings-Fingerprint}) = 이력의 시작점, 이전 값 = 직전 변경 후 값을 확인한다. 하나라도 어긋나면
 * 정상 이력으로 보여 주지 않고 오류로 처리한다. 이력이 없는데 설정이 빌드 때와 다르면(이력 없이 수정됨) 역시 오류다.</p>
 *
 * <p><b>저장 표현</b>: JAR에는 이력 본문 전체를 obf1(경량 난독화, {@link LightObfuscation})로 저장한다. 압축을 풀어 열었을 때
 * 글자 그대로 보이지 않게 하는 단순 열람 방지일 뿐이며, 읽을 때 되돌린 뒤 위의 검사를 그대로 한다. 표시가 없는 구형 평문 이력도
 * 읽는다.</p>
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
    /** 항목이 없음(추가 전·제거 후)을 나타내는 표시. 빈 값({@code 이름=})과 구분한다. */
    static final String ABSENT = "[none]";
    /** 키 요약 줄의 이름 앞부분({@code key.<Key ID>}). 설정 이름({@code crypto.})과 겹치지 않는다. */
    static final String KEY_SUMMARY_PREFIX = "key.";
    /** 관리자 비밀번호 최초 설정 기록의 명령 이름. */
    static final String ADMIN_SETUP = "admin setup";
    /** 관리자 비밀번호 변경 기록의 명령 이름. */
    static final String ADMIN_CHANGE = "admin password change";
    /** 이력에 기록하는 명령 이름(config 하위 명령과 admin 명령). */
    static final List<String> COMMANDS = Collections.unmodifiableList(java.util.Arrays.asList(
            "set", "embed-key", "key add", "key use", "key remove", ADMIN_SETUP, ADMIN_CHANGE));
    /**
     * 관리자 기록의 요약 줄 이름. 설정 항목이 아니며 값은 고정 표시뿐이다(설정 {@value #ABSENT} → {@value #SECRET_BEFORE},
     * 변경 {@value #SECRET_BEFORE} → {@value #SECRET_AFTER}). 비밀번호·검증값·Salt는 남기지 않는다.
     */
    static final String ADMIN_SUMMARY = "admin.password";
    /** 이력 파일 최대 크기(바이트, 되돌린 본문 기준). */
    static final int MAX_BYTES = 1024 * 1024;
    /**
     * JAR 안 이력 항목(저장 표현)의 읽기 상한. obf1은 [확인값 4바이트 + 본문]을 Base64url로 쓰므로 본문보다 약 1/3 크다(본문 상한
     * {@link #MAX_BYTES} 1MiB → 저장 약 1.34MiB). 이 상한을 넘는 항목은 읽지 않고, 되돌린 본문이 1MiB를 넘으면 손상으로 본다.
     */
    static final int MAX_STORED_BYTES = MAX_BYTES * 2;
    /** 이력 분류: pass 키 관련. */
    static final String TYPE_PASS = "pass";
    /** 이력 분류: key 키 관련. */
    static final String TYPE_KEY = "key";
    /** 이력 분류: 키와 무관한 일반 설정. */
    static final String TYPE_GENERAL = "general";
    /** 이력 분류: CLI 관리자 비밀번호 설정·변경(pass·key 키 변경이 아님). */
    static final String TYPE_ADMIN = "admin";
    /** Manifest의 빌드 시각 속성. */
    static final String BUILD_TIME = "Build-Time";
    /** Manifest의 기본 설정 지문 속성. */
    static final String SETTINGS_FINGERPRINT = "Settings-Fingerprint";
    /** 수정자 ID 형식(문자·숫자와 . _ @ -, 1~64자). */
    static final Pattern OPERATOR = Pattern.compile("[\\p{L}\\p{N}._@-]{1,64}");
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]{1,80}");
    private static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    /** 키 요약 기록의 이름=값 한 쌍. */
    private static final Pattern RECORD_ITEM = Pattern.compile("([a-z0-9-]{1,32})=([A-Za-z0-9._*-]{0,128})");

    private ConfigHistory() { }

    /**
     * 키 요약 기록({@code key.<Key ID>}의 값): 번역하지 않는 {@code 이름=값;...} 형식. 키 원문·Passphrase·Salt 값은 넣지 않는다.
     * 예: {@code type=pass;source=embedded;origin=generated;fingerprint=<64자>;kdf=pbkdf2-sha256;iterations=600000;salt-sha256=<64자>}.
     * 표시가 {@code type=}이 없는 예전 개발 형식이면 {@link #parse}가 null을 돌려준다(표시는 원문 그대로, 같은 키 확인에는 못 씀).
     */
    static final class KeyRecord {
        final String type;
        final String source;
        /** 출처: generated, restored, copied, file, input, external, moved(없으면 null). */
        final String origin;
        /** 전체 키 지문(64자, 모르면 null). */
        final String fingerprint;
        final String kdf;
        final String iterations;
        /** Salt의 SHA-256(64자, pass만). Salt 값 자체는 남기지 않는다. */
        final String saltSha256;
        final boolean publicKey;
        /** 레거시 AES 슬롯({@code crypto.key.*})의 키였으면 true. */
        final boolean slot;

        KeyRecord(String type, String source, String origin, String fingerprint, String kdf, String iterations,
                  String saltSha256, boolean publicKey, boolean slot) {
            this.type = type;
            this.source = source;
            this.origin = origin;
            this.fingerprint = fingerprint;
            this.kdf = kdf;
            this.iterations = iterations;
            this.saltSha256 = saltSha256;
            this.publicKey = publicKey;
            this.slot = slot;
        }

        /** @return 저장 형식 문자열 */
        String format() {
            StringBuilder text = new StringBuilder();
            item(text, "type", type);
            item(text, "source", source);
            item(text, "origin", origin);
            if (slot) item(text, "slot", "yes");
            if (publicKey) item(text, "public", "yes");
            item(text, "kdf", kdf);
            item(text, "iterations", iterations);
            item(text, "salt-sha256", saltSha256);
            item(text, "fingerprint", fingerprint);
            return text.toString();
        }

        private static void item(StringBuilder text, String name, String value) {
            if (value == null || value.isEmpty()) return;
            if (text.length() > 0) text.append(';');
            text.append(name).append('=').append(value);
        }

        /**
         * @param value 이력에 기록된 값
         * @return 해석한 기록, 고정 표시({@value #ABSENT} 등)·예전 형식·형식 오류면 null
         */
        static KeyRecord parse(String value) {
            if (value == null || isMarker(value) || !value.startsWith("type=")) return null;
            Map<String, String> items = new HashMap<>();
            for (String part : value.split(";", -1)) {
                java.util.regex.Matcher m = RECORD_ITEM.matcher(part);
                if (!m.matches() || items.put(m.group(1), m.group(2)) != null) return null;
            }
            String type = items.get("type");
            if (!TYPE_PASS.equals(type) && !TYPE_KEY.equals(type)) return null;
            String fingerprint = items.get("fingerprint");
            if (fingerprint != null && !HEX64.matcher(fingerprint).matches()) return null;
            return new KeyRecord(type, items.get("source"), items.get("origin"), fingerprint, items.get("kdf"),
                    items.get("iterations"), items.get("salt-sha256"), "yes".equals(items.get("public")),
                    "yes".equals(items.get("slot")));
        }
    }

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
                        if (value != null && !value.isEmpty() && !isMarker(value)) values.add(value);
                    }
                }
            }
            return values;
        }

        /**
         * 이력에서 한 번이라도 쓰인 Key ID를 모은다: {@code crypto.key.id}의 이전·변경 값, 키 프로필 설정 이름
         * ({@code crypto.keys.<id>.*}), 키 요약 줄({@code key.<id>}). 한 번 쓴 Key ID를 다른 키에 다시 쓰지 못하게 할 때 쓴다.
         *
         * @return Key ID(기록 순서 유지)
         */
        /**
         * 한 항목에 마지막으로 기록된 변경 후 값. 기존 키의 요약을 다시 적을 때(제거·슬롯에서 옮김) "이전 값"으로 그대로 써서
         * "이전 값 = 직전 변경 후 값" 검증을 지킨다.
         *
         * @param key 항목 이름(예: {@code key.<Key ID>})
         * @return 마지막 변경 후 값, 기록이 없거나 마지막이 "없음"이면 null
         */
        String lastAfter(String key) {
            for (int i = entries.size() - 1; i >= 0; i--) {
                List<Change> changes = entries.get(i).changes;
                for (int j = changes.size() - 1; j >= 0; j--) {
                    Change change = changes.get(j);
                    if (change.key.equals(key)) return ABSENT.equals(change.after) ? null : change.after;
                }
            }
            return null;
        }

        /**
         * 이 Key ID의 가장 최근 키 요약 기록(추가 기록의 변경 후 값, 제거 기록이면 변경 전 값).
         *
         * @return 기록, 없거나 같은 키 확인에 쓸 수 없는 예전 형식이면 null
         */
        KeyRecord lastRecord(String keyId) {
            String name = KEY_SUMMARY_PREFIX + keyId;
            for (int i = entries.size() - 1; i >= 0; i--) {
                List<Change> changes = entries.get(i).changes;
                boolean slotIdAssigned = false;
                for (int j = changes.size() - 1; j >= 0; j--) {
                    Change change = changes.get(j);
                    if (change.key.equals(name)) {
                        return KeyRecord.parse(ABSENT.equals(change.after) ? change.before : change.after);
                    }
                    if (change.key.equals(io.javacryptokit.config.CryptoSettings.KEY_ID) && change.after.equals(keyId)) {
                        slotIdAssigned = true;
                    }
                }
                // Older config set entries could assign an ID without establishing the slot's fingerprint.
                if (slotIdAssigned) return null;
            }
            return null;
        }

        /** @return 관리자 비밀번호 설정·변경 기록이 하나라도 있으면 true(검증값을 지운 JAR를 "미설정"으로 보지 않기 위함) */
        boolean hasAdminRecords() {
            for (Entry entry : entries) {
                if (isAdminCommand(entry.command)) return true;
            }
            return false;
        }

        /**
         * 관리자 검증값이 있는 JAR의 이력 조건: 최초 설정 기록이 정확히 1건이고, 비밀번호 변경 기록은 모두 그 뒤에 있다(설정 전의 일반
         * 변경 기록은 허용). 검증 실패한 이력(항목 없음)은 false.
         *
         * @return 조건을 만족하면 true
         */
        boolean adminRecordsValid() {
            int setup = -1;
            for (int i = 0; i < entries.size(); i++) {
                String command = entries.get(i).command;
                if (ADMIN_SETUP.equals(command)) {
                    if (setup >= 0) return false;
                    setup = i;
                } else if (ADMIN_CHANGE.equals(command) && setup < 0) {
                    return false;
                }
            }
            return setup >= 0;
        }

        Set<String> usedKeyIds() {
            Set<String> ids = new LinkedHashSet<>(recordedValues(io.javacryptokit.config.CryptoSettings.KEY_ID));
            for (Entry entry : entries) {
                for (Change change : entry.changes) {
                    String[] profile = SettingCatalog.parseProfileName(change.key);
                    if (profile != null) ids.add(profile[0]);
                    if (change.key.startsWith(KEY_SUMMARY_PREFIX)) ids.add(change.key.substring(KEY_SUMMARY_PREFIX.length()));
                }
            }
            return ids;
        }
    }

    /** @return 값이 아니라 고정 표시(비밀·교체됨·없음)이면 true */
    static boolean isMarker(String value) {
        return SECRET_BEFORE.equals(value) || SECRET_AFTER.equals(value) || ABSENT.equals(value);
    }

    /** @return 관리자 비밀번호 기록의 명령이면 true */
    static boolean isAdminCommand(String command) {
        return ADMIN_SETUP.equals(command) || ADMIN_CHANGE.equals(command);
    }

    /** @return 화면에 쓸 명령 이름(config 하위 명령은 앞에 {@code config}를 붙인다) */
    static String commandLabel(String command) {
        return isAdminCommand(command) ? command : "config " + command;
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
        if (!COMMANDS.contains(command)) throw new IllegalStateException("command");
        String reason = history.getProperty(prefix + "reason", "");
        String keys = require(history, prefix + "keys");
        List<Change> changes = new ArrayList<>();
        for (String key : keys.split(",")) {
            // 일반 설정 이름(80자 상한)과 키 프로필 설정 이름(crypto.keys.<1~64자 Key ID>.<항목>)을 구분해 받는다.
            if (!NAME.matcher(key).matches() && SettingCatalog.parseProfileName(key) == null) throw new IllegalStateException("key");
            String before = history.getProperty(prefix + "before." + key);
            String after = history.getProperty(prefix + "after." + key);
            if (before == null || after == null) throw new IllegalStateException("change");
            // 비밀 항목은 값 대신 고정 표시만 허용한다: 교체 [secret]->[replaced], 추가 [none]->[secret], 제거 [secret]->[none].
            // (Salt 줄은 이전 형식의 고정 표시와 새 형식의 값을 모두 읽는다.)
            if (SettingCatalog.isHistoryMasked(key) && !(SECRET_BEFORE.equals(before) && SECRET_AFTER.equals(after)
                    || ABSENT.equals(before) && SECRET_BEFORE.equals(after) || SECRET_BEFORE.equals(before) && ABSENT.equals(after))) {
                throw new IllegalStateException("secret");
            }
            changes.add(new Change(key, before, after));
        }
        // 관리자 기록은 요약 줄 하나(고정 표시)만, 설정 변경 기록에는 관리자 요약 줄이 없어야 한다.
        boolean admin = isAdminCommand(command);
        boolean adminLine = false;
        for (Change change : changes) adminLine |= ADMIN_SUMMARY.equals(change.key);
        if (admin) {
            boolean initial = ADMIN_SETUP.equals(command) && changes.size() == 3
                    && initialKey(changes.get(1), TYPE_PASS) && initialKey(changes.get(2), TYPE_KEY);
            Change only = changes.size() == 1 || initial ? changes.get(0) : null;
            boolean valid = only != null && ADMIN_SUMMARY.equals(only.key) && (ADMIN_SETUP.equals(command)
                    ? ABSENT.equals(only.before) && SECRET_BEFORE.equals(only.after)
                    : SECRET_BEFORE.equals(only.before) && SECRET_AFTER.equals(only.after));
            if (!valid) throw new IllegalStateException("admin");
        } else if (adminLine) {
            throw new IllegalStateException("admin-line");
        }
        String settings = require(history, prefix + "settings");
        String hash = require(history, prefix + "hash");
        if (!HEX64.matcher(hash).matches() || !hash.equals(chain(previousHash, time, operator, command, reason, changes, settings))) {
            throw new IllegalStateException("hash");
        }
        return new Entry(number, time, operator, command, reason, changes, settings, hash);
    }

    private static boolean initialKey(Change change, String type) {
        KeyRecord record = KeyRecord.parse(change.after);
        return change.key.matches("key\\." + type + "-[0-9a-f]{32}") && ABSENT.equals(change.before)
                && record != null && type.equals(record.type) && "generated".equals(record.origin)
                && "embedded".equals(record.source) && record.fingerprint != null && record.format().equals(change.after);
    }

    private static String require(Properties history, String key) {
        String value = history.getProperty(key);
        if (value == null || value.isEmpty()) throw new IllegalStateException(key);
        return value;
    }

    /**
     * JAR 안 이력 항목의 바이트를 Properties로 읽는다. obf1 표현이면 먼저 되돌리고, 표시가 없으면 구형 평문 이력으로 읽는다.
     * 되돌릴 수 없거나(손상·모르는 버전) Properties로 읽을 수 없으면 빈 Properties를 돌려주어 {@link #read}가 이력 손상으로
     * 판정하게 한다(다른 값으로 대체하지 않음).
     *
     * @param stored JAR 항목 바이트
     * @return 이력 Properties
     */
    static Properties parse(byte[] stored) {
        try {
            byte[] plain = LightObfuscation.decodeFile(stored);
            if (plain.length > MAX_BYTES) return new Properties();
            return load(plain);
        } catch (IOException | IllegalArgumentException e) {
            return new Properties();
        }
    }

    /**
     * 이력 본문을 JAR에 저장할 표현(obf1)으로 바꾼다.
     *
     * @param plain {@link #append}가 만든 본문
     * @return JAR 항목 바이트
     */
    static byte[] store(byte[] plain) {
        return LightObfuscation.encodeFile(plain);
    }

    /**
     * 이력 항목마다 관련 유형을 정한다(저장은 하나, 조회할 때만 거른다). 레거시 AES 슬롯·key 프로필·{@code crypto.key.active.key}는
     * key, pass 프로필·{@code crypto.key.active.pass}는 pass, {@code crypto.key.type}은 둘 다, 그 밖의 설정만 바꾼 항목은 일반이다.
     * 키 프로필의 유형은 그 Key ID를 추가한 기록(유형 줄·키 요약 기록)에서 알아낸다. 이전 형식 이력에는 pass 항목이 생기지 않는다.
     *
     * 관리자 비밀번호 설정·변경 기록은 관리자 유형이다(pass·key 조회에는 나오지 않고 {@code --all}에만 나온다).
     *
     * @param entries 검증된 이력 항목(순서대로)
     * @return 항목마다 {@link #TYPE_PASS}·{@link #TYPE_KEY}·{@link #TYPE_GENERAL}·{@link #TYPE_ADMIN} 중 해당하는 것
     */
    static List<Set<String>> classify(List<Entry> entries) {
        Map<String, String> profileTypes = new HashMap<>();
        List<Set<String>> result = new ArrayList<>();
        for (Entry entry : entries) {
            if (isAdminCommand(entry.command)) {
                result.add(Collections.singleton(TYPE_ADMIN));
                continue;
            }
            for (Change change : entry.changes) {
                String[] profile = SettingCatalog.parseProfileName(change.key);
                if (profile != null && io.javacryptokit.config.KeyProfile.TYPE.equals(profile[1])) {
                    String value = ABSENT.equals(change.after) ? change.before : change.after;
                    if (TYPE_PASS.equals(value) || TYPE_KEY.equals(value)) profileTypes.put(profile[0], value);
                }
                if (change.key.startsWith(KEY_SUMMARY_PREFIX)) {
                    KeyRecord record = KeyRecord.parse(ABSENT.equals(change.after) ? change.before : change.after);
                    if (record != null) profileTypes.put(change.key.substring(KEY_SUMMARY_PREFIX.length()), record.type);
                }
            }
            Set<String> types = new java.util.TreeSet<>();
            for (Change change : entry.changes) {
                String[] profile = SettingCatalog.parseProfileName(change.key);
                if (io.javacryptokit.config.CryptoSettings.LEGACY_SLOT_SETTINGS.contains(change.key)
                        || io.javacryptokit.config.CryptoSettings.KEY_ACTIVE_KEY.equals(change.key)) {
                    types.add(TYPE_KEY);
                } else if (io.javacryptokit.config.CryptoSettings.KEY_ACTIVE_PASS.equals(change.key)) {
                    types.add(TYPE_PASS);
                } else if (io.javacryptokit.config.CryptoSettings.KEY_TYPE.equals(change.key)) {
                    types.add(TYPE_PASS);
                    types.add(TYPE_KEY);
                } else if (profile != null || change.key.startsWith(KEY_SUMMARY_PREFIX)) {
                    String id = profile != null ? profile[0] : change.key.substring(KEY_SUMMARY_PREFIX.length());
                    String type = profileTypes.get(id);
                    types.add(type == null ? TYPE_KEY : type);
                }
            }
            if (types.isEmpty()) types.add(TYPE_GENERAL);
            result.add(Collections.unmodifiableSet(types));
        }
        return result;
    }

    /**
     * 기존 이력(검증된 것)에 성공한 변경 1건을 더한 새 이력 파일 내용을 만든다.
     *
     * @param log         검증된 기존 이력(문제가 있으면 호출하지 않는다)
     * @param version     JAR 버전(최초 기록용)
     * @param time        UTC 시각
     * @param operator    수정자 ID
     * @param command     {@link #COMMANDS} 중 하나
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
        text.append("# java-crypto-kit JAR internal settings change history (written by config set / embed-key / key / admin).\n");
        text.append("# Secret values and the admin password are never recorded. This is not a tamper-proof audit log: anyone who\n");
        text.append("# can modify the JAR can modify this file. The operator ID is a record, not authentication.\n");
        text.append("# java-crypto-kit JAR 내부 설정 변경 이력(config set / embed-key / key / admin이 기록). 비밀값·관리자 비밀번호는 기록하지 않는다.\n");
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
     * 실행 중인 JAR의 이력 요약({@code info}용). 활성 설정 상태의 검증 결과를 사용한다.
     *
     * @return 예: "최초 기본 상태(변경 이력 없음)" 또는 "변경됨 - 3회, 마지막 ... 수정자 ..."
     */
    static String describeRunningJar() {
        try {
            Path running = ConfigCommand.runningJar();
            if (running == null) return Messages.get("history.summary.none");
            Log log = JarConfigEditor.read(running).history;
            if (log.problem != null) return Messages.get("history.summary.invalid");
            if (!log.present) return Messages.get("history.summary.none");
            Entry last = log.last();
            return Messages.get("history.summary.changed", log.entries.size(), last.time, last.operator);
        } catch (CryptoCli.CliException | RuntimeException e) {
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

    /** @return 표시용 값(비밀 표시는 현재 언어로 바꾸고, 빈 값은 "(비어 있음)") */
    static String display(String value) {
        if (SECRET_BEFORE.equals(value)) return Messages.get("history.value.secret");
        if (SECRET_AFTER.equals(value)) return Messages.get("history.value.replaced");
        if (ABSENT.equals(value)) return Messages.get("history.value.none");
        return value == null || value.isEmpty() ? Messages.get("history.value.empty") : value;
    }
}
