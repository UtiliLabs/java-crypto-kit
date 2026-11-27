package io.javacryptokit.cli;

import io.javacryptokit.KeyType;
import io.javacryptokit.config.JarState;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.key.PassKdf;
import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.SecureRandoms;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.LightObfuscation;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.KeyResolver;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/** Validates managed settings, administrator state and History before publishing a JAR snapshot. */
final class JarConfigEditor {
    /** JAR 안의 내부 기본 설정 리소스 이름. */
    static final String SETTINGS_ENTRY = "java-crypto-kit.properties";
    /** java-crypto-kit JAR인지 확인하는 표지 항목(설정 로더 클래스). */
    static final String MARKER_ENTRY = "io/javacryptokit/config/CryptoSettings.class";
    /** 이 클래스가 있는 JAR(코드)만 obf1 저장 표현을 읽는다. */
    static final String OBFUSCATION_MARKER = "io/javacryptokit/config/LightObfuscation.class";
    /** 설정 파일이 비정상적으로 큰 경우를 막는 상한. */
    private static final int MAX_SETTINGS_BYTES = 256 * 1024;
    /** 서명 관련 항목(서명된 JAR 판별). */
    private static final Pattern SIGNATURE_ENTRY = Pattern.compile("META-INF/([^/]+\\.(SF|RSA|DSA|EC)|SIG-[^/]+)",
            Pattern.CASE_INSENSITIVE);

    private JarConfigEditor() { }

    /** JAR 하나를 읽은 결과(읽기 전용). 비밀값은 {@link #settings}에만 들어 있고 출력하지 않는다. */
    static final class Snapshot {
        final Path jar;
        final String title;
        final String version;
        final String mainClass;
        final String buildTime;
        final boolean signed;
        final List<String> entryNames;
        final byte[] settingsBytes;
        final Properties settings;
        final ConfigHistory.Log history;
        final String fileSha256;
        final String stateFormat;
        /** 내부 설정 검증 실패 사유(정상이면 null). */
        final String validationError;
        /** CLI 관리자 비밀번호 검증값 항목({@link AdminPassword#ENTRY}) 내용, 없으면 null. */
        final byte[] adminBytes;

        Snapshot(Path jar, String title, String version, String mainClass, String buildTime, boolean signed,
                 List<String> entryNames, byte[] settingsBytes, Properties settings, ConfigHistory.Log history,
                 String fileSha256, String validationError, byte[] adminBytes, String stateFormat) {
            this.jar = jar;
            this.title = title;
            this.version = version;
            this.mainClass = mainClass;
            this.buildTime = buildTime;
            this.signed = signed;
            this.entryNames = entryNames;
            this.settingsBytes = settingsBytes;
            this.settings = settings;
            this.history = history;
            this.fileSha256 = fileSha256;
            this.stateFormat = stateFormat;
            this.validationError = validationError;
            this.adminBytes = adminBytes;
        }

        /**
         * @return 이 JAR의 코드가 CLI 관리자 비밀번호를 지원하면 true. 관리자 기능 도입 전 JAR이면 false다.
         */
        boolean supportsAdmin() {
            return entryNames.contains(AdminPassword.MARKER);
        }

        /** @return 설정 텍스트(UTF-8) */
        String settingsText() {
            return new String(settingsBytes, StandardCharsets.UTF_8);
        }

        /**
         * @return 이 JAR의 코드가 JAR 안 저장 표현 obf1(경량 난독화)을 읽을 수 있으면 true. obf1 도입 전 JAR이면 false다.
         */
        boolean readsObfuscation() {
            return entryNames.contains(OBFUSCATION_MARKER);
        }

        /** @return 내부 설정을 검증한 설정 객체(검증 실패면 null). 외부 설정·JVM 속성은 반영되지 않는다. */
        CryptoSettings validated() {
            try {
                return CryptoSettings.fromEmbeddedDefaults(settings);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    /** 바꿀 내용. */
    static final class Change {
        final String command;
        final Map<String, String> values;
        /** 지울 항목(키 프로필 제거, {@code key remove}만). */
        final java.util.Set<String> removals;
        /** 이력에 함께 남길 키 요약 줄({@code key.<Key ID>}, 설정 항목이 아님). */
        final List<ConfigHistory.Change> summaries;
        final String operator;
        final String reason;

        /**
         * @param command  이력에 남길 명령 이름(set 또는 embed-key)
         * @param values   바꿀 항목과 새 값(순서 유지). 비밀 항목 값은 embed-key만 넣는다.
         * @param operator 수정자 ID(필수)
         * @param reason   변경 사유(선택, 없으면 null)
         */
        Change(String command, Map<String, String> values, String operator, String reason) {
            this(command, values, Collections.<String>emptySet(), Collections.<ConfigHistory.Change>emptyList(), operator, reason);
        }

        /**
         * @param command   이력에 남길 명령 이름({@link ConfigHistory#COMMANDS})
         * @param values    바꾸거나 추가할 항목과 새 값(순서 유지). 없는 항목 추가는 키 프로필 항목만, {@code embed-key}·{@code key add}만
         *                  (그리고 {@code set}이 등록된 프로필에 처음 지정하는 위치 항목)
         * @param removals  지울 항목(키 프로필 항목만, {@code key remove}만)
         * @param summaries 키 요약 줄
         * @param operator  수정자 ID(필수)
         * @param reason    변경 사유(선택, 없으면 null)
         */
        Change(String command, Map<String, String> values, java.util.Set<String> removals,
               List<ConfigHistory.Change> summaries, String operator, String reason) {
            this.command = command;
            this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
            this.removals = Collections.unmodifiableSet(new java.util.LinkedHashSet<>(removals));
            this.summaries = Collections.unmodifiableList(new ArrayList<>(summaries));
            this.operator = operator;
            this.reason = reason;
        }

        /** @return 없던 키 프로필 항목을 추가할 수 있는 명령이면 true */
        boolean addsProfiles() {
            return "embed-key".equals(command) || "key add".equals(command);
        }
    }

    /** 변경 결과. */
    static final class Result {
        final Path output;
        final List<String> changedKeys;
        final Map<String, String> before;
        final Snapshot after;

        private Result(Path output, List<String> changedKeys,
                       Map<String, String> before, Snapshot after) {
            this.output = output;
            this.changedKeys = changedKeys;
            this.before = before;
            this.after = after;
        }
    }

    // ===================================================================================================
    // 읽기
    // ===================================================================================================

    /**
     * JAR의 내부 설정·이력·Manifest를 읽는다. 외부 설정·JVM 속성·환경변수는 전혀 읽지 않는다.
     *
     * @param jar 대상 JAR
     * @return 읽은 결과(이력 검증 결과 포함)
     * @throws CryptoCli.CliException 파일이 없거나, JAR가 아니거나, java-crypto-kit JAR가 아닌 경우
     */
    static Snapshot read(Path jar) throws CryptoCli.CliException {
        if (!Files.isRegularFile(jar)) {
            throw new CryptoCli.CliException(Messages.get("jar.err.notFound", name(jar)));
        }
        String digest = sha256(jar);
        List<String> names = new ArrayList<>();
        boolean signed = false;
        byte[] settingsBytes = null;
        byte[] historyBytes = null;
        byte[] adminBytes = null;
        boolean marker = false;
        String title;
        String version;
        String mainClass;
        String buildTime;
        String manifestFingerprint;
        String stateFormat;
        try (JarFile file = new JarFile(jar.toFile(), false)) {
            Manifest manifest = file.getManifest();
            if (manifest == null) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.noManifest", name(jar)));
            Attributes main = manifest.getMainAttributes();
            title = main.getValue(Attributes.Name.IMPLEMENTATION_TITLE);
            version = main.getValue(Attributes.Name.IMPLEMENTATION_VERSION);
            mainClass = main.getValue(Attributes.Name.MAIN_CLASS);
            buildTime = main.getValue(ConfigHistory.BUILD_TIME);
            manifestFingerprint = main.getValue(ConfigHistory.SETTINGS_FINGERPRINT);
            stateFormat = main.getValue(JarState.ATTRIBUTE);
            for (Enumeration<JarEntry> entries = file.entries(); entries.hasMoreElements(); ) {
                JarEntry entry = entries.nextElement();
                String entryName = entry.getName();
                names.add(entryName);
                if (SIGNATURE_ENTRY.matcher(entryName).matches()) signed = true;
                if (MARKER_ENTRY.equals(entryName)) marker = true;
                if (SETTINGS_ENTRY.equals(entryName)) settingsBytes = readEntry(file, entry, MAX_SETTINGS_BYTES);
                if (ConfigHistory.ENTRY.equals(entryName)) historyBytes = readEntry(file, entry, ConfigHistory.MAX_STORED_BYTES);
                // 관리자 검증값은 크기 상한 초과도 "손상"으로 판정하도록 상한보다 조금 더 읽는다(AdminPassword.parse가 거부).
                if (AdminPassword.ENTRY.equals(entryName)) adminBytes = readAtMost(file, entry, AdminPassword.MAX_ENTRY_BYTES + 1);
            }
        } catch (CryptoCli.CliException e) {
            throw e;
        } catch (IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.structure", name(jar), e.getClass().getSimpleName()));
        }
        if (!marker || settingsBytes == null) {
            throw new CryptoCli.CliException(Messages.get("jar.err.notJck", name(jar), SETTINGS_ENTRY));
        }
        if (stateFormat != null) {
            try {
                JarState.State state = JarState.read(jar, stateFormat);
                if (historyBytes != null || adminBytes != null) throw new IOException("unexpected legacy state");
                if (state != null) {
                    if (state.history == null && state.admin == null) throw new IOException("empty operational state");
                    settingsBytes = state.settings;
                    historyBytes = state.history;
                    adminBytes = state.admin;
                }
            } catch (IOException e) {
                throw new CryptoCli.CliException("INTEGRITY", Messages.get("jar.err.stateRead"));
            }
        }
        Properties settings = loadProperties(settingsBytes, SETTINGS_ENTRY);
        Properties history = historyBytes == null ? null : ConfigHistory.parse(historyBytes);
        ConfigHistory.Log log = ConfigHistory.read(history, settingsBytes, manifestFingerprint, buildTime, version);
        requireDigest(jar, digest);
        return new Snapshot(jar, title, version, mainClass, buildTime, signed, Collections.unmodifiableList(names),
                settingsBytes, settings, log, digest, validate(settings), adminBytes, stateFormat);
    }

    /**
     * 내부 설정을 실행 때와 같은 규칙으로 검증한다(외부 설정 없이). 내장 키는 형식(Base64·32바이트)만 확인하고 값은 버린다.
     *
     * @return 실패 사유(정상이면 null)
     */
    /**
     * {@code config set}이 처음 지정하는 위치 항목인지 판단한다: 등록된 키 프로필({@code crypto.keys.<id>.type}이 있음)의 위치 항목
     * ({@link SettingCatalog.ProfileItem#location}) 중 그 프로필의 공급원에 속하고({@link CryptoSettings#belongsTo}) 아직 JAR 설정에
     * 없는 이름이면 true다. 새 프로필·정체 항목·다른 공급원의 항목은 해당하지 않는다.
     */
    static boolean addsLocation(Properties settings, String key) {
        String[] parts = SettingCatalog.parseProfileName(key);
        SettingCatalog.ProfileItem item = parts == null ? null : SettingCatalog.profileItem(parts[1]);
        if (item == null || !item.location || settings.containsKey(key)) return false;
        String prefix = KeyProfile.PREFIX + parts[0] + ".";
        String source = settings.getProperty(prefix + KeyProfile.SOURCE);
        return settings.containsKey(prefix + KeyProfile.TYPE) && source != null && CryptoSettings.belongsTo(item.name, source.trim());
    }

    static String validate(Properties settings) {
        try {
            CryptoSettings.fromEmbeddedDefaults(settings);
            String embedded = settings.getProperty(CryptoSettings.KEY_EMBEDDED, "").trim();
            if (!embedded.isEmpty()) {
                byte[] key = KeyResolver.decodeEmbedded(embedded);
                Arrays.fill(key, (byte) 0);
            }
            return null;
        } catch (SafeMessageException e) {
            return e.getMessage();
        } catch (IllegalArgumentException e) {
            return Messages.get("jar.err.validate", e.getClass().getSimpleName());
        }
    }

    // ===================================================================================================
    // 변경
    // ===================================================================================================

    /**
     * 검증된 설정과 이력을 동일 JAR의 예약 영역에 발행한다.
     *
     * @param before 인증 시 확인한 원본의 스냅샷
     * @param change     바꿀 내용
     * @param now        기록할 시각(UTC, 초 단위)
     * @return 결과
     * @throws CryptoCli.CliException    사용법·입출력·이력 문제(USAGE·IO_ERROR·INTEGRITY)
     * @throws CredentialCryptoException 설정값이 올바르지 않은 경우(CONFIGURATION) 또는 키 검증 실패
     */
    static Result apply(Snapshot before, Change change, Instant now)
            throws CryptoCli.CliException, CredentialCryptoException {
        checkOperator(change.operator);
        checkReason(change.reason);
        if (before.signed) throw new CryptoCli.CliException(Messages.get("jar.err.signed"));
        requireIntact(before);
        if (before.stateFormat == null) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.noState"));

        // [1] 항목 이름·값 검사: 지원 항목(JAR 설정에 있는 이름)만, 제어문자·앞뒤 공백 없는 값만 받는다. 없던 항목은 키를 추가하는
        //     명령(embed-key·key add)의 키 프로필 항목과, config set이 등록된 프로필에 처음 지정하는 위치 항목만 추가할 수 있다.
        Map<String, String> beforeValues = new LinkedHashMap<>();
        boolean addsLocation = false;
        for (Map.Entry<String, String> item : change.values.entrySet()) {
            String key = item.getKey();
            // 등록된 프로필의 위치 항목은 config set으로 처음 지정할 수도 있다(그 프로필의 공급원에 속하는 항목만).
            boolean firstLocation = "set".equals(change.command) && addsLocation(before.settings, key);
            addsLocation |= firstLocation;
            if (!before.settings.containsKey(key) && !(change.addsProfiles() && SettingCatalog.isProfileSetting(key))
                    && !firstLocation) {
                if (SettingCatalog.isProfileSetting(key)) {
                    String[] parts = SettingCatalog.parseProfileName(key);
                    String source = before.settings.getProperty(KeyProfile.PREFIX + parts[0] + "." + KeyProfile.SOURCE);
                    if (before.settings.containsKey(KeyProfile.PREFIX + parts[0] + "." + KeyProfile.TYPE) && source != null) {
                        throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                                Messages.get("config.err.profileItemSource", safeName(key), source.trim()));
                    }
                    throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                            Messages.get("jar.err.profileNotRegistered", safeName(key)));
                }
                String suggestion = key.matches("[A-Za-z0-9._-]{1,80}")
                        ? CryptoSettings.suggest(key, before.settings.stringPropertyNames()) : null;
                throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                        Messages.get("jar.err.unknownKey", safeName(key),
                                suggestion != null ? " " + Messages.get("config.hint.didYouMean", suggestion) : ""));
            }
            if (SettingCatalog.isSensitive(key) && !change.addsProfiles()) {
                throw new CryptoCli.CliException(Messages.get("jar.err.sensitiveSet", key));
            }
            checkValue(key, item.getValue());
            beforeValues.put(key, before.settings.getProperty(key));
        }
        for (String key : change.removals) {
            if (!"key remove".equals(change.command) || !SettingCatalog.isProfileSetting(key) || !before.settings.containsKey(key)
                    || change.values.containsKey(key)) {
                throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.lineMissing", safeName(key)));
            }
            beforeValues.put(key, before.settings.getProperty(key));
        }

        // [2] 설정 파일의 해당 줄만 바꾼다(주석·순서 보존, 새 키 프로필 항목은 파일 끝에 추가, 제거 항목은 그 줄만 삭제). 다시 읽어
        //     의도한 값이 들어갔는지, 다른 항목은 그대로인지 확인한다. 내장 키 값은 JAR 안 저장 표현(obf1, 경량 난독화)으로 쓰고,
        //     바꾸지 않는 구형 평문 내장 값도 같은 표현으로 다시 쓴다(키 바이트는 그대로이므로 변경 항목·이력에는 넣지 않는다).
        //     obf1을 읽지 못하는 이전 버전 JAR는 그 버전의 형식(표준 Base64, 평문 이력)으로 쓰고 기존 값은 건드리지 않는다.
        boolean obfuscate = before.readsObfuscation();
        Map<String, String> stored = new LinkedHashMap<>();
        for (Map.Entry<String, String> item : change.values.entrySet()) {
            String key = item.getKey();
            stored.put(key, SettingCatalog.isSensitive(key) ? storedSecret(key, item.getValue(), obfuscate) : item.getValue());
        }
        java.util.Set<String> reencoded = new java.util.LinkedHashSet<>();
        for (String key : before.settings.stringPropertyNames()) {
            if (!obfuscate) break;
            if (!SettingCatalog.isSensitive(key) || change.values.containsKey(key) || change.removals.contains(key)) continue;
            String value = before.settings.getProperty(key).trim();
            if (value.isEmpty() || LightObfuscation.isEncoded(value)) continue;
            try {
                stored.put(key, storedSecret(key, value, true));
                reencoded.add(key);
            } catch (CredentialCryptoException e) {
                // 키로 읽을 수 없는 값(쓰이지 않는 자리 등)은 바꿀 수 없으므로 그대로 둔다. 실제 사용 여부는 아래 재검증이 판단한다.
            }
        }
        String newText = rewrite(before.settingsText(), stored, change.removals, change.addsProfiles() || addsLocation);
        byte[] newSettingsBytes = newText.getBytes(StandardCharsets.UTF_8);
        Properties newSettings = loadProperties(newSettingsBytes, SETTINGS_ENTRY);
        List<String> changed = new ArrayList<>();
        List<ConfigHistory.Change> recorded = new ArrayList<>();
        for (Map.Entry<String, String> item : change.values.entrySet()) {
            String key = item.getKey();
            String value = stored.get(key);
            if (!value.equals(newSettings.getProperty(key))) {
                throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.writeValue", key));
            }
            String old = beforeValues.get(key);
            boolean same = SettingCatalog.isSensitive(key) ? sameSecret(old, value) : value.equals(old == null ? null : old.trim());
            if (!same) {
                changed.add(key);
                // 비밀 항목·Salt는 값을 기록하지 않고 고정 표시만 남긴다(교체 / 추가). 없던 항목은 "없음" 표시로 남긴다.
                if (SettingCatalog.isHistoryMasked(key)) {
                    recorded.add(old == null ? new ConfigHistory.Change(key, ConfigHistory.ABSENT, ConfigHistory.SECRET_BEFORE)
                            : new ConfigHistory.Change(key, ConfigHistory.SECRET_BEFORE, ConfigHistory.SECRET_AFTER));
                } else {
                    recorded.add(new ConfigHistory.Change(key, old == null ? ConfigHistory.ABSENT : old.trim(), value));
                }
            }
        }
        for (String key : change.removals) {
            if (newSettings.containsKey(key)) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.writeValue", key));
            changed.add(key);
            // 예전 이력이 값 대신 고정 표시로 남긴 항목(이전 형식의 Salt 줄)은 제거 기록의 이전 값도 고정 표시로 이어 쓴다(체인 유지).
            String last = before.history.lastAfter(key);
            boolean masked = SettingCatalog.isHistoryMasked(key) || last != null && ConfigHistory.isMarker(last);
            recorded.add(masked
                    ? new ConfigHistory.Change(key, ConfigHistory.SECRET_BEFORE, ConfigHistory.ABSENT)
                    : new ConfigHistory.Change(key, beforeValues.get(key).trim(), ConfigHistory.ABSENT));
        }
        for (String key : before.settings.stringPropertyNames()) {
            if (change.values.containsKey(key) || change.removals.contains(key)) continue;
            String oldValue = before.settings.getProperty(key);
            String newValue = newSettings.getProperty(key);
            boolean same = reencoded.contains(key) ? sameSecret(oldValue, newValue) : oldValue.equals(newValue);
            if (!same) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.unchangedValue", key));
        }
        for (String key : newSettings.stringPropertyNames()) {
            if (!before.settings.containsKey(key) && !change.values.containsKey(key)) {
                throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.unchangedValue", safeName(key)));
            }
        }
        // 바뀐 값이 하나도 없으면 실패로 끝내고 이력에도 남기지 않는다.
        if (changed.isEmpty()) throw new CryptoCli.CliException(Messages.get("jar.err.noChange"));
        recorded.addAll(change.summaries);

        // [3] 바꾼 뒤의 전체 설정 조합을 실행 때와 같은 규칙으로 재검증한다(보안 정책 위반값·잘못된 조합 거부).
        String invalid = validate(newSettings);
        if (invalid != null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("jar.err.invalidAfter", invalid));
        }

        if ("set".equals(change.command)) {
            if (changed.contains(CryptoSettings.KEY_ID)) {
                recordSlotIdChange(before, CryptoSettings.fromEmbeddedDefaults(newSettings), recorded);
            } else {
                checkSlotMaterialChange(before, newSettings, changed);
            }
        }

        // [4] 이력 갱신(기존 전체 이력 + 이번 변경 1건, 비밀값 없음). 해시 체인은 항목의 정규 표현으로 계산하고, JAR에는 본문 전체를
        //     obf1(경량 난독화, 단순 열람 방지)로 저장한다. 읽을 때 되돌린 뒤 같은 검증을 하므로 무결성 검사를 건너뛰지 않는다.
        //     obf1을 읽지 못하는 이전 버전 JAR에는 그 버전이 읽는 평문 이력으로 쓴다.
        byte[] historyPlain = ConfigHistory.append(before.history, before.version, now, change.operator, change.command,
                change.reason == null ? "" : change.reason, recorded, newSettingsBytes);
        if (historyPlain.length > ConfigHistory.MAX_BYTES) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.historyFull"));
        }
        byte[] historyBytes = obfuscate ? ConfigHistory.store(historyPlain) : historyPlain;

        // [5] 설정·이력·기존 관리자 검증값을 하나의 상태로 저장한다.
        return commit(before, newSettingsBytes, historyBytes, null,
                () -> checkRoundTrip(newSettings, changed), changed, beforeValues);
    }

    /** Checks only the active legacy AES source against the previously established identity. */
    private static void checkSlotMaterialChange(Snapshot before, Properties newSettings, List<String> changed)
            throws CredentialCryptoException {
        String source = newSettings.getProperty(CryptoSettings.KEY_SOURCE, "").trim();
        boolean affectsMaterial = changed.contains(CryptoSettings.KEY_SOURCE);
        for (String name : changed) {
            SettingCatalog.Setting setting = SettingCatalog.find(name);
            if (setting != null && setting.sources.contains(source)
                    && (setting.keyAffecting || CryptoSettings.AWS_REGION.equals(name))) {
                affectsMaterial = true;
                break;
            }
        }
        if (!affectsMaterial) return;

        String id = newSettings.getProperty(CryptoSettings.KEY_ID, "").trim();
        ConfigHistory.KeyRecord established = before.history.lastRecord(id);
        if (established == null || established.fingerprint == null) return;

        CryptoSettings settings = CryptoSettings.fromEmbeddedDefaults(newSettings);
        KeyProfile slot = settings.legacyProfile();
        if (slot == null) {
            KeyringCommand.checkEstablishedKey(id, established, null);
            return;
        }
        CryptoService.KeyCheck candidate = CryptoService.of(settings).checkKey(slot);
        KeyringCommand.checkEstablishedKey(id, established, candidate.fingerprint());
    }

    /** Checks the candidate AES slot and records its new identity before publishing anything. */
    private static void recordSlotIdChange(Snapshot before, CryptoSettings after, List<ConfigHistory.Change> recorded)
            throws CryptoCli.CliException, CredentialCryptoException {
        CryptoSettings original = KeyringCommand.validated(before);
        String newId = after.keyId();
        KeyringCommand.checkNewKeyId(newId, original, before, true);
        KeyProfile candidate = after.legacyProfile();
        String fingerprint = null;
        if (candidate != null) {
            CryptoService.KeyCheck check = CryptoService.of(after).checkKey(candidate);
            fingerprint = check.fingerprint();
            if (!check.available() && "embedded".equals(candidate.source())) throw check.failureException();
            // A new external ID may be configured later. Restoring a used ID always requires a fingerprint.
        }

        ConfigHistory.KeyRecord newKey = KeyringView.record(KeyType.KEY, after.keySource(), "moved", fingerprint,
                null, false, true);
        boolean restored = KeyringCommand.checkRestore(newId, newKey, before);
        KeyProfile oldSlot = original.legacyProfile();
        if (oldSlot != null) {
            String oldId = oldSlot.id();
            String summary = ConfigHistory.KEY_SUMMARY_PREFIX + oldId;
            String previous = before.history.lastAfter(summary);
            if (previous != null && before.history.lastRecord(oldId) != null) {
                recorded.add(new ConfigHistory.Change(summary, previous, ConfigHistory.ABSENT));
            } else if (!before.history.usedKeyIds().contains(oldId)) {
                recorded.add(new ConfigHistory.Change(summary, KeyringView.record(oldSlot, null).format(), ConfigHistory.ABSENT));
            }
        }
        if (candidate != null) {
            ConfigHistory.KeyRecord entry = restored ? KeyringView.record(KeyType.KEY, candidate.source(), "restored",
                    fingerprint, null, false, true) : newKey;
            recorded.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + newId, ConfigHistory.ABSENT, entry.format()));
        }
    }

    /**
     * 최초 등록은 독립된 두 키를 함께 생성하고 비밀번호 변경은 기존 키를 보존한다.
     * @param before 관리자 상태와 권한을 확인한 스냅샷
     * @param adminBytes 새 검증값 항목({@link AdminPassword#create})
     * @param operator   작업자 ID
     * @param command    {@code admin setup} 또는 {@code admin password change}
     * @param reason     사유(최초 설정은 자동 표기)
     * @param now        기록 시각
     * @return 결과
     */
    static Result applyAdmin(Snapshot before, byte[] adminBytes, String operator, String command,
                             String reason, Instant now, Path passExport) throws CryptoCli.CliException, CredentialCryptoException, IOException {
        checkOperator(operator);
        checkReason(reason);
        if (before.signed) throw new CryptoCli.CliException(Messages.get("jar.err.signed"));
        requireIntact(before);
        if (before.stateFormat == null) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.noState"));
        if (!before.supportsAdmin()) throw new CryptoCli.CliException(Messages.get("admin.err.legacyJar", name(before.jar)));
        boolean setup = ConfigHistory.ADMIN_SETUP.equals(command);
        if (setup != (before.adminBytes == null)) throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get(setup
                ? "admin.err.alreadySet" : "admin.err.notSetCli"));
        List<ConfigHistory.Change> recorded = new ArrayList<>();
        recorded.add(setup
                ? new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.ABSENT, ConfigHistory.SECRET_BEFORE)
                : new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.SECRET_BEFORE, ConfigHistory.SECRET_AFTER));
        byte[] settings = before.settingsBytes;
        boolean exported = false;
        try {
            if (setup) {
                Map<String, String> values = new LinkedHashMap<>();
                byte[] backup = initialKeys(before, values, recorded, passExport != null);
                try {
                    settings = rewrite(before.settingsText(), values, Collections.<String>emptySet(), true)
                            .getBytes(StandardCharsets.UTF_8);
                    CryptoSettings.fromEmbeddedDefaults(loadProperties(settings, SETTINGS_ENTRY));
                    if (passExport != null) {
                        KeyringCommand.writeNewSecretFile(passExport, backup);
                        exported = true;
                    }
                } finally {
                    if (backup != null) Arrays.fill(backup, (byte) 0);
                }
            }
            byte[] historyPlain = ConfigHistory.append(before.history, before.version, now, operator, command,
                    reason == null ? "" : reason, recorded, settings);
            if (historyPlain.length > ConfigHistory.MAX_BYTES) {
                throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.historyFull"));
            }
            byte[] historyBytes = before.readsObfuscation() ? ConfigHistory.store(historyPlain) : historyPlain;
            Result result = commit(before, settings, historyBytes, adminBytes, () -> { },
                    Collections.<String>emptyList(), Collections.<String, String>emptyMap());
            return result;
        } catch (CryptoCli.CliException | CredentialCryptoException | IOException | RuntimeException e) {
            if (exported && !publicationInterrupted(e)) {
                try {
                    Files.deleteIfExists(passExport);
                } catch (IOException cleanup) {
                    e.addSuppressed(new CryptoCli.CliException("IO_ERROR",
                            Messages.get("admin.err.backupCleanup", name(passExport))));
                }
            }
            throw e;
        }
    }

    /** Generates independent initial keys. Only an explicitly requested backup contains the passphrase. */
    private static byte[] initialKeys(Snapshot before, Map<String, String> values, List<ConfigHistory.Change> recorded,
                                      boolean export) {
        String passId = "pass-" + SecureRandoms.token(16, Encoding.HEX);
        String aesId = "key-" + SecureRandoms.token(16, Encoding.HEX);
        char[] pass = PassKdf.generate();
        byte[] salt = PassKdf.newSalt();
        byte[] aes = SecureRandoms.bytes(32);
        byte[] derived = null;
        try {
            int iterations = SettingCatalog.KDF_DEFAULT_ITERATIONS;
            derived = PassKdf.derive(pass, salt, iterations);
            Map<String, String> items = new LinkedHashMap<>();
            items.put(KeyProfile.KDF, PassKdf.NAME);
            items.put(KeyProfile.KDF_ITERATIONS, Integer.toString(iterations));
            items.put(KeyProfile.SALT, Encoding.BASE64.encode(salt));
            String prefix = KeyProfile.PREFIX + passId + ".";
            for (Map.Entry<String, String> item : items.entrySet()) values.put(prefix + item.getKey(), item.getValue());
            values.put(prefix + KeyProfile.TYPE, "pass");
            values.put(prefix + KeyProfile.SOURCE, "embedded");
            values.put(prefix + KeyProfile.EMBEDDED, KeyResolver.encodeEmbedded(derived));
            values.put(CryptoSettings.KEY_TYPE, "pass");
            values.put(CryptoSettings.KEY_ACTIVE_PASS, passId);
            boolean slot = CryptoSettings.fromEmbeddedDefaults(before.settings).legacyProfile() == null;
            if (slot) {
                values.put(CryptoSettings.KEY_ID, aesId);
                values.put(CryptoSettings.KEY_SOURCE, "embedded");
                values.put(CryptoSettings.KEY_EMBEDDED, KeyResolver.encodeEmbedded(aes));
                values.put(CryptoSettings.KEY_ACTIVE_KEY, "");
            } else {
                prefix = KeyProfile.PREFIX + aesId + ".";
                values.put(prefix + KeyProfile.TYPE, "key");
                values.put(prefix + KeyProfile.SOURCE, "embedded");
                values.put(prefix + KeyProfile.EMBEDDED, KeyResolver.encodeEmbedded(aes));
                values.put(CryptoSettings.KEY_ACTIVE_KEY, aesId);
            }
            String fingerprint = KeyResolver.fingerprint(derived);
            recorded.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + passId, ConfigHistory.ABSENT,
                    KeyringView.record(KeyType.PASS, "embedded", "generated", fingerprint, items, false, false).format()));
            recorded.add(new ConfigHistory.Change(ConfigHistory.KEY_SUMMARY_PREFIX + aesId, ConfigHistory.ABSENT,
                    KeyringView.record(KeyType.KEY, "embedded", "generated", KeyResolver.fingerprint(aes), null, false, slot).format()));
            return export ? KeyringCommand.PassBackup.write(passId, items, fingerprint, pass) : null;
        } finally {
            Arrays.fill(pass, '\0');
            Arrays.fill(aes, (byte) 0);
            if (derived != null) Arrays.fill(derived, (byte) 0);
        }
    }

    /**
     * 손상된 원본에서는 결과를 만들지 않는다(모든 JAR 변경의 공통 관문): 이력이 손상되었거나 관리자 검증값·관리자 기록이 맞지
     * 않으면({@link AdminPassword#statusOf}) 새 이력을 시작하거나 이어 쓰지 않는다. 명령 전에 같은 판단으로 이미 거부하지만, 변경
     * 경로가 늘어나도 손상된 JAR가 정상 결과로 바뀌지 않게 여기서 한 번 더 막는다.
     */
    private static void requireIntact(Snapshot before) throws CryptoCli.CliException {
        if (before.history.problem != null) throw new CryptoCli.CliException("INTEGRITY", Messages.get("jar.err.historyInvalid"));
        AdminPassword.Status status = AdminPassword.statusOf(before);
        if (status.state == AdminPassword.State.DAMAGED) {
            throw new CryptoCli.CliException("INTEGRITY", Messages.get("admin.err.damaged", status.detail));
        }
    }

    /** 갱신 후보를 발행하기 전 하는 추가 확인(키 왕복 검사 등). */
    private interface Check {
        void run() throws CredentialCryptoException;
    }

    private static Result commit(Snapshot before, byte[] settingsBytes, byte[] historyBytes, byte[] adminBytes,
                                 Check check, List<String> changed, Map<String, String> beforeValues)
            throws CryptoCli.CliException, CredentialCryptoException {
        Path target = before.jar.toAbsolutePath().normalize();
        byte[] verifier = adminBytes == null ? before.adminBytes : adminBytes;
        if (settingsBytes.length > MAX_SETTINGS_BYTES || historyBytes.length > ConfigHistory.MAX_STORED_BYTES ||
                verifier == null || verifier.length > AdminPassword.MAX_ENTRY_BYTES) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.stateCapacity"));
        }
        Properties settings = loadProperties(settingsBytes, SETTINGS_ENTRY);
        ConfigHistory.Log history = ConfigHistory.read(ConfigHistory.parse(historyBytes), settingsBytes,
                before.history.baseSettings, before.buildTime, before.version);
        Snapshot candidate = new Snapshot(target, before.title, before.version, before.mainClass, before.buildTime,
                before.signed, before.entryNames, settingsBytes, settings, history, null, validate(settings), verifier, before.stateFormat);
        if (history.problem != null || history.entries.size() != before.history.entries.size() + 1 ||
                candidate.validationError != null || AdminPassword.statusOf(candidate).state != AdminPassword.State.INITIALIZED) {
            throw new CryptoCli.CliException("INTEGRITY", Messages.get("jar.err.stateInvalid"));
        }
        check.run();
        try {
            JarState.update(target, before.stateFormat, before.fileSha256, settingsBytes, historyBytes, verifier, before.adminBytes == null);
        } catch (JarState.PublicationException e) {
            CryptoCli.CliException failure = new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.statePublished"));
            failure.initCause(e);
            throw failure;
        } catch (IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.stateWrite"));
        }
        return new Result(target, Collections.unmodifiableList(changed), beforeValues, candidate);
    }

    static boolean publicationInterrupted(Exception error) {
        return error.getCause() instanceof JarState.PublicationException;
    }

    static void requireDigest(Path jar, String expected) throws CryptoCli.CliException {
        if (!expected.equals(sha256(jar))) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.changedDuring"));
        }
    }

    // ===================================================================================================
    // 세부 단계
    // ===================================================================================================

    /** 수정자 ID 검사: 필수, 문자·숫자·. _ @ - 만, 1~64자. 값은 기록용이며 인증이 아니다. */
    static void checkOperator(String operator) throws CryptoCli.CliException {
        if (operator == null || operator.trim().isEmpty()) {
            throw new CryptoCli.CliException(Messages.get("jar.err.operatorMissing"));
        }
        if (!ConfigHistory.OPERATOR.matcher(operator).matches()) {
            throw new CryptoCli.CliException(Messages.get("jar.err.operatorFormat"));
        }
    }

    /** 변경 사유 검사: 선택, 200자 이하, 줄바꿈·제어문자 불가. */
    static void checkReason(String reason) throws CryptoCli.CliException {
        if (reason == null) return;
        if (reason.trim().isEmpty() || reason.length() > 200 || hasControl(reason)) {
            throw new CryptoCli.CliException(Messages.get("jar.err.reason"));
        }
    }

    /** 설정값 형식 검사: 제어문자·줄바꿈 불가, 앞뒤 공백 불가, 4096자 이하(내용 검증은 전체 재검증에서 한다). */
    private static void checkValue(String key, String value) throws CredentialCryptoException {
        if (value == null || value.length() > 4096 || hasControl(value) || !value.equals(value.trim())) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, Messages.get("jar.err.value", key));
        }
    }

    /**
     * 설정 텍스트에서 지정한 항목의 줄만 새 값으로 바꾼다. 항목 줄이 정확히 하나여야 하며(주석 줄 제외), 값은 Properties
     * 형식에 맞게 이스케이프한다(역슬래시·앞 공백).
     */
    static String rewrite(String text, Map<String, String> values) throws CryptoCli.CliException {
        return rewrite(text, values, Collections.<String>emptySet(), false);
    }

    /**
     * 설정 텍스트를 고친다: 있는 항목은 그 줄만 새 값으로 바꾸고, 없는 항목은 {@code append}일 때만 파일 끝에 한 덩어리로 추가하며,
     * 제거 항목은 그 줄만 지운다. 항목 줄은 정확히 하나여야 한다(주석 줄 제외).
     */
    static String rewrite(String text, Map<String, String> values, java.util.Set<String> removals, boolean append)
            throws CryptoCli.CliException {
        List<String> lines = new ArrayList<>(Arrays.asList(text.split("\n", -1)));
        String eol = text.contains("\r\n") ? "\r" : "";
        List<String> added = new ArrayList<>();
        for (Map.Entry<String, String> item : values.entrySet()) {
            int found = findLine(lines, item.getKey());
            if (found < 0) {
                if (!append) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.lineMissing", item.getKey()));
                added.add(item.getKey() + "=" + escapeValue(item.getValue()) + eol);
                continue;
            }
            String newline = lines.get(found).endsWith("\r") ? "\r" : "";
            lines.set(found, item.getKey() + "=" + escapeValue(item.getValue()) + newline);
        }
        for (String key : removals) {
            int found = findLine(lines, key);
            if (found < 0) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.lineMissing", key));
            lines.remove(found);
        }
        if (!added.isEmpty()) {
            // 파일 끝의 빈 줄 앞에 빈 줄 하나로 구분해 붙인다(추가한 키 프로필이 한 덩어리로 보이게).
            int at = lines.size();
            while (at > 0 && lines.get(at - 1).replace("\r", "").trim().isEmpty()) at--;
            List<String> block = new ArrayList<>();
            block.add(eol);
            block.addAll(added);
            lines.addAll(at, block);
        }
        return String.join("\n", lines);
    }

    /** @return 항목 줄의 위치(없으면 -1). 같은 항목 줄이 둘 이상이면 오류다. */
    private static int findLine(List<String> lines, String key) throws CryptoCli.CliException {
        Pattern keyLine = Pattern.compile("^\\s*" + Pattern.quote(key) + "\\s*[=:].*$");
        int found = -1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i).endsWith("\r") ? lines.get(i).substring(0, lines.get(i).length() - 1) : lines.get(i);
            if (keyLine.matcher(line).matches()) {
                if (found >= 0) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.multiLine", key));
                found = i;
            }
        }
        return found;
    }

    /** Properties 값 이스케이프: 역슬래시는 두 번, 맨 앞 공백은 \ 로 시작(값에 줄바꿈·제어문자는 이미 거부됨). */
    private static String escapeValue(String value) {
        String escaped = value.replace("\\", "\\\\");
        if (escaped.startsWith(" ")) escaped = "\\" + escaped;
        return escaped;
    }

    /**
     * 내장 키 값(표준 Base64 또는 obf1)을 JAR 안 저장 표현으로 바꾼다: obf1을 읽는 JAR면 obf1, 이전 버전 JAR면 표준 Base64.
     * 키 바이트는 그대로다.
     *
     * @throws CredentialCryptoException 키로 읽을 수 없는 값(CONFIGURATION, 값은 메시지에 넣지 않음)
     */
    private static String storedSecret(String key, String value, boolean obfuscate) throws CredentialCryptoException {
        byte[] bytes = null;
        try {
            bytes = KeyResolver.decodeEmbedded(value);
            return obfuscate ? KeyResolver.encodeEmbedded(bytes) : java.util.Base64.getEncoder().encodeToString(bytes);
        } catch (IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, Messages.get("jar.err.value", key));
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    /** @return 두 내장 키 값(표현이 달라도)이 같은 키 바이트이면 true. 읽을 수 없는 값은 글자 그대로 비교한다 */
    private static boolean sameSecret(String a, String b) {
        if (a == null || b == null) return false;
        byte[] x = null;
        byte[] y = null;
        try {
            x = KeyResolver.decodeEmbedded(a);
            y = KeyResolver.decodeEmbedded(b);
            return MessageDigest.isEqual(x, y);
        } catch (IllegalArgumentException e) {
            return a.trim().equals(b.trim());
        } finally {
            if (x != null) Arrays.fill(x, (byte) 0);
            if (y != null) Arrays.fill(y, (byte) 0);
        }
    }

    /**
     * 이번 변경으로 새로 들어간 내장 키(레거시 AES 슬롯 {@code crypto.key.embedded}, 키 프로필 {@code crypto.keys.<id>.embedded})마다
     * 그 Key ID로 실제 암복호화가 되는지 확인한다(임의 값 사용, 결과·키는 출력하지 않음, 자동 경고 없음).
     *
     * @param newSettings 변경 후 설정
     * @param changed     바뀐 항목 이름
     */
    private static void checkRoundTrip(Properties newSettings, List<String> changed) throws CredentialCryptoException {
        List<String> keyIds = new ArrayList<>();
        for (String key : changed) {
            if (CryptoSettings.KEY_EMBEDDED.equals(key)) {
                keyIds.add(newSettings.getProperty(CryptoSettings.KEY_ID, "").trim());
            } else if (SettingCatalog.isSensitive(key) && newSettings.containsKey(key)) {
                String[] profile = SettingCatalog.parseProfileName(key);
                if (profile != null) keyIds.add(profile[0]);
            }
        }
        if (keyIds.isEmpty()) return;
        CryptoSettings settings = CryptoSettings.fromEmbeddedDefaults(newSettings);
        CryptoService service = CryptoService.of(settings);
        try (io.javacryptokit.key.DefaultKeyWarning.Quiet ignored = io.javacryptokit.key.DefaultKeyWarning.quiet()) {
            for (String keyId : keyIds) {
                io.javacryptokit.config.KeyProfile profile = settings.profile(keyId);
                // 레거시 슬롯의 공급 방식이 embedded가 아니면 내장 값은 쓰이지 않으므로 왕복 검사 대상이 아니다.
                if (profile == null || !"embedded".equals(profile.source())) continue;
                byte[] probe = new byte[16];
                new SecureRandom().nextBytes(probe);
                byte[] back = null;
                try {
                    String token = service.encryptBytes(probe, null, keyId);
                    back = service.decryptBytes(token);
                    if (!Arrays.equals(probe, back)) {
                        throw new CredentialCryptoException(CredentialCryptoException.Reason.CRYPTO_PROVIDER,
                                Messages.get("jar.err.roundTrip"));
                    }
                } finally {
                    Arrays.fill(probe, (byte) 0);
                    if (back != null) Arrays.fill(back, (byte) 0);
                }
            }
        }
    }

    /** @return 기본 파일 시스템이 POSIX 권한을 지원하면 true(Linux·macOS) */
    static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    // ===================================================================================================
    // 공통 도우미
    // ===================================================================================================

    /** 항목을 최대 limit바이트까지만 읽는다(넘는 부분은 읽지 않음, 오류 없음). */
    private static byte[] readAtMost(JarFile file, JarEntry entry, int limit) throws IOException {
        try (InputStream in = file.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int read;
            while (out.size() < limit && (read = in.read(buffer, 0, Math.min(buffer.length, limit - out.size()))) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static byte[] readEntry(JarFile file, JarEntry entry, int limit) throws IOException, CryptoCli.CliException {
        try (InputStream in = file.getInputStream(entry)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                if (out.size() > limit) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.tooLarge", entry.getName()));
            }
            return out.toByteArray();
        }
    }

    /** UTF-8로 엄격하게 읽는다(깨진 바이트는 오류). */
    static Properties loadProperties(byte[] bytes, String what) throws CryptoCli.CliException {
        try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
            Properties properties = new Properties();
            try (Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
            return properties;
        } catch (CharacterCodingException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.notUtf8", what));
        } catch (IOException | IllegalArgumentException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.format", what, e.getClass().getSimpleName()));
        }
    }

    static String sha256(Path file) throws CryptoCli.CliException {
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) md.update(buffer, 0, read);
            return ConfigHistory.hex(md.digest());
        } catch (IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.read", name(file), e.getClass().getSimpleName()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

    private static boolean hasControl(String text) {
        for (int i = 0; i < text.length(); i++) if (Character.isISOControl(text.charAt(i))) return true;
        return false;
    }

    private static String safeName(String key) {
        return key.matches("[A-Za-z0-9._-]{1,80}") || SettingCatalog.parseProfileName(key) != null ? key : Messages.get("jar.name.unsafe");
    }

    /** 파일 이름만(전체 경로는 오류 메시지에 넣지 않는다). */
    static String name(Path path) {
        Path fileName = path.getFileName();
        return fileName == null ? Messages.get("jar.name.none") : SecretFiles.fileName(path);
    }

}
