package io.javacryptokit.cli;

import io.javacryptokit.key.SecretFiles;
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
import java.io.OutputStream;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: 빌드가 끝난 java-crypto-kit JAR의 <b>내부 기본 설정</b>({@code java-crypto-kit.properties})과
 * <b>변경 이력</b>({@link ConfigHistory#ENTRY})을 읽고, 바꾼 내용을 담은 <b>새 JAR</b>를 안전하게 만든다.
 * CLI {@code config show / history / set / embed-key}가 사용한다.
 *
 * <p><b>왜 필요한가</b>: 공개 배포 JAR를 받은 운영자가 소스 수정·Gradle 재빌드·외부 Properties·매번 {@code -D} 지정 없이 JAR
 * 자체의 기본값(메시지 언어, 경고 정책, 사용자 지정 내장 키·키ID 등)을 정해 배포할 수 있게 한다. 실행 시 우선순위(JVM {@code -D}
 * &gt; 외부 Properties &gt; JAR 내부 값)는 그대로이며, 이 클래스는 가장 마지막 단계인 JAR 내부 값만 바꾼다.</p>
 *
 * <p><b>안전 규칙(원본 보존)</b></p>
 * <ol>
 *   <li>원본 JAR는 절대 제자리에서 고치지 않는다. 결과 JAR가 놓일 폴더에 임시 파일을 만들어 새 JAR를 쓴다.</li>
 *   <li>원본의 모든 항목(클래스·리소스·Manifest)을 같은 순서로 옮기고, 설정 파일과 이력 파일만 새 내용으로 쓴다. 두 파일은
 *       한 번의 JAR 쓰기로 함께 바뀌므로 "설정은 바뀌었는데 이력은 없는" 부분 성공 상태가 생기지 않는다. 이전 이력은 모두 옮긴다.</li>
 *   <li>임시 파일을 다시 열어 ZIP/JAR 구조(CRC 포함), Manifest·Main-Class, 항목 목록, 설정 재검증, 이력 검증을 확인한다.</li>
 *   <li>검증을 통과한 경우에만 원자적 이동으로 결과 파일을 만든다. 실패하면 임시 파일을 지우고 원본은 그대로 둔다.</li>
 *   <li>교체 모드({@code --replace})는 실행 중이 아닌 대상 JAR에만 허용한다. 잠금 파일로 동시 수정을 막고, 작업 중 원본이
 *       바뀌었는지 해시로 다시 확인한 뒤, 백업을 만들고 원자적 이동으로 교체한다. 원자적 이동을 보장할 수 없으면 교체하지 않는다.</li>
 *   <li>서명된 JAR는 수정하면 서명이 깨지므로 거부한다. 이력이 손상·변조 의심인 JAR도 거부한다.</li>
 * </ol>
 *
 * <p><b>비밀정보</b>: 내장 키 값은 화면·이력·오류 메시지에 쓰지 않는다(이력에는 "교체됨" 표시만). 수정자 ID는 기록용이며 본인
 * 인증이 아니다. 이력도 JAR를 수정할 수 있는 사람은 바꿀 수 있으므로 위변조 방지 감사 로그가 아니다.</p>
 */
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
        /** 내부 설정 검증 실패 사유(정상이면 null). */
        final String validationError;
        /** CLI 관리자 비밀번호 검증값 항목({@link AdminPassword#ENTRY}) 내용, 없으면 null. */
        final byte[] adminBytes;

        Snapshot(Path jar, String title, String version, String mainClass, String buildTime, boolean signed,
                 List<String> entryNames, byte[] settingsBytes, Properties settings, ConfigHistory.Log history,
                 String fileSha256, String validationError, byte[] adminBytes) {
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
            this.validationError = validationError;
            this.adminBytes = adminBytes;
        }

        /**
         * @return 이 JAR의 코드가 CLI 관리자 비밀번호를 지원하면 true. 이전 형식 JAR이면 false이며, 그 JAR에는 관리자
         *         검증값을 쓰지 않는다(그 코드가 읽지 못해 아무 효과가 없음).
         */
        boolean supportsAdmin() {
            return entryNames.contains(AdminPassword.MARKER);
        }

        /** @return 설정 텍스트(UTF-8) */
        String settingsText() {
            return new String(settingsBytes, StandardCharsets.UTF_8);
        }

        /**
         * @return 이 JAR의 코드가 JAR 안 저장 표현 obf1(경량 난독화)을 읽을 수 있으면 true. obf1 이전 형식 JAR이면 false이며,
         *         그 JAR를 편집할 때는 그 버전이 읽는 기존 형식(표준 Base64 내장 키, 평문 이력)으로 쓴다(편집 후에도 그 JAR가 동작).
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
        final Path source;
        final Path output;
        final boolean replaced;
        final Path backup;
        final List<String> changedKeys;
        final Map<String, String> before;
        final Snapshot after;

        private Result(Path source, Path output, boolean replaced, Path backup, List<String> changedKeys,
                       Map<String, String> before, Snapshot after) {
            this.source = source;
            this.output = output;
            this.replaced = replaced;
            this.backup = backup;
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
        try (JarFile file = new JarFile(jar.toFile(), false)) {
            Manifest manifest = file.getManifest();
            if (manifest == null) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.noManifest", name(jar)));
            Attributes main = manifest.getMainAttributes();
            title = main.getValue(Attributes.Name.IMPLEMENTATION_TITLE);
            version = main.getValue(Attributes.Name.IMPLEMENTATION_VERSION);
            mainClass = main.getValue(Attributes.Name.MAIN_CLASS);
            buildTime = main.getValue(ConfigHistory.BUILD_TIME);
            manifestFingerprint = main.getValue(ConfigHistory.SETTINGS_FINGERPRINT);
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
        Properties settings = loadProperties(settingsBytes, SETTINGS_ENTRY);
        Properties history = historyBytes == null ? null : ConfigHistory.parse(historyBytes);
        ConfigHistory.Log log = ConfigHistory.read(history, settingsBytes, manifestFingerprint, buildTime, version);
        return new Snapshot(jar, title, version, mainClass, buildTime, signed, Collections.unmodifiableList(names),
                settingsBytes, settings, log, sha256(jar), validate(settings), adminBytes);
    }

    /**
     * 내부 설정을 실행 때와 같은 규칙으로 검증한다(외부 설정 없이). 내장 키는 형식(Base64·32바이트)만 확인하고 값은 버린다.
     *
     * @return 실패 사유(정상이면 null)
     */
    static String validate(Properties settings) {
        try {
            CryptoSettings.fromEmbeddedDefaults(settings);
            byte[] key = KeyResolver.decodeEmbedded(settings.getProperty(CryptoSettings.KEY_EMBEDDED));
            Arrays.fill(key, (byte) 0);
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
     * 바꾼 설정과 갱신한 이력을 담은 새 JAR를 만든다. 실패하면 원본·기존 출력 파일을 그대로 두고 임시 파일을 지운다.
     *
     * @param source     원본 JAR
     * @param output     결과 JAR 경로(교체 모드가 아니면 필수, 이미 있으면 거부)
     * @param replace    true면 원본 자리에 결과를 넣는다(백업 후 원자적 교체)
     * @param runningJar 지금 실행 중인 JAR(없으면 null). 교체 모드에서 자기 자신의 교체를 막는 데 쓴다.
     * @param change     바꿀 내용
     * @param now        기록할 시각(UTC, 초 단위)
     * @return 결과
     * @throws CryptoCli.CliException    사용법·입출력·이력 문제(USAGE·IO_ERROR·INTEGRITY)
     * @throws CredentialCryptoException 설정값이 올바르지 않은 경우(CONFIGURATION) 또는 키 검증 실패
     */
    static Result apply(Path source, Path output, boolean replace, Path runningJar, Change change, Instant now)
            throws CryptoCli.CliException, CredentialCryptoException {
        checkOperator(change.operator);
        checkReason(change.reason);
        Snapshot before = read(source);
        if (before.signed) throw new CryptoCli.CliException(Messages.get("jar.err.signed"));
        requireIntact(before);

        // [1] 항목 이름·값 검사: 지원 항목(JAR 설정에 있는 이름)만, 제어문자·앞뒤 공백 없는 값만 받는다. 없던 항목은 키를 추가하는
        //     명령(embed-key·key add)의 키 프로필 항목만 추가할 수 있다.
        Map<String, String> beforeValues = new LinkedHashMap<>();
        for (Map.Entry<String, String> item : change.values.entrySet()) {
            String key = item.getKey();
            if (!before.settings.containsKey(key) && !(change.addsProfiles() && SettingCatalog.isProfileSetting(key))) {
                if (SettingCatalog.isProfileSetting(key)) {
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
        String newText = rewrite(before.settingsText(), stored, change.removals, change.addsProfiles());
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

        // [4] 이력 갱신(기존 전체 이력 + 이번 변경 1건, 비밀값 없음). 해시 체인은 항목의 정규 표현으로 계산하고, JAR에는 본문 전체를
        //     obf1(경량 난독화, 단순 열람 방지)로 저장한다. 읽을 때 되돌린 뒤 같은 검증을 하므로 무결성 검사를 건너뛰지 않는다.
        //     obf1을 읽지 못하는 이전 버전 JAR에는 그 버전이 읽는 평문 이력으로 쓴다.
        byte[] historyPlain = ConfigHistory.append(before.history, before.version, now, change.operator, change.command,
                change.reason == null ? "" : change.reason, recorded, newSettingsBytes);
        if (historyPlain.length > ConfigHistory.MAX_BYTES) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.historyFull"));
        }
        byte[] historyBytes = obfuscate ? ConfigHistory.store(historyPlain) : historyPlain;

        // [5] 새 JAR 작성 → 검증 → 이동. 관리자 검증값 항목은 그대로 옮긴다(키를 바꿔도 관리자 비밀번호는 유지).
        return commit(before, source, output, replace, runningJar, newSettingsBytes, historyBytes, null,
                () -> checkRoundTrip(newSettings, changed), changed, beforeValues, now);
    }

    /**
     * CLI 관리자 비밀번호 검증값을 넣은 새 JAR를 만든다({@code admin setup}·{@code admin password change}). 설정 파일·키는 바꾸지
     * 않고, 이력에 관리자 기록 1건(시각·작업자·사유, 비밀번호·검증값·Salt 없음)을 더한다. 원본 교체는 하지 않는다(실행 중인 JAR는
     * 바꿀 수 없음). 관리자 비밀번호를 모르는 이전 버전 JAR에는 쓰지 않는다.
     *
     * @param source     원본 JAR(실행 중인 CLI JAR)
     * @param output     결과 JAR(이미 있으면 거부)
     * @param runningJar 실행 중인 JAR(없으면 null)
     * @param adminBytes 새 검증값 항목({@link AdminPassword#create})
     * @param operator   작업자 ID
     * @param command    {@code admin setup} 또는 {@code admin password change}
     * @param reason     사유(최초 설정은 자동 표기)
     * @param now        기록 시각
     * @return 결과
     */
    static Result applyAdmin(Path source, Path output, Path runningJar, byte[] adminBytes, String operator, String command,
                             String reason, Instant now) throws CryptoCli.CliException, CredentialCryptoException {
        checkOperator(operator);
        checkReason(reason);
        Snapshot before = read(source);
        if (before.signed) throw new CryptoCli.CliException(Messages.get("jar.err.signed"));
        requireIntact(before);
        if (!before.supportsAdmin()) throw new CryptoCli.CliException(Messages.get("admin.err.legacyJar", name(source)));
        boolean setup = ConfigHistory.ADMIN_SETUP.equals(command);
        if (setup != (before.adminBytes == null)) throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get(setup
                ? "admin.err.alreadySet" : "admin.err.notSetCli"));
        List<ConfigHistory.Change> recorded = Collections.singletonList(setup
                ? new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.ABSENT, ConfigHistory.SECRET_BEFORE)
                : new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.SECRET_BEFORE, ConfigHistory.SECRET_AFTER));
        byte[] historyPlain = ConfigHistory.append(before.history, before.version, now, operator, command,
                reason == null ? "" : reason, recorded, before.settingsBytes);
        if (historyPlain.length > ConfigHistory.MAX_BYTES) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.historyFull"));
        }
        byte[] historyBytes = before.readsObfuscation() ? ConfigHistory.store(historyPlain) : historyPlain;
        return commit(before, source, output, false, runningJar, before.settingsBytes, historyBytes, adminBytes, () -> { },
                Collections.<String>emptyList(), Collections.<String, String>emptyMap(), now);
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

    /** 새 JAR를 쓴 뒤 하는 추가 확인(키 왕복 검사 등). */
    private interface Check {
        void run() throws CredentialCryptoException;
    }

    /**
     * 새 JAR 작성 → 다시 읽어 검증 → 원자적 이동(교체 모드면 백업 후 교체). 실패하면 원본·기존 출력 파일을 그대로 두고 임시 파일을
     * 지운다.
     *
     * @param adminBytes 새 관리자 검증값(바꾸지 않으면 null: 원본 항목을 그대로 옮기고 그대로인지 확인)
     */
    private static Result commit(Snapshot before, Path source, Path output, boolean replace, Path runningJar,
                                 byte[] newSettingsBytes, byte[] historyBytes, byte[] adminBytes, Check check,
                                 List<String> changed, Map<String, String> beforeValues, Instant now)
            throws CryptoCli.CliException, CredentialCryptoException {
        Path target = replace ? source : output;
        if (replace) {
            if (runningJar != null && sameFile(source, runningJar)) {
                throw new CryptoCli.CliException(Messages.get("jar.err.runningJar"));
            }
        } else {
            if (output == null) throw new CryptoCli.CliException(Messages.get("jar.err.noOut"));
            if (sameFile(source, output) || source.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize())) {
                throw new CryptoCli.CliException(Messages.get("jar.err.sameOut"));
            }
        }
        Path dir = target.toAbsolutePath().getParent();
        if (dir == null || !Files.isDirectory(dir)) {
            throw new CryptoCli.CliException(Messages.get("jar.err.noDir", name(target)));
        }
        Path lock = replace ? dir.resolve(target.getFileName() + ".lock") : null;
        boolean lockCreated = false;
        Path placeholder = null;
        Path temp = null;
        Path backup = null;
        boolean success = false;
        try {
            if (lock != null) {
                createLock(lock);
                lockCreated = true;
            }
            if (!replace) placeholder = reserve(output);
            temp = Files.createTempFile(dir, "." + target.getFileName(), ".tmp");
            writeJar(source, temp, newSettingsBytes, historyBytes, adminBytes);
            // 권한(POSIX): 새 결과 JAR는 사용자 키·관리자 검증값이 들어 있으므로 소유자만(600). 원본 교체(--replace)는 운영 중인 파일의
            // 권한을 그대로 둔다(서비스 계정이 계속 읽을 수 있게). Windows는 폴더 ACL을 상속한다.
            if (replace) {
                copyPermissions(source, temp);
            } else {
                ownerOnly(temp);
            }
            Snapshot written = verify(temp, before, newSettingsBytes, adminBytes == null ? before.adminBytes : adminBytes);
            check.run();
            if (replace) {
                // 작업 중 다른 작업이 원본을 바꿨다면 그 변경을 덮어쓰지 않는다(잃어버린 갱신 방지).
                if (!before.fileSha256.equals(sha256(source))) {
                    throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.changedDuring"));
                }
                // 백업 이름: <이름>.bak-<UTC 초>, 같은 초에 이미 있으면 -2, -3 ... (기존 백업을 덮어쓰지 않음)
                for (int n = 1; backup == null; n++) {
                    Path candidate = dir.resolve(target.getFileName() + ".bak-" + compact(now) + (n == 1 ? "" : "-" + n));
                    try {
                        Files.copy(source, candidate, StandardCopyOption.COPY_ATTRIBUTES);
                        backup = candidate;
                        ownerOnly(backup); // 백업(이전 키가 든 JAR)은 배포하지 않으므로 소유자만
                    } catch (FileAlreadyExistsException e) {
                        if (n >= 99) throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.backupExists", name(candidate)));
                    }
                }
                atomicMove(temp, source);
            } else {
                atomicMove(temp, output);
            }
            temp = null;
            success = true;
            return new Result(source, replace ? source : output, replace, backup, Collections.unmodifiableList(changed),
                    beforeValues, written);
        } catch (IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", ioMessage(e, replace));
        } finally {
            if (temp != null) deleteQuietly(temp);
            if (!success) {
                if (placeholder != null) deleteQuietly(placeholder);
                if (backup != null) deleteQuietly(backup);
            }
            // 내가 만든 잠금 파일만 지운다(다른 작업이 잡고 있는 잠금을 지우면 동시 수정을 막지 못함).
            if (lockCreated) deleteQuietly(lock);
        }
    }

    /** 실패 원인 유형별로 사용자가 할 일을 안내한다(경로 전체는 넣지 않는다). */
    private static String ioMessage(IOException e, boolean replace) {
        String hint;
        if (e instanceof AtomicMoveNotSupportedException) {
            hint = Messages.get("jar.io.atomic");
        } else if (e instanceof java.nio.file.FileSystemException) {
            // 권한 없음·사용 중(Windows 파일 잠금)·읽기 전용 파일 시스템 등. OS 메시지는 언어마다 달라 유형으로만 판단한다.
            hint = Messages.get(replace ? "jar.io.inUse" : "jar.io.outDir");
        } else {
            hint = Messages.get("jar.io.disk");
        }
        return Messages.get("jar.io.write", e.getClass().getSimpleName(), hint);
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
     * 원본의 모든 항목을 같은 순서·같은 시각으로 옮기고 설정·이력(관리자 검증값을 바꾸면 그 항목도)만 새 내용으로 쓴다. 끝나면 디스크에
     * 강제로 기록한다.
     *
     * @param adminBytes 새 관리자 검증값(null이면 원본 항목을 그대로 옮김)
     */
    private static void writeJar(Path source, Path temp, byte[] settingsBytes, byte[] historyBytes, byte[] adminBytes)
            throws IOException {
        try (JarFile in = new JarFile(source.toFile(), false);
             OutputStream file = Files.newOutputStream(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
             JarOutputStream out = new JarOutputStream(new java.io.BufferedOutputStream(file))) {
            boolean historyWritten = false;
            boolean adminWritten = false;
            long time = 0L;
            for (Enumeration<JarEntry> entries = in.entries(); entries.hasMoreElements(); ) {
                JarEntry src = entries.nextElement();
                String entryName = src.getName();
                JarEntry dst = new JarEntry(entryName);
                if (src.getTime() != -1) dst.setTime(src.getTime());
                if (SETTINGS_ENTRY.equals(entryName)) time = src.getTime();
                out.putNextEntry(dst);
                if (SETTINGS_ENTRY.equals(entryName)) {
                    out.write(settingsBytes);
                } else if (ConfigHistory.ENTRY.equals(entryName)) {
                    out.write(historyBytes);
                    historyWritten = true;
                } else if (adminBytes != null && AdminPassword.ENTRY.equals(entryName)) {
                    out.write(adminBytes);
                    adminWritten = true;
                } else if (!src.isDirectory()) {
                    try (InputStream data = in.getInputStream(src)) {
                        copy(data, out);
                    }
                }
                out.closeEntry();
            }
            if (!historyWritten) {
                // 최초 변경: 이력 폴더와 파일을 맨 뒤에 추가한다.
                if (in.getEntry("META-INF/java-crypto-kit/") == null) {
                    JarEntry dirEntry = new JarEntry("META-INF/java-crypto-kit/");
                    if (time > 0) dirEntry.setTime(time);
                    out.putNextEntry(dirEntry);
                    out.closeEntry();
                }
                JarEntry history = new JarEntry(ConfigHistory.ENTRY);
                if (time > 0) history.setTime(time);
                out.putNextEntry(history);
                out.write(historyBytes);
                out.closeEntry();
            }
            if (adminBytes != null && !adminWritten) {
                // 최초 관리자 설정: 검증값 항목을 맨 뒤에 추가한다(이력 폴더는 위에서 이미 있음).
                JarEntry admin = new JarEntry(AdminPassword.ENTRY);
                if (time > 0) admin.setTime(time);
                out.putNextEntry(admin);
                out.write(adminBytes);
                out.closeEntry();
            }
        }
        try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    /**
     * 새로 쓴 JAR를 처음부터 다시 읽어 검증한다: ZIP/JAR 구조와 CRC(순차 읽기), Manifest·Main-Class 일치, 원본 항목이 빠짐없이
     * 있는지, 설정이 의도한 내용과 같은지, 이력 검증(이전 기록 + 1건), 설정 재검증, 관리자 검증값이 의도한 내용(바꾸지 않았으면
     * 원본과 같음)인지.
     */
    private static Snapshot verify(Path temp, Snapshot before, byte[] settingsBytes, byte[] adminBytes)
            throws IOException, CryptoCli.CliException {
        try (JarInputStream in = new JarInputStream(Files.newInputStream(temp), true)) {
            if (in.getManifest() == null) throw verifyFailure("jar.verify.manifest");
            byte[] buffer = new byte[8192];
            while (in.getNextJarEntry() != null) {
                while (in.read(buffer) != -1) { /* 끝까지 읽어 CRC·크기를 확인한다 */ }
            }
        } catch (java.util.zip.ZipException e) {
            throw verifyFailure("jar.verify.zip");
        }
        Snapshot written = read(temp);
        if (!same(before.mainClass, written.mainClass)) throw verifyFailure("jar.verify.mainClass");
        if (!same(before.version, written.version)) throw verifyFailure("jar.verify.version");
        if (!written.entryNames.containsAll(before.entryNames)) throw verifyFailure("jar.verify.entries");
        if (!Arrays.equals(settingsBytes, written.settingsBytes)) throw verifyFailure("jar.verify.settings");
        if (written.history.problem != null || !written.history.present
                || written.history.entries.size() != before.history.entries.size() + 1) {
            throw verifyFailure("jar.verify.history");
        }
        if (written.validationError != null) throw verifyFailure("jar.verify.validation");
        if (!Arrays.equals(adminBytes, written.adminBytes)) throw verifyFailure("jar.verify.admin");
        // 결과 JAR도 같은 상태 판단으로 다시 확인한다(관리자 검증값과 이력의 관리자 기록이 맞아야 함).
        if (AdminPassword.statusOf(written).state == AdminPassword.State.DAMAGED) throw verifyFailure("jar.verify.admin");
        return written;
    }

    private static CryptoCli.CliException verifyFailure(String whatKey) {
        return new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.verify", Messages.get(whatKey)));
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

    /** 결과 파일 이름을 먼저 차지한다(이미 있으면 덮어쓰지 않고 거부, 두 작업이 같은 출력에 쓰는 것도 막음). */
    private static Path reserve(Path output) throws CryptoCli.CliException, IOException {
        try {
            return Files.createFile(output);
        } catch (FileAlreadyExistsException e) {
            throw new CryptoCli.CliException(Messages.get("jar.err.outExists", name(output)));
        }
    }

    /** 잠금 파일을 만든다(같은 JAR를 동시에 교체하지 못하게 함). */
    private static void createLock(Path lock) throws CryptoCli.CliException, IOException {
        try {
            Files.createFile(lock);
        } catch (FileAlreadyExistsException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("jar.err.lock", name(lock)));
        }
    }

    /** 같은 폴더 안의 원자적 이동. 원자적 이동을 보장할 수 없으면(AtomicMoveNotSupportedException) 교체하지 않는다. */
    private static void atomicMove(Path temp, Path target) throws IOException {
        // 결과 파일 이름은 reserve로 먼저 만들어 두었으므로(빈 파일) 두 경우 모두 그 자리를 원자적으로 바꾼다.
        Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    /** 원본 교체(--replace)에서만: POSIX에서 원본 JAR의 권한을 교체 결과에 적용한다(운영 중인 Tomcat이 계속 읽을 수 있게). */
    private static void copyPermissions(Path source, Path temp) throws IOException {
        if (posix()) Files.setPosixFilePermissions(temp, Files.getPosixFilePermissions(source));
    }

    /** POSIX에서 소유자만 읽고 쓰게 한다(600). POSIX 권한이 없는 파일 시스템(Windows)은 폴더의 ACL을 상속한다. */
    private static void ownerOnly(Path file) throws IOException {
        if (posix()) Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
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

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
    }

    private static boolean hasControl(String text) {
        for (int i = 0; i < text.length(); i++) if (Character.isISOControl(text.charAt(i))) return true;
        return false;
    }

    private static boolean same(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }

    /** 오류 메시지용 이름: 안전한 형식이 아니면 표시하지 않는다. */
    private static String safeName(String key) {
        return key.matches("[A-Za-z0-9._-]{1,80}") ? key : Messages.get("jar.name.unsafe");
    }

    /** 파일 이름만(전체 경로는 오류 메시지에 넣지 않는다). */
    static String name(Path path) {
        Path fileName = path.getFileName();
        return fileName == null ? Messages.get("jar.name.none") : SecretFiles.fileName(path);
    }

    /** 백업 파일 이름용 시각(예: 20261121T053012Z). */
    static String compact(Instant now) {
        return now.truncatedTo(ChronoUnit.SECONDS).toString().replace("-", "").replace(":", "");
    }

    private static boolean sameFile(Path a, Path b) {
        try {
            return Files.exists(a) && Files.exists(b) && Files.isSameFile(a, b);
        } catch (IOException e) {
            return false;
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // 정리 실패는 결과에 영향을 주지 않는다(임시·잠금 파일 이름은 고유하거나 안내 문구에 포함됨).
        }
    }
}
