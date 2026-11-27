package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.key.aws.AwsKmsKeyProvider;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: JAR 내부 키 목록을 바꾸는 {@code config key add / use / remove}와, {@code config embed-key}가 AES 키를
 * 바꿀 때 이전 키를 키 목록에 남기는 처리를 맡는다. JAR 읽기·쓰기·검증·이력은 {@link JarConfigEditor}가 한다.
 *
 * <p><b>키 추가 규칙</b></p>
 * <ul>
 *   <li>재료(무엇으로 키를 만드는가)와 공급(실행할 때 어디서 읽는가)을 나눈다. 재료: {@code --generate}(새로 생성),
 *       {@code --from-file}(파일), {@code --from-jar}(다른 JAR의 같은 Key ID 정의 복사), pass 유형은 입력(숨김 2회). 공급:
 *       {@code --source embedded|file|env|vault|aws-kms}(기본 embedded)와 {@code --location}.</li>
 *   <li>외부 공급원(file·env·vault·aws-kms)은 등록할 때 재료를 한 번 읽어 키 지문을 고정한다({@code crypto.keys.<id>.fingerprint}).
 *       실행 중에 그 위치의 값이 바뀌면 다른 키로 조용히 동작하지 않고 실패한다(값을 바꾸려면 새 Key ID로 회전).</li>
 *   <li>pass 유형은 키마다 새 난수 Salt(16바이트)와 PBKDF2 반복 600,000회로 AES 키를 파생한다. embedded·aws-kms는 파생한 키만
 *       저장하며 Passphrase 원문은 JAR에 들어가지 않는다({@code --from-jar}로도 원문을 꺼낼 수 없다).</li>
 *   <li>Key ID: 영문·숫자·_·- 1~64자. 공개 기본 키 전용 ID({@code pass-default}·{@code default}), 이미 등록된 ID, 이 JAR 이력에서 쓰인 ID는
 *       거부한다(같은 Key ID가 다른 키를 가리키면 예전 암호문의 실패 원인을 구분할 수 없다). 공개 기본 키와 같은 재료, 이미 등록된
 *       키와 같은 재료도 거부한다.</li>
 *   <li>키를 추가해도 기본 키는 바뀌지 않는다({@code --active} 또는 {@code config key use}로만 바꾼다).</li>
 *   <li>대상 JAR의 키 변경에는 {@code CHANGE} 입력 또는 {@code --yes}가 필요하다. 발행 후 I/O 오류는 현재 키와 이력을 확인하도록 안내한다.</li>
 * </ul>
 */
final class KeyringCommand {
    /** 이전 공개 키의 예약 Key ID(사용자 키에 쓸 수 없다). */
    static final Set<String> RESERVED_IDS = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            PassKdf.PUBLIC_KEY_ID, "default")));
    /** 키 목록(config key)을 지원하는 JAR인지 판별하는 표지 항목(이 클래스가 없는 이전 버전 JAR는 템플릿 프로필을 모른다). */
    static final String KEYRING_MARKER = "io/javacryptokit/KeyType.class";
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Pattern ENV_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,127}");

    private KeyringCommand() { }

    static int run(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        switch (parsed.spec.name) {
            case "config key add":
                return add(parsed, terminals, out);
            case "config key use":
                return use(parsed, terminals, out);
            case "config key show":
                return KeyShowCommand.run(parsed, terminals, out);
            default:
                return remove(parsed, terminals, out);
        }
    }

    // ===================================================================================================
    // 공통
    // ===================================================================================================

    /** 대상 JAR와 그 내부 설정(검증된 것). */
    private static final class Target {
        final Path jar;
        final JarConfigEditor.Snapshot snap;
        final CryptoSettings settings;

        Target(Path jar, JarConfigEditor.Snapshot snap, CryptoSettings settings) {
            this.jar = jar;
            this.snap = snap;
            this.settings = settings;
        }
    }

    /** key add·use·remove 사전 검사(관리자 인증 전, JAR 내용은 읽지 않음): {@code --key-id} 지정과 형식. */
    private static void checkKeyIdOption(CliCommands.Parsed parsed, String missingKey) throws CryptoCli.CliException {
        String keyId = parsed.value("--key-id");
        if (keyId == null) throw new CryptoCli.CliException(Messages.get(missingKey, parsed.spec.name));
        if (!KEY_ID.matcher(keyId).matches()) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdFormat"));
    }

    /** key add·use·remove 사전 검사(관리자 인증 전): 갱신 대상 경로와 작업자 ID. */
    private static void checkOutput(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        JarConfigEditor.checkOperator(parsed.value("--operator"));
        ConfigCommand.checkUpdatePath(ConfigCommand.sourceJar(parsed));
    }

    /** config key use·remove 사전 검사(관리자 인증 전). */
    static void checkUseOrRemove(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        checkKeyIdOption(parsed, "cfg.err.keyIdNeeded");
        CryptoCli.typeOption(parsed);
        checkOutput(parsed);
    }

    /**
     * 대상 JAR를 읽는다(키 목록 지원·서명·이력·설정 검증). {@link CryptoCli}가 사전 검사·관리자 인증을 마친 뒤에만 부른다. 사유는
     * 각 명령이 JAR 기준 검사(등록 여부·이력에서 쓰인 Key ID 등)를 마친 뒤, 재료 입력·키 생성·KMS 호출·JAR 변경보다 먼저 받는다.
     */
    private static Target target(CliCommands.Parsed parsed) throws CryptoCli.CliException, CredentialCryptoException {
        Path jar = ConfigCommand.sourceJar(parsed);
        JarConfigEditor.Snapshot snap = parsed.admin.snapshot(jar);
        if (!supportsKeyring(snap)) throw new CryptoCli.CliException(Messages.get("cfg.err.noKeyring", JarConfigEditor.name(jar)));
        if (snap.signed) throw new CryptoCli.CliException(Messages.get("jar.err.signed"));
        if (snap.history.problem != null) throw new CryptoCli.CliException("INTEGRITY", Messages.get("jar.err.historyInvalid"));
        return new Target(jar, snap, validated(snap));
    }

    /** @return 이 JAR가 키 목록(템플릿 프로필)을 지원하는 버전이면 true */
    static boolean supportsKeyring(JarConfigEditor.Snapshot snap) {
        return snap.entryNames.contains(KEYRING_MARKER);
    }

    /** @return JAR 내부 설정을 검증한 설정(외부 설정·-D 없음). 검증 실패면 CONFIGURATION */
    static CryptoSettings validated(JarConfigEditor.Snapshot snap) throws CredentialCryptoException {
        CryptoSettings settings = snap.validated();
        if (settings == null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("cfg.err.jarInvalid", snap.validationError == null ? "" : snap.validationError));
        }
        return settings;
    }

    /**
     * 새 키에 쓸 Key ID 검사: 형식, 공개 기본 키 전용 ID, 이미 등록됨, 이 JAR 이력에서 쓰인 ID. 이력에서 쓰인 ID는 같은 키를 되살리는
     * 복원만 허용하므로, 재료가 기존 키일 수 있으면({@code restoreCapable}: 파일·다른 JAR·외부 공급원) 키를 만든 뒤
     * {@link #checkRestore}로 확인하고, 새로 생성·입력하는 재료면 여기서 바로 거부한다.
     *
     * @throws CryptoCli.CliException 쓸 수 없는 Key ID
     */
    static void checkNewKeyId(String keyId, CryptoSettings settings, JarConfigEditor.Snapshot snap, boolean restoreCapable)
            throws CryptoCli.CliException {
        if (!KEY_ID.matcher(keyId).matches()) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdFormat"));
        if (RESERVED_IDS.contains(keyId)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdReserved", keyId));
        if (settings.profile(keyId) != null) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdRegistered", keyId));
        if (!restoreCapable && snap.history.usedKeyIds().contains(keyId)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdUsedBefore", keyId));
        }
    }

    /**
     * 이 JAR 이력에서 쓰인 Key ID에 키를 다시 등록하려면 같은 키여야 한다: 이력에 남은 그 Key ID의 마지막 키 기록과 유형, 전체 키
     * 지문(SHA-256 64자), pass는 KDF·반복 횟수·Salt의 SHA-256까지 모두 같아야 한다. 하나라도 다르거나 비교할 기록이 없으면 거부한다
     * (같은 Key ID에 다른 키를 조용히 넣지 않음). 이력에서 쓰이지 않은 Key ID면 아무것도 하지 않는다.
     *
     * @param candidate 등록하려는 키의 기록({@link KeyringView#record})
     * @return 이력에서 쓰인 Key ID를 같은 키로 복원하면 true
     * @throws CryptoCli.CliException 같은 키가 아닌 경우
     */
    static boolean checkRestore(String keyId, ConfigHistory.KeyRecord candidate, JarConfigEditor.Snapshot snap)
            throws CryptoCli.CliException {
        if (!snap.history.usedKeyIds().contains(keyId)) return false;
        ConfigHistory.KeyRecord recorded = snap.history.lastRecord(keyId);
        if (recorded == null || recorded.fingerprint == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdUsedBefore", keyId));
        }
        List<String> different = new ArrayList<>();
        if (!recorded.type.equals(candidate.type)) different.add(Messages.get("cfg.restore.type"));
        if (!recorded.fingerprint.equals(candidate.fingerprint)) different.add(Messages.get("cfg.restore.fingerprint"));
        // KDF 항목은 둘 다 pass일 때만 비교해 알린다(유형이 다르면 유형·지문 차이만으로 충분하고, 거부는 위에서 이미 정해짐).
        if (KeyType.PASS.code().equals(recorded.type) && KeyType.PASS.code().equals(candidate.type)) {
            if (!java.util.Objects.equals(recorded.kdf, candidate.kdf)) different.add(Messages.get("cfg.restore.kdf"));
            if (!java.util.Objects.equals(recorded.iterations, candidate.iterations)) {
                different.add(Messages.get("cfg.restore.iterations"));
            }
            if (recorded.saltSha256 == null || !recorded.saltSha256.equals(candidate.saltSha256)) {
                different.add(Messages.get("cfg.restore.salt"));
            }
        }
        if (!different.isEmpty()) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdRestoreMismatch", keyId, String.join(", ", different)));
        }
        return true;
    }

    /** Keeps an established AES identity when its material is moved without changing its ID. */
    static void checkEstablishedKey(String id, ConfigHistory.KeyRecord established, String fingerprint)
            throws CredentialCryptoException {
        if (established == null || established.fingerprint == null) return;
        if (fingerprint == null || !KeyType.KEY.code().equals(established.type) || !established.fingerprint.equals(fingerprint)) {
            String message = fingerprint == null ? "cfg.err.slotKeyUnverified" : "cfg.err.slotKeyMismatch";
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, Messages.get(message, id));
        }
    }

    /**
     * 같은 키(지문)가 이미 다른 Key ID로 등록되어 있으면 거부한다. 내장 키는 값으로, 외부 키는 고정 지문으로 비교한다(고정 지문이 없는
     * 레거시 외부 키는 비교하지 않는다).
     */
    static void checkNotRegistered(CryptoSettings settings, String fingerprint) throws CryptoCli.CliException {
        for (KeyProfile profile : settings.profiles()) {
            String known = KeyringView.jarFingerprint(profile);
            if (known != null && known.equals(fingerprint)) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.keyDuplicate", profile.id()));
            }
        }
    }

    // ===================================================================================================
    // config key add
    // ===================================================================================================

    /** 등록할 새 키(설정 항목 값과 확인용 정보). 재료 원문은 내보내기·대화형 표시에만 잠시 보관하고 바로 지운다. */
    private static final class NewKey {
        final KeyType type;
        final String source;
        /** 항목 이름(예: {@code type}) → 값. */
        final Map<String, String> items;
        /** 실제 AES 키(또는 파생 키)의 지문(64자). */
        final String fingerprint;
        /** 출처({@link KeyringView#ORIGINS}). */
        final String origin;
        /** --export로 한 번 저장할 내용(key: keygen 형식 한 줄, pass: 백업 파일). 없으면 null. */
        final byte[] exportBytes;
        /** 자동 생성한 원문(대화형 표시용: pass는 Passphrase, key는 표준 Base64 44자). 생성하지 않았으면 null. */
        final char[] secret;
        /** aws-kms로 새로 만든 데이터 키 파일 내용(없으면 null). */
        final byte[] dataKeyFile;
        /** pass 백업 파일에서 Salt·반복 횟수를 되살렸으면 true. */
        final boolean fromBackup;
        /** 한 줄 Passphrase 파일로 새 Salt를 만들었으면 true(같은 Passphrase라도 이전 등록과 다른 키). */
        final boolean newSalt;

        NewKey(KeyType type, String source, Map<String, String> items, String fingerprint, String origin, byte[] exportBytes,
               char[] secret, byte[] dataKeyFile, boolean fromBackup, boolean newSalt) {
            this.type = type;
            this.source = source;
            this.items = items;
            this.fingerprint = fingerprint;
            this.origin = origin;
            this.exportBytes = exportBytes;
            this.secret = secret;
            this.dataKeyFile = dataKeyFile;
            this.fromBackup = fromBackup;
            this.newSalt = newSalt;
        }

        /** @return 이력 기록(출처를 바꿔 쓸 수 있음) */
        ConfigHistory.KeyRecord record(String recordOrigin) {
            return KeyringView.record(type, source, recordOrigin, fingerprint, type == KeyType.PASS ? items : null, false, false);
        }

        void wipe() {
            if (exportBytes != null) Arrays.fill(exportBytes, (byte) 0);
            if (secret != null) Arrays.fill(secret, '\0');
            if (dataKeyFile != null) Arrays.fill(dataKeyFile, (byte) 0);
        }
    }

    /**
     * config key add 사전 검사(관리자 인증 전, JAR 내용·키 재료는 읽지 않음): Key ID 지정·형식, 재료·공급원 옵션 조합, 비대화형 생성의
     * {@code --export}, 결과·내보내기·데이터 키 파일 자리.
     */
    static void checkAdd(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals) throws CryptoCli.CliException {
        checkKeyIdOption(parsed, "cfg.err.keyAddNeeds");
        String source = supply(parsed, terminals);
        checkOutput(parsed);
        String export = parsed.value("--export");
        if (export != null) newFilePath(export, "--export");
        if (createsDataKey(parsed, source)) newFilePath(parsed.value("--location"), "--location");
    }

    /**
     * key add의 재료(--from-jar·--from-file·--generate 중 하나)와 공급원 옵션 조합을 검사한다.
     *
     * @return 새 키의 공급원(--from-jar면 null: 원본 JAR의 정의를 그대로 씀)
     */
    private static String supply(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals) throws CryptoCli.CliException {
        KeyType type = CryptoCli.typeOption(parsed);
        String fromJar = parsed.value("--from-jar");
        String fromFile = parsed.value("--from-file");
        boolean generate = parsed.flag("--generate");
        String export = parsed.value("--export");
        String sourceOption = parsed.value("--source");
        String location = parsed.value("--location");
        int materials = (fromJar != null ? 1 : 0) + (fromFile != null ? 1 : 0) + (generate ? 1 : 0);
        if (materials > 1) throw new CryptoCli.CliException(Messages.get("cfg.err.keyMaterialOne"));
        if (export != null && !generate) throw new CryptoCli.CliException(Messages.get("cfg.err.keyExportGenerate"));
        if (fromJar != null && (sourceOption != null || location != null)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyFromJarSupply"));
        }
        String source = fromJar != null ? null : (sourceOption == null ? "embedded" : sourceOption);
        if (source != null) checkSupply(type == null ? KeyType.PASS : type, source, location, generate, fromFile != null);
        // 자동 생성값은 대화형 터미널에서만 보여 준다. 대화형이 아니면 원문을 받을 곳(--export)이 있어야 하며, 없으면 만들기 전에 멈춘다.
        if (generate && export == null && CryptoCli.interactive(terminals) == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.generateNeedsExport"));
        }
        return source;
    }

    /** @return aws-kms로 새 데이터 키 파일을 만드는 경우 true(KMS를 부르기 전에 파일 자리를 확인, 기존 파일은 덮어쓰지 않음) */
    private static boolean createsDataKey(CliCommands.Parsed parsed, String source) throws CryptoCli.CliException {
        KeyType type = CryptoCli.typeOption(parsed);
        return "aws-kms".equals(source) && (parsed.flag("--generate") || parsed.value("--from-file") != null
                || (type == null ? KeyType.PASS : type) == KeyType.PASS);
    }

    private static int add(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        // 사전 검사(checkAdd)·관리자 인증(실행 중인 JAR·--jar·--from-jar)은 CryptoCli가 마쳤다. 여기서부터 JAR 내용·재료를 다룬다.
        String keyId = parsed.value("--key-id");
        KeyType type = CryptoCli.typeOption(parsed);
        String fromJar = parsed.value("--from-jar");
        String fromFile = parsed.value("--from-file");
        boolean generate = parsed.flag("--generate");
        String export = parsed.value("--export");
        String location = parsed.value("--location");
        String source = supply(parsed, terminals);
        KeyType chosen = type == null ? KeyType.PASS : type;

        Target target = target(parsed);
        // 기존 키일 수 있는 재료(파일·다른 JAR·외부 공급원)는 키를 만든 뒤 이력의 같은 키인지 확인한다(복원).
        boolean restoreCapable = !generate && (fromJar != null || fromFile != null || !"embedded".equals(source));
        checkNewKeyId(keyId, target.settings, target.snap, restoreCapable);
        Path output = target.jar;
        Path exportPath = export == null ? null : newFilePath(export, "--export");
        Path dataKeyPath = createsDataKey(parsed, source) ? newFilePath(location, "--location") : null;
        // 사유: JAR 기준 검사를 마친 뒤, 재료 입력·생성·KMS 호출보다 먼저(사유 → 재료 → 바꿀 내용 → CHANGE).
        String reason = CryptoCli.reasonOption(parsed, terminals);

        NewKey key = fromJar != null ? copyFromJar(parsed.admin.snapshot(path(fromJar, "--from-jar")), keyId, type)
                : build(keyId, chosen, source, location, generate, fromFile, terminals, target);
        try {
            boolean restoredFromHistory = checkRestore(keyId, key.record(key.origin), target.snap);
            checkNotRegistered(target.settings, key.fingerprint);
            Map<String, String> values = new LinkedHashMap<>();
            for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
                String value = key.items.get(item.name);
                if (value != null) values.put(KeyProfile.PREFIX + keyId + "." + item.name, value);
            }
            if (parsed.flag("--active")) values.put(activeSetting(key.type), keyId);
            String origin = restoredFromHistory || key.fromBackup ? "restored" : key.origin;
            List<ConfigHistory.Change> summaries = Collections.singletonList(new ConfigHistory.Change(
                    ConfigHistory.KEY_SUMMARY_PREFIX + keyId, ConfigHistory.ABSENT, key.record(origin).format()));

            List<String> items = new ArrayList<>();
            for (Map.Entry<String, String> item : values.entrySet()) {
                items.add(ConfigCommand.change(item.getKey(), target.snap.settings.getProperty(item.getKey()), item.getValue()));
            }
            if (!ConfigCommand.confirm(parsed, terminals, out, Messages.get("cfg.confirm.keyAdd"), output, items, reason)) {
                return 0;
            }

            // 키 재료 파일(aws-kms 데이터 키, --export 원본)을 먼저 만든다. 발행 전 실패 시 정리하고 발행 후 오류 시 보존한다.
            List<Path> created = new ArrayList<>();
            boolean done = false;
            try {
                if (dataKeyPath != null) {
                    writeNewSecretFile(dataKeyPath, key.dataKeyFile);
                    created.add(dataKeyPath);
                }
                if (exportPath != null) {
                    writeNewSecretFile(exportPath, key.exportBytes);
                    created.add(exportPath);
                }
                JarConfigEditor.Change change = new JarConfigEditor.Change("key add", values, Collections.<String>emptySet(),
                        summaries, parsed.value("--operator"), reason);
                JarConfigEditor.Result result = JarConfigEditor.apply(target.snap, change, Instant.now());
                done = true;
                ConfigCommand.printResult(result, out);
                out.println(Messages.get("cfg.result.keyAdded", keyId, key.type.code(), key.source,
                        KeyResolver.shortFingerprint(key.fingerprint)));
                if (key.fromBackup) {
                    out.println(Messages.get("cfg.result.restoredBackup"));
                } else if (restoredFromHistory) {
                    out.println(Messages.get("cfg.result.restoredHistory"));
                } else if (key.newSalt) {
                    out.println(Messages.get("cfg.result.newSalt"));
                }
                if (dataKeyPath != null) out.println(Messages.get("cfg.result.dataKey", display(dataKeyPath)));
                if (exportPath != null) out.println(Messages.get("cfg.result.exported", display(exportPath)));
                // 자동 생성값: 모든 작업이 성공한 뒤 대화형 터미널에만 한 번 보여 준다(표준 출력·로그에는 쓰지 않음).
                if (key.secret != null) {
                    CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
                    if (terminal != null) {
                        out.flush();
                        KeyringView.showGenerated(terminal, key.type, keyId, key.secret,
                                key.type == KeyType.PASS ? key.items : null, key.type == KeyType.PASS ? key.fingerprint : null,
                                exportPath != null ? KeyringView.Kept.EXPORT : KeyringView.Kept.NONE);
                    }
                }
                return 0;
            } catch (CryptoCli.CliException e) {
                // Keep explicitly requested key files when publication succeeded before an I/O failure.
                if (JarConfigEditor.publicationInterrupted(e)) done = true;
                throw e;
            } finally {
                if (!done) for (Path file : created) deleteQuietly(file);
            }
        } finally {
            key.wipe();
        }
    }

    /** 재료·공급 옵션 조합 검사(입력을 받거나 JAR를 읽기 전에). */
    private static void checkSupply(KeyType type, String source, String location, boolean generate, boolean fromFile)
            throws CryptoCli.CliException {
        if (!SettingCatalog.KEY_SOURCES.contains(source)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keySourceValue", String.join(", ", SettingCatalog.KEY_SOURCES)));
        }
        boolean embedded = "embedded".equals(source);
        if (embedded && location != null) throw new CryptoCli.CliException(Messages.get("cfg.err.keyLocationEmbedded"));
        if (!embedded && (location == null || location.trim().isEmpty() || !location.equals(location.trim()))) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyLocationNeeded", source));
        }
        if (generate && !embedded && !"aws-kms".equals(source)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyGenerateSource"));
        }
        if (embedded && type == KeyType.KEY && !generate && !fromFile) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyMaterialNeeded"));
        }
        if ("env".equals(source) && !ENV_NAME.matcher(location).matches()) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.envName"));
        }
    }

    /**
     * 새 재료로 키를 만든다: 생성·파일·입력·외부 공급원 한 번 읽기. 외부 공급원은 지문을 고정하고, aws-kms는 데이터 키 파일 내용을
     * 만든다(파일은 확인 뒤에 쓴다).
     */
    private static NewKey build(String keyId, KeyType type, String source, String location, boolean generate, String fromFile,
                                CryptoCli.TerminalProvider terminals, Target target) throws Exception {
        Map<String, String> items = new LinkedHashMap<>();
        items.put(KeyProfile.TYPE, type.code());
        items.put(KeyProfile.SOURCE, source);
        switch (source) {
            case "file":
                items.put(KeyProfile.FILE, location);
                break;
            case "env":
                items.put(KeyProfile.ENV, location);
                break;
            case "vault": {
                int hash = location.lastIndexOf('#');
                items.put(KeyProfile.VAULT_PATH, hash > 0 ? location.substring(0, hash) : location);
                if (hash > 0 && hash < location.length() - 1) items.put(KeyProfile.VAULT_FIELD, location.substring(hash + 1));
                break;
            }
            case "aws-kms":
                items.put(KeyProfile.AWS_KMS_DATA_KEY_FILE, location);
                break;
            default:
                break;
        }
        if (type == KeyType.PASS) {
            items.put(KeyProfile.KDF, PassKdf.NAME);
            items.put(KeyProfile.KDF_ITERATIONS, String.valueOf(SettingCatalog.KDF_DEFAULT_ITERATIONS));
            items.put(KeyProfile.SALT, Base64.getEncoder().encodeToString(PassKdf.newSalt()));
        }
        boolean external = !"embedded".equals(source);
        boolean kms = "aws-kms".equals(source);
        byte[] key = null;
        byte[] exportBytes = null;
        char[] secret = null;
        byte[] blob = null;
        boolean built = false;
        String origin;
        boolean fromBackup = false;
        boolean newSalt = false;
        try {
            if (external && !kms && !generate && fromFile == null) {
                // 실행할 때와 같은 위치에서 재료를 한 번 읽어 지문을 계산한다.
                key = probe(keyId, type, items, target.settings);
                origin = "external";
            } else if (kms && type == KeyType.KEY && !generate && fromFile == null) {
                // 이미 있는 데이터 키 파일을 KMS로 풀어 지문을 계산한다(파일은 그대로 둔다).
                key = probe(keyId, type, items, target.settings);
                origin = "external";
            } else if (type == KeyType.KEY) {
                if (generate && kms) {
                    AwsKmsKeyProvider.DataKey dataKey = kmsCall(() -> AwsKmsKeyProvider.generate(connection(), keyId));
                    try {
                        key = dataKey.plaintext.clone();
                        blob = dataKey.ciphertextBlob.clone();
                    } finally {
                        dataKey.wipe();
                    }
                } else if (generate) {
                    key = new byte[32];
                    new SecureRandom().nextBytes(key);
                } else {
                    if (PassBackup.isBackupFile(path(fromFile, "--from-file"))) {
                        throw new CryptoCli.CliException(Messages.get("cfg.err.backupType"));
                    }
                    key = readAesKeyFile(fromFile);
                }
                origin = generate ? "generated" : "file";
                if (generate) {
                    // 내보내기·화면 표시 모두 keygen 키 파일과 같은 표준 Base64 한 줄(32바이트)이다.
                    byte[] encoded = Base64.getEncoder().encode(key);
                    secret = new char[encoded.length];
                    for (int i = 0; i < encoded.length; i++) secret[i] = (char) encoded[i];
                    exportBytes = lineBytes(encoded);
                }
            } else {
                char[] passphrase = null;
                PassBackup backup = null;
                try {
                    if (generate) {
                        passphrase = PassKdf.generate();
                    } else if (fromFile != null) {
                        byte[] raw = readPassFileBytes(fromFile);
                        try {
                            if (PassBackup.isBackup(raw)) {
                                backup = PassBackup.parse(raw);
                                passphrase = backup.passphrase;
                            } else {
                                passphrase = plainPassphrase(raw);
                            }
                        } finally {
                            Arrays.fill(raw, (byte) 0);
                        }
                    } else {
                        passphrase = promptPassphrase(terminals);
                    }
                    if (backup != null) {
                        // 백업 복원: 같은 Key ID·KDF·반복 횟수·Salt로 파생해 백업의 지문과 같은 키인지 확인한다.
                        if (!backup.keyId.equals(keyId)) {
                            throw new CryptoCli.CliException(Messages.get("cfg.err.backupKeyId", backup.keyId, keyId));
                        }
                        items.put(KeyProfile.KDF, backup.kdf);
                        items.put(KeyProfile.KDF_ITERATIONS, backup.iterations);
                        items.put(KeyProfile.SALT, backup.salt);
                    }
                    key = derive(passphrase, items);
                    if (backup != null && !KeyResolver.fingerprint(key).equals(backup.fingerprint)) {
                        throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                                Messages.get("cfg.err.backupFingerprint"));
                    }
                    fromBackup = backup != null;
                    newSalt = fromFile != null && backup == null;
                    origin = generate ? "generated" : backup != null ? "restored" : fromFile != null ? "file" : "input";
                    if (generate) {
                        secret = passphrase.clone();
                        exportBytes = PassBackup.write(keyId, items, KeyResolver.fingerprint(key), passphrase);
                    }
                } finally {
                    if (passphrase != null) Arrays.fill(passphrase, '\0');
                }
            }
            if (DefaultKeyWarning.isPublicDefaultKey(key)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyPublic"));
            String fingerprint = KeyResolver.fingerprint(key);
            if (!external) {
                items.put(KeyProfile.EMBEDDED, Base64.getEncoder().encodeToString(key));
            } else {
                items.put(KeyProfile.FINGERPRINT, fingerprint);
            }
            if (kms && blob == null && (generate || fromFile != null || type == KeyType.PASS)) {
                final byte[] wrapKey = key;
                blob = kmsCall(() -> AwsKmsKeyProvider.wrap(connection(), keyId, wrapKey));
            }
            byte[] dataKeyFile = blob == null ? null : lineBytes(Base64.getEncoder().encode(blob));
            built = true;
            return new NewKey(type, source, items, fingerprint, origin, exportBytes, secret, dataKeyFile, fromBackup, newSalt);
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
            if (blob != null) Arrays.fill(blob, (byte) 0);
            if (!built && exportBytes != null) Arrays.fill(exportBytes, (byte) 0);
            if (!built && secret != null) Arrays.fill(secret, '\0');
        }
    }

    /** Passphrase를 검사·정규화해 이 키의 Salt·반복 횟수로 AES 키를 파생한다(공개 예제 Passphrase는 거부). */
    private static byte[] derive(char[] passphrase, Map<String, String> items) throws CryptoCli.CliException, CredentialCryptoException {
        char[] normalized = null;
        try {
            normalized = PassKdf.normalize(passphrase);
            if (PassKdf.isPublicPassphrase(normalized)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyPublic"));
            return PassKdf.derive(normalized, Base64.getDecoder().decode(items.get(KeyProfile.SALT)),
                    Integer.parseInt(items.get(KeyProfile.KDF_ITERATIONS)));
        } catch (SafeMessageException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, e.getMessage());
        } finally {
            if (normalized != null) Arrays.fill(normalized, '\0');
        }
    }

    /** 외부 공급원(또는 기존 KMS 데이터 키 파일)을 실행 때와 같은 방법으로 한 번 읽어 키를 만든다. */
    private static byte[] probe(String keyId, KeyType type, Map<String, String> items, CryptoSettings jarSettings)
            throws CredentialCryptoException {
        KeyProfile probe = KeyProfile.probe(keyId, type, items);
        String source = items.get(KeyProfile.SOURCE);
        try {
            return KeyResolver.probeKey(needsConnection(source) ? connection() : jarSettings, probe);
        } catch (SafeMessageException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        } catch (IOException | IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, Messages.get("service.err.keyRead"), e);
        }
    }

    /** @return 공급원이 연결 설정(주소·토큰·지역)을 쓰면 true(vault·aws-kms) */
    private static boolean needsConnection(String source) {
        return "vault".equals(source) || "aws-kms".equals(source);
    }

    /**
     * Vault·AWS KMS 연결 설정: 실행 설정(JVM {@code -D}, {@code CRYPTO_CONFIG_FILE}, 실행 중인 JAR 값)의 주소·토큰·지역을 쓴다
     * (다른 명령과 같은 설정 탐색 규칙).
     */
    private static CryptoSettings connection() throws CredentialCryptoException {
        return CryptoService.load(null).settings();
    }

    /** KMS 호출 결과(이 라이브러리의 고정 문구는 KEY_SOURCE로 알린다). */
    private interface KmsCall<T> {
        T call() throws CredentialCryptoException;
    }

    private static <T> T kmsCall(KmsCall<T> call) throws CredentialCryptoException {
        try {
            return call.call();
        } catch (SafeMessageException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        }
    }

    /** --from-jar: 다른 JAR에 등록된 같은 Key ID의 정의를 그대로 복사한다(pass 원문은 어느 JAR에도 없다). */
    private static NewKey copyFromJar(JarConfigEditor.Snapshot other, String keyId, KeyType expected) throws Exception {
        Path otherJar = other.jar;
        if (!supportsKeyring(other) && other.settings.getProperty(CryptoSettings.KEY_ID, "").trim().isEmpty()) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.fromJarMissing", keyId, JarConfigEditor.name(otherJar)));
        }
        CryptoSettings settings = validated(other);
        KeyProfile profile = settings.profile(keyId);
        if (profile == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.fromJarMissing", keyId, JarConfigEditor.name(otherJar)));
        }
        if (expected != null && profile.type() != expected) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("config.err.keyTypeMismatch", keyId, profile.type().code(), expected.code()));
        }
        Map<String, String> items = new LinkedHashMap<>();
        if (profile.legacy()) {
            if (!"embedded".equals(profile.source())) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.fromJarLegacyExternal", keyId));
            }
            items.put(KeyProfile.TYPE, KeyType.KEY.code());
            items.put(KeyProfile.SOURCE, "embedded");
            items.put(KeyProfile.EMBEDDED, profile.value(KeyProfile.EMBEDDED));
        } else {
            for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
                String raw = other.settings.getProperty(KeyProfile.PREFIX + keyId + "." + item.name);
                if (raw != null) items.put(item.name, raw.trim());
            }
        }
        String fingerprint = KeyringView.jarFingerprint(profile);
        if (fingerprint == null) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.fromJarMissing", keyId, JarConfigEditor.name(otherJar)));
        }
        if ("embedded".equals(profile.source())) {
            byte[] key = KeyResolver.decodeEmbedded(profile.value(KeyProfile.EMBEDDED));
            try {
                if (DefaultKeyWarning.isPublicDefaultKey(key)) throw new CryptoCli.CliException(Messages.get("cfg.err.keyPublic"));
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
        return new NewKey(profile.type(), profile.source(), items, fingerprint, "copied", null, null, null, false, false);
    }

    /** pass 입력: 화면에 표시하지 않고 두 번 받아 같은지 확인한다(빈 값·불일치는 거부, 길이 정책 없음). */
    private static char[] promptPassphrase(CryptoCli.TerminalProvider terminals) throws CryptoCli.CliException {
        CryptoCli.Terminal terminal = terminals.open();
        char[] first = terminal.readSecret(Messages.get("cfg.key.passPrompt") + " ");
        char[] second = null;
        try {
            if (first == null || first.length == 0) throw new CryptoCli.CliException(Messages.get("cli.err.noInput"));
            second = terminal.readSecret(Messages.get("cfg.key.passConfirm") + " ");
            if (second == null || !Arrays.equals(first, second)) {
                throw new CryptoCli.CliException(Messages.get("cfg.err.passMismatch"));
            }
            return first.clone();
        } finally {
            if (first != null) Arrays.fill(first, '\0');
            if (second != null) Arrays.fill(second, '\0');
        }
    }

    /** pass 재료 파일(한 줄 Passphrase 파일 또는 pass 키 백업)을 원본 바이트로 읽는다(백업 상한까지, 일반 파일만). */
    private static byte[] readPassFileBytes(String file) throws CredentialCryptoException, CryptoCli.CliException {
        Path path = path(file, "--from-file");
        try {
            return SecretFiles.readBytes(path, PassBackup.MAX_BYTES, "--from-file");
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

    /** 한 줄 Passphrase 파일(UTF-8, 1KiB 이하, 앞의 BOM 하나·끝 줄바꿈 하나는 제외)을 해석한다(기존 형식, 새 Salt로 등록). */
    private static char[] plainPassphrase(byte[] raw) throws CredentialCryptoException {
        if (raw.length > PassKdf.MAX_FILE_BYTES) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("key.err.tooLarge", "--from-file", PassKdf.MAX_FILE_BYTES));
        }
        try {
            return PassKdf.decodeUtf8(raw, true);
        } catch (IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        }
    }

    /** AES 키 파일(keygen 형식)을 읽는다. */
    private static byte[] readAesKeyFile(String file) throws CredentialCryptoException, CryptoCli.CliException {
        Path path = path(file, "--from-file");
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
    // config key use
    // ===================================================================================================

    private static int use(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        // 사전 검사(checkUseOrRemove)·관리자 인증은 CryptoCli가 마쳤다. 등록 여부 등 JAR 기준 검사는 여기서부터.
        String keyId = parsed.value("--key-id");
        KeyType type = CryptoCli.typeOption(parsed);
        Target target = target(parsed);
        KeyProfile profile = registered(target.settings, keyId, type);
        if (KeyringView.isActive(target.settings, profile)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyAlreadyActive", keyId, profile.type().code()));
        }
        String setting = activeSetting(profile.type());
        // key 유형의 crypto.key.* AES 키는 빈 값으로 둔다(빈 값 = crypto.key.*를 따른다. 이후 embed-key로 바꿔도 따라간다).
        String value = profile.legacy() ? "" : keyId;
        Map<String, String> values = Collections.singletonMap(setting, value);
        Path output = target.jar;
        String reason = CryptoCli.reasonOption(parsed, terminals);
        List<String> items = Collections.singletonList(ConfigCommand.change(setting, target.snap.settings.getProperty(setting), value));
        if (!ConfigCommand.confirm(parsed, terminals, out, Messages.get("cfg.confirm.keyUse"), output, items, reason)) return 0;
        JarConfigEditor.Change change = new JarConfigEditor.Change("key use", values, parsed.value("--operator"), reason);
        JarConfigEditor.Result result = JarConfigEditor.apply(target.snap, change, Instant.now());
        ConfigCommand.printResult(result, out);
        out.println(Messages.get("cfg.result.active", profile.type().code(), keyId));
        return 0;
    }

    // ===================================================================================================
    // config key remove
    // ===================================================================================================

    private static int remove(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        // 사전 검사(checkUseOrRemove)·관리자 인증은 CryptoCli가 마쳤다. 등록 여부 등 JAR 기준 검사는 여기서부터.
        String keyId = parsed.value("--key-id");
        Target target = target(parsed);
        KeyProfile profile = registered(target.settings, keyId, null);
        if (profile.legacy()) throw new CryptoCli.CliException(Messages.get("cfg.err.keyRemoveLegacy", keyId));
        if (KeyringView.isActive(target.settings, profile)) {
            throw new CryptoCli.CliException(Messages.get("cfg.err.keyRemoveActive", keyId, profile.type().code()));
        }
        // 지울 항목: 이 Key ID의 모든 키 프로필 줄(추가할 때와 같은 항목 순서로).
        List<String> ordered = new ArrayList<>();
        for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
            String name = KeyProfile.PREFIX + keyId + "." + item.name;
            if (target.snap.settings.containsKey(name)) ordered.add(name);
        }
        if (ordered.isEmpty()) throw new CryptoCli.CliException(Messages.get("jar.err.noChange"));
        Path output = target.jar;
        String reason = CryptoCli.reasonOption(parsed, terminals);
        List<String> items = new ArrayList<>();
        for (String name : ordered) items.add(ConfigCommand.change(name, target.snap.settings.getProperty(name), null));
        if (!ConfigCommand.confirm(parsed, terminals, out, Messages.get("cfg.confirm.keyRemove"), output, items, reason)) {
            return 0;
        }
        // 이전 값: 이력에 남은 이 키의 마지막 기록을 그대로(없으면 지금 JAR의 정보로 만든 기록).
        String recorded = target.snap.history.lastAfter(ConfigHistory.KEY_SUMMARY_PREFIX + keyId);
        List<ConfigHistory.Change> summaries = Collections.singletonList(new ConfigHistory.Change(
                ConfigHistory.KEY_SUMMARY_PREFIX + keyId, recorded != null ? recorded : KeyringView.record(profile, null).format(),
                ConfigHistory.ABSENT));
        JarConfigEditor.Change change = new JarConfigEditor.Change("key remove", Collections.<String, String>emptyMap(),
                new LinkedHashSet<>(ordered), summaries, parsed.value("--operator"), reason);
        JarConfigEditor.Result result = JarConfigEditor.apply(target.snap, change, Instant.now());
        ConfigCommand.printResult(result, out);
        out.println(Messages.get("cfg.result.keyRemoved", keyId));
        return 0;
    }

    /** 등록된 키를 찾는다(없으면 CONFIGURATION, 유형을 주면 같아야 함). */
    private static KeyProfile registered(CryptoSettings settings, String keyId, KeyType type) throws CredentialCryptoException {
        KeyProfile profile = settings.profile(keyId);
        if (profile == null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("config.err.keyIdUnknown", KEY_ID.matcher(keyId).matches() ? keyId : "?"));
        }
        if (type != null && profile.type() != type) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("config.err.keyTypeMismatch", keyId, profile.type().code(), type.code()));
        }
        return profile;
    }

    private static String activeSetting(KeyType type) {
        return type == KeyType.PASS ? CryptoSettings.KEY_ACTIVE_PASS : CryptoSettings.KEY_ACTIVE_KEY;
    }

    // ===================================================================================================
    // config embed-key: 이전 AES 키 보존
    // ===================================================================================================

    /**
     * {@code config embed-key}가 {@code crypto.key.*} AES 키를 바꾸기 전에, 지금 그 자리의 키를 같은 Key ID의 키 프로필
     * ({@code crypto.keys.<id>.*})로 옮길 항목을 만든다. 그래서 다른 유형·다른 Key ID의 키가 사라지지 않고 기존 암호문도 계속
     * 복호화된다. 내장 키는 값을 그대로 옮긴다. 외부 공급원 키는 JAR에 적힌 위치를 옮긴 뒤 지금 한 번 읽어 지문을 고정한다. 위치가
     * JAR 밖(실행 시 -D·외부 설정)에서 정해지거나 지금 읽을 수 없으면 지문을 고정할 수 없으므로 남기지 않는다(빈 결과, 이전 형식와 같이
     * 그 키의 암호문은 rekey). 호출자는 이 사실을 확인 화면과 결과에 보여 준다.
     *
     * @param settings 대상 JAR 내부 설정(검증된 것)
     * @return 추가할 항목(설정 이름 → 값). 남길 수 없으면 빈 맵
     */
    static Map<String, String> preservedSlot(CryptoSettings settings) {
        KeyProfile slot = settings.legacyProfile();
        String prefix = KeyProfile.PREFIX + slot.id() + ".";
        Map<String, String> values = new LinkedHashMap<>();
        values.put(prefix + KeyProfile.TYPE, KeyType.KEY.code());
        values.put(prefix + KeyProfile.SOURCE, slot.source());
        if ("embedded".equals(slot.source())) {
            values.put(prefix + KeyProfile.EMBEDDED, slot.value(KeyProfile.EMBEDDED));
            return values;
        }
        Map<String, String> items = new LinkedHashMap<>();
        items.put(KeyProfile.TYPE, KeyType.KEY.code());
        items.put(KeyProfile.SOURCE, slot.source());
        for (String item : new String[] {KeyProfile.FILE, KeyProfile.ENV, KeyProfile.VAULT_PATH, KeyProfile.VAULT_FIELD,
                KeyProfile.VAULT_VER, KeyProfile.AWS_KMS_DATA_KEY_FILE}) {
            String value = slot.value(item);
            if (value.isEmpty() || !belongs(item, slot.source())) continue;
            items.put(item, value);
            values.put(prefix + item, value);
        }
        if (items.size() <= 2) return Collections.emptyMap(); // 위치가 JAR에 없다(실행 시 -D·외부 설정이 정함)
        byte[] key = null;
        try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
            CryptoSettings connection = needsConnection(slot.source()) ? connection() : settings;
            key = KeyResolver.probeKey(connection, KeyProfile.probe(slot.id(), KeyType.KEY, items));
            values.put(prefix + KeyProfile.FINGERPRINT, KeyResolver.fingerprint(key));
            return values;
        } catch (IOException | IllegalArgumentException | CredentialCryptoException e) {
            return Collections.emptyMap(); // 지금 읽을 수 없다: 지문을 고정할 수 없으므로 남기지 않는다(확인·결과에 표시)
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /** @return 위치 항목이 그 공급원의 것이면 true */
    private static boolean belongs(String item, String source) {
        switch (source) {
            case "file": return KeyProfile.FILE.equals(item);
            case "env": return KeyProfile.ENV.equals(item);
            case "vault": return item.startsWith("vault.");
            case "aws-kms": return KeyProfile.AWS_KMS_DATA_KEY_FILE.equals(item);
            default: return false;
        }
    }

    // ===================================================================================================
    // pass 키 백업(--export 결과, --from-file 복원 입력)
    // ===================================================================================================

    /**
     * pass 키 백업 파일: 머리줄({@value #HEADER}) 다음에 {@code 이름=값} 줄. 같은 키를 되살리는 데 필요한 Key ID·KDF·반복 횟수·
     * Salt·전체 키 지문과 Passphrase 원문이 들어 있는 <b>비밀 파일</b>이다(UTF-8). 값은 첫 '=' 뒤 줄 끝까지 그대로(앞뒤 공백도 값)
     * 읽고, 줄 끝의 CR 하나만 뗀다. '#'으로 시작하는 줄과 빈 줄은 건너뛴다. 각 이름은 한 번씩만 있어야 한다. Passphrase만 있는
     * 한 줄 파일(기존 형식)은 머리줄이 없으므로 이 형식으로 해석하지 않는다.
     */
    static final class PassBackup {
        static final String HEADER = "# java-crypto-kit pass-key-backup v1";
        /** 백업 파일 최대 크기(바이트): Passphrase 부분은 기존 pass 파일과 같은 1KiB, 나머지는 복원 정보(머리줄·키 ID·KDF·Salt·지문). */
        static final int MAX_BYTES = PassKdf.MAX_FILE_BYTES + 512;
        private static final String[] NAMES = {"key-id", "kdf", "kdf.iterations", "salt", "fingerprint", "passphrase"};

        final String keyId;
        final String kdf;
        final String iterations;
        final String salt;
        final String fingerprint;
        final char[] passphrase;

        private PassBackup(String keyId, String kdf, String iterations, String salt, String fingerprint, char[] passphrase) {
            this.keyId = keyId;
            this.kdf = kdf;
            this.iterations = iterations;
            this.salt = salt;
            this.fingerprint = fingerprint;
            this.passphrase = passphrase;
        }

        /** @return 앞의 BOM 하나를 뺀 내용이 머리줄로 시작하면 true */
        static boolean isBackup(byte[] raw) {
            byte[] header = (HEADER).getBytes(StandardCharsets.US_ASCII);
            int start = bomLength(raw);
            if (raw.length - start < header.length) return false;
            for (int i = 0; i < header.length; i++) if (raw[start + i] != header[i]) return false;
            int end = start + header.length;
            return end == raw.length || raw[end] == '\n' || raw[end] == '\r' && end + 1 < raw.length && raw[end + 1] == '\n';
        }

        /** @return 파일이 pass 키 백업이면 true(읽을 수 없으면 false, 오류는 실제 읽기에서 알린다) */
        static boolean isBackupFile(Path file) {
            try {
                if (!Files.isRegularFile(file)) return false; // 폴더·장치·FIFO는 읽지 않는다(실제 읽기에서 거부)
                byte[] head = SecretFiles.readAtMost(file, HEADER.length() + 8);
                try {
                    return isBackup(head) || isBackupPrefix(head);
                } finally {
                    Arrays.fill(head, (byte) 0);
                }
            } catch (IOException | RuntimeException e) {
                return false;
            }
        }

        private static boolean isBackupPrefix(byte[] head) {
            byte[] header = HEADER.getBytes(StandardCharsets.US_ASCII);
            int start = bomLength(head);
            if (head.length - start < header.length) return false;
            for (int i = 0; i < header.length; i++) if (head[start + i] != header[i]) return false;
            return true;
        }

        private static int bomLength(byte[] raw) {
            return raw.length >= 3 && (raw[0] & 0xff) == 0xEF && (raw[1] & 0xff) == 0xBB && (raw[2] & 0xff) == 0xBF ? 3 : 0;
        }

        /**
         * 백업 파일 내용을 만든다(Passphrase를 String으로 만들지 않음).
         *
         * @return UTF-8 바이트(호출자가 저장 후 지운다)
         */
        static byte[] write(String keyId, Map<String, String> items, String fingerprint, char[] passphrase) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            String head = HEADER + "\n"
                    + "# SECRET file (contains the passphrase). 비밀 파일(Passphrase 포함)\n"
                    + "# Restore / 복원: config key add --key-id " + keyId + " --from-file <this file>\n"
                    + "key-id=" + keyId + "\n"
                    + "kdf=" + items.get(KeyProfile.KDF) + "\n"
                    + "kdf.iterations=" + items.get(KeyProfile.KDF_ITERATIONS) + "\n"
                    + "salt=" + items.get(KeyProfile.SALT) + "\n"
                    + "fingerprint=" + fingerprint + "\n"
                    + "passphrase=";
            byte[] headBytes = head.getBytes(StandardCharsets.UTF_8);
            out.write(headBytes, 0, headBytes.length);
            java.nio.ByteBuffer encoded = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(passphrase));
            byte[] secret = new byte[encoded.remaining()];
            encoded.get(secret);
            if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
            out.write(secret, 0, secret.length);
            Arrays.fill(secret, (byte) 0);
            out.write('\n');
            return out.toByteArray();
        }

        /**
         * 백업 파일을 해석하고 각 값의 형식을 확인한다(Key ID 일치·지문 일치는 호출자가 키를 만든 뒤 확인).
         *
         * @throws CredentialCryptoException 형식이 맞지 않는 경우(KEY_SOURCE, 값은 메시지에 넣지 않고 항목 이름만)
         */
        static PassBackup parse(byte[] raw) throws CredentialCryptoException {
            int start = bomLength(raw);
            char[] text;
            try {
                text = PassKdf.decodeUtf8(Arrays.copyOfRange(raw, start, raw.length), false);
            } catch (IllegalArgumentException e) {
                throw invalid("UTF-8");
            }
            Map<String, String> values = new LinkedHashMap<>();
            char[] passphrase = null;
            boolean ok = false;
            try {
                int lineStart = 0;
                boolean first = true;
                for (int i = 0; i <= text.length; i++) {
                    if (i < text.length && text[i] != '\n') continue;
                    int end = i > lineStart && text[i - 1] == '\r' ? i - 1 : i;
                    int length = end - lineStart;
                    if (first) {
                        if (!HEADER.equals(new String(text, lineStart, length))) throw invalid("header");
                        first = false;
                    } else if (length > 0 && text[lineStart] != '#') {
                        int eq = -1;
                        for (int j = lineStart; j < end; j++) {
                            if (text[j] == '=') {
                                eq = j;
                                break;
                            }
                        }
                        if (eq < 0) throw invalid("=");
                        String name = new String(text, lineStart, eq - lineStart);
                        if (!Arrays.asList(NAMES).contains(name)) throw invalid(name.matches("[a-z.-]{1,32}") ? name : "?");
                        if (values.containsKey(name) || "passphrase".equals(name) && passphrase != null) throw invalid(name);
                        if ("passphrase".equals(name)) {
                            passphrase = Arrays.copyOfRange(text, eq + 1, end);
                            values.put(name, "");
                        } else {
                            values.put(name, new String(text, eq + 1, end - eq - 1));
                        }
                    }
                    lineStart = i + 1;
                }
                for (String name : NAMES) if (!values.containsKey(name)) throw invalid(name);
                String keyId = values.get("key-id");
                if (!KEY_ID.matcher(keyId).matches()) throw invalid("key-id");
                if (!PassKdf.NAME.equals(values.get("kdf"))) throw invalid("kdf");
                String iterations = values.get("kdf.iterations");
                if (!iterations.matches("[1-9][0-9]{0,8}")) throw invalid("kdf.iterations");
                int count = Integer.parseInt(iterations);
                if (count < SettingCatalog.KDF_MIN_ITERATIONS || count > SettingCatalog.KDF_MAX_ITERATIONS) {
                    throw invalid("kdf.iterations");
                }
                String salt = values.get("salt");
                byte[] saltBytes;
                try {
                    saltBytes = Base64.getDecoder().decode(salt);
                } catch (IllegalArgumentException e) {
                    throw invalid("salt");
                }
                if (saltBytes.length != 16 || !salt.equals(Base64.getEncoder().encodeToString(saltBytes))) throw invalid("salt");
                String fingerprint = values.get("fingerprint");
                if (!fingerprint.matches("[0-9a-f]{64}")) throw invalid("fingerprint");
                if (passphrase.length == 0) throw invalid("passphrase");
                if (StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(passphrase)).remaining() > PassKdf.MAX_FILE_BYTES) {
                    throw invalid("passphrase");
                }
                ok = true;
                return new PassBackup(keyId, values.get("kdf"), iterations, salt, fingerprint, passphrase);
            } finally {
                Arrays.fill(text, '\0');
                if (!ok && passphrase != null) Arrays.fill(passphrase, '\0');
            }
        }

        private static CredentialCryptoException invalid(String item) {
            return new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("cfg.err.backupFormat", item));
        }
    }

    // ===================================================================================================
    // 파일 도우미
    // ===================================================================================================

    static Path path(String value, String option) throws CryptoCli.CliException {
        try {
            return Paths.get(value);
        } catch (InvalidPathException e) {
            throw new CryptoCli.CliException(Messages.get("cli.err.path", option));
        }
    }

    /** 새로 만들 파일 경로 검사(상위 폴더 있음, 파일 없음). 실제로 만드는 것은 확인 뒤다. */
    static Path newFilePath(String value, String option) throws CryptoCli.CliException {
        Path file = path(value, option);
        Path parent = file.toAbsolutePath().getParent();
        if (parent == null || !Files.isDirectory(parent)) throw new CryptoCli.CliException(Messages.get("cfg.err.fileDir", option));
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) throw new CryptoCli.CliException(Messages.get("cfg.err.fileExists", option));
        return file;
    }

    /** 비밀 파일을 새로 만든다(기존 파일 덮어쓰기 없음, POSIX 600). 기록 중 실패하면 지운다. */
    static void writeNewSecretFile(Path file, byte[] content) throws IOException, CryptoCli.CliException {
        CryptoCli.createSecretFile(file, "cfg.err.fileDirAny", "cfg.err.fileExistsAny");
        try (OutputStream output = Files.newOutputStream(file, StandardOpenOption.WRITE)) {
            output.write(content);
        } catch (IOException e) {
            deleteQuietly(file);
            throw e;
        }
    }

    /** 내용 + 줄바꿈(원본 배열은 지운다). */
    static byte[] lineBytes(byte[] content) {
        byte[] line = Arrays.copyOf(content, content.length + 1);
        line[content.length] = '\n';
        Arrays.fill(content, (byte) 0);
        return line;
    }

    /** 결과 줄의 경로: 갱신한 JAR·키 파일 줄과 같은 운영체제 표기(절대 경로). */
    static String display(Path file) {
        return Messages.singleLine(file.toAbsolutePath().normalize().toString());
    }

    private static void deleteQuietly(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignored) {
            // 정리 실패는 결과를 바꾸지 않는다.
        }
    }
}
