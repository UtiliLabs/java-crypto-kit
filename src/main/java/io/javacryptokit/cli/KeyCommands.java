package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.key.aws.AwsKmsKeyProvider;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

/**
 * <b>내부 구현 클래스</b>: 키 관리 명령 {@code fingerprint}, {@code rekey}, {@code kms datakey}.
 *
 * <ul>
 *   <li>{@code fingerprint}: 실제 적용 키(또는 키 파일)의 지문으로 "같은 키인지" 비교한다. 키 원문은 출력하지 않는다.
 *       AWS KMS는 마스터 키가 아니라 실제로 쓰는 AES 데이터 키의 지문이고, pass 유형은 Passphrase에서 파생한 AES 키의 지문이다.</li>
 *   <li>{@code rekey}: 기존 암호문을 그 Key ID의 키로 복호화해 대상 키로 다시 암호화한다. 대상은 신규 설정의 기본 키(또는
 *       {@code --type}·{@code --key-id}로 고른 키)이며, 같은 설정 안의 다른 키로 바꾸는 회전과 유형 간 재암호화(pass↔key)도 된다.
 *       이전·신규 설정은 서로 독립적으로 고르며(전역 설정을 임시로 바꾸지 않음) 평문은 화면·로그에 나오지 않는다. 기존 암호문은
 *       바꾸거나 지우지 않는다.</li>
 *   <li>{@code kms datakey}: AWS KMS로 보호한 데이터 키 파일을 한 번 만든다(새로 만들거나 기존 키를 감쌈). {@code crypto.key.*}
 *       AES 키용이며 pass 유형·추가 키는 {@code config key add --source aws-kms}로 만든다. 사유는 필수지만(KMS 호출 전에 확인)
 *       JAR를 바꾸지 않으므로 어떤 이력에도 저장하지 않는다. 데이터 키 원문은 화면에 보여 주지 않는다(KMS로 보호한 파일만 남김).</li>
 * </ul>
 */
final class KeyCommands {
    private KeyCommands() { }

    // ===================================================================================================
    // fingerprint
    // ===================================================================================================

    /**
     * fingerprint: 실제 적용 키(또는 {@code --key-file}의 키)의 전체 지문(64자)을 보여 준다. 두 곳의 지문이 같으면 같은 키다.
     * 키 원문·일부는 출력하지 않는다. 키를 읽지 못하면 실제 원인(사유 코드 포함)으로 실패한다.
     */
    static int fingerprint(CliCommands.Parsed parsed, PrintStream out) throws Exception {
        String keyFile = parsed.value("--key-file");
        KeyType type = CryptoCli.typeOption(parsed);
        String keyId = CryptoCli.keyIdOption(parsed);
        if (keyFile != null) {
            if (parsed.value("--config") != null) throw new CryptoCli.CliException(Messages.get("fp.err.both"));
            if (type != null || keyId != null) throw new CryptoCli.CliException(Messages.get("fp.err.keyFileSelect"));
            Path path = path(keyFile, "--key-file");
            byte[] key = readKeyFile(path);
            try {
                out.println(Messages.get("fp.file", SecretFiles.fileName(path)));
                out.println(Messages.get("fp.status", CryptoCli.keyStatus(DefaultKeyWarning.isPublicDefaultKey(key))));
                out.println(Messages.get("fp.value", KeyResolver.fingerprint(key)));
            } finally {
                Arrays.fill(key, (byte) 0);
            }
            return 0;
        }
        CryptoService crypto = CryptoService.load(parsed.value("--config"));
        // 옵션이 없으면 유형·Key ID를 정하지 않은 새 암호화가 쓰는 키, --type은 그 유형의 기본 키, --key-id는 그 키.
        KeyProfile profile = crypto.select(type, keyId);
        CryptoService.KeyCheck check = crypto.checkKey(profile);
        // 이미 원인·조치까지 담긴 정제된 예외를 다시 감싸지 않고 그대로 던진다(원인·조치가 한 번만 나오게).
        if (!check.available()) throw check.failureException();
        out.println(Messages.get("fp.source", profile.source()));
        out.println(Messages.get("fp.location", crypto.describeKeyLocation(profile)));
        out.println(Messages.get("fp.keyId", profile.id()));
        out.println(Messages.get("fp.type", profile.type().code()));
        out.println(Messages.get("fp.status", CryptoCli.keyStatus(check.publicDefaultKey())));
        out.println(Messages.get("fp.value", check.fingerprint()));
        return 0;
    }

    // ===================================================================================================
    // rekey
    // ===================================================================================================

    /**
     * rekey: 기존 암호문을 그 Key ID의 키(이전 설정)로 복호화해 대상 키(신규 설정)로 다시 암호화하고, 신규 설정으로 복호화되는지와
     * 새 암호문의 Key ID가 대상 키인지 확인한 뒤 새 암호문 한 줄만 표준 출력에 쓴다(평문은 어디에도 출력하지 않음).
     *
     * <p>대상 키: 신규 설정({@code --to-config}·{@code --to-jar}, 없으면 실행 설정)에서 {@code --key-id}면 그 키, {@code --type}이면
     * 그 유형의 기본 키, 둘 다 없으면 <b>원래 암호문과 같은 유형</b>의 기본 키다(재암호화는 새 암호화가 아니므로 유형을 바꾸지 않는다.
     * 예: 이전 형식의 AES 키 교체 흐름 embed-key → rekey가 공개 pass 키로 옮겨 가지 않게). 이전·신규 설정 옵션 없이 {@code --type}·
     * {@code --key-id}만 주면 같은 설정 안에서 다른 키로 바꾼다(회전, 유형 간 재암호화 포함). 원래 Key ID와 같은 Key ID, 같은 키(지문
     * 동일)로는 바꾸지 않는다.</p>
     *
     * <p>자동 경고: 작업 전체를 자동 경고 억제 범위에서 실행한다. 이전 키(공개 기본 키일 수 있음)로 기존 암호문을 푸는 일은
     * 경고하지 않고, 키 지문 조회·복호화·검증 중 실패하면 경고 없이 오류만 남긴다. 재암호화와 검증이 모두 성공해 새 암호문을
     * 내보낼 때, 새 키가 공개 기본 키이면 그때 공통 경고를 한 번 남긴다(경고 정책·JVM당 1회 규칙은 같음).</p>
     */
    /**
     * rekey 사전 검사(관리자 인증 전): 유형·Key ID 형식, 이전·신규 설정 옵션을 한쪽에 둘 다 쓰지 않았는지, 바꿀 대상이 있는지만 본다
     * (설정 파일·JAR의 키는 읽지 않음).
     */
    static void checkRekey(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        KeyType type = CryptoCli.typeOption(parsed);
        String keyId = CryptoCli.keyIdOption(parsed);
        boolean from = given(parsed, "--from-config", "--from-jar", "rekey.err.bothFrom");
        boolean to = given(parsed, "--to-config", "--to-jar", "rekey.err.bothTo");
        if (!from && !to && type == null && keyId == null) throw new CryptoCli.CliException(Messages.get("rekey.err.sameSides"));
    }

    /** @return 한쪽(이전 또는 신규) 설정 옵션을 썼으면 true(설정 파일과 JAR를 함께 쓰면 오류) */
    private static boolean given(CliCommands.Parsed parsed, String configOption, String jarOption, String bothKey)
            throws CryptoCli.CliException {
        boolean config = parsed.value(configOption) != null;
        boolean jar = parsed.value(jarOption) != null;
        if (config && jar) throw new CryptoCli.CliException(Messages.get(bothKey));
        return config || jar;
    }

    static int rekey(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
            // 사전 검사·관리자 인증(실행 중인 JAR·--from-jar, --to-jar는 무결성만)은 CryptoCli가 마쳤다. 여기서부터 설정·키를 읽는다.
            KeyType type = CryptoCli.typeOption(parsed);
            String keyId = CryptoCli.keyIdOption(parsed);
            CryptoService from = side(parsed, "--from-config", "--from-jar");
            CryptoService to = side(parsed, "--to-config", "--to-jar");
            if (from == null && to == null) {
                from = CryptoService.load(null);
                to = from; // 같은 설정 안에서 다른 키로 바꾼다
            }
            if (from == null) from = CryptoService.load(null);
            if (to == null) to = CryptoService.load(null);
            // 대상을 직접 정했으면 입력을 받기 전에 대상 키를 확인한다(유형·Key ID가 없으면 원래 암호문의 유형을 본 뒤에 정한다).
            if (type != null || keyId != null) to.select(type, keyId);
            String token = parsed.value("--value");
            if (token == null) token = CryptoCli.readHidden(terminals, Messages.get("rekey.prompt") + " ");

            // 원래 암호문의 Key ID로 이전 키를 고른다(등록되지 않은 Key ID면 KEY_ID_MISMATCH).
            String sourceId = from.keyIdOf(token);
            KeyProfile source = from.settings().profile(sourceId);
            if (source == null) throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
            KeyProfile target = type == null && keyId == null ? to.select(source.type(), null) : to.select(type, keyId);
            if (sourceId.equals(target.id())) throw new CryptoCli.CliException(Messages.get("rekey.err.sameKeyId", sourceId));
            CryptoService.KeyCheck toKey = to.checkKey(target);
            if (!toKey.available()) throw toKey.failureException();
            CryptoService.KeyCheck fromKey = from.checkKey(source);
            if (!fromKey.available()) throw fromKey.failureException();
            if (MessageDigest.isEqual(fromKey.fingerprint().getBytes(StandardCharsets.US_ASCII),
                    toKey.fingerprint().getBytes(StandardCharsets.US_ASCII))) {
                throw new CryptoCli.CliException(Messages.get("rekey.err.sameKey"));
            }

            byte[] plain = from.decryptBytes(token);
            byte[] check = null;
            String newToken;
            try {
                // 새 IV로 대상 키·Key ID 암호문을 만들고, 신규 설정으로 실제 복호화해 같은 값인지 확인한다(평문은 출력하지 않음).
                newToken = to.encryptBytes(plain, null, target.id());
                check = to.decryptBytes(newToken);
                if (!MessageDigest.isEqual(plain, check) || !target.id().equals(to.keyIdOf(newToken))) {
                    throw new CryptoCli.CliException(Messages.get("rekey.err.verify"));
                }
            } finally {
                Arrays.fill(plain, (byte) 0);
                if (check != null) Arrays.fill(check, (byte) 0);
            }

            // 모두 성공했다: 새 암호문이 공개 기본 키로 만들어졌으면 지금 경고하고(표준 오류), 표준 출력에는 새 암호문 한 줄만 쓴다.
            if (toKey.publicDefaultKey()) DefaultKeyWarning.warnPublicKeyInUse(to.settings());
            out.println(newToken);
            return 0;
        }
    }

    /**
     * rekey 한쪽 설정을 만든다. 설정 파일은 실행 중인 JAR 내부 값 위에 그 파일만 덮어쓰며 JVM {@code -D}·환경변수 설정 경로는
     * 적용하지 않는다(이전·신규 설정이 서로 섞이지 않게). JAR는 그 JAR 내부 값만 쓴다.
     *
     * @return 설정(옵션이 없으면 null = 현재 실행 설정)
     */
    private static CryptoService side(CliCommands.Parsed parsed, String configOption, String jarOption)
            throws CryptoCli.CliException, CredentialCryptoException {
        String config = parsed.value(configOption);
        String jar = parsed.value(jarOption);
        if (config != null) {
            try {
                CryptoSettings settings = CryptoSettings.load(config, name -> null, name -> null, Collections.<String>emptySet());
                return CryptoService.of(settings);
            } catch (SafeMessageException e) {
                throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION, e.getMessage());
            } catch (IOException | RuntimeException e) {
                throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                        Messages.get("service.err.configRead"), e);
            }
        }
        if (jar != null) {
            JarConfigEditor.Snapshot snap = JarConfigEditor.read(path(jar, jarOption));
            CryptoSettings settings = snap.validated();
            if (settings == null) {
                throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                        snap.validationError == null ? "" : snap.validationError);
            }
            return CryptoService.of(settings);
        }
        return null;
    }

    // ===================================================================================================
    // kms datakey
    // ===================================================================================================

    /** kms datakey 사전 검사(관리자 인증 전): {@code --out} 필수·기존 파일 없음, 작업자 ID 형식. */
    static void checkKmsDataKey(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        outputFile(parsed);
        String operator = parsed.value("--operator");
        if (operator != null) JarConfigEditor.checkOperator(operator);
    }

    /** @return 새로 만들 데이터 키 파일(이미 있으면 덮어쓰지 않음) */
    private static Path outputFile(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        String outValue = parsed.value("--out");
        if (outValue == null) throw new CryptoCli.CliException(Messages.get("kms.err.out"));
        Path output = path(outValue, "--out");
        if (Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoCli.CliException(Messages.get("kms.err.exists"));
        }
        return output;
    }

    static int kmsDataKey(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        // 사전 검사·관리자 인증은 CryptoCli가 마쳤다. 사유는 KMS를 부르기 전에 확인한다.
        Path output = outputFile(parsed);
        String operator = parsed.value("--operator");
        String reason = CryptoCli.reasonOption(parsed, terminals);
        CryptoSettings settings = CryptoService.load(parsed.value("--config")).settings();
        String keyFile = parsed.value("--from-file");
        byte[] blob;
        String fingerprint;
        try {
            if (keyFile != null) {
                // 이미 쓰고 있는 키를 KMS로 감싼다: 같은 키·키ID이므로 기존 암호문을 다시 암호화할 필요가 없다.
                byte[] key = readKeyFile(path(keyFile, "--from-file"));
                byte[] restored = null;
                try {
                    blob = AwsKmsKeyProvider.wrap(settings, settings.keyId(), key);
                    restored = AwsKmsKeyProvider.unwrap(settings, settings.keyId(), blob);
                    if (!MessageDigest.isEqual(key, restored)) throw new CryptoCli.CliException(Messages.get("kms.err.verify"));
                    fingerprint = KeyResolver.fingerprint(key);
                } finally {
                    Arrays.fill(key, (byte) 0);
                    if (restored != null) Arrays.fill(restored, (byte) 0);
                }
            } else {
                // 레거시 AES 슬롯(crypto.key.id)의 데이터 키를 만든다(기존 동작). pass 키·추가 키는 config key add로 만든다.
                AwsKmsKeyProvider.DataKey dataKey = AwsKmsKeyProvider.generate(settings, settings.keyId());
                byte[] restored = null;
                try {
                    if (dataKey.plaintext.length != 32) throw new CryptoCli.CliException(Messages.get("kms.err.verify"));
                    blob = dataKey.ciphertextBlob;
                    restored = AwsKmsKeyProvider.unwrap(settings, settings.keyId(), blob);
                    if (!MessageDigest.isEqual(dataKey.plaintext, restored)) {
                        throw new CryptoCli.CliException(Messages.get("kms.err.verify"));
                    }
                    fingerprint = KeyResolver.fingerprint(dataKey.plaintext);
                } finally {
                    dataKey.wipe();
                    if (restored != null) Arrays.fill(restored, (byte) 0);
                }
            }
        } catch (SafeMessageException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        }
        // 검증이 끝난 뒤에만 파일을 만든다(기존 파일은 덮어쓰지 않음, POSIX 600).
        CryptoCli.createSecretFile(output, "kms.err.dir", "kms.err.exists");
        try (OutputStream file = Files.newOutputStream(output, StandardOpenOption.WRITE)) {
            file.write(Base64.getEncoder().encode(blob));
            file.write('\n');
        } catch (IOException e) {
            Files.deleteIfExists(output);
            throw e;
        }
        // 결과: 만든 파일(설정 crypto.aws.kms.data-key.file에 쓸 경로), 방식(새 키 / 기존 키 감싸기), 키 ID, 데이터 키 지문.
        out.println(Messages.get("kms.done.file", Messages.singleLine(output.toAbsolutePath().normalize().toString().replace('\\', '/'))));
        out.println(Messages.get(keyFile != null ? "kms.done.mode.wrapped" : "kms.done.mode.generated"));
        out.println(Messages.get("kms.done.keyId", settings.keyId()));
        out.println(Messages.get("kms.done.fingerprint", fingerprint));
        out.println(Messages.get("kms.done.reason", reason));
        if (operator != null) out.println(Messages.get("kms.done.operator", operator));
        out.println(Messages.get("kms.done.notRecorded"));
        return 0;
    }

    // ===================================================================================================
    // 공통
    // ===================================================================================================

    private static Path path(String value, String option) throws CryptoCli.CliException {
        try {
            return Paths.get(value);
        } catch (InvalidPathException e) {
            throw new CryptoCli.CliException(Messages.get("cli.err.path", option));
        }
    }

    /** 키 파일을 읽는다(KEY_SOURCE로 알리며 경로 전체·키 내용은 메시지에 넣지 않는다). */
    private static byte[] readKeyFile(Path path) throws CredentialCryptoException {
        try {
            return KeyResolver.readKeyFile(path, SecretFiles.fileName(path));
        } catch (NoSuchFileException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("cfg.err.keyFileMissing", SecretFiles.fileName(path)));
        } catch (IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, e.getMessage());
        } catch (IOException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("cfg.err.keyFileRead", SecretFiles.fileName(path)), e);
        }
    }
}
