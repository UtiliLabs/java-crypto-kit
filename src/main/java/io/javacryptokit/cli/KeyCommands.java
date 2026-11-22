package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
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
 *       AWS KMS는 마스터 키가 아니라 실제로 쓰는 AES 데이터 키의 지문이다.</li>
 *   <li>{@code rekey}: 기존 암호문을 이전 설정으로 복호화해 신규 설정의 키·키ID로 다시 암호화한다. 이전·신규 설정은 서로
 *       독립적으로 고르며(전역 설정을 임시로 바꾸지 않음) 평문은 화면·로그에 나오지 않는다. 기존 암호문은 바꾸거나 지우지 않는다.</li>
 *   <li>{@code kms datakey}: AWS KMS로 보호한 데이터 키 파일을 한 번 만든다(새로 만들거나 기존 키를 감쌈).</li>
 * </ul>
 */
final class KeyCommands {
    private KeyCommands() { }

    // ===================================================================================================
    // fingerprint
    // ===================================================================================================

    static int fingerprint(CliCommands.Parsed parsed, PrintStream out) throws Exception {
        String keyFile = parsed.value("--key-file");
        if (keyFile != null) {
            if (parsed.value("--config") != null) throw new CryptoCli.CliException(Messages.get("fp.err.both"));
            Path path = path(keyFile, "--key-file");
            byte[] key = readKeyFile(path);
            try {
                out.println(Messages.get("fp.source", "file", Messages.get("key.describe.file", SecretFiles.fileName(path))));
                out.println(Messages.get("fp.keyId", "-"));
                out.println(Messages.get("fp.value", KeyResolver.fingerprint(key)));
                if (DefaultKeyWarning.isPublicDefaultKey(key)) out.println(Messages.get("fp.public"));
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } else {
            CryptoService crypto = CryptoService.load(parsed.value("--config"));
            CryptoService.KeyCheck check = crypto.checkKey();
            if (!check.available()) {
                throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE, Messages.get("fp.err.key"));
            }
            out.println(Messages.get("fp.source", crypto.settings().keySource(), crypto.describeKeyLocation()));
            out.println(Messages.get("fp.keyId", crypto.settings().keyId()));
            out.println(Messages.get("fp.value", check.fingerprint()));
            if (check.publicDefaultKey()) out.println(Messages.get("fp.public"));
        }
        out.println(Messages.get("fp.note"));
        return 0;
    }

    // ===================================================================================================
    // rekey
    // ===================================================================================================

    /** rekey 한쪽(이전 또는 신규) 설정. */
    private static final class Side {
        final CryptoService service;
        final String label;

        Side(CryptoService service, String label) {
            this.service = service;
            this.label = label;
        }
    }

    static int rekey(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out, PrintStream err)
            throws Exception {
        Side from = side(parsed, "--from-config", "--from-jar", "rekey.err.bothFrom");
        Side to = side(parsed, "--to-config", "--to-jar", "rekey.err.bothTo");
        if (from == null && to == null) throw new CryptoCli.CliException(Messages.get("rekey.err.sameSides"));
        if (from == null) from = new Side(CryptoService.load(null), Messages.get("rekey.label.runtime"));
        if (to == null) to = new Side(CryptoService.load(null), Messages.get("rekey.label.runtime"));
        String fromId = from.service.settings().keyId();
        String toId = to.service.settings().keyId();
        if (fromId.equals(toId)) throw new CryptoCli.CliException(Messages.get("rekey.err.sameKeyId", fromId));
        String fromPrint = from.service.keyFingerprint();
        String toPrint = to.service.keyFingerprint();
        if (MessageDigest.isEqual(fromPrint.getBytes(StandardCharsets.US_ASCII), toPrint.getBytes(StandardCharsets.US_ASCII))) {
            throw new CryptoCli.CliException(Messages.get("rekey.err.sameKey"));
        }
        String token = parsed.value("--value");
        if (token == null) token = CryptoCli.readHidden(terminals, Messages.get("rekey.prompt") + " ");

        byte[] plain = from.service.decryptBytes(token);
        byte[] check = null;
        String newToken;
        try {
            // 새 IV로 신규 키·키ID 암호문을 만들고, 신규 설정으로 실제 복호화해 같은 값인지 확인한다(평문은 출력하지 않음).
            newToken = to.service.encryptBytes(plain);
            check = to.service.decryptBytes(newToken);
            if (!MessageDigest.isEqual(plain, check)) throw new CryptoCli.CliException(Messages.get("rekey.err.verify"));
        } finally {
            Arrays.fill(plain, (byte) 0);
            if (check != null) Arrays.fill(check, (byte) 0);
        }
        // 이전 설정으로는 새 암호문을 복호화할 수 없어야 한다(키ID가 다르므로 KEY_ID_MISMATCH).
        if (from.service.verify(newToken)) throw new CryptoCli.CliException(Messages.get("rekey.err.verify"));

        // 표준 출력에는 새 암호문 한 줄만 쓴다(스크립트로 받기 쉽게). 안내는 표준 오류로 보낸다.
        out.println(newToken);
        err.println(Messages.get("rekey.done.sides", from.label, to.label));
        err.println(Messages.get("rekey.done.from", fromId, fromPrint));
        err.println(Messages.get("rekey.done.to", toId, toPrint));
        err.println(Messages.get("rekey.done.verified"));
        err.println(Messages.get("rekey.done.next"));
        return 0;
    }

    /**
     * rekey 한쪽 설정을 만든다. 설정 파일은 실행 중인 JAR 내부 값 위에 그 파일만 덮어쓰며 JVM {@code -D}·환경변수 설정 경로는
     * 적용하지 않는다(이전·신규 설정이 서로 섞이지 않게). JAR는 그 JAR 내부 값만 쓴다.
     *
     * @return 설정(옵션이 없으면 null = 현재 실행 설정)
     */
    private static Side side(CliCommands.Parsed parsed, String configOption, String jarOption, String bothKey)
            throws CryptoCli.CliException, CredentialCryptoException {
        String config = parsed.value(configOption);
        String jar = parsed.value(jarOption);
        if (config != null && jar != null) throw new CryptoCli.CliException(Messages.get(bothKey));
        if (config != null) {
            try {
                CryptoSettings settings = CryptoSettings.load(config, name -> null, name -> null, Collections.<String>emptySet());
                return new Side(CryptoService.of(settings), Messages.get("rekey.label.config", SecretFiles.fileName(config)));
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
            return new Side(CryptoService.of(settings), Messages.get("rekey.label.jar", JarConfigEditor.name(snap.jar)));
        }
        return null;
    }

    // ===================================================================================================
    // kms datakey
    // ===================================================================================================

    static int kmsDataKey(CliCommands.Parsed parsed, PrintStream out) throws Exception {
        String outValue = parsed.value("--out");
        if (outValue == null) throw new CryptoCli.CliException(Messages.get("kms.err.out"));
        Path output = path(outValue, "--out");
        if (Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new CryptoCli.CliException(Messages.get("kms.err.exists"));
        }
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
                    blob = AwsKmsKeyProvider.wrap(settings, key);
                    restored = AwsKmsKeyProvider.unwrap(settings, blob);
                    if (!MessageDigest.isEqual(key, restored)) throw new CryptoCli.CliException(Messages.get("kms.err.verify"));
                    fingerprint = KeyResolver.fingerprint(key);
                } finally {
                    Arrays.fill(key, (byte) 0);
                    if (restored != null) Arrays.fill(restored, (byte) 0);
                }
            } else {
                AwsKmsKeyProvider.DataKey dataKey = AwsKmsKeyProvider.generate(settings);
                byte[] restored = null;
                try {
                    if (dataKey.plaintext.length != 32) throw new CryptoCli.CliException(Messages.get("kms.err.verify"));
                    blob = dataKey.ciphertextBlob;
                    restored = AwsKmsKeyProvider.unwrap(settings, blob);
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
        out.println(Messages.get("kms.done.created", SecretFiles.fileName(output)));
        out.println(Messages.get(keyFile != null ? "kms.done.mode.wrapped" : "kms.done.mode.generated"));
        out.println(Messages.get("kms.done.keyId", settings.keyId()));
        out.println(Messages.get("kms.done.fingerprint", fingerprint));
        out.println(Messages.get("kms.done.verified"));
        out.println(Messages.get("kms.done.next", output.toAbsolutePath().toString().replace('\\', '/'),
                settings.get(CryptoSettings.AWS_KMS_KEY_ID)));
        out.println(Messages.get("kms.done.keep"));
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
