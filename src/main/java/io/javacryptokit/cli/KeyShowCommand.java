package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyProvider;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <b>내부 구현 클래스</b>: {@code config key show --key-id <ID> [--show] [--export <파일>]}. 관리자 인증 뒤 JAR에 등록된 키 하나의
 * 관리정보를 마스킹 없이 보여 주고, 명시적으로 요청하면 실제 보존된 키 원문을 보여 주거나 복원 가능한 형식으로 내보낸다.
 *
 * <ul>
 *   <li><b>관리정보</b>(옵션 없음): Key ID, 유형, 공급원(외부 키는 위치), 상태, 전체 지문(64자), pass는 KDF·반복 횟수·Salt·Salt
 *       SHA-256, 원문 확인 가능 여부. 외부 키는 읽지 않는다(고정 지문 표시).</li>
 *   <li><b>{@code --show}</b>(대화형 전용): 노출 경고 뒤 {@value #CONFIRM_WORD}를 정확히 입력해야 원문을 대화형 터미널에만 보여 준다
 *       (표준 출력·표준 오류·로그·이력에 쓰지 않음). 관리자 인증과 별도 단계다.</li>
 *   <li><b>{@code --export}</b>: 새 파일(기존 파일 덮어쓰기 없음, POSIX 600)에 key는 keygen 형식 한 줄(표준 Base64), pass는 복원
 *       백업 형식으로 쓴다. 비대화형에서도 관리자 비밀번호 파일 인증으로 쓸 수 있다.</li>
 *   <li><b>pass 원문</b>: Passphrase 원문이 공급원(file·env·vault)에 실제로 보관된 경우에만 다룬다. JAR·KMS 데이터 키 파일에는
 *       PBKDF2 파생 키만 있으므로(embedded·aws-kms) 원문을 복원할 수 없다고 알리고 생성 때 만든 백업으로 복원하도록 안내한다(파생 키에서
 *       원문을 되돌릴 수 없으며, 원문을 새로 가역 저장하지도 않는다).</li>
 * </ul>
 *
 * <p>JAR를 바꾸지 않는 조회라 사유를 받지 않고 이력에도 남기지 않는다. JAR 내부 설정 기준이다(외부 Properties·-D 미반영).</p>
 */
final class KeyShowCommand {
    /** 원문을 화면에 보여 주기 전에 사용자가 직접 입력해야 하는 확인 문구(번역하지 않음). */
    static final String CONFIRM_WORD = "SHOW";

    private KeyShowCommand() { }

    /**
     * 사전 검사(관리자 인증 전, JAR 내용은 읽지 않음): {@code --key-id} 지정, {@code --show}는 대화형 터미널에서만, {@code --export}는
     * 새 파일 자리. 키가 등록되어 있는지·공급원 같은 JAR 내용은 인증 뒤에 확인한다(인증 전 응답으로 키 등록 여부를 알 수 없게).
     */
    static void check(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals) throws CryptoCli.CliException {
        String keyId = parsed.value("--key-id");
        if (keyId == null) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdNeeded", parsed.spec.name));
        if (!keyId.matches("[A-Za-z0-9_-]{1,64}")) throw new CryptoCli.CliException(Messages.get("cfg.err.keyIdFormat"));
        if (parsed.flag("--show") && CryptoCli.interactive(terminals) == null) {
            throw new CryptoCli.CliException(Messages.get("keyshow.err.showInteractive", CONFIRM_WORD));
        }
        String export = parsed.value("--export");
        if (export != null) KeyringCommand.newFilePath(export, "--export");
    }

    static int run(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out) throws Exception {
        // 사전 검사·관리자 인증(실행 중인 JAR와 --jar 대상)은 CryptoCli가 마쳤다. 여기서부터 대상 JAR의 키 목록을 읽는다.
        String keyId = parsed.value("--key-id");
        boolean show = parsed.flag("--show");
        String export = parsed.value("--export");
        CryptoCli.Terminal terminal = show ? CryptoCli.interactive(terminals) : null;
        Path jar = ConfigCommand.sourceJar(parsed);
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(jar);
        CryptoSettings settings = KeyringCommand.validated(snap);
        KeyProfile profile = settings.profile(keyId);
        if (profile == null) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CONFIGURATION,
                    Messages.get("config.err.keyIdUnknown", keyId)); // 형식은 사전 검사에서 확인했다
        }
        Path exportPath = export == null ? null : KeyringCommand.newFilePath(export, "--export");

        boolean passKept = profile.type() == KeyType.PASS && KeyResolver.provider(profile.source()).textMaterial();
        printInfo(settings, profile, passKept, out);
        if (!show && exportPath == null) return 0;
        if (profile.type() == KeyType.PASS && !passKept) {
            throw new CryptoCli.CliException("KEY_SOURCE", Messages.get("keyshow.err.passNotKept", profile.source(), keyId));
        }
        if (show && !confirm(terminal, out)) return 0;

        Secret secret = read(settings, profile);
        try {
            if (exportPath != null) KeyringCommand.writeNewSecretFile(exportPath, secret.exportBytes);
            if (show) {
                out.flush();
                KeyringView.showSecret(terminal, profile.type(), keyId, secret.text, secret.items, secret.fingerprint);
            }
            if (exportPath != null) {
                out.println(Messages.get("cfg.result.exported", KeyringCommand.display(exportPath)));
                out.println(Messages.get(profile.type() == KeyType.PASS ? "keyshow.exported.pass" : "keyshow.exported.key"));
            }
            out.println(Messages.get("keyshow.notRecorded"));
            return 0;
        } finally {
            secret.wipe();
        }
    }

    /** 관리정보(마스킹 없음, 원문 없음)를 표준 출력에 쓴다. */
    private static void printInfo(CryptoSettings settings, KeyProfile profile, boolean passKept, PrintStream out) {
        out.println(Messages.get("gen.keyId", profile.id()));
        out.println(Messages.get("gen.type", profile.type().code()));
        out.println(Messages.get("keyshow.source", profile.source()));
        if (!"embedded".equals(profile.source())) {
            out.println(Messages.get("keyshow.location", CryptoService.of(settings).describeKeyLocation(profile)));
        }
        String status = KeyringView.status(profile);
        if (KeyringView.isActive(settings, profile)) status += ", " + Messages.get("keyshow.active", profile.type().code());
        if (profile.legacy()) status += ", crypto.key.*";
        out.println(Messages.get("keyshow.status", status));
        String fingerprint = KeyringView.jarFingerprint(profile);
        if (fingerprint == null) {
            out.println(Messages.get("keyshow.fingerprint", Messages.get("keys.detail.unknown")));
        } else {
            out.println(Messages.get("keyshow.fingerprint", "embedded".equals(profile.source()) ? fingerprint
                    : Messages.get("keys.detail.pinned", fingerprint)));
        }
        if (profile.type() == KeyType.PASS) {
            out.println(Messages.get("keyshow.kdf", profile.value(KeyProfile.KDF),
                    KeyringView.rounds(profile.value(KeyProfile.KDF_ITERATIONS))));
            String salt = profile.value(KeyProfile.SALT);
            out.println(Messages.get("keyshow.salt", salt));
            String saltSha256 = KeyringView.saltSha256(salt);
            out.println(Messages.get("keyshow.saltSha256", saltSha256 == null ? Messages.get("keys.detail.notRecorded") : saltSha256));
            out.println(Messages.get("keyshow.secret", Messages.get(passKept ? "keyshow.secret.passKept"
                    : "keyshow.secret.passDerived")));
        } else {
            out.println(Messages.get("keyshow.secret", Messages.get("embedded".equals(profile.source())
                    ? "keyshow.secret.key" : "keyshow.secret.keyExternal")));
        }
    }

    /** 노출 경고 뒤 SHOW를 정확히 입력받는다. 그 밖의 입력·빈 입력은 취소(원문을 읽지도 보여 주지도 않음). */
    private static boolean confirm(CryptoCli.Terminal terminal, PrintStream out) {
        out.flush();
        terminal.println("");
        for (String line : Messages.get("keyshow.warning").split("\n")) terminal.println(line);
        String answer = terminal.readLine(Messages.get("keyshow.confirm", CONFIRM_WORD) + " ");
        if (answer == null || !CONFIRM_WORD.equals(answer.trim())) {
            out.println(Messages.get("keyshow.cancel"));
            return false;
        }
        return true;
    }

    /** 읽은 원문(화면 표시용 글자, 내보낼 파일 내용)과 복원 정보. */
    private static final class Secret {
        final char[] text;
        final Map<String, String> items;
        final String fingerprint;
        final byte[] exportBytes;

        Secret(char[] text, Map<String, String> items, String fingerprint, byte[] exportBytes) {
            this.text = text;
            this.items = items;
            this.fingerprint = fingerprint;
            this.exportBytes = exportBytes;
        }

        void wipe() {
            Arrays.fill(text, '\0');
            Arrays.fill(exportBytes, (byte) 0);
        }
    }

    /**
     * 실제 키 원문을 읽는다(관리자 인증·SHOW 확인 뒤). 먼저 일반 경로로 키를 확인해(고정 지문 검사 포함) 실패 원인을 같은 방식으로
     * 알리고, key는 32바이트 키를 표준 Base64로, pass는 공급원의 Passphrase 원문을 돌려준다(그 원문으로 다시 만든 키의 지문이 등록된
     * 키와 같아야 함). 자동 공개 키 경고는 내지 않는다(명시적 조회).
     */
    private static Secret read(CryptoSettings settings, KeyProfile profile) throws CredentialCryptoException {
        try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
            CryptoService.KeyCheck check = CryptoService.of(settings).checkKey(profile);
            if (!check.available()) throw check.failureException();
            if (profile.type() == KeyType.KEY) {
                byte[] key = KeyResolver.resolve(settings, profile);
                try {
                    byte[] encoded = Base64.getEncoder().encode(key);
                    char[] text = new char[encoded.length];
                    for (int i = 0; i < encoded.length; i++) text[i] = (char) encoded[i];
                    String fingerprint = KeyResolver.fingerprint(key);
                    return new Secret(text, null, fingerprint, KeyringCommand.lineBytes(encoded));
                } finally {
                    Arrays.fill(key, (byte) 0);
                }
            }
            KeyProvider provider = KeyResolver.provider(profile.source());
            byte[] material = provider.loadMaterial(settings, profile);
            byte[] key = null;
            try {
                key = KeyResolver.materialToKey(profile, material, true);
                String fingerprint = KeyResolver.fingerprint(key);
                if (!fingerprint.equals(check.fingerprint())) {
                    throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                            Messages.get("keyshow.err.changed", profile.id()));
                }
                char[] text = PassKdf.decodeUtf8(material, "file".equals(profile.source()));
                Map<String, String> items = new LinkedHashMap<>();
                items.put(KeyProfile.KDF, profile.value(KeyProfile.KDF));
                items.put(KeyProfile.KDF_ITERATIONS, profile.value(KeyProfile.KDF_ITERATIONS));
                items.put(KeyProfile.SALT, profile.value(KeyProfile.SALT));
                return new Secret(text, items, fingerprint, KeyringCommand.PassBackup.write(profile.id(), items, fingerprint, text));
            } finally {
                Arrays.fill(material, (byte) 0);
                if (key != null) Arrays.fill(key, (byte) 0);
            }
        } catch (IOException | IllegalArgumentException e) {
            // 공급원 읽기 실패: 경로·값은 넣지 않고 종류만 알린다(Fail Closed, 다른 키로 대체하지 않음).
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_SOURCE,
                    Messages.get("keyshow.err.read", profile.id(), e.getClass().getSimpleName()));
        }
    }
}
