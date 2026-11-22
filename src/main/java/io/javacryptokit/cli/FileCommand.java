package io.javacryptokit.cli;

import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.SecretFiles;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * <b>내부 구현 클래스</b>: {@code file encrypt / file decrypt}. 공개 API {@code CredentialCrypto.encryptFile/decryptFile}과 같은
 * 구현({@code core.CryptoService} → {@code file.FileCipher}, JCKF v1)을 호출한다.
 *
 * <p>출력 경로를 생략하면 암호화는 {@code <입력>.jck}, 복호화는 입력 이름에서 {@code .jck}를 뗀 이름을 쓴다(그 밖의 이름이면
 * {@code --out} 필수). 원본은 바꾸지 않고, 출력 파일이 이미 있으면 덮어쓰지 않는다.</p>
 */
final class FileCommand {
    /** 암호화 파일 기본 확장자. */
    static final String EXTENSION = ".jck";

    private FileCommand() { }

    static int run(CliCommands.Parsed parsed, PrintStream out) throws Exception {
        boolean encrypt = "file encrypt".equals(parsed.spec.name);
        String inValue = parsed.value("--in");
        if (inValue == null) throw new CryptoCli.CliException(Messages.get("filecli.err.in", parsed.spec.name));
        Path in = path(inValue, "--in");
        String outValue = parsed.value("--out");
        Path out2;
        if (outValue != null) {
            out2 = path(outValue, "--out");
        } else if (encrypt) {
            out2 = path(inValue + EXTENSION, "--out");
        } else if (inValue.toLowerCase(java.util.Locale.ROOT).endsWith(EXTENSION) && inValue.length() > EXTENSION.length()) {
            out2 = path(inValue.substring(0, inValue.length() - EXTENSION.length()), "--out");
        } else {
            throw new CryptoCli.CliException(Messages.get("filecli.err.out"));
        }
        CryptoService crypto = CryptoService.load(parsed.value("--config"));
        if (encrypt) {
            crypto.encryptFile(in, out2);
            out.println(Messages.get("filecli.encrypted", SecretFiles.fileName(in), SecretFiles.fileName(out2),
                    crypto.settings().keyId(), size(out2)));
            out.println(Messages.get("filecli.note.original"));
        } else {
            crypto.decryptFile(in, out2);
            out.println(Messages.get("filecli.decrypted", SecretFiles.fileName(in), SecretFiles.fileName(out2), size(out2)));
            out.println(Messages.get("filecli.note.plain"));
        }
        return 0;
    }

    private static long size(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return -1;
        }
    }

    private static Path path(String value, String option) throws CryptoCli.CliException {
        try {
            return Paths.get(value);
        } catch (InvalidPathException e) {
            throw new CryptoCli.CliException(Messages.get("cli.err.path", option));
        }
    }
}
