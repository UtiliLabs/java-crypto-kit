package io.javacryptokit.cli;

import io.javacryptokit.config.KeyProfile;
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
 * {@code --out} 필수). 원본은 바꾸지 않고, 출력 파일이 이미 있으면 덮어쓰지 않는다. 암호화 키는 {@code --type}·{@code --key-id}로
 * 고르고, 복호화는 파일 헤더의 Key ID로 키를 고른다. 복호화는 {@link CryptoCli}의 관리자 인증 뒤에만 진행한다(암호화는 인증 없음).</p>
 */
final class FileCommand {
    /** 암호화 파일 기본 확장자. */
    static final String EXTENSION = ".jck";

    private FileCommand() { }

    /** file decrypt 사전 검사(관리자 인증 전): 입력·출력 경로 형식만 본다(파일 내용·키는 읽지 않음). */
    static void check(CliCommands.Parsed parsed) throws CryptoCli.CliException {
        paths(parsed, false);
    }

    /** @return {입력, 출력} 경로(출력을 생략하면 암호화는 입력.jck, 복호화는 .jck를 뗀 이름) */
    private static Path[] paths(CliCommands.Parsed parsed, boolean encrypt) throws CryptoCli.CliException {
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
        return new Path[] {in, out2};
    }

    static int run(CliCommands.Parsed parsed, PrintStream out) throws Exception {
        boolean encrypt = "file encrypt".equals(parsed.spec.name);
        Path[] paths = paths(parsed, encrypt);
        Path in = paths[0];
        Path out2 = paths[1];
        // 복호화(평문 파일 생성)는 CryptoCli가 관리자 인증을 마친 뒤에만 여기 온다. 암호화는 인증하지 않는다.
        CryptoService crypto = CryptoService.load(parsed.value("--config"));
        // 결과는 한 줄(입력 -> 결과 파일 이름, 크기). 원본 보존·덮어쓰기 거부·임시 파일 정리는 그대로이며 안내 문구는 붙이지 않는다.
        if (encrypt) {
            // 키 선택은 encrypt와 같다(옵션 없음: 기본 유형의 기본 키, --type: 그 유형의 기본 키, --key-id: 그 키).
            KeyProfile profile = crypto.select(CryptoCli.typeOption(parsed), CryptoCli.keyIdOption(parsed));
            crypto.encryptFile(in, out2, null, profile.id());
            out.println(Messages.get("filecli.encrypted", SecretFiles.fileName(in), SecretFiles.fileName(out2),
                    profile.id(), size(out2)));
        } else {
            crypto.decryptFile(in, out2);
            out.println(Messages.get("filecli.decrypted", SecretFiles.fileName(in), SecretFiles.fileName(out2), size(out2)));
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
