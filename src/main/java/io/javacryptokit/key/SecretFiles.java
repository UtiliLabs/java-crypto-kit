package io.javacryptokit.key;

import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 키 파일·Vault 토큰 파일·KMS 데이터 키 파일처럼 "작은 비밀 텍스트 파일"을 안전하게
 * 읽고 점검하는 공통 도우미다(같은 규칙을 공급원마다 따로 구현하지 않기 위함).
 *
 * <p><b>읽기 규칙</b></p>
 * <ul>
 *   <li>일반 파일만 허용한다. 폴더·장치 파일(/dev/zero 등)·FIFO(열면 쓰는 쪽이 나타날 때까지 멈춤)는 거부한다. 심볼릭 링크는
 *       따라가서 대상이 일반 파일이면 허용한다(Kubernetes Secret·systemd credential 마운트가 링크를 쓴다).</li>
 *   <li>크기를 미리 조회하지 않고 상한 + 1바이트까지만 읽는다(조회와 읽기 사이에 파일이 바뀌어도 메모리를 상한 이상 쓰지 않음).</li>
 *   <li>읽은 원본 바이트 버퍼는 돌려주기 전에 지운다. 오류 메시지에는 경로·내용을 넣지 않고 설정 이름만 쓴다.</li>
 *   <li>파일이 없으면 {@link java.nio.file.NoSuchFileException}으로 실패한다(다른 키로 대체하지 않음).</li>
 * </ul>
 */
public final class SecretFiles {
    private SecretFiles() { }

    /**
     * 작은 비밀 텍스트 파일을 읽어 앞뒤 공백을 지운 ASCII 문자열로 돌려준다.
     *
     * @param path        파일 경로
     * @param limit       허용 최대 바이트 수
     * @param settingName 오류 메시지에 쓸 설정 이름(경로 대신)
     * @return 파일 내용(앞뒤 공백 제거)
     * @throws IOException              파일이 없거나(NoSuchFileException) 읽을 권한이 없는 경우
     * @throws IllegalArgumentException 일반 파일이 아니거나 상한을 넘는 경우({@link SafeMessageException})
     */
    public static String readText(Path path, int limit, String settingName) throws IOException {
        if (Files.exists(path) && !Files.isRegularFile(path)) {
            throw new SafeMessageException(Messages.get("key.err.notRegular", settingName));
        }
        byte[] content = readAtMost(path, limit + 1);
        try {
            if (content.length > limit) {
                throw new SafeMessageException(Messages.get("key.err.tooLarge", settingName, limit));
            }
            return new String(content, StandardCharsets.US_ASCII).trim();
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    /**
     * 파일을 최대 {@code limit}바이트까지만 읽는다. 읽기 버퍼는 돌려주기 전에 지운다.
     *
     * @param path  읽을 파일
     * @param limit 최대 읽기 바이트 수
     * @return 읽은 바이트(호출자가 사용 후 지운다)
     * @throws IOException 파일이 없거나 읽을 권한이 없는 경우
     */
    public static byte[] readAtMost(Path path, int limit) throws IOException {
        byte[] buffer = new byte[limit];
        int total = 0;
        try (InputStream in = Files.newInputStream(path)) {
            int read;
            while (total < limit && (read = in.read(buffer, total, limit - total)) != -1) {
                total += read;
            }
            return Arrays.copyOf(buffer, total);
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    /**
     * 파일을 읽지 않고 준비 상태만 점검한다({@code doctor}). 내용은 열지 않는다.
     *
     * @param settingName 설정 이름(메시지용)
     * @param pathValue   설정값(경로)
     * @param secret      비밀 파일이면 true(POSIX에서 그룹·기타 사용자가 읽을 수 있으면 WARN)
     * @return 점검 결과
     */
    public static List<Diagnostic> check(String settingName, String pathValue, boolean secret) {
        List<Diagnostic> results = new ArrayList<>();
        if (pathValue == null || pathValue.isEmpty()) {
            results.add(Diagnostic.fail(Messages.get("key.check.pathEmpty", settingName),
                    Messages.get("key.action.setPath", settingName)));
            return results;
        }
        Path path;
        try {
            path = Paths.get(pathValue);
        } catch (InvalidPathException e) {
            results.add(Diagnostic.fail(Messages.get("key.check.pathInvalid", settingName),
                    Messages.get("key.action.setPath", settingName)));
            return results;
        }
        String name = fileName(path);
        if (!Files.exists(path)) {
            results.add(Diagnostic.fail(Messages.get("key.check.fileMissing", settingName, name),
                    Messages.get("key.action.fileAccess")));
        } else if (!Files.isRegularFile(path)) {
            results.add(Diagnostic.fail(Messages.get("key.err.notRegular", settingName),
                    Messages.get("key.action.setPath", settingName)));
        } else if (!Files.isReadable(path)) {
            results.add(Diagnostic.fail(Messages.get("key.check.fileUnreadable", settingName, name),
                    Messages.get("key.action.fileAccess")));
        } else {
            results.add(Diagnostic.pass(Messages.get("key.check.fileOk", settingName, name)));
            if (secret && FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                try {
                    Set<PosixFilePermission> mode = Files.getPosixFilePermissions(path);
                    if (mode.contains(PosixFilePermission.GROUP_READ) || mode.contains(PosixFilePermission.OTHERS_READ)) {
                        results.add(Diagnostic.warn(Messages.get("key.check.filePermissive", settingName, name),
                                Messages.get("key.action.chmod")));
                    }
                } catch (IOException | UnsupportedOperationException | SecurityException ignored) {
                    // 권한을 조회할 수 없으면 권한 경고만 생략한다(읽기 가능 여부는 위에서 확인함).
                }
            }
        }
        return results;
    }

    /**
     * @param path 경로
     * @return 파일 이름만(전체 경로는 메시지에 넣지 않는다)
     */
    public static String fileName(Path path) {
        Path name = path.getFileName();
        return name == null ? "-" : name.toString();
    }

    /**
     * @param pathValue 경로 문자열
     * @return 파일 이름만, 경로 형식이 잘못됐으면 "-"
     */
    public static String fileName(String pathValue) {
        try {
            return pathValue == null || pathValue.isEmpty() ? "-" : fileName(Paths.get(pathValue));
        } catch (InvalidPathException e) {
            return "-";
        }
    }
}
