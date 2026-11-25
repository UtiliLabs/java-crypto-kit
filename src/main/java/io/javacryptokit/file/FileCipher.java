package io.javacryptokit.file;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.core.Gcm;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.SecretFiles;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 일반 파일(텍스트·CSV·JSON·PDF·이미지 등 형식 무관)을 AES-256-GCM으로 암복호화하는
 * <b>JCKF v1</b> 바이너리 형식 엔진이다. 문자열 토큰 {@code ENC[v1:...]} 형식과는 별개이며 그 형식을 바꾸지 않는다.
 * CLI {@code file encrypt/decrypt}와 공개 API {@code CredentialCrypto.encryptFile/decryptFile}이 {@code core.CryptoService}를
 * 거쳐 이 클래스를 쓴다(같은 구현).
 *
 * <p><b>형식(JCKF v1)</b></p>
 * <pre>
 * 헤더: "JCKF"(4) | 버전 0x01(1) | 청크 크기 65536(4, big-endian) | 키ID 길이 n(1, 1~64) | 키ID(n, ASCII)
 * 청크: 표시(1: 0x00 중간, 0x01 마지막) | IV(12, 청크마다 SecureRandom) | 암호문+태그(평문 길이 + 16)
 *       중간 청크의 평문은 정확히 65536바이트, 마지막 청크는 0~65536바이트(빈 파일은 마지막 청크 하나)
 * AAD : 헤더 전체 | 청크 번호(8, big-endian, 0부터) | 표시(1)
 * </pre>
 *
 * <p><b>보안 판단</b></p>
 * <ul>
 *   <li>청크마다 새 난수 IV와 128비트 태그를 쓴다(문자열 엔진과 같은 IV·태그 규칙, 키 유도 없음). 같은 키에서 난수 IV를 쓰는
 *       GCM 호출 횟수 권장 상한(2^32)을 고려해 파일 하나의 청크 수를 2^32 미만(약 256TiB)으로 제한한다.</li>
 *   <li>헤더(버전·키ID·청크 크기)를 모든 청크의 AAD에 넣어 메타데이터 변조를 탐지한다. 청크 번호로 순서 바꾸기·중복을,
 *       마지막 표시로 잘라내기를, 마지막 청크 뒤 데이터 거부로 덧붙이기를 탐지한다.</li>
 *   <li>스트리밍 처리: 한 번에 청크 하나(64KiB)만 메모리에 둔다. 큰 파일도 전체를 메모리에 올리지 않는다.</li>
 *   <li>복호화 결과는 출력 폴더의 접근 제한 임시 파일(POSIX 600)에만 쓴다. 각 청크는 GCM 태그 검증이 끝난 뒤에만 쓰이고,
 *       파일 끝까지 모든 검증(마지막 청크 확인 포함)이 끝난 경우에만 최종 이름으로 옮긴다. 실패하면 임시 파일을 지운다.</li>
 *   <li>원본은 바꾸지 않는다. 출력 파일이 이미 있으면(심볼릭 링크 포함) 덮어쓰지 않는다. 같은 출력 경로에 동시에 쓰는 다른
 *       작업(다른 프로세스 포함)이 있어도 최종 이름을 파일시스템의 원자적 생성으로 차지하므로 하나만 성공한다. 입력과 출력이 같은 경로면 거부한다.
 *       입력은 일반 파일만 허용한다(심볼릭 링크는 대상이 일반 파일이면 허용, 폴더·장치·FIFO 거부).</li>
 *   <li>오류 메시지에는 파일 이름만 쓰고 경로 전체·내용·키는 넣지 않는다.</li>
 * </ul>
 */
public final class FileCipher {
    /** 형식 표식. */
    private static final byte[] MAGIC = "JCKF".getBytes(StandardCharsets.US_ASCII);
    /** 형식 버전. */
    private static final int VERSION = 1;
    /** 청크 평문 크기(v1 고정). */
    static final int CHUNK = 64 * 1024;
    /** GCM IV 길이(공용 엔진 {@link Gcm}과 같다). */
    private static final int IV_LENGTH = Gcm.IV_BYTES;
    /** GCM 태그 길이(바이트). */
    private static final int TAG_LENGTH = Gcm.TAG_BYTES;
    /** 파일 하나의 최대 청크 수(2^32 - 1). */
    private static final long MAX_CHUNKS = 0xFFFFFFFFL;
    /** 중간 청크 표시. */
    private static final int FLAG_MORE = 0;
    /** 마지막 청크 표시. */
    private static final int FLAG_LAST = 1;
    /** 임시 파일 접미사. */
    static final String TEMP_SUFFIX = ".jck-tmp";

    private FileCipher() { }

    /**
     * 입력·출력 경로를 검사한다(키를 읽기 전에 호출).
     *
     * @param in  입력 파일
     * @param out 출력 파일(아직 없어야 한다)
     * @throws CredentialCryptoException INVALID_INPUT(입력 없음·일반 파일 아님·읽기 불가, 출력이 이미 있음·폴더 없음, 같은 경로)
     */
    public static void checkPaths(Path in, Path out) throws CredentialCryptoException {
        String inName = SecretFiles.fileName(in);
        String outName = SecretFiles.fileName(out);
        if (!Files.exists(in)) throw input("file.err.inMissing", inName);
        if (!Files.isRegularFile(in)) throw input("file.err.inNotRegular", inName);
        if (!Files.isReadable(in)) throw input("file.err.inUnreadable", inName);
        if (in.toAbsolutePath().normalize().equals(out.toAbsolutePath().normalize())) throw input("file.err.samePath");
        if (Files.exists(out, LinkOption.NOFOLLOW_LINKS)) throw input("file.err.outExists", outName);
        Path dir = out.toAbsolutePath().getParent();
        if (dir == null || !Files.isDirectory(dir)) throw input("file.err.outDir", outName);
    }

    /**
     * 암호화 파일의 헤더만 읽어 키ID를 돌려준다(키를 읽기 전에 키ID 불일치를 알리기 위함).
     *
     * @param in 암호화 파일
     * @return 키ID
     * @throws CredentialCryptoException INVALID_TOKEN(형식 아님), INVALID_INPUT(읽기 실패)
     */
    public static String readKeyId(Path in) throws CredentialCryptoException {
        try (InputStream stream = new BufferedInputStream(Files.newInputStream(in))) {
            return keyIdOf(readHeader(stream));
        } catch (IOException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                    Messages.get("file.err.read", SecretFiles.fileName(in)), e);
        }
    }

    /**
     * 파일을 암호화한다. 결과는 같은 폴더의 임시 파일에 쓴 뒤 다 쓰면 최종 이름으로 옮긴다(부분 결과를 남기지 않음).
     *
     * @param in    입력 파일(바꾸지 않는다)
     * @param out   출력 파일(없어야 한다)
     * @param keyId 키ID(헤더에 기록)
     * @param key   32바이트 키(호출자가 지운다)
     * @throws CredentialCryptoException INVALID_INPUT(경로·입출력), CRYPTO_PROVIDER
     */
    public static void encryptFile(Path in, Path out, String keyId, byte[] key) throws CredentialCryptoException {
        checkPaths(in, out);
        process(in, out, true, keyId, key, Files::deleteIfExists);
    }

    /**
     * 파일을 복호화한다. 모든 청크의 인증과 마지막 청크 확인이 끝난 뒤에만 결과가 최종 이름으로 나타난다.
     *
     * @param in    암호화 파일
     * @param out   출력 파일(없어야 한다)
     * @param keyId 현재 설정의 키ID
     * @param key   32바이트 키(호출자가 지운다)
     * @throws CredentialCryptoException INVALID_TOKEN(형식), KEY_ID_MISMATCH, INTEGRITY(변조·손상·잘림), INVALID_INPUT(입출력)
     */
    public static void decryptFile(Path in, Path out, String keyId, byte[] key) throws CredentialCryptoException {
        checkPaths(in, out);
        process(in, out, false, keyId, key, Files::deleteIfExists);
    }

    @FunctionalInterface
    interface TempDeletion {
        void delete(Path temp) throws IOException;
    }

    /** 최종 이름을 공개한 뒤에도 임시 이름의 삭제는 별도로 실패할 수 있다. */
    static void process(Path in, Path out, boolean encrypt, String keyId, byte[] key, TempDeletion deletion)
            throws CredentialCryptoException {
        Path dir = out.toAbsolutePath().getParent();
        Path temp = null;
        Throwable failure = null;
        try {
            temp = createTemp(dir, out.getFileName().toString());
            try (InputStream input = Files.newInputStream(in);
                 OutputStream output = new BufferedOutputStream(Files.newOutputStream(temp, StandardOpenOption.WRITE,
                         StandardOpenOption.TRUNCATE_EXISTING), CHUNK)) {
                if (encrypt) {
                    encryptStream(input, output, keyId, key);
                } else {
                    decryptStream(input, output, keyId, key);
                }
            }
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                channel.force(true);
            }
            publish(temp, out);
        } catch (IOException e) {
            CredentialCryptoException ioFailure = new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                    Messages.get("file.err.io", SecretFiles.fileName(in), SecretFiles.fileName(out)), e);
            failure = ioFailure;
            throw ioFailure;
        } catch (CredentialCryptoException | RuntimeException | Error e) {
            failure = e;
            throw e;
        } finally {
            if (temp != null) {
                try {
                    deletion.delete(temp);
                } catch (IOException | RuntimeException cleanup) {
                    String tempName = SecretFiles.fileName(temp);
                    if (failure == null) { // publish가 성공했고 임시 이름만 남았다.
                        throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                                Messages.get("file.err.publishedTempLeft", SecretFiles.fileName(out), tempName), cleanup);
                    }
                    failure.addSuppressed(new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                            Messages.get("file.err.tempLeft", tempName), cleanup));
                }
            }
        }
    }

    /** 완성된 임시 파일에 최종 이름을 붙인다. 하드 링크 생성은 기존 엔트리를 교체하지 않는다. */
    private static void publish(Path temp, Path out) throws CredentialCryptoException {
        try {
            Files.createLink(out, temp);
        } catch (FileAlreadyExistsException e) {
            throw input("file.err.outExists", SecretFiles.fileName(out));
        } catch (IOException | UnsupportedOperationException e) {
            throw input("file.err.publish", SecretFiles.fileName(out));
        }
    }

    /** 출력 폴더에 접근 제한 임시 파일을 만든다(POSIX 600. Windows는 폴더 ACL을 상속). */
    private static Path createTemp(Path dir, String outName) throws IOException {
        String prefix = "." + (outName.length() > 40 ? outName.substring(0, 40) : outName) + ".";
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempFile(dir, prefix, TEMP_SUFFIX,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        return Files.createTempFile(dir, prefix, TEMP_SUFFIX);
    }

    /**
     * 스트림을 JCKF v1로 암호화한다(테스트·파일 처리 공통).
     *
     * @throws IOException 입출력 실패
     * @throws CredentialCryptoException CRYPTO_PROVIDER, INVALID_INPUT(너무 큰 입력)
     */
    static void encryptStream(InputStream rawInput, OutputStream output, String keyId, byte[] key)
            throws IOException, CredentialCryptoException {
        byte[] header = header(keyId);
        output.write(header);
        PushbackInputStream input = new PushbackInputStream(rawInput, 1);
        byte[] plain = new byte[CHUNK];
        long index = 0;
        try {
            while (true) {
                int length = readFully(input, plain, CHUNK);
                boolean last;
                if (length < CHUNK) {
                    last = true;
                } else {
                    int next = input.read();
                    last = next == -1;
                    if (!last) input.unread(next);
                }
                if (index >= MAX_CHUNKS) {
                    throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT,
                            Messages.get("file.err.tooLarge"));
                }
                byte[] iv = Gcm.newIv();
                byte[] sealed = gcm(true, key, iv, aad(header, index, last), plain, length);
                output.write(last ? FLAG_LAST : FLAG_MORE);
                output.write(iv);
                output.write(sealed);
                index++;
                if (last) return;
            }
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /**
     * JCKF v1 스트림을 복호화해 쓴다. 각 청크는 태그 검증이 끝난 뒤에만 쓴다. 호출자는 끝까지 성공한 경우에만 결과를 공개한다.
     *
     * @throws IOException 입출력 실패
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, CRYPTO_PROVIDER
     */
    static void decryptStream(InputStream rawInput, OutputStream output, String keyId, byte[] key)
            throws IOException, CredentialCryptoException {
        InputStream input = new BufferedInputStream(rawInput, CHUNK + 64);
        byte[] header = readHeader(input);
        if (!keyId.equals(keyIdOf(header))) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
        }
        int fullRecord = IV_LENGTH + CHUNK + TAG_LENGTH;
        byte[] record = new byte[fullRecord + 1];
        long index = 0;
        while (true) {
            int flag = input.read();
            if (flag == -1) throw truncated();
            int length;
            if (flag == FLAG_MORE) {
                length = readFully(input, record, fullRecord);
                if (length < fullRecord) throw truncated();
            } else if (flag == FLAG_LAST) {
                // 마지막 청크는 파일 끝까지다. 최대 길이보다 길면(덧붙인 데이터) 거부한다.
                length = readFully(input, record, fullRecord + 1);
                if (length > fullRecord || length < IV_LENGTH + TAG_LENGTH) throw truncated();
            } else {
                throw truncated();
            }
            if (index >= MAX_CHUNKS) throw truncated();
            byte[] iv = Arrays.copyOfRange(record, 0, IV_LENGTH);
            byte[] sealed = Arrays.copyOfRange(record, IV_LENGTH, length);
            byte[] plain = gcm(false, key, iv, aad(header, index, flag == FLAG_LAST), sealed, sealed.length);
            try {
                output.write(plain);
            } finally {
                Arrays.fill(plain, (byte) 0);
            }
            index++;
            if (flag == FLAG_LAST) {
                Arrays.fill(record, (byte) 0);
                return;
            }
        }
    }

    /** 헤더를 만든다. */
    private static byte[] header(String keyId) {
        byte[] id = keyId.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer buffer = ByteBuffer.allocate(MAGIC.length + 1 + 4 + 1 + id.length);
        buffer.put(MAGIC).put((byte) VERSION).putInt(CHUNK).put((byte) id.length).put(id);
        return buffer.array();
    }

    /** 헤더를 읽고 형식(표식·버전·청크 크기·키ID 형식)을 검증한다. */
    private static byte[] readHeader(InputStream input) throws IOException, CredentialCryptoException {
        byte[] fixed = new byte[MAGIC.length + 1 + 4 + 1];
        if (readFully(input, fixed, fixed.length) < fixed.length) throw notFormat();
        if (!Arrays.equals(Arrays.copyOf(fixed, MAGIC.length), MAGIC)) throw notFormat();
        if ((fixed[4] & 0xff) != VERSION) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("file.err.version"));
        }
        if (ByteBuffer.wrap(fixed, 5, 4).getInt() != CHUNK) throw notFormat();
        int idLength = fixed[9] & 0xff;
        if (idLength < 1 || idLength > 64) throw notFormat();
        byte[] id = new byte[idLength];
        if (readFully(input, id, idLength) < idLength) throw notFormat();
        String keyId = new String(id, StandardCharsets.US_ASCII);
        if (!keyId.matches("[A-Za-z0-9_-]{1,64}")) throw notFormat();
        byte[] header = Arrays.copyOf(fixed, fixed.length + idLength);
        System.arraycopy(id, 0, header, fixed.length, idLength);
        return header;
    }

    private static String keyIdOf(byte[] header) {
        return new String(header, 10, header.length - 10, StandardCharsets.US_ASCII);
    }

    /** AAD = 헤더 | 청크 번호(8) | 표시(1). */
    private static byte[] aad(byte[] header, long index, boolean last) {
        ByteBuffer buffer = ByteBuffer.allocate(header.length + 9);
        buffer.put(header).putLong(index).put((byte) (last ? FLAG_LAST : FLAG_MORE));
        return buffer.array();
    }

    /** AES-GCM 한 번(청크 하나, 공용 엔진 {@link Gcm}). */
    private static byte[] gcm(boolean encrypt, byte[] key, byte[] iv, byte[] aad, byte[] data, int length)
            throws CredentialCryptoException {
        try {
            return encrypt ? Gcm.seal(key, iv, aad, data, 0, length) : Gcm.open(key, iv, aad, data, 0, length);
        } catch (AEADBadTagException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INTEGRITY, Messages.get("file.err.integrity"));
        } catch (GeneralSecurityException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CRYPTO_PROVIDER, null, e);
        }
    }

    /** 최대 {@code length}바이트를 채울 때까지 읽는다. @return 실제로 읽은 바이트 수(끝이면 더 적다) */
    private static int readFully(InputStream input, byte[] buffer, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int read = input.read(buffer, total, length - total);
            if (read == -1) break;
            total += read;
        }
        return total;
    }

    private static CredentialCryptoException notFormat() {
        return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("file.err.notFormat"));
    }

    private static CredentialCryptoException truncated() {
        return new CredentialCryptoException(CredentialCryptoException.Reason.INTEGRITY, Messages.get("file.err.truncated"));
    }

    private static CredentialCryptoException input(String key, Object... args) {
        return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get(key, args));
    }
}
