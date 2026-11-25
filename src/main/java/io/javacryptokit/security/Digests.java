package io.javacryptokit.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * <b>공개 API</b>: SHA-256·SHA-512 해시(데이터·파일 지문).
 *
 * <p><b>언제 쓰는가</b>: 받은 파일·데이터가 미리 확보한(신뢰할 수 있는 경로로 받은) 해시와 같은지 확인할 때, 배포 파일 지문을
 * 만들 때. <b>쓰지 않는 경우</b>: 비밀번호 저장({@link Passwords}), 보낸 쪽 인증(공유 키는 {@link Hmac}, 공개키는
 * {@link Signatures}). 해시는 키가 없어 누구나 같은 값을 다시 만들 수 있다.</p>
 *
 * <p>문자열은 UTF-8로 바꿔 해시한다({@link Bytes#utf8}). 파일은 64KiB씩 읽어 스트리밍으로 계산하며(전체를 메모리에 올리지 않음)
 * 파일을 바꾸지 않는다. 파일이 없거나 읽을 수 없으면 {@link IOException}, 기대값과 다르면 {@code false}다. 상태가 없어 스레드
 * 안전하다.</p>
 */
public final class Digests {
    private static final int BUFFER = 64 * 1024;

    private Digests() { }

    /** @return SHA-256(data) */
    public static byte[] sha256(byte[] data) {
        return hash(DigestAlgorithm.SHA256, data);
    }

    /** @return SHA-256(UTF-8(text))의 소문자 16진수 64자 */
    public static String sha256Hex(String text) {
        return hash(DigestAlgorithm.SHA256, text, Encoding.HEX);
    }

    /** @return SHA-256(data)의 소문자 16진수 64자 */
    public static String sha256Hex(byte[] data) {
        return hash(DigestAlgorithm.SHA256, data, Encoding.HEX);
    }

    /**
     * @param file 파일
     * @return 파일 SHA-256의 소문자 16진수 64자
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static String sha256File(Path file) throws IOException {
        return hashFile(DigestAlgorithm.SHA256, file, Encoding.HEX);
    }

    /**
     * @param algorithm 알고리즘
     * @param data      원본(바꾸지 않는다)
     * @return 해시
     */
    public static byte[] hash(DigestAlgorithm algorithm, byte[] data) {
        Text.require(data, "data");
        return digest(algorithm).digest(data);
    }

    /**
     * @param algorithm 알고리즘
     * @param text      원본 문자열(UTF-8로 해시)
     * @return 해시
     */
    public static byte[] hash(DigestAlgorithm algorithm, String text) {
        return hash(algorithm, Bytes.utf8(text));
    }

    /**
     * @param algorithm 알고리즘
     * @param data      원본
     * @param encoding  출력 형식
     * @return 인코딩한 해시
     */
    public static String hash(DigestAlgorithm algorithm, byte[] data, Encoding encoding) {
        Text.require(encoding, "encoding");
        return encoding.encode(hash(algorithm, data));
    }

    /**
     * @param algorithm 알고리즘
     * @param text      원본 문자열(UTF-8로 해시)
     * @param encoding  출력 형식
     * @return 인코딩한 해시
     */
    public static String hash(DigestAlgorithm algorithm, String text, Encoding encoding) {
        Text.require(encoding, "encoding");
        return encoding.encode(hash(algorithm, text));
    }

    /**
     * 파일을 스트리밍으로 해시한다.
     *
     * @param algorithm 알고리즘
     * @param file      파일(바꾸지 않는다)
     * @return 해시
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static byte[] hashFile(DigestAlgorithm algorithm, Path file) throws IOException {
        Text.require(file, "file");
        MessageDigest digest = digest(algorithm);
        byte[] buffer = new byte[BUFFER];
        try (InputStream input = Files.newInputStream(file)) {
            int read;
            while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
        }
        return digest.digest();
    }

    /**
     * @param algorithm 알고리즘
     * @param file      파일
     * @param encoding  출력 형식
     * @return 인코딩한 해시
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static String hashFile(DigestAlgorithm algorithm, Path file, Encoding encoding) throws IOException {
        Text.require(encoding, "encoding");
        return encoding.encode(hashFile(algorithm, file));
    }

    /**
     * 파일 해시가 기대값과 같은지 확인한다(안전 비교).
     *
     * @param algorithm 알고리즘
     * @param file      파일
     * @param expected  신뢰할 수 있는 경로로 받은 기대 해시
     * @param encoding  기대값의 형식
     * @return 같으면 true, 다르면 false
     * @throws IOException              파일이 없거나 읽을 수 없음
     * @throws IllegalArgumentException 기대값이 그 형식이 아님
     */
    public static boolean verifyFile(DigestAlgorithm algorithm, Path file, String expected, Encoding encoding) throws IOException {
        Text.require(encoding, "encoding");
        byte[] wanted = encoding.decode(Text.require(expected, "expected"));
        return Bytes.equalsConstantTime(hashFile(algorithm, file), wanted);
    }

    private static MessageDigest digest(DigestAlgorithm algorithm) {
        Text.require(algorithm, "algorithm");
        try {
            return MessageDigest.getInstance(algorithm.jcaName());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", algorithm.jcaName()));
        }
    }
}
