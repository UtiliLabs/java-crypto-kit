package io.javacryptokit.file;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.TestSupport;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 파일 암복호화(JCKF v1): 왕복·변조·잘림·키 오류·경로 보호·임시 파일 정리·공개 API. */
class FileCipherTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    @TempDir
    Path dir;

    private static byte[] key() {
        byte[] key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    private static byte[] encrypt(byte[] plain, String keyId, byte[] key) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FileCipher.encryptStream(new ByteArrayInputStream(plain), out, keyId, key);
        return out.toByteArray();
    }

    private static byte[] decrypt(byte[] sealed, String keyId, byte[] key) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FileCipher.decryptStream(new ByteArrayInputStream(sealed), out, keyId, key);
        return out.toByteArray();
    }

    @ParameterizedTest(name = "평문 {0}바이트 왕복")
    @ValueSource(ints = {0, 1, 15, 16, 65535, 65536, 65537, 131072, 200003})
    void roundTripAtChunkBoundaries(int size) throws Exception {
        byte[] plain = new byte[size];
        RANDOM.nextBytes(plain);
        byte[] key = key();
        byte[] sealed = encrypt(plain, "prod01", key);
        assertArrayEquals(plain, decrypt(sealed, "prod01", key));
        int chunks = Math.max(1, (size + FileCipher.CHUNK - 1) / FileCipher.CHUNK + (size % FileCipher.CHUNK == 0 && size > 0 ? 0 : 0));
        assertTrue(sealed.length >= size + chunks * 29, "청크마다 표시·IV·태그가 붙는다");
    }

    @Test
    void sameFileEncryptsDifferentlyEveryTime() throws Exception {
        byte[] plain = "같은 내용".getBytes(StandardCharsets.UTF_8);
        byte[] key = key();
        assertFalse(Arrays.equals(encrypt(plain, "k1", key), encrypt(plain, "k1", key)), "청크마다 새 IV");
    }

    @Test
    void everyTamperingIsDetected() throws Exception {
        byte[] plain = new byte[3 * FileCipher.CHUNK + 100];
        RANDOM.nextBytes(plain);
        byte[] key = key();
        byte[] sealed = encrypt(plain, "prod01", key);
        int header = 4 + 1 + 4 + 1 + "prod01".length();
        int record = 1 + 12 + FileCipher.CHUNK + 16;
        // 1) 헤더의 키ID 글자 바꾸기(같은 길이) -> 키ID 불일치 또는 인증 실패
        byte[] badId = sealed.clone();
        badId[header - 1] = (byte) '2';
        assertThrows(CredentialCryptoException.class, () -> decrypt(badId, "prod01", key));
        // 2) 청크 본문 1비트 변조
        byte[] flipped = sealed.clone();
        flipped[header + record + 500] ^= 1;
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> decrypt(flipped, "prod01", key));
        // 3) 중간 청크를 마지막 청크로 표시 바꾸기
        byte[] flag = sealed.clone();
        flag[header] = 1;
        assertThrows(CredentialCryptoException.class, () -> decrypt(flag, "prod01", key));
        // 4) 청크 순서 바꾸기
        byte[] swapped = sealed.clone();
        System.arraycopy(sealed, header + record, swapped, header, record);
        System.arraycopy(sealed, header, swapped, header + record, record);
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> decrypt(swapped, "prod01", key));
        // 5) 마지막 청크 잘라내기(완전한 청크 단위로)
        byte[] truncated = Arrays.copyOf(sealed, header + 3 * record);
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> decrypt(truncated, "prod01", key));
        // 6) 뒤에 데이터 덧붙이기
        byte[] appended = Arrays.copyOf(sealed, sealed.length + 5);
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> decrypt(appended, "prod01", key));
        // 7) 다른 키
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> decrypt(sealed, "prod01", key()));
        // 8) 다른 키ID 설정
        assertReason(CredentialCryptoException.Reason.KEY_ID_MISMATCH, () -> decrypt(sealed, "prod02", key));
        // 9) 형식이 아닌 파일
        assertReason(CredentialCryptoException.Reason.INVALID_TOKEN,
                () -> decrypt("plain text".getBytes(StandardCharsets.US_ASCII), "prod01", key));
        // 10) 지원하지 않는 버전
        byte[] version = sealed.clone();
        version[4] = 2;
        assertReason(CredentialCryptoException.Reason.INVALID_TOKEN, () -> decrypt(version, "prod01", key));
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void assertReason(CredentialCryptoException.Reason reason, Action action) {
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, action::run);
        assertEquals(reason, ex.getReason(), ex.getMessage());
    }

    @Test
    void publicApiProtectsPathsKeepsOriginalAndLeavesNoTemporaryFiles() throws Exception {
        CredentialCrypto crypto = TestSupport.jarDefaults();
        Path folder = Files.createDirectories(dir.resolve("월간 보고서 폴더"));
        Path in = folder.resolve("고객 목록 2026.csv");
        byte[] content = ("이름,전화\n홍길동,010-0000-0000\n" + new String(new char[100000]).replace('\0', 'x'))
                .getBytes(StandardCharsets.UTF_8);
        Files.write(in, content);
        Path sealed = folder.resolve("고객 목록 2026.csv.jck");
        crypto.encryptFile(in, sealed);
        assertArrayEquals(content, Files.readAllBytes(in), "원본은 바뀌지 않는다");
        Path restored = folder.resolve("restored.csv");
        crypto.decryptFile(sealed, restored);
        assertArrayEquals(content, Files.readAllBytes(restored), "바이트 단위로 같아야 한다");
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            Set<PosixFilePermission> mode = Files.getPosixFilePermissions(restored);
            assertFalse(mode.contains(PosixFilePermission.GROUP_READ) || mode.contains(PosixFilePermission.OTHERS_READ));
        }
        // 기존 출력 파일은 덮어쓰지 않는다
        byte[] keep = Files.readAllBytes(restored);
        assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.decryptFile(sealed, restored));
        assertArrayEquals(keep, Files.readAllBytes(restored));
        // 입력 = 출력 거부, 없는 입력 거부, 폴더 입력 거부
        assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.encryptFile(in, in));
        assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.encryptFile(folder.resolve("none"), folder.resolve("x")));
        assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.encryptFile(folder, folder.resolve("y")));
        // 변조된 파일 복호화 실패 시 출력·임시 파일이 남지 않는다
        byte[] bytes = Files.readAllBytes(sealed);
        bytes[bytes.length - 3] ^= 1;
        Path broken = Files.write(folder.resolve("broken.jck"), bytes);
        Path out = folder.resolve("broken-out.csv");
        assertReason(CredentialCryptoException.Reason.INTEGRITY, () -> crypto.decryptFile(broken, out));
        assertFalse(Files.exists(out), "인증 전 평문을 최종 파일로 내보내면 안 된다");
        try (Stream<Path> files = Files.list(folder)) {
            assertEquals(0, files.filter(p -> p.getFileName().toString().endsWith(FileCipher.TEMP_SUFFIX)).count(),
                    "임시 파일이 남으면 안 된다");
        }
        // 예외 메시지에 경로·내용이 없다
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> crypto.decryptFile(broken, out));
        assertFalse(ex.getMessage().contains(folder.toString()));
        assertFalse(ex.getMessage().contains("홍길동"));
    }

    @Test
    void decryptFileChecksKeyIdBeforeReadingTheKey() throws Exception {
        Path in = Files.write(dir.resolve("a.bin"), new byte[]{1, 2, 3});
        Path sealed = dir.resolve("a.bin.jck");
        TestSupport.jarDefaults().encryptFile(in, sealed);
        Path config = TestSupport.writeConfig(dir, "other.properties", "crypto.key.source=file", "crypto.key.id=other01",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("does-not-exist.key")));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(config).decryptFile(sealed, dir.resolve("out.bin")));
        assertEquals(CredentialCryptoException.Reason.KEY_ID_MISMATCH, ex.getReason(), "키 파일을 읽기 전에 키ID로 거부");
    }

    @Test
    void symbolicLinkToRegularFileIsAcceptedAsInput() throws Exception {
        Path target = Files.write(dir.resolve("target.txt"), "link".getBytes(StandardCharsets.US_ASCII));
        Path link;
        try {
            link = Files.createSymbolicLink(dir.resolve("link.txt"), target);
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException e) {
            assumeTrue(false, "이 환경에서는 심볼릭 링크를 만들 수 없음");
            return;
        }
        TestSupport.jarDefaults().encryptFile(link, dir.resolve("link.txt.jck"));
        TestSupport.jarDefaults().decryptFile(dir.resolve("link.txt.jck"), dir.resolve("back.txt"));
        assertArrayEquals(Files.readAllBytes(target), Files.readAllBytes(dir.resolve("back.txt")));
    }
}
