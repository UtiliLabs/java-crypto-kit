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
import java.io.IOException;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.SecretFiles;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
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

    /** 두 작업을 동시에 시작해 성공한 입력 번호를 반환한다(둘 다 거부되면 -1). */
    private static int race(Action first, Action second) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(2);
        AtomicInteger winner = new AtomicInteger(-1);
        List<Throwable> unexpected = Collections.synchronizedList(new ArrayList<>());
        Thread[] threads = new Thread[2];
        Action[] actions = {first, second};
        for (int i = 0; i < 2; i++) {
            final int index = i;
            Action action = actions[i];
            threads[i] = new Thread(() -> {
                try {
                    barrier.await();
                    action.run();
                    assertTrue(winner.compareAndSet(-1, index), "두 작업이 같은 출력에 성공함");
                } catch (CredentialCryptoException e) {
                    if (e.getReason() != CredentialCryptoException.Reason.INVALID_INPUT) unexpected.add(e);
                } catch (Throwable e) {
                    unexpected.add(e);
                }
            });
            threads[i].start();
        }
        for (Thread thread : threads) {
            thread.join(60_000);
            assertFalse(thread.isAlive(), "파일 작업 시간 초과");
        }
        assertTrue(unexpected.isEmpty(), unexpected.toString());
        return winner.get();
    }

    private static byte[] decryptToBytes(CredentialCrypto crypto, Path sealed, Path scratch) throws Exception {
        crypto.decryptFile(sealed, scratch);
        try {
            return Files.readAllBytes(scratch);
        } finally {
            Files.delete(scratch);
        }
    }

    /**
     * QA P1-01: 같은 출력 경로에 서로 다른 입력을 동시에 암호화·복호화하면 하나만 성공하고 덮어쓰지 않는다(존재 확인과 이름 변경 사이의
     * 경쟁). 관리형·직접 키 API 모두 같은 처리 경로(FileCipher)를 쓰는지 함께 확인한다. 성공한 결과는 이긴 쪽 입력과 같고, 이미 있던
     * 파일은 바뀌지 않으며, 임시 파일·빈 자리 파일이 남지 않는다. 경로 별칭·심볼릭 링크 출력 거부도 그대로다.
     */
    @Test
    void concurrentWritersToTheSameOutputPathNeverOverwrite() throws Exception {
        byte[][] plain = {new byte[FileCipher.CHUNK], new byte[FileCipher.CHUNK + 7]};
        RANDOM.nextBytes(plain[0]);
        RANDOM.nextBytes(plain[1]);
        Path[] in = {Files.write(dir.resolve("a.bin"), plain[0]), Files.write(dir.resolve("b.bin"), plain[1])};
        CredentialCrypto[] cryptos = {CredentialCrypto.fromRawKey("race01", key()), TestSupport.jarDefaults()};
        String[] names = {"direct", "managed"};
        for (int c = 0; c < cryptos.length; c++) {
            CredentialCrypto crypto = cryptos[c];
            Path[] sealed = {dir.resolve(names[c] + "-a.jck"), dir.resolve(names[c] + "-b.jck")};
            crypto.encryptFile(in[0], sealed[0]);
            crypto.encryptFile(in[1], sealed[1]);
            Path encOut = dir.resolve(names[c] + "-race.jck");
            Path decOut = dir.resolve(names[c] + "-race.bin");
            Path check = dir.resolve(names[c] + "-check.bin");
            for (int round = 0; round < 25; round++) {
                int encrypted = race(() -> crypto.encryptFile(in[0], encOut), () -> crypto.encryptFile(in[1], encOut));
                assertTrue(encrypted >= 0, "암호화 결과가 있어야 한다");
                assertArrayEquals(plain[encrypted], decryptToBytes(crypto, encOut, check));
                Files.delete(encOut);
                int decrypted = race(() -> crypto.decryptFile(sealed[0], decOut), () -> crypto.decryptFile(sealed[1], decOut));
                assertTrue(decrypted >= 0, "복호화 결과가 있어야 한다");
                assertArrayEquals(plain[decrypted], Files.readAllBytes(decOut));
                Files.delete(decOut);
            }
            // 이미 있는 파일: 동시에 써도 둘 다 실패하고 내용은 그대로
            byte[] keep = "기존 파일".getBytes(StandardCharsets.UTF_8);
            Files.write(decOut, keep);
            assertEquals(-1, race(() -> crypto.decryptFile(sealed[0], decOut), () -> crypto.decryptFile(sealed[1], decOut)));
            assertArrayEquals(keep, Files.readAllBytes(decOut));
            // 같은 파일을 가리키는 다른 경로 표기(별칭)도 기존 파일로 보고 거부
            Path alias = dir.resolve("sub").resolve("..").resolve(decOut.getFileName());
            Files.createDirectories(dir.resolve("sub"));
            assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.encryptFile(in[0], alias));
            assertArrayEquals(keep, Files.readAllBytes(decOut));
            Files.delete(decOut);
        }
        // 출력 자리에 있는 심볼릭 링크(대상이 없어도)는 따라가지 않고 거부한다
        Path target = dir.resolve("link-target.bin");
        Path link = null;
        try {
            link = Files.createSymbolicLink(dir.resolve("link-out.jck"), target);
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException e) {
            // 이 환경에서는 심볼릭 링크를 만들 수 없음(Windows 일반 권한 등): 링크 부분만 건너뛴다
        }
        if (link != null) {
            Path out = link;
            assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> cryptos[0].encryptFile(in[0], out));
            assertFalse(Files.exists(target), "링크 대상에 쓰면 안 된다");
        }
        try (Stream<Path> files = Files.list(dir)) {
            List<String> left = files.map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(FileCipher.TEMP_SUFFIX) || n.contains("-race.") || n.contains("-check.")).collect(Collectors.toList());
            assertTrue(left.isEmpty(), "임시 파일·빈 자리 파일이 남으면 안 된다: " + left);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ko", "en"})
    void cleanupFailureBeforeAndAfterPublicationPreservesPrimaryState(String language) throws Exception {
        boolean korean = language.equals("ko");
        try (Messages.Scope ignored = Messages.use(korean ? Messages.Language.KO : Messages.Language.EN)) {
            byte[] key = key();
            byte[] plain = "private test content".getBytes(StandardCharsets.UTF_8);
            byte[] sealed = encrypt(plain, "sample", key);
            Path input = Files.write(dir.resolve("input.jck"), sealed);
            Path output = dir.resolve("완성본.txt");
            List<Path> leftover = new ArrayList<>();
            FileCipher.TempDeletion denied = path -> {
                leftover.add(path);
                throw new IOException("private diagnostic: " + dir);
            };

            CredentialCryptoException published = assertThrows(CredentialCryptoException.class,
                    () -> FileCipher.process(input, output, false, "sample", key, denied));
            assertEquals(CredentialCryptoException.Reason.INVALID_INPUT, published.getReason());
            assertEquals(0, published.getSuppressed().length);
            assertEquals("IOException", published.getCauseType());
            assertEquals(null, published.getCause());
            assertTrue(published.getMessage().contains(korean ? "완성되었습니다" : "is complete"));
            assertTrue(published.getMessage().contains(SecretFiles.fileName(leftover.get(0))));
            assertFalse(published.getMessage().contains(dir.toString()));
            assertFalse(published.getMessage().contains("private"));
            assertFalse(published.getMessage().contains("12KB"));
            assertTrue(Files.isSameFile(output, leftover.get(0)));
            Files.delete(leftover.get(0));
            assertArrayEquals(plain, Files.readAllBytes(output));

            sealed[sealed.length - 1] ^= 1;
            Files.write(input, sealed);
            Path other = dir.resolve("unpublished.txt");
            CredentialCryptoException primary = assertThrows(CredentialCryptoException.class,
                    () -> FileCipher.process(input, other, false, "sample", key, denied));
            assertEquals(CredentialCryptoException.Reason.INTEGRITY, primary.getReason());
            assertTrue(primary.getMessage().contains(korean ? "인증에 실패" : "failed authentication"));
            assertFalse(Files.exists(other));
            assertEquals(1, primary.getSuppressed().length);
            Throwable cleanup = primary.getSuppressed()[0];
            assertTrue(cleanup.getMessage().contains(SecretFiles.fileName(leftover.get(1))));
            assertTrue(cleanup.getMessage().contains(korean ? "임시 파일만 삭제" : "delete only"));
            assertFalse(cleanup.getMessage().contains(dir.toString()));
            assertFalse(cleanup.getMessage().contains("private"));
            assertEquals(null, cleanup.getCause());
            assertTrue(Files.deleteIfExists(leftover.get(1)));
            assertArrayEquals(plain, Files.readAllBytes(output));
        }
    }

    @Test
    void unsupportedOutputFileSystemLeavesNoPartialResult() throws Exception {
        Path archive = dir.resolve("results.zip");
        Path source = Files.write(dir.resolve("original.bin"), new byte[] {1, 2, 3});
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("local", key());
        try (FileSystem zip = FileSystems.newFileSystem(URI.create("jar:" + archive.toUri()), Collections.singletonMap("create", "true"))) {
            Path folder = zip.getPath("/");
            assertReason(CredentialCryptoException.Reason.INVALID_INPUT, () -> crypto.encryptFile(source, folder.resolve("out.jck")));
            try (Stream<Path> contents = Files.list(folder)) {
                assertEquals(0, contents.count());
            }
        }
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(source));
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
        // 공개 AES 키(default)로 만든 파일: 아래 설정에는 그 Key ID가 없다(crypto.key.*가 other01로 바뀜).
        TestSupport.jarDefaults().encryptFile(in, sealed, io.javacryptokit.KeyType.KEY);
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
