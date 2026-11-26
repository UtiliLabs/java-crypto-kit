package io.javacryptokit.cli;

import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.SecretFiles;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * <b>내부 구현 클래스</b>: CLI 관리자 비밀번호. 규칙 검사, JAR 안 검증값(단방향) 만들기·확인, JAR의 관리자 상태 판정, 비대화형
 * 비밀번호 파일({@value #FILE_OPTION}) 읽기를 맡는다.
 *
 * <p><b>범위</b>: CLI 사용 통제다. Java API·Tomcat({@code EncryptedDataSourceFactory})은 이 항목을 읽지 않으며 비밀번호 없이
 * 그대로 동작한다. JAR 파일을 고칠 수 있는 사람은 이 항목을 지우거나 바꿀 수 있고 내장 키는 JAR에서 직접 꺼낼 수 있으므로, 키 추출을
 * 막는 수단이 아니다. 시도 횟수 제한은 실행 1회 안에서만이며 영구 잠금이 아니다.</p>
 *
 * <p><b>규칙</b>: {@value #MIN_LENGTH}~{@value #MAX_LENGTH}자, 인쇄 가능한 ASCII만(영문자·숫자·특수문자 32개, 공백·한글 등 불가),
 * 영문자·숫자·특수문자 각 1자 이상. 대문자·소문자를 따로 요구하지 않는다. 최초 설정·변경·비밀번호 파일에 똑같이 적용한다.</p>
 *
 * <p><b>저장</b>: {@value #ENTRY}에 PBKDF2-HMAC-SHA256 결과만 둔다(목적 표지 + 16바이트 보안 난수 Salt, 600,000회, 32바이트).
 * 원문·가역 표현은 저장하지 않는다. 입력은 늘 다시 파생해 일정 시간 비교하므로 저장된 값을 비밀번호로 넣어도 통과하지 않는다.
 * 형식이 다르거나 알 수 없는 버전이면 손상으로 보고 CLI를 멈춘다(Fail Closed). 데이터 암호화 키(pass·key)와는 별개다.</p>
 */
final class AdminPassword {
    /** JAR 안의 검증값 항목(설정 파일이 아니므로 -D·외부 Properties로 바꿀 수 없다). */
    static final String ENTRY = "META-INF/java-crypto-kit/admin.properties";
    /** 이 클래스가 있는 JAR(코드)만 관리자 비밀번호를 지원한다. 없으면 이전 버전 JAR이다. */
    static final String MARKER = "io/javacryptokit/cli/AdminPassword.class";
    /** 비대화형 비밀번호 파일 옵션. */
    static final String FILE_OPTION = "--admin-pass-file";
    static final int MIN_LENGTH = 10;
    static final int MAX_LENGTH = 128;
    /** 특수문자로 인정하는 ASCII 문장부호·기호 32개(공백은 포함하지 않음). */
    static final String SPECIALS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    static final String KDF = "PBKDF2WithHmacSHA256";
    /** 새 검증값의 반복 횟수. */
    static final int ITERATIONS = 600_000;
    /** 읽을 때 받는 반복 횟수 범위(낮춘 검증값으로 빠른 대입을 쉽게 만드는 변조를 거부). */
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 5_000_000;
    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    static final String FORMAT = "1";
    /** 실행 1회에서 비밀번호를 다시 입력할 수 있는 횟수. */
    static final int ATTEMPTS = 3;
    static final int MAX_ENTRY_BYTES = 4096;
    /** 비밀번호 파일 최대 크기(바이트, BOM·줄바꿈 포함). */
    static final int MAX_FILE_BYTES = 1024;
    /** 목적 구분 표지: Passphrase 키 파생(PBKDF2)과 같은 입력이 같은 결과가 되지 않게 Salt 앞에 붙인다. */
    private static final byte[] PURPOSE = "java-crypto-kit/cli-admin-password/v1".getBytes(StandardCharsets.US_ASCII);
    private static final List<String> FIELDS = Collections.unmodifiableList(
            Arrays.asList("format.version", "kdf", "kdf.iterations", "salt", "verifier"));
    private static final SecureRandom RANDOM = new SecureRandom();

    private AdminPassword() { }

    /** JAR의 관리자 비밀번호 상태. */
    enum State {
        /** CLI가 JAR가 아닌 곳(클래스 폴더)에서 실행 중이라 확인할 수 없음. */
        NO_JAR,
        /** 관리자 비밀번호를 모르는 이전 버전 JAR. */
        LEGACY,
        /** 아직 설정하지 않음(최초 설정 필요). */
        UNINITIALIZED,
        /** 설정됨. */
        INITIALIZED,
        /** 검증값 손상·삭제·알 수 없는 형식(CLI 사용 불가). */
        DAMAGED
    }

    /** 상태와 (손상이면) 원인 문구. */
    static final class Status {
        final State state;
        /** 손상 원인(비밀 없음), 손상이 아니면 null. */
        final String detail;

        Status(State state, String detail) {
            this.state = state;
            this.detail = detail;
        }
    }

    /**
     * JAR의 관리자 상태를 정한다(CLI의 상태·무결성 판단 기준 하나). 다음이면 {@link State#DAMAGED}로 보고 CLI가 그 JAR로는 아무
     * 작업도 하지 않는다(새 이력을 시작하거나 결과 JAR를 만들지 않음, Java API·Tomcat은 이 판단을 쓰지 않음):
     * <ul>
     *   <li>변경 이력이 손상되었거나(해시 체인·형식·설정 지문 불일치) 설정이 이력 없이 바뀜(모든 JAR, 이전 버전 JAR 포함)</li>
     *   <li>검증값 형식·버전·반복 횟수가 올바르지 않음</li>
     *   <li>검증값은 있는데 이력이 없음(이력 삭제), 또는 이력의 관리자 기록이 최초 설정 1건 + 그 뒤 변경이 아님</li>
     *   <li>검증값은 없는데 이력에 관리자 기록이 있음(검증값 삭제)</li>
     * </ul>
     * 해시 체인은 키 없는 SHA-256이므로 이력 파일을 마음대로 다시 쓰는 사람의 위조까지 막지는 못한다(식별 가능한 결손·손상만 막음).
     *
     * @param snap 읽은 JAR
     * @return 상태
     */
    static Status statusOf(JarConfigEditor.Snapshot snap) {
        // 변경 이력의 무결성(해시 체인·설정 지문·이력 없는 설정 변경)은 모든 JAR에서 먼저 본다(이전 버전 JAR 포함).
        if (snap.history.problem != null) return new Status(State.DAMAGED, snap.history.problem);
        if (!snap.supportsAdmin()) return new Status(State.LEGACY, null);
        if (snap.adminBytes != null) {
            try {
                parse(snap.adminBytes);
            } catch (SafeMessageException e) {
                return new Status(State.DAMAGED, e.getMessage());
            }
            // 검증값은 admin setup으로만 생기므로 이력과 그 안의 최초 설정 기록이 함께 있어야 한다(이력만 지운 JAR가 새 이력을 시작하지 못하게).
            if (!snap.history.present) return new Status(State.DAMAGED, Messages.get("admin.damaged.noHistory"));
            if (!snap.history.adminRecordsValid()) return new Status(State.DAMAGED, Messages.get("admin.damaged.records"));
            return new Status(State.INITIALIZED, null);
        }
        if (snap.history.hasAdminRecords()) return new Status(State.DAMAGED, Messages.get("admin.damaged.missing"));
        return new Status(State.UNINITIALIZED, null);
    }

    // ===================================================================================================
    // 규칙
    // ===================================================================================================

    /**
     * 새 비밀번호의 규칙 위반을 찾는다(순서 고정: 길이 → 허용 문자 → 영문자 → 숫자 → 특수문자).
     *
     * @param password 입력(바꾸지 않음)
     * @return 위반 항목의 메시지 키(통과하면 빈 목록)
     */
    static List<String> violations(char[] password) {
        boolean letter = false;
        boolean digit = false;
        boolean special = false;
        boolean other = false;
        for (char c : password) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                letter = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else if (SPECIALS.indexOf(c) >= 0) {
                special = true;
            } else {
                other = true;
            }
        }
        int length = Character.codePointCount(password, 0, password.length);
        List<String> found = new ArrayList<>();
        if (length < MIN_LENGTH) found.add("admin.rule.short");
        if (length > MAX_LENGTH) found.add("admin.rule.long");
        if (other) found.add("admin.rule.chars");
        if (!letter) found.add("admin.rule.letter");
        if (!digit) found.add("admin.rule.digit");
        if (!special) found.add("admin.rule.special");
        return found;
    }

    /** @return 위반 항목을 현재 언어로 이은 한 줄(예: "10자 미만, 특수문자 없음") */
    static String describe(List<String> violations) {
        List<String> texts = new ArrayList<>();
        for (String key : violations) texts.add(Messages.get(key, MIN_LENGTH, MAX_LENGTH));
        return String.join(", ", texts);
    }

    // ===================================================================================================
    // 검증값
    // ===================================================================================================

    /** JAR에 저장한 검증값(Salt·결과·반복 횟수). 비밀번호 원문은 없다. */
    static final class Verifier {
        final int iterations;
        private final byte[] salt;
        private final byte[] hash;

        private Verifier(int iterations, byte[] salt, byte[] hash) {
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }

        /**
         * @param password 입력(바꾸지 않음)
         * @return 저장한 결과와 같으면 true(입력을 다시 파생해 일정 시간 비교)
         */
        boolean matches(char[] password) {
            if (password == null || password.length == 0) return false;
            byte[] candidate = derive(password, salt, iterations);
            try {
                return MessageDigest.isEqual(candidate, hash);
            } finally {
                Arrays.fill(candidate, (byte) 0);
            }
        }
    }

    /**
     * 새 검증값 항목을 만든다(보안 난수 Salt, {@value #ITERATIONS}회).
     *
     * @param password 규칙을 통과한 비밀번호(바꾸지 않음)
     * @return {@value #ENTRY} 내용(ASCII)
     */
    static byte[] create(char[] password) {
        return create(password, ITERATIONS);
    }

    /** {@link #create(char[])}와 같고 반복 횟수만 정한다(시험에서 허용 범위의 낮은 값으로 시간을 줄일 때). */
    static byte[] create(char[] password, int iterations) {
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw new IllegalArgumentException("iterations");
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, iterations);
        try {
            String text = "# java-crypto-kit CLI admin password verifier: one-way PBKDF2-HMAC-SHA256 (the password is not stored).\n"
                    + "# Read only by the CLI. The Java API and Tomcat never use this file.\n"
                    + "format.version=" + FORMAT + "\n"
                    + "kdf=" + KDF + "\n"
                    + "kdf.iterations=" + iterations + "\n"
                    + "salt=" + Base64.getEncoder().encodeToString(salt) + "\n"
                    + "verifier=" + Base64.getEncoder().encodeToString(hash) + "\n";
            return text.getBytes(StandardCharsets.US_ASCII);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * 검증값 항목을 엄격하게 읽는다: ASCII, 항목마다 정확히 한 번, 알려진 항목만, 형식 버전·KDF·반복 횟수 범위·Salt(16바이트)·결과
     * (32바이트) 확인.
     *
     * @param entry 항목 내용
     * @return 검증값
     * @throws SafeMessageException 손상·알 수 없는 형식(값은 메시지에 넣지 않음)
     */
    static Verifier parse(byte[] entry) {
        if (entry == null || entry.length == 0 || entry.length > MAX_ENTRY_BYTES) throw damaged("admin.damaged.format");
        for (byte b : entry) {
            if ((b & 0x80) != 0) throw damaged("admin.damaged.format");
        }
        Map<String, String> values = new HashMap<>();
        for (String raw : new String(entry, StandardCharsets.US_ASCII).split("\n", -1)) {
            String line = raw.endsWith("\r") ? raw.substring(0, raw.length() - 1) : raw;
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.indexOf('=');
            if (eq <= 0) throw damaged("admin.damaged.format");
            String name = line.substring(0, eq);
            if (!FIELDS.contains(name) || values.put(name, line.substring(eq + 1)) != null) {
                throw damaged("admin.damaged.format");
            }
        }
        if (!FORMAT.equals(values.get("format.version"))) {
            throw damaged(values.containsKey("format.version") ? "admin.damaged.version" : "admin.damaged.format");
        }
        if (!values.keySet().containsAll(FIELDS) || !KDF.equals(values.get("kdf"))) throw damaged("admin.damaged.format");
        int iterations;
        try {
            iterations = Integer.parseInt(values.get("kdf.iterations"));
        } catch (NumberFormatException e) {
            throw damaged("admin.damaged.format");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) throw damaged("admin.damaged.format");
        byte[] salt = decode(values.get("salt"), SALT_BYTES);
        byte[] hash = decode(values.get("verifier"), HASH_BYTES);
        return new Verifier(iterations, salt, hash);
    }

    private static byte[] decode(String value, int length) {
        try {
            byte[] bytes = Base64.getDecoder().decode(value);
            if (bytes.length != length) throw damaged("admin.damaged.format");
            return bytes;
        } catch (IllegalArgumentException e) {
            if (e instanceof SafeMessageException) throw e;
            throw damaged("admin.damaged.format");
        }
    }

    private static SafeMessageException damaged(String key) {
        return new SafeMessageException(Messages.get(key));
    }

    /** PBKDF2-HMAC-SHA256(비밀번호, 목적 표지 || 0x00 || Salt). */
    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        byte[] input = new byte[PURPOSE.length + 1 + salt.length];
        System.arraycopy(PURPOSE, 0, input, 0, PURPOSE.length);
        System.arraycopy(salt, 0, input, PURPOSE.length + 1, salt.length);
        PBEKeySpec spec = new PBEKeySpec(password, input, iterations, HASH_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            // Java 8 기본 JCE에 있는 알고리즘이다. 없으면 진행하지 않는다(다른 방식으로 대체하지 않음).
            throw new IllegalStateException(KDF);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * @return 두 입력이 같은 글자인지(길이가 같으면 끝까지 비교하는 일정 시간 비교, 입력은 바꾸지 않음)
     */
    static boolean same(char[] a, char[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    // ===================================================================================================
    // 비밀번호 파일
    // ===================================================================================================

    /**
     * 비밀번호 파일을 읽는다: 일반 파일, {@value #MAX_FILE_BYTES}바이트 이하, UTF-8, 한 줄(앞의 BOM 하나와 끝의 줄바꿈 하나는 뗀다).
     * 경로·내용은 오류 메시지에 넣지 않는다.
     *
     * @param value 옵션 값(경로)
     * @param code  오류 코드(인증이면 ADMIN_AUTH, 새 비밀번호면 ADMIN_PASSWORD)
     * @return 비밀번호 글자(호출자가 지운다)
     */
    /**
     * 비밀번호 파일 권한(POSIX, 읽기 전에 확인): 다른 사용자(other)가 읽거나 쓸 수 있으면 쓰지 않는다(인증 비밀 원문). 소유자·그룹
     * 권한만 있는 파일(600·400·640·440 등)은 허용한다. 심볼릭 링크는 최종 대상의 권한을 본다(Kubernetes Secret 볼륨 등 링크로
     * 마운트하는 환경). Windows(NTFS)는 POSIX 권한이 없어 검사하지 않으며, 파일을 둘 폴더의 ACL로 보호한다(사용자 가이드 1.4).
     */
    static void checkPermissions(Path path, String code, String option) throws CryptoCli.CliException {
        if (!JarConfigEditor.posix()) return;
        java.util.Set<java.nio.file.attribute.PosixFilePermission> permissions;
        try {
            permissions = java.nio.file.Files.getPosixFilePermissions(path);
        } catch (NoSuchFileException e) {
            return; // 없는 파일은 읽기 단계에서 같은 안내로 끝난다
        } catch (UnsupportedOperationException e) {
            return; // POSIX 권한이 없는 파일 시스템(마운트)
        } catch (IOException e) {
            throw new CryptoCli.CliException(code, Messages.get("admin.err.fileRead", option, e.getClass().getSimpleName()));
        }
        if (othersCanAccess(permissions)) {
            throw new CryptoCli.CliException(code, Messages.get("admin.err.filePerm", option,
                    java.nio.file.attribute.PosixFilePermissions.toString(permissions)));
        }
    }

    /** @return 다른 사용자(other)의 읽기·쓰기 권한이 하나라도 있으면 true */
    static boolean othersCanAccess(java.util.Set<java.nio.file.attribute.PosixFilePermission> permissions) {
        return permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ)
                || permissions.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
    }

    static char[] readFile(String value, String code) throws CryptoCli.CliException {
        Path path;
        try {
            path = Paths.get(value);
        } catch (InvalidPathException e) {
            throw new CryptoCli.CliException(Messages.get("cli.err.path", FILE_OPTION));
        }
        checkPermissions(path, code, FILE_OPTION);
        byte[] raw;
        try {
            raw = SecretFiles.readBytes(path, MAX_FILE_BYTES, FILE_OPTION);
        } catch (NoSuchFileException e) {
            throw new CryptoCli.CliException(code, Messages.get("admin.err.fileMissing", FILE_OPTION));
        } catch (SafeMessageException e) {
            throw new CryptoCli.CliException(code, e.getMessage());
        } catch (IOException e) {
            throw new CryptoCli.CliException(code, Messages.get("admin.err.fileRead", FILE_OPTION, e.getClass().getSimpleName()));
        }
        try {
            int start = raw.length >= 3 && (raw[0] & 0xff) == 0xEF && (raw[1] & 0xff) == 0xBB && (raw[2] & 0xff) == 0xBF ? 3 : 0;
            int end = raw.length;
            if (end > start && raw[end - 1] == '\n') {
                end--;
                if (end > start && raw[end - 1] == '\r') end--;
            }
            for (int i = start; i < end; i++) {
                if (raw[i] == '\n' || raw[i] == '\r') throw new CryptoCli.CliException(code, Messages.get("admin.err.fileLines", FILE_OPTION));
            }
            if (end == start) throw new CryptoCli.CliException(code, Messages.get("admin.err.fileEmpty", FILE_OPTION));
            CharBuffer chars;
            try {
                chars = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw, start, end - start));
            } catch (CharacterCodingException e) {
                throw new CryptoCli.CliException(code, Messages.get("admin.err.fileFormat", FILE_OPTION));
            }
            char[] password = new char[chars.remaining()];
            chars.get(password);
            Arrays.fill(chars.array(), '\0');
            return password;
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
}
