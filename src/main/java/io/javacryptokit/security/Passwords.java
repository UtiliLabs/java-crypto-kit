package io.javacryptokit.security;

import io.javacryptokit.core.Kdf;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>공개 API</b>: 애플리케이션 사용자 비밀번호 해시(저장)·검증·재해시 판단. 비밀번호 원문이나 되돌릴 수 있는 값을 저장하지 않고
 * 단방향 검증값만 저장한다. <b>복호화 용도가 아니다</b>(원문을 다시 써야 하는 값은 {@link AesGcm} 등 암호화를 쓴다).
 *
 * <p><b>저장 형식(버전 1)</b>: {@code $pbkdf2-sha256$v=1$i=600000$<Salt>$<해시>}</p>
 * <ul>
 *   <li>PHC 문자열 문법. 알고리즘은 {@code pbkdf2-sha256}·{@code pbkdf2-sha512}, {@code v=1}은 이 형식의 버전(입력은 NFC 정규화 +
 *       UTF-8, 해시 길이 = SHA256 32바이트·SHA512 64바이트), {@code i}는 반복 횟수, Salt·해시는 표준 Base64(패딩 없음).</li>
 *   <li>해시할 때마다 16바이트 보안 난수 Salt를 새로 만든다(같은 비밀번호도 매번 다른 값).</li>
 *   <li>기본: PBKDF2-HMAC-SHA256 600,000회. SHA512는 권장 210,000회. 새 해시의 반복 횟수는 100,000~5,000,000.</li>
 *   <li>검증은 저장값에 적힌 알고리즘·반복 횟수로 다시 계산해 안전 비교한다. 예전의 약한 값(반복 1,000회 이상)도 검증하며
 *       {@link #needsRehash}로 재해시 필요성을 알려 준다. 반복 5,000,000회 초과·모르는 알고리즘·형식 오류는 계산하지 않고
 *       거부한다(지나친 연산으로 인한 서비스 거부 방지).</li>
 * </ul>
 * <p><b>호출자 책임</b>: 비밀번호 복잡도·로그인 시도 제한·계정 잠금·업무 이력. 이 클래스는 CLI 관리자 비밀번호 규칙(10~128자)을
 * 강제하지 않는다. 비밀번호는 빈 값·공백만·제어문자·깨진 문자를 거부하고 UTF-8 1,024바이트까지 받는다. 비밀번호 배열은 바꾸지
 * 않으므로 다 쓰면 호출자가 지운다. 상태가 없어 스레드 안전하다(관리자 비밀번호·관리형 키 KDF와 저장소를 공유하지 않는다).</p>
 */
public final class Passwords {
    /** 검증할 때 받는 최소 반복 횟수(예전 값 검증용, 새 해시는 {@link Pbkdf2#MIN_ITERATIONS} 이상). */
    public static final int MIN_VERIFY_ITERATIONS = 1_000;
    private static final Pattern FORMAT = Pattern.compile(
            "\\$(pbkdf2-sha256|pbkdf2-sha512)\\$v=1\\$i=([1-9][0-9]{0,8})\\$([A-Za-z0-9+/]{22,86})\\$([A-Za-z0-9+/]{43,86})");

    private Passwords() { }

    /**
     * 기본 정책(PBKDF2-HMAC-SHA256, 600,000회)으로 해시한다.
     *
     * @param password 비밀번호(바꾸지 않는다)
     * @return 저장 문자열
     */
    public static String hash(char[] password) {
        return hash(password, Pbkdf2Algorithm.SHA256, Pbkdf2Algorithm.SHA256.recommendedIterations());
    }

    /**
     * 알고리즘·반복 횟수를 지정해 해시한다.
     *
     * @param password   비밀번호(바꾸지 않는다)
     * @param algorithm  알고리즘
     * @param iterations 반복 횟수(100,000~5,000,000)
     * @return 저장 문자열
     * @throws IllegalArgumentException 입력이 규칙에 맞지 않음
     */
    public static String hash(char[] password, Pbkdf2Algorithm algorithm, int iterations) {
        Text.require(algorithm, "algorithm");
        byte[] salt = Pbkdf2.newSalt();
        Pbkdf2.checkSaltAndIterations(salt, iterations, Pbkdf2.MIN_ITERATIONS);
        byte[] hash = derive(algorithm, password, salt, iterations);
        try {
            return "$" + algorithm.id() + "$v=1$i=" + iterations + "$" + b64(salt) + "$" + b64(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * 비밀번호가 저장값과 맞는지 확인한다.
     *
     * @param password 입력 비밀번호(바꾸지 않는다)
     * @param stored   {@link #hash}가 만든 저장 문자열
     * @return 맞으면 true. 다르거나, 입력이 해시할 수 없는 값(빈 값·공백만·제어문자 등)이면 false
     * @throws IllegalArgumentException password가 null이거나 저장값 형식 오류·지원하지 않는 알고리즘·반복 횟수 범위 밖
     */
    public static boolean verify(char[] password, String stored) {
        Parsed parsed = parse(stored);
        Text.require(password, "password");
        char[] normalized;
        try {
            normalized = Pbkdf2.normalize(password);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] actual = null;
        try {
            actual = Kdf.pbkdf2(parsed.algorithm.jcaName(), normalized, parsed.salt, parsed.iterations, parsed.algorithm.hashLength());
            return Bytes.equalsConstantTime(actual, parsed.hash);
        } finally {
            Arrays.fill(normalized, '\0');
            if (actual != null) Arrays.fill(actual, (byte) 0);
        }
    }

    /**
     * 기본 정책(PBKDF2-HMAC-SHA256 600,000회)과 비교해 다시 해시해야 하는지 알려 준다. 저장값을 바꾸지 않는다. 보통 로그인
     * 성공({@link #verify}가 true) 직후 true이면 같은 비밀번호로 {@link #hash}를 다시 만들어 저장한다.
     *
     * @param stored 저장 문자열
     * @return 알고리즘이 다르거나 반복 횟수가 정책보다 적으면 true
     * @throws IllegalArgumentException 저장값 형식 오류
     */
    public static boolean needsRehash(String stored) {
        return needsRehash(stored, Pbkdf2Algorithm.SHA256, Pbkdf2Algorithm.SHA256.recommendedIterations());
    }

    /**
     * 지정한 정책과 비교해 다시 해시해야 하는지 알려 준다.
     *
     * @param stored     저장 문자열
     * @param algorithm  현재 정책의 알고리즘
     * @param iterations 현재 정책의 반복 횟수
     * @return 알고리즘이 다르거나 반복 횟수가 정책보다 적으면 true
     */
    public static boolean needsRehash(String stored, Pbkdf2Algorithm algorithm, int iterations) {
        Text.require(algorithm, "algorithm");
        Parsed parsed = parse(stored);
        return parsed.algorithm != algorithm || parsed.iterations < iterations;
    }

    private static byte[] derive(Pbkdf2Algorithm algorithm, char[] password, byte[] salt, int iterations) {
        char[] normalized = Pbkdf2.normalize(password);
        try {
            return Kdf.pbkdf2(algorithm.jcaName(), normalized, salt, iterations, algorithm.hashLength());
        } finally {
            Arrays.fill(normalized, '\0');
        }
    }

    private static Parsed parse(String stored) {
        Text.require(stored, "stored");
        Matcher m = FORMAT.matcher(stored);
        if (stored.length() > 256 || !m.matches()) throw Text.invalid("sec.err.passwordFormat");
        Pbkdf2Algorithm algorithm = Pbkdf2Algorithm.fromId(m.group(1));
        long iterations = Long.parseLong(m.group(2));
        if (iterations < MIN_VERIFY_ITERATIONS || iterations > Pbkdf2.MAX_ITERATIONS) {
            throw Text.invalid("sec.err.iterations", MIN_VERIFY_ITERATIONS, Pbkdf2.MAX_ITERATIONS);
        }
        byte[] salt;
        byte[] hash;
        try {
            salt = Encoding.BASE64.decode(pad(m.group(3)));
            hash = Encoding.BASE64.decode(pad(m.group(4)));
        } catch (IllegalArgumentException e) {
            throw Text.invalid("sec.err.passwordFormat");
        }
        if (salt.length < Pbkdf2.MIN_SALT_BYTES || salt.length > Pbkdf2.MAX_SALT_BYTES || hash.length != algorithm.hashLength()) {
            throw Text.invalid("sec.err.passwordFormat");
        }
        return new Parsed(algorithm, (int) iterations, salt, hash);
    }

    private static String b64(byte[] data) {
        return Encoding.BASE64.encode(data).replace("=", "");
    }

    private static String pad(String unpadded) {
        StringBuilder out = new StringBuilder(unpadded);
        while (out.length() % 4 != 0) out.append('=');
        return out.toString();
    }

    private static final class Parsed {
        final Pbkdf2Algorithm algorithm;
        final int iterations;
        final byte[] salt;
        final byte[] hash;

        Parsed(Pbkdf2Algorithm algorithm, int iterations, byte[] salt, byte[] hash) {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.salt = salt;
            this.hash = hash;
        }
    }
}
