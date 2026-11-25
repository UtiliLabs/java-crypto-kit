package io.javacryptokit.security;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * <b>공개 API</b>: RSA·ECDSA(P-256) 전자서명 키 생성·서명·검증.
 *
 * <p><b>언제 쓰는가</b>: 서명하는 쪽만 개인키를 갖고 여러 상대가 공개키로 검증해야 할 때(외부 기관 전문 검증, 파일 전자서명,
 * JWT 비대칭 서명). <b>서명은 데이터를 숨기지 않는다</b>(기밀성은 {@link AesGcm} 등 암호화). 공개키가 정말 상대의 것인지(신뢰)는
 * 별도로 확보해야 한다(인증서는 {@link Certificates}). 같은 비밀키를 양쪽이 나눠 가지면 {@link Hmac}이 더 간단하다.</p>
 *
 * <ul>
 *   <li>RSA: 키 2048비트 이상(새 키 기본 3072비트), {@code SHA256withRSA}(PKCS#1 v1.5 서명, RSA 암호화가 아님).</li>
 *   <li>ECDSA: P-256(secp256r1)만. 서명 형식은 DER({@link SignatureAlgorithm#ECDSA_P256_SHA256}) 또는 R‖S 64바이트
 *       ({@link SignatureAlgorithm#ECDSA_P256_SHA256_P1363})를 명시한다. ECDSA는 서명할 때마다 값이 달라지는 것이 정상이다.
 *       검증 전에 r·s가 1 ~ n-1 범위인지와 DER 정규형을 직접 확인한다(공급자 결함 유형 방어).</li>
 *   <li>키 종류·길이·곡선이 알고리즘과 맞지 않으면 {@link IllegalArgumentException}. 서명이 맞지 않거나 형식이 깨진 서명 바이트는
 *       {@code false}. 서명 문자열이 지정한 인코딩이 아니면 {@link IllegalArgumentException}.</li>
 *   <li>파일은 64KiB씩 스트리밍으로 서명·검증한다(전체를 메모리에 올리지 않음). 상태가 없고 호출마다 새 {@link Signature}를 쓴다.</li>
 * </ul>
 * <p>키 읽기·쓰기(PKCS#8·SPKI PEM/DER)는 {@link PemKeys}. 키를 저장소에 자동 생성·보관하거나 로그에 남기지 않는다.</p>
 */
public final class Signatures {
    /** 새 RSA 키 기본 길이(비트). */
    public static final int DEFAULT_RSA_BITS = 3072;
    /** RSA 최소 길이(비트). */
    public static final int MIN_RSA_BITS = 2048;
    private static final int BUFFER = 64 * 1024;
    private static final int P256_BYTES = 32;
    static final BigInteger P256_P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    static final BigInteger P256_A = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
    static final BigInteger P256_B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    static final BigInteger P256_N = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger P256_GX = new BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16);
    private static final BigInteger P256_GY = new BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16);

    private Signatures() { }

    /**
     * 키 쌍을 만든다(RSA는 3072비트, EC는 P-256).
     *
     * @param algorithm 알고리즘
     * @return 키 쌍(저장·보관은 호출자 책임)
     */
    public static KeyPair generateKeyPair(SignatureAlgorithm algorithm) {
        Text.require(algorithm, "algorithm");
        if (algorithm == SignatureAlgorithm.RSA_SHA256) return generateRsaKeyPair(DEFAULT_RSA_BITS);
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "EC secp256r1"));
        }
    }

    /**
     * @param bits 2048, 3072 또는 4096
     * @return RSA 키 쌍
     */
    public static KeyPair generateRsaKeyPair(int bits) {
        if (bits != 2048 && bits != 3072 && bits != 4096) throw Text.invalid("sec.err.rsaBits");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "RSA"));
        }
    }

    /**
     * @param algorithm 알고리즘
     * @param key       개인키
     * @param data      원본(바꾸지 않는다)
     * @return 서명
     */
    public static byte[] sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] data) {
        Text.require(data, "data");
        Signature signature = signer(algorithm, key);
        try {
            signature.update(data);
            return finish(algorithm, signature.sign());
        } catch (SignatureException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", algorithm.jcaName()));
        }
    }

    /**
     * @param algorithm 알고리즘
     * @param key       개인키
     * @param text      원본 문자열(UTF-8)
     * @return 서명
     */
    public static byte[] sign(SignatureAlgorithm algorithm, PrivateKey key, String text) {
        return sign(algorithm, key, Bytes.utf8(text));
    }

    /**
     * @param algorithm 알고리즘
     * @param key       개인키
     * @param data      원본
     * @param encoding  서명 출력 형식
     * @return 인코딩한 서명
     */
    public static String sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] data, Encoding encoding) {
        return Text.require(encoding, "encoding").encode(sign(algorithm, key, data));
    }

    /**
     * @param algorithm 알고리즘
     * @param key       개인키
     * @param text      원본 문자열(UTF-8)
     * @param encoding  서명 출력 형식
     * @return 인코딩한 서명
     */
    public static String sign(SignatureAlgorithm algorithm, PrivateKey key, String text, Encoding encoding) {
        return Text.require(encoding, "encoding").encode(sign(algorithm, key, text));
    }

    /**
     * 파일을 스트리밍으로 서명한다.
     *
     * @param algorithm 알고리즘
     * @param key       개인키
     * @param file      파일(바꾸지 않는다)
     * @return 서명
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static byte[] signFile(SignatureAlgorithm algorithm, PrivateKey key, Path file) throws IOException {
        Text.require(file, "file");
        Signature signature = signer(algorithm, key);
        try {
            stream(signature, file);
            return finish(algorithm, signature.sign());
        } catch (SignatureException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", algorithm.jcaName()));
        }
    }

    /**
     * @param algorithm 알고리즘
     * @param key       공개키
     * @param data      원본
     * @param signature 서명
     * @return 서명이 맞으면 true(형식이 깨진 서명·null·빈 값은 false)
     * @throws IllegalArgumentException 키 종류·길이·곡선이 알고리즘과 맞지 않음
     */
    public static boolean verify(SignatureAlgorithm algorithm, PublicKey key, byte[] data, byte[] signature) {
        Text.require(data, "data");
        Signature verifier = verifier(algorithm, key);
        byte[] der = derSignature(algorithm, signature);
        if (der == null) return false;
        try {
            verifier.update(data);
            return verifier.verify(der);
        } catch (SignatureException e) {
            return false;
        }
    }

    /**
     * @param algorithm 알고리즘
     * @param key       공개키
     * @param data      원본
     * @param signature 서명 문자열
     * @param encoding  서명 문자열의 형식
     * @return 서명이 맞으면 true
     * @throws IllegalArgumentException 서명 문자열이 그 형식이 아니거나 키가 맞지 않음
     */
    public static boolean verify(SignatureAlgorithm algorithm, PublicKey key, byte[] data, String signature, Encoding encoding) {
        Text.require(encoding, "encoding");
        return verify(algorithm, key, data, encoding.decode(Text.require(signature, "signature")));
    }

    /**
     * @param algorithm 알고리즘
     * @param key       공개키
     * @param text      원본 문자열(UTF-8)
     * @param signature 서명 문자열
     * @param encoding  서명 문자열의 형식
     * @return 서명이 맞으면 true
     */
    public static boolean verify(SignatureAlgorithm algorithm, PublicKey key, String text, String signature, Encoding encoding) {
        return verify(algorithm, key, Bytes.utf8(text), signature, encoding);
    }

    /**
     * 파일을 스트리밍으로 검증한다.
     *
     * @param algorithm 알고리즘
     * @param key       공개키
     * @param file      파일(바꾸지 않는다)
     * @param signature 서명
     * @return 서명이 맞으면 true
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static boolean verifyFile(SignatureAlgorithm algorithm, PublicKey key, Path file, byte[] signature) throws IOException {
        Text.require(file, "file");
        Signature verifier = verifier(algorithm, key);
        byte[] der = derSignature(algorithm, signature);
        if (der == null) return false;
        try {
            stream(verifier, file);
            return verifier.verify(der);
        } catch (SignatureException e) {
            return false;
        }
    }

    // ---------------------------------------------------------------- 키 검사

    /**
     * 키 종류·길이·곡선이 알고리즘과 맞는지 미리 확인한다(서명·검증 메서드도 매번 같은 확인을 한다).
     *
     * @param algorithm 알고리즘
     * @param key       개인키 또는 공개키
     * @throws IllegalArgumentException RSA 2048비트 미만, P-256이 아닌 EC, 곡선 밖의 점, 알고리즘과 다른 종류의 키
     */
    public static void checkKey(SignatureAlgorithm algorithm, Key key) {
        Text.require(algorithm, "algorithm");
        Text.require(key, "key");
        if (algorithm == SignatureAlgorithm.RSA_SHA256) {
            if (!(key instanceof RSAKey)) throw Text.invalid("sec.err.keyType", algorithm.name(), "RSA");
            if (((RSAKey) key).getModulus().bitLength() < MIN_RSA_BITS) throw Text.invalid("sec.err.rsaShort", MIN_RSA_BITS);
            return;
        }
        if (!(key instanceof ECKey) || !isP256(((ECKey) key).getParams())) throw Text.invalid("sec.err.keyType", algorithm.name(), "EC P-256");
        if (key instanceof ECPublicKey && !onP256(((ECPublicKey) key).getW())) throw Text.invalid("sec.err.ecPoint");
    }

    /** 패키지 내부: P-256 곡선 매개변수인지. */
    static boolean isP256(ECParameterSpec params) {
        if (params == null || !(params.getCurve().getField() instanceof ECFieldFp)) return false;
        ECFieldFp field = (ECFieldFp) params.getCurve().getField();
        return field.getP().equals(P256_P) && params.getCurve().getA().equals(P256_A) && params.getCurve().getB().equals(P256_B)
                && params.getOrder().equals(P256_N) && params.getGenerator().getAffineX().equals(P256_GX)
                && params.getGenerator().getAffineY().equals(P256_GY) && params.getCofactor() == 1;
    }

    /** 패키지 내부: 점이 P-256 위에 있는지(y² = x³ + ax + b mod p). */
    static boolean onP256(ECPoint point) {
        if (point == null || point == ECPoint.POINT_INFINITY) return false;
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(P256_P) >= 0 || y.compareTo(P256_P) >= 0) return false;
        BigInteger left = y.multiply(y).mod(P256_P);
        BigInteger right = x.multiply(x).multiply(x).add(P256_A.multiply(x)).add(P256_B).mod(P256_P);
        return left.equals(right);
    }

    private static Signature signer(SignatureAlgorithm algorithm, PrivateKey key) {
        checkKey(algorithm, key);
        Signature signature = instance(algorithm);
        try {
            signature.initSign(key);
            return signature;
        } catch (InvalidKeyException e) {
            throw Text.invalid("sec.err.keyType", algorithm.name(), algorithm.keyAlgorithm());
        }
    }

    private static Signature verifier(SignatureAlgorithm algorithm, PublicKey key) {
        checkKey(algorithm, key);
        Signature signature = instance(algorithm);
        try {
            signature.initVerify(key);
            return signature;
        } catch (InvalidKeyException e) {
            throw Text.invalid("sec.err.keyType", algorithm.name(), algorithm.keyAlgorithm());
        }
    }

    private static Signature instance(SignatureAlgorithm algorithm) {
        try {
            return Signature.getInstance(algorithm.jcaName());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", algorithm.jcaName()));
        }
    }

    private static void stream(Signature signature, Path file) throws IOException, SignatureException {
        byte[] buffer = new byte[BUFFER];
        try (InputStream input = Files.newInputStream(file)) {
            int read;
            while ((read = input.read(buffer)) != -1) signature.update(buffer, 0, read);
        }
    }

    // ---------------------------------------------------------------- ECDSA 서명 형식(DER ↔ R‖S)

    private static byte[] finish(SignatureAlgorithm algorithm, byte[] jcaSignature) {
        return algorithm == SignatureAlgorithm.ECDSA_P256_SHA256_P1363 ? derToP1363(jcaSignature) : jcaSignature;
    }

    /** 검증할 JCA 서명(DER)을 만든다. 형식이 깨졌거나 r·s 범위 밖이면 null(검증 실패). */
    private static byte[] derSignature(SignatureAlgorithm algorithm, byte[] signature) {
        if (signature == null || signature.length == 0) return null;
        switch (algorithm) {
            case RSA_SHA256:
                return signature;
            case ECDSA_P256_SHA256: {
                BigInteger[] rs = parseDer(signature);
                if (rs == null || !inRange(rs[0]) || !inRange(rs[1])) return null;
                byte[] canonical = encodeDer(rs[0], rs[1]);
                return Arrays.equals(canonical, signature) ? signature : null;
            }
            default: {
                if (signature.length != 2 * P256_BYTES) return null;
                BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, P256_BYTES));
                BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, P256_BYTES, 2 * P256_BYTES));
                if (!inRange(r) || !inRange(s)) return null;
                return encodeDer(r, s);
            }
        }
    }

    private static boolean inRange(BigInteger value) {
        return value.signum() > 0 && value.compareTo(P256_N) < 0;
    }

    private static byte[] derToP1363(byte[] der) {
        BigInteger[] rs = parseDer(der);
        if (rs == null) throw new IllegalStateException(Text.get("sec.err.provider", "SHA256withECDSA"));
        byte[] out = new byte[2 * P256_BYTES];
        copyUnsigned(rs[0], out, 0);
        copyUnsigned(rs[1], out, P256_BYTES);
        return out;
    }

    private static void copyUnsigned(BigInteger value, byte[] out, int offset) {
        byte[] raw = value.toByteArray();
        int start = raw.length > P256_BYTES ? raw.length - P256_BYTES : 0;
        int length = raw.length - start;
        System.arraycopy(raw, start, out, offset + P256_BYTES - length, length);
    }

    /** 엄격한 DER {@code SEQUENCE { INTEGER r, INTEGER s }} 해석(양수·최소 길이·남는 바이트 없음). 아니면 null. */
    private static BigInteger[] parseDer(byte[] der) {
        if (der.length < 8 || der.length > 72 || der[0] != 0x30) return null;
        int length = der[1] & 0xff;
        if (length >= 0x80 || length != der.length - 2) return null;
        int[] position = {2};
        BigInteger r = readInteger(der, position);
        BigInteger s = r == null ? null : readInteger(der, position);
        if (s == null || position[0] != der.length) return null;
        return new BigInteger[] {r, s};
    }

    private static BigInteger readInteger(byte[] der, int[] position) {
        int p = position[0];
        if (p + 2 > der.length || der[p] != 0x02) return null;
        int length = der[p + 1] & 0xff;
        if (length == 0 || length >= 0x80 || p + 2 + length > der.length) return null;
        byte[] value = Arrays.copyOfRange(der, p + 2, p + 2 + length);
        if ((value[0] & 0x80) != 0) return null;                          // 음수
        if (length > 1 && value[0] == 0 && (value[1] & 0x80) == 0) return null; // 최소 길이 아님
        position[0] = p + 2 + length;
        return new BigInteger(1, value);
    }

    private static byte[] encodeDer(BigInteger r, BigInteger s) {
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream(8 + rb.length + sb.length);
        out.write(0x30);
        out.write(4 + rb.length + sb.length);
        out.write(0x02);
        out.write(rb.length);
        out.write(rb, 0, rb.length);
        out.write(0x02);
        out.write(sb.length);
        out.write(sb, 0, sb.length);
        return out.toByteArray();
    }
}
