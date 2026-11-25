package io.javacryptokit.security;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <b>공개 API</b>: 서명 키를 PEM·DER로 읽고 쓴다.
 *
 * <ul>
 *   <li>개인키: <b>PKCS#8</b>({@code -----BEGIN PRIVATE KEY-----} 또는 그 DER).</li>
 *   <li>공개키: <b>X.509 SubjectPublicKeyInfo</b>({@code -----BEGIN PUBLIC KEY-----} 또는 그 DER).</li>
 *   <li>키 종류: RSA(2048비트 이상), EC P-256. 그 밖의 키·곡선은 거부한다.</li>
 * </ul>
 * <p><b>지원하지 않는 형식</b>(지원하는 척하지 않고 변환 방법을 알려 주며 거부): PKCS#1 {@code RSA PRIVATE KEY}·
 * {@code RSA PUBLIC KEY}, SEC1 {@code EC PRIVATE KEY}, 암호화된 {@code ENCRYPTED PRIVATE KEY}. 예: {@code openssl pkcs8 -topk8
 * -nocrypt -in old.pem -out key.pem}, {@code openssl pkey -in key.pem -pubout -out pub.pem}. 인증서의 공개키는
 * {@link Certificates#read(String)}로 읽은 뒤 {@code getPublicKey()}를 쓴다.</p>
 * <p>PEM 블록 앞뒤의 다른 텍스트(예: OpenSSL이 붙이는 설명)는 무시하지만, 같은 종류의 블록이 둘 이상이면 모호하므로 거부한다.
 * 파일은 64KiB까지. 개인키 내용은 오류 문구·로그에 넣지 않는다. 상태가 없어 스레드 안전하다.</p>
 */
public final class PemKeys {
    private static final int MAX_FILE_BYTES = 64 * 1024;
    private static final Pattern BEGIN = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----");

    private PemKeys() { }

    /**
     * @param pem PKCS#8 PEM 문자열
     * @return 개인키
     * @throws IllegalArgumentException 형식·키 종류가 맞지 않음
     */
    public static PrivateKey readPrivateKey(String pem) {
        return readPrivateKey(pemBody(Text.require(pem, "pem"), "PRIVATE KEY"));
    }

    /**
     * @param der PKCS#8 DER
     * @return 개인키
     */
    public static PrivateKey readPrivateKey(byte[] der) {
        Text.require(der, "der");
        for (String algorithm : new String[] {"RSA", "EC"}) {
            try {
                return checked(KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der)));
            } catch (GeneralSecurityException e) {
                // 다음 키 종류를 시도한다(형식은 하나뿐이고 종류만 다름).
            }
        }
        throw Text.invalid("sec.err.keyFormat", "PKCS#8");
    }

    /**
     * @param file PKCS#8 PEM 또는 DER 파일
     * @return 개인키
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static PrivateKey readPrivateKeyFile(Path file) throws IOException {
        byte[] content = readFile(file);
        return looksLikePem(content) ? readPrivateKey(new String(content, StandardCharsets.US_ASCII)) : readPrivateKey(content);
    }

    /**
     * @param pem SubjectPublicKeyInfo PEM 문자열
     * @return 공개키
     */
    public static PublicKey readPublicKey(String pem) {
        return readPublicKey(pemBody(Text.require(pem, "pem"), "PUBLIC KEY"));
    }

    /**
     * @param der SubjectPublicKeyInfo DER
     * @return 공개키
     */
    public static PublicKey readPublicKey(byte[] der) {
        Text.require(der, "der");
        for (String algorithm : new String[] {"RSA", "EC"}) {
            try {
                return checked(KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der)));
            } catch (GeneralSecurityException e) {
                // 다음 키 종류를 시도한다.
            }
        }
        throw Text.invalid("sec.err.keyFormat", "SubjectPublicKeyInfo");
    }

    /**
     * @param file SubjectPublicKeyInfo PEM 또는 DER 파일
     * @return 공개키
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static PublicKey readPublicKeyFile(Path file) throws IOException {
        byte[] content = readFile(file);
        return looksLikePem(content) ? readPublicKey(new String(content, StandardCharsets.US_ASCII)) : readPublicKey(content);
    }

    /**
     * @param key 개인키(RSA·EC)
     * @return PKCS#8 PEM({@code -----BEGIN PRIVATE KEY-----}, 64자 줄바꿈). 비밀이므로 안전하게 보관한다
     */
    public static String toPem(PrivateKey key) {
        return pem("PRIVATE KEY", toDer(key));
    }

    /**
     * @param key 공개키(RSA·EC)
     * @return SubjectPublicKeyInfo PEM({@code -----BEGIN PUBLIC KEY-----})
     */
    public static String toPem(PublicKey key) {
        return pem("PUBLIC KEY", toDer(key));
    }

    /**
     * @param key 개인키 또는 공개키
     * @return PKCS#8(개인키) 또는 SubjectPublicKeyInfo(공개키) DER
     */
    public static byte[] toDer(Key key) {
        Text.require(key, "key");
        String format = key.getFormat();
        byte[] encoded = key.getEncoded();
        boolean expected = key instanceof PrivateKey ? "PKCS#8".equals(format) : key instanceof PublicKey && "X.509".equals(format);
        if (!expected || encoded == null) throw Text.invalid("sec.err.keyFormat", key instanceof PrivateKey ? "PKCS#8" : "SubjectPublicKeyInfo");
        return encoded;
    }

    private static <T extends Key> T checked(T key) {
        if (key instanceof RSAKey) {
            if (((RSAKey) key).getModulus().bitLength() < Signatures.MIN_RSA_BITS) throw Text.invalid("sec.err.rsaShort", Signatures.MIN_RSA_BITS);
            return key;
        }
        if (key instanceof ECKey && Signatures.isP256(((ECKey) key).getParams())) {
            if (key instanceof ECPublicKey && !Signatures.onP256(((ECPublicKey) key).getW())) {
                throw Text.invalid("sec.err.ecPoint");
            }
            return key;
        }
        throw Text.invalid("sec.err.keyUnsupported");
    }

    private static byte[] pemBody(String pem, String label) {
        Matcher begin = BEGIN.matcher(pem);
        String unsupported = null;
        int count = 0;
        while (begin.find()) {
            if (begin.group(1).equals(label)) {
                count++;
            } else if (unsupported == null && unsupported(begin.group(1))) {
                unsupported = begin.group(1);
            }
        }
        if (count == 0) {
            throw unsupported != null ? Text.invalid("sec.err.pemUnsupported", unsupported) : Text.invalid("sec.err.pemMissing", label);
        }
        if (count > 1) throw Text.invalid("sec.err.pemMultiple", label);
        Matcher block = Pattern.compile("-----BEGIN " + label + "-----([A-Za-z0-9+/=\\s]*)-----END " + label + "-----").matcher(pem);
        if (!block.find()) throw Text.invalid("sec.err.pemBody", label);
        try {
            return Encoding.BASE64.decode(block.group(1).replaceAll("\\s", ""));
        } catch (IllegalArgumentException e) {
            throw Text.invalid("sec.err.pemBody", label);
        }
    }

    private static boolean unsupported(String label) {
        return label.equals("RSA PRIVATE KEY") || label.equals("EC PRIVATE KEY") || label.equals("ENCRYPTED PRIVATE KEY")
                || label.equals("RSA PUBLIC KEY") || label.equals("CERTIFICATE");
    }

    /** PEM 표식이 어디든 있으면 PEM(앞에 설명 텍스트가 붙은 파일 포함), 없으면 DER로 본다. */
    private static boolean looksLikePem(byte[] content) {
        return new String(content, StandardCharsets.ISO_8859_1).contains("-----BEGIN ");
    }

    /** 패키지 내부: 최대 64KiB 파일 읽기(초과는 거부). */
    static byte[] readFile(Path file) throws IOException {
        return readLimited(file, MAX_FILE_BYTES);
    }

    static byte[] readLimited(Path file, int limit) throws IOException {
        Text.require(file, "file");
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[limit + 1];
            int total = 0;
            int read;
            while (total < buffer.length && (read = input.read(buffer, total, buffer.length - total)) != -1) total += read;
            if (total > limit) throw Text.invalid("sec.err.fileTooLarge", limit);
            return Arrays.copyOf(buffer, total);
        }
    }

    private static String pem(String label, byte[] der) {
        String body = Encoding.BASE64.encode(der);
        StringBuilder out = new StringBuilder("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < body.length(); i += 64) out.append(body, i, Math.min(body.length(), i + 64)).append('\n');
        return out.append("-----END ").append(label).append("-----\n").toString();
    }
}
