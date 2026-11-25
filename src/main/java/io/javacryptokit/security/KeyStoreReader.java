package io.javacryptokit.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <b>공개 API</b>: 이미 가진 PKCS12({@code .p12}·{@code .pfx})·JKS({@code .jks}) 키 저장소를 <b>읽기 전용</b>으로 열어 개인키·
 * 인증서·공개키·인증서 체인을 꺼낸다. 꺼낸 표준 {@code Key}·{@code X509Certificate}는 {@link Signatures}·{@link RsaOaep}·
 * {@link HybridEncryption}·{@link Certificates}·JWT({@code JwtKey})에 그대로 쓴다.
 *
 * <pre>{@code
 * KeyStoreReader store = KeyStoreReader.load(Paths.get("signing.p12"), KeyStoreType.PKCS12, storePassword);
 * PrivateKey signingKey = store.privateKey("signer", keyPassword);     // 엔트리 비밀번호(PKCS12는 보통 저장소와 같음)
 * List<X509Certificate> chain = store.certificateChain("signer");
 * }</pre>
 *
 * <ul>
 *   <li>형식은 호출자가 {@link KeyStoreType}으로 지정한다(확장자로 추측하지 않고, 파일 앞 표식으로 지정한 형식인지 확인해 다른 형식은
 *       JDK의 자동 인식에 맡기지 않고 거부). 저장소 비밀번호는 필수다(빈 값 허용, null 거부:
 *       null이면 JKS가 무결성 확인을 건너뛰기 때문). 비밀번호를 추측하거나 기본값으로 대신하지 않는다.</li>
 *   <li>파일은 최대 16MiB까지 한 번에 읽고 바로 닫으며 <b>바꾸지 않는다</b>(생성·수정·변환·삭제·비밀번호 변경 기능 없음).
 *       {@link #load(InputStream, KeyStoreType, char[])}은 스트림을 닫지 않는다(호출자 소유).</li>
 *   <li>별칭은 정확히 지정해야 한다(첫 번째 엔트리를 임의로 고르지 않음). 개인키는 엔트리 비밀번호를 명시했을 때만 꺼낸다.</li>
 *   <li>저장소에 있는 인증서라는 사실은 신뢰를 뜻하지 않는다. 신뢰 체인은 {@link Certificates#validateChain}으로 따로 확인한다.</li>
 *   <li>Java 버전마다 PKCS12 보호 알고리즘 지원이 다르다(예: 최신 JDK 기본 PKCS12의 PBES2·HmacPBESHA256을 오래된 Java 8 업데이트는
 *       읽지 못할 수 있다). 이 경우 약한 알고리즘으로 바꾸지 않고 "지원하지 않는 보호 알고리즘"으로 알린다. PKCS12의 SecretKey
 *       엔트리는 지원 범위가 아니다.</li>
 *   <li>오류: 파일을 읽을 수 없으면 {@link IOException}, 비밀번호·형식·별칭·엔트리 종류 문제는 {@link KeyStoreException}(문구에 경로·
 *       비밀번호를 넣지 않음). 호출자 비밀번호 배열은 바꾸지 않는다. 읽은 결과 객체는 스레드 안전하다.</li>
 * </ul>
 */
public final class KeyStoreReader {
    /** 읽을 수 있는 최대 크기(16MiB). */
    public static final int MAX_BYTES = 16 * 1024 * 1024;
    /** PBES2 알고리즘 식별자(1.2.840.113549.1.5.13)의 DER: 최신 JDK가 기본으로 만드는 PKCS12의 보호 방식. */
    private static final byte[] PBES2_OID = {0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x05, 0x0D};
    /** PKCS12가 넘기는 형태의 PBES2 매개변수(PBKDF2-HmacSHA256, AES-256-CBC). 이 Java가 해석할 수 있는지만 확인한다. */
    private static final String PBES2_PARAMS = "3055303406092a864886f70d01050c3027041001010101010101010101010101010101"
            + "02022710020120300c06082a864886f70d02090500301d060960864801650304012a041002020202020202020202020202020202";

    private final KeyStoreType type;
    private final KeyStore store;

    private KeyStoreReader(KeyStoreType type, KeyStore store) {
        this.type = type;
        this.store = store;
    }

    /**
     * @param file          키 저장소 파일(읽기만 한다)
     * @param type          형식
     * @param storePassword 저장소 비밀번호(바꾸지 않는다)
     * @return 읽은 저장소
     * @throws IOException       파일이 없거나 읽을 수 없음
     * @throws KeyStoreException 비밀번호가 틀림·형식이 다름·손상·지원하지 않는 보호 알고리즘
     */
    public static KeyStoreReader load(Path file, KeyStoreType type, char[] storePassword) throws IOException, KeyStoreException {
        return load(PemKeys.readLimited(Text.require(file, "file"), MAX_BYTES), type, storePassword);
    }

    /**
     * @param input         키 저장소 내용(닫지 않는다, 최대 16MiB)
     * @param type          형식
     * @param storePassword 저장소 비밀번호
     * @return 읽은 저장소
     * @throws IOException       스트림을 읽을 수 없음
     * @throws KeyStoreException 비밀번호·형식·손상·보호 알고리즘 문제
     */
    public static KeyStoreReader load(InputStream input, KeyStoreType type, char[] storePassword) throws IOException, KeyStoreException {
        Text.require(input, "input");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            out.write(buffer, 0, read);
            if (out.size() > MAX_BYTES) throw Text.invalid("sec.err.fileTooLarge", MAX_BYTES);
        }
        return load(out.toByteArray(), type, storePassword);
    }

    /**
     * @param content       키 저장소 바이트(바꾸지 않는다)
     * @param type          형식
     * @param storePassword 저장소 비밀번호
     * @return 읽은 저장소
     * @throws KeyStoreException 비밀번호·형식·손상·보호 알고리즘 문제
     */
    public static KeyStoreReader load(byte[] content, KeyStoreType type, char[] storePassword) throws KeyStoreException {
        Text.require(content, "content");
        Text.require(type, "type");
        Text.require(storePassword, "storePassword");
        if (content.length > MAX_BYTES) throw Text.invalid("sec.err.fileTooLarge", MAX_BYTES);
        // 지정한 형식만 읽는다(JDK의 JKS·PKCS12 상호 자동 인식에 기대지 않음): JKS는 0xFEEDFEED, PKCS12는 DER SEQUENCE(0x30).
        boolean jksMagic = content.length >= 4 && (content[0] & 0xff) == 0xFE && (content[1] & 0xff) == 0xED
                && (content[2] & 0xff) == 0xFE && (content[3] & 0xff) == 0xED;
        if (type == KeyStoreType.JKS ? !jksMagic : (content.length == 0 || content[0] != 0x30)) {
            throw new KeyStoreException(Text.get("sec.err.ksFormat"));
        }
        KeyStore store;
        try {
            store = KeyStore.getInstance(type.jcaName());
        } catch (KeyStoreException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", type.jcaName()));
        }
        try {
            store.load(new ByteArrayInputStream(content), storePassword.clone());
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            throw new KeyStoreException(Text.get(classify(e, type, content, Pbes2.SUPPORTED)));
        }
        return new KeyStoreReader(type, store);
    }

    /** @return 형식 */
    public KeyStoreType type() {
        return type;
    }

    /**
     * @return 별칭 목록(정렬)
     * @throws KeyStoreException 저장소 오류
     */
    public synchronized List<String> aliases() throws KeyStoreException {
        List<String> out = Collections.list(store.aliases());
        Collections.sort(out);
        return Collections.unmodifiableList(out);
    }

    /**
     * @param alias 별칭
     * @return 개인키(+인증서) 엔트리이면 true
     * @throws KeyStoreException 저장소 오류
     */
    public synchronized boolean isPrivateKeyEntry(String alias) throws KeyStoreException {
        return store.entryInstanceOf(Text.require(alias, "alias"), KeyStore.PrivateKeyEntry.class);
    }

    /**
     * @param alias 별칭
     * @return 신뢰 인증서(인증서만) 엔트리이면 true
     * @throws KeyStoreException 저장소 오류
     */
    public synchronized boolean isCertificateEntry(String alias) throws KeyStoreException {
        return store.isCertificateEntry(Text.require(alias, "alias"));
    }

    /**
     * 개인키를 꺼낸다(엔트리 비밀번호를 명시해야 한다).
     *
     * @param alias       별칭
     * @param keyPassword 엔트리 비밀번호(PKCS12는 보통 저장소 비밀번호와 같다, 바꾸지 않는다)
     * @return 개인키
     * @throws KeyStoreException 별칭 없음·개인키 엔트리가 아님·엔트리 비밀번호가 틀림·지원하지 않는 보호 알고리즘
     */
    public synchronized PrivateKey privateKey(String alias, char[] keyPassword) throws KeyStoreException {
        Text.require(keyPassword, "keyPassword");
        requireAlias(alias);
        if (!store.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) throw new KeyStoreException(Text.get("sec.err.ksNotPrivate"));
        Key key;
        try {
            key = store.getKey(alias, keyPassword.clone());
        } catch (UnrecoverableKeyException e) {
            throw new KeyStoreException(Text.get("sec.err.ksKeyPassword"));
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreException(Text.get("sec.err.ksUnsupported"));
        }
        if (!(key instanceof PrivateKey)) throw new KeyStoreException(Text.get("sec.err.ksNotPrivate"));
        return (PrivateKey) key;
    }

    /**
     * @param alias 별칭(개인키 엔트리면 그 인증서, 인증서 엔트리면 그 인증서)
     * @return X.509 인증서
     * @throws KeyStoreException 별칭 없음·인증서 없음·X.509가 아님
     */
    public synchronized X509Certificate certificate(String alias) throws KeyStoreException {
        requireAlias(alias);
        Certificate certificate = store.getCertificate(alias);
        if (!(certificate instanceof X509Certificate)) throw new KeyStoreException(Text.get("sec.err.ksNoCertificate"));
        return (X509Certificate) certificate;
    }

    /**
     * @param alias 별칭
     * @return 그 인증서의 공개키
     * @throws KeyStoreException 별칭 없음·인증서 없음
     */
    public PublicKey publicKey(String alias) throws KeyStoreException {
        return certificate(alias).getPublicKey();
    }

    /**
     * @param alias 개인키 엔트리의 별칭
     * @return 인증서 체인(끝 인증서부터, 인증서 엔트리면 그 인증서 하나)
     * @throws KeyStoreException 별칭 없음·체인 없음·X.509가 아님
     */
    public synchronized List<X509Certificate> certificateChain(String alias) throws KeyStoreException {
        requireAlias(alias);
        Certificate[] chain = store.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            Certificate single = store.getCertificate(alias);
            chain = single == null ? new Certificate[0] : new Certificate[] {single};
        }
        if (chain.length == 0) throw new KeyStoreException(Text.get("sec.err.ksNoCertificate"));
        List<X509Certificate> out = new ArrayList<>();
        for (Certificate certificate : chain) {
            if (!(certificate instanceof X509Certificate)) throw new KeyStoreException(Text.get("sec.err.ksNoCertificate"));
            out.add((X509Certificate) certificate);
        }
        return Collections.unmodifiableList(out);
    }

    @Override
    public String toString() {
        return "KeyStoreReader[" + type + "]";
    }

    private void requireAlias(String alias) throws KeyStoreException {
        Text.require(alias, "alias");
        if (!store.containsAlias(alias)) throw new KeyStoreException(Text.get("sec.err.ksNoAlias"));
    }

    /**
     * 패키지 내부(시험용): 원인 체인으로 비밀번호 오류·지원하지 않는 보호 알고리즘·그 밖의 형식 오류를 나눈다(문구에 경로·비밀번호
     * 없음). 오래된 Java 8 업데이트는 PBES2 매개변수를 해석하지 못해 알고리즘 미지원을 형식 오류처럼 던지므로, 이 Java가 PBES2를
     * 해석하지 못하고 PKCS12가 PBES2로 보호된 경우에는 지원하지 않는 보호 알고리즘으로 알린다.
     */
    static String classify(Throwable error, KeyStoreType type, byte[] content, boolean pbes2Supported) {
        for (Throwable t = error; t != null; t = t.getCause()) {
            if (t instanceof UnrecoverableKeyException) return "sec.err.ksPassword";
            if (t instanceof NoSuchAlgorithmException) return "sec.err.ksUnsupported";
        }
        if (type == KeyStoreType.PKCS12 && !pbes2Supported && contains(content, PBES2_OID)) return "sec.err.ksUnsupported";
        return "sec.err.ksFormat";
    }

    private static boolean contains(byte[] content, byte[] part) {
        outer:
        for (int i = 0; i + part.length <= content.length; i++) {
            for (int j = 0; j < part.length; j++) {
                if (content[i + j] != part[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    /** 이 Java가 PKCS12의 PBES2 매개변수를 해석할 수 있는지(처음 쓸 때 한 번 확인). */
    private static final class Pbes2 {
        static final boolean SUPPORTED = probe();

        private static boolean probe() {
            try {
                AlgorithmParameters.getInstance("PBES2").init(Encoding.HEX.decode(PBES2_PARAMS));
                return true;
            } catch (GeneralSecurityException | IOException | RuntimeException e) {
                return false;
            }
        }
    }
}
