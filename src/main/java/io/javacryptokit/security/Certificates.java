package io.javacryptokit.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <b>공개 API</b>: X.509 인증서 읽기·분석과 호출자가 정한 신뢰 기준(TrustAnchor)으로 하는 PKIX 신뢰 체인 검증.
 *
 * <table border="1">
 *   <caption>인증서 확인의 종류와 이 클래스의 지원 범위</caption>
 *   <tr><th>확인</th><th>뜻</th><th>지원</th></tr>
 *   <tr><td>분석</td><td>주체·발급자·기간·공개키·지문 읽기</td><td>{@link #info(X509Certificate)}</td></tr>
 *   <tr><td>유효기간</td><td>지금 날짜가 기간 안인지</td><td>{@link CertificateInfo#isValidAt(Instant)}</td></tr>
 *   <tr><td>신뢰 체인</td><td>믿는 루트까지 서명이 이어지는지(PKIX)</td><td>{@link #validateChain}(호출자가 루트 제공)</td></tr>
 *   <tr><td>호스트명</td><td>접속한 서버 이름과 맞는지</td><td>미지원(HTTPS 클라이언트가 수행)</td></tr>
 *   <tr><td>폐기 여부</td><td>CRL·OCSP로 폐기됐는지</td><td>미지원(네트워크·기반 시설 필요)</td></tr>
 * </table>
 *
 * <p>분석·날짜 확인 성공을 신뢰 성공으로 쓰면 안 된다. 입력은 PEM({@code -----BEGIN CERTIFICATE-----}) 또는 DER(1MiB까지)이며
 * JDK {@link CertificateFactory}를 쓴다. 인증서 발급·갱신 기능은 없다. 상태가 없어 스레드 안전하다.</p>
 */
public final class Certificates {
    private static final int MAX_BYTES = 1024 * 1024;

    private Certificates() { }

    /**
     * @param pem 인증서 하나의 PEM
     * @return 인증서
     * @throws IllegalArgumentException 인증서가 아니거나 둘 이상
     */
    public static X509Certificate read(String pem) {
        return read(Text.require(pem, "pem").getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * @param derOrPem 인증서 하나의 DER 또는 PEM 바이트
     * @return 인증서
     * @throws IllegalArgumentException 인증서가 아니거나 둘 이상
     */
    public static X509Certificate read(byte[] derOrPem) {
        List<X509Certificate> all = parse(derOrPem);
        if (all.size() != 1) throw Text.invalid("sec.err.certCount", all.size());
        return all.get(0);
    }

    /**
     * @param file 인증서 하나의 PEM 또는 DER 파일
     * @return 인증서
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static X509Certificate readFile(Path file) throws IOException {
        return read(PemKeys.readLimited(file, MAX_BYTES));
    }

    /**
     * @param pem 여러 인증서를 이어 붙인 PEM(보통 끝 인증서 → 중간 인증서 순서)
     * @return 인증서 목록(입력 순서)
     */
    public static List<X509Certificate> readChain(String pem) {
        List<X509Certificate> all = parse(Text.require(pem, "pem").getBytes(StandardCharsets.US_ASCII));
        if (all.isEmpty()) throw Text.invalid("sec.err.certCount", 0);
        return Collections.unmodifiableList(all);
    }

    /**
     * @param file 여러 인증서 PEM 파일
     * @return 인증서 목록(입력 순서)
     * @throws IOException 파일이 없거나 읽을 수 없음
     */
    public static List<X509Certificate> readChainFile(Path file) throws IOException {
        List<X509Certificate> all = parse(PemKeys.readLimited(file, MAX_BYTES));
        if (all.isEmpty()) throw Text.invalid("sec.err.certCount", 0);
        return Collections.unmodifiableList(all);
    }

    /**
     * @param certificate 인증서
     * @return 분석 결과(신뢰 검증 아님)
     */
    public static CertificateInfo info(X509Certificate certificate) {
        return new CertificateInfo(Text.require(certificate, "certificate"));
    }

    /**
     * 호출자가 정한 신뢰 루트로 PKIX 신뢰 체인을 검증한다(JDK {@link CertPathValidator}). 폐기 여부(CRL·OCSP)는 확인하지 않고,
     * 호스트명도 확인하지 않는다. 신뢰 루트는 JVM 기본 저장소가 아니라 이 인자로만 정한다.
     *
     * @param chain        끝(서버·서명자) 인증서부터 중간 인증서 순서. 끝에 신뢰 루트가 붙어 있으면 제외하고 검증한다
     * @param trustAnchors 신뢰하는 루트(또는 중간) 인증서
     * @param at           검증 기준 시각
     * @throws CertPathValidatorException 체인이 이어지지 않음·기간 밖·서명 불일치·용도 위반 등(원인은 {@code getReason()})
     * @throws IllegalArgumentException   인자가 비었음
     */
    public static void validateChain(List<X509Certificate> chain, Collection<X509Certificate> trustAnchors, Instant at)
            throws CertPathValidatorException {
        Text.require(chain, "chain");
        Text.require(trustAnchors, "trustAnchors");
        Text.require(at, "at");
        if (chain.isEmpty() || trustAnchors.isEmpty()) throw Text.invalid("sec.err.certCount", 0);
        Set<TrustAnchor> anchors = new HashSet<>();
        for (X509Certificate anchor : trustAnchors) anchors.add(new TrustAnchor(Text.require(anchor, "trustAnchor"), null));
        List<X509Certificate> path = new ArrayList<>(chain);
        while (path.size() > 1 && trustAnchors.contains(path.get(path.size() - 1))) path.remove(path.size() - 1);
        try {
            PKIXParameters parameters = new PKIXParameters(anchors);
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(at));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(path), parameters);
        } catch (CertPathValidatorException e) {
            throw e;
        } catch (InvalidAlgorithmParameterException e) {
            throw Text.invalid("sec.err.certCount", 0);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "PKIX"));
        }
    }

    private static List<X509Certificate> parse(byte[] content) {
        Text.require(content, "content");
        if (content.length > MAX_BYTES) throw Text.invalid("sec.err.fileTooLarge", MAX_BYTES);
        try {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(content));
            List<X509Certificate> out = new ArrayList<>();
            for (Certificate certificate : certificates) out.add((X509Certificate) certificate);
            return out;
        } catch (CertificateException | ClassCastException e) {
            throw Text.invalid("sec.err.certFormat");
        }
    }
}
