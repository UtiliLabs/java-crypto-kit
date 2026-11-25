package io.javacryptokit.security;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * <b>공개 API</b>: X.509 인증서의 분석 결과(읽기 전용). {@link Certificates#info(X509Certificate)}가 만든다.
 *
 * <p><b>분석은 신뢰 검증이 아니다</b>: 이 객체의 값과 {@link #isValidAt(Instant)}(날짜 확인)는 인증서에 적힌 내용을 보여 줄 뿐,
 * 믿을 수 있는 발급자가 발급했는지(신뢰 체인: {@link Certificates#validateChain}), 접속한 호스트의 인증서인지(호스트명 검증: TLS
 * 클라이언트 몫), 폐기되지 않았는지(CRL·OCSP: 이 라이브러리 범위 밖)를 판단하지 않는다.</p>
 */
public final class CertificateInfo {
    private final String subject;
    private final String issuer;
    private final String serialNumberHex;
    private final Instant notBefore;
    private final Instant notAfter;
    private final String publicKeyAlgorithm;
    private final int publicKeySize;
    private final String signatureAlgorithm;
    private final String sha256Fingerprint;
    private final List<String> subjectAlternativeNames;

    CertificateInfo(X509Certificate cert) {
        this.subject = cert.getSubjectX500Principal().getName();
        this.issuer = cert.getIssuerX500Principal().getName();
        this.serialNumberHex = cert.getSerialNumber().toString(16).toLowerCase(Locale.ROOT);
        this.notBefore = cert.getNotBefore().toInstant();
        this.notAfter = cert.getNotAfter().toInstant();
        PublicKey key = cert.getPublicKey();
        this.publicKeyAlgorithm = key.getAlgorithm();
        this.publicKeySize = key instanceof RSAKey ? ((RSAKey) key).getModulus().bitLength()
                : key instanceof ECKey ? ((ECKey) key).getParams().getCurve().getField().getFieldSize() : 0;
        this.signatureAlgorithm = cert.getSigAlgName();
        try {
            String hex = Encoding.HEX.encode(Digests.sha256(cert.getEncoded())).toUpperCase(Locale.ROOT);
            StringBuilder colon = new StringBuilder();
            for (int i = 0; i < hex.length(); i += 2) {
                if (i > 0) colon.append(':');
                colon.append(hex, i, i + 2);
            }
            this.sha256Fingerprint = colon.toString();
        } catch (CertificateEncodingException e) {
            throw Text.invalid("sec.err.certFormat");
        }
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> alternatives = cert.getSubjectAlternativeNames();
            if (alternatives != null) {
                for (List<?> entry : alternatives) {
                    Object type = entry.get(0);
                    Object value = entry.get(1);
                    if (Integer.valueOf(2).equals(type) && value instanceof String) names.add("DNS:" + value);
                    else if (Integer.valueOf(7).equals(type) && value instanceof String) names.add("IP:" + value);
                    else if (Integer.valueOf(1).equals(type) && value instanceof String) names.add("EMAIL:" + value);
                    else if (Integer.valueOf(6).equals(type) && value instanceof String) names.add("URI:" + value);
                }
            }
        } catch (CertificateParsingException e) {
            throw Text.invalid("sec.err.certFormat");
        }
        this.subjectAlternativeNames = Collections.unmodifiableList(names);
    }

    /** @return 주체 DN(RFC 2253) */
    public String subject() {
        return subject;
    }

    /** @return 발급자 DN(RFC 2253) */
    public String issuer() {
        return issuer;
    }

    /** @return 일련번호(소문자 16진수) */
    public String serialNumberHex() {
        return serialNumberHex;
    }

    /** @return 유효 시작 시각 */
    public Instant notBefore() {
        return notBefore;
    }

    /** @return 유효 종료 시각 */
    public Instant notAfter() {
        return notAfter;
    }

    /** @return 공개키 알고리즘(예: {@code RSA}, {@code EC}) */
    public String publicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    /** @return 공개키 크기(RSA 모듈러스 비트, EC 곡선 필드 비트, 그 밖은 0) */
    public int publicKeySize() {
        return publicKeySize;
    }

    /** @return 서명 알고리즘(예: {@code SHA256withRSA}) */
    public String signatureAlgorithm() {
        return signatureAlgorithm;
    }

    /** @return DER 전체의 SHA-256 지문(대문자 16진수 콜론 구분, {@code openssl x509 -fingerprint -sha256}·keytool과 같은 표기) */
    public String sha256Fingerprint() {
        return sha256Fingerprint;
    }

    /** @return 주체 대체 이름({@code DNS:}·{@code IP:}·{@code EMAIL:}·{@code URI:} 접두어, 없으면 빈 목록) */
    public List<String> subjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    /**
     * 날짜만 확인한다(신뢰·호스트명·폐기 확인 아님).
     *
     * @param time 기준 시각
     * @return notBefore ≤ time ≤ notAfter이면 true
     */
    public boolean isValidAt(Instant time) {
        Text.require(time, "time");
        return !time.isBefore(notBefore) && !time.isAfter(notAfter);
    }

    /**
     * @param now 기준 시각
     * @return 만료까지 남은 날(이미 지났으면 음수)
     */
    public long daysUntilExpiry(Instant now) {
        Text.require(now, "now");
        return Duration.between(now, notAfter).toDays();
    }

    @Override
    public String toString() {
        return "CertificateInfo[subject=" + subject + ", issuer=" + issuer + ", notAfter=" + notAfter + ", sha256=" + sha256Fingerprint + "]";
    }
}
