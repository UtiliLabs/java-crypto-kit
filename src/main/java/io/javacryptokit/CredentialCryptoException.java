package io.javacryptokit;

import io.javacryptokit.i18n.Messages;
import java.security.GeneralSecurityException;

/**
 * <b>공개 API</b>: {@link CredentialCrypto}와 CLI·Tomcat 어댑터가 공통으로 사용하는 "정제된" 실패 예외다.
 *
 * <p><b>왜 별도 예외가 필요한가</b>: JDK·파일 시스템·네트워크 예외의 메시지에는 파일 경로나 입력값 일부가 들어갈 수 있다.
 * 이 예외는 사람이 원인을 판단할 수 있는 고정 문구와 실패 사유({@link Reason})만 담고, 원래 예외 객체는 원인(cause)으로
 * 붙이지 않는다. 원래 예외는 클래스 이름({@link #getCauseType()})만 남겨 진단에 쓰게 한다. 따라서 이 예외를 로그에
 * 스택 트레이스째 남겨도 평문·키·암호문·경로·토큰이 노출되지 않는다.</p>
 *
 * <p><b>메시지 형식</b>: "원인 설명(+ 추가 설명, 원인 종류) 조치: 확인할 설정"이다. 문구는 설정 {@code crypto.lang}의 언어
 * (영어·한국어)로 만든다. CLI와 Tomcat Factory는 이 메시지 앞에 {@code [java-crypto-kit] [사유: <Reason 이름>]}(영어는
 * {@code [reason: ...]})만 붙여 그대로 보여 주므로, 세 진입점에서 같은 오류는 같은 의미·같은 조치로 보인다. 사유 이름
 * ({@link Reason#name()})은 언어와 관계없이 같으므로 자동화 프로그램은 사유 이름으로 판별한다.</p>
 *
 * <p>{@link GeneralSecurityException}의 하위 클래스이므로 {@code catch (GeneralSecurityException e)}로도 받을 수 있다.
 * 생성자는 라이브러리 내부용이며, 추가 설명({@code safeDetail})에는 비밀값·입력값·경로를 넣지 않는다.</p>
 */
public final class CredentialCryptoException extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    /**
     * 실패 사유. 호출자는 이 값으로 "설정을 고칠 문제"와 "암호문·키가 맞지 않는 문제"를 구분할 수 있다.
     * 값의 이름은 공개 API의 일부이므로 바꾸지 않는다(번역하지 않는다).
     */
    public enum Reason {
        /** 외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님, 허용되지 않은 설정값, 설정 경로 문제, 모호한 키 설정. */
        CONFIGURATION,
        /** 키 파일·환경변수·Vault·AWS KMS에서 키를 읽을 수 없거나 키 형식(Base64)·길이(32바이트)가 올바르지 않음. */
        KEY_SOURCE,
        /** 빈 값, 너무 긴 값, UTF-8로 표현할 수 없는 문자, 텍스트로 해석할 수 없는 복호화 결과, 파일 입출력 문제. */
        INVALID_INPUT,
        /** {@code ENC[v1:...]}·{@code B64[...]} 또는 암호화 파일(JCKF v1/v2) 형식이 아니거나 손상됨. */
        INVALID_TOKEN,
        /** 암호문(또는 암호화 파일)에 기록된 키 식별자와 현재 설정의 키 식별자가 다름. */
        KEY_ID_MISMATCH,
        /** AES-GCM 인증 태그 검증 실패: 다른 키로 만들었거나 암호문이 변조·손상·잘림. */
        INTEGRITY,
        /** 실행 중인 Java가 AES-256-GCM을 제공하지 않는 등 암호화 기능 자체를 쓸 수 없음. */
        CRYPTO_PROVIDER;

        /** @return 사람이 읽을 수 있는 고정 설명(현재 메시지 언어, 비밀값 없음) */
        public String description() {
            return Messages.get("reason." + name());
        }

        /** @return 암호문 자체의 문제(형식·키ID·무결성)이면 true. {@code verify}가 false로 응답하는 사유들이다. */
        public boolean isTokenProblem() {
            return this == INVALID_TOKEN || this == KEY_ID_MISMATCH || this == INTEGRITY;
        }
    }

    private final Reason reason;
    private final String causeType;

    /**
     * 사유만으로 예외를 만든다(라이브러리 내부용).
     *
     * @param reason 실패 사유
     */
    public CredentialCryptoException(Reason reason) {
        this(reason, null, null);
    }

    /**
     * 사유와 추가 설명으로 예외를 만든다(라이브러리 내부용).
     *
     * @param reason     실패 사유
     * @param safeDetail 비밀값·입력값·경로가 들어 있지 않은 고정 문구(없으면 null)
     */
    public CredentialCryptoException(Reason reason, String safeDetail) {
        this(reason, safeDetail, null);
    }

    /**
     * 사유·추가 설명·원인 예외의 "종류"로 예외를 만든다(라이브러리 내부용). 원인 예외 객체와 그 메시지는 보관하지 않는다.
     *
     * @param reason     실패 사유
     * @param safeDetail 비밀값·입력값·경로가 들어 있지 않은 고정 문구(없으면 null)
     * @param cause      원인 예외. 클래스 이름만 기록한다(없으면 null).
     */
    public CredentialCryptoException(Reason reason, String safeDetail, Throwable cause) {
        super(buildMessage(reason, safeDetail, cause));
        this.reason = reason;
        this.causeType = cause == null ? null : cause.getClass().getSimpleName();
    }

    /** @return 실패 사유 */
    public Reason getReason() {
        return reason;
    }

    /** @return 원인 예외의 클래스 단순 이름(예: {@code NoSuchFileException}). 없으면 null. 비밀값이 아니다. */
    public String getCauseType() {
        return causeType;
    }

    /**
     * "원인 설명(고정 설명 + 추가 설명 + 원인 종류) + 조치: 확인할 설정"을 현재 메시지 언어로 이어 붙인다. 원인·조치 문구는
     * 이 한 곳에서 만들어 CLI·Java API·JNDI가 같은 의미를 갖게 한다.
     */
    private static String buildMessage(Reason reason, String safeDetail, Throwable cause) {
        // 원인과 조치를 모두 제공한 작업별 메시지에는 포괄적인 Reason 안내를 다시 붙이지 않는다.
        if ((reason == Reason.INVALID_INPUT || reason == Reason.INVALID_TOKEN || reason == Reason.INTEGRITY)
                && safeDetail != null && safeDetail.contains(Messages.get("exception.action", ""))) {
            return safeDetail;
        }
        StringBuilder message = new StringBuilder(reason.description());
        if (safeDetail != null && !safeDetail.isEmpty()) {
            message.append(' ').append(safeDetail);
        }
        if (cause != null) {
            message.append(Messages.get("exception.causeType", cause.getClass().getSimpleName()));
        }
        return message.append(Messages.get("exception.action", Messages.get("action." + reason.name()))).toString();
    }
}
