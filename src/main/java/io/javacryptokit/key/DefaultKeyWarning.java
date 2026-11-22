package io.javacryptokit.key;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.i18n.Messages;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 키 사용 위험을 탐지해 비차단형 안내 WARNING을 남긴다. 경고는 실행을 막지 않는다.
 *
 * <p><b>탐지하는 두 가지 위험</b></p>
 * <ol>
 *   <li><b>공개 기본 키</b>: 공개 저장소·JAR에 들어 있어 누구나 아는 키다. 이 키로 만든 암호문은 사실상 평문과 같다.
 *       {@code embedded}뿐 아니라 같은 키 값을 다른 공급원으로 공급한 경우도 탐지한다(공급 방식과 무관).</li>
 *   <li><b>교체한 내장 키</b>: {@code embedded} 모드에서 공개 키가 아닌 값을 쓰더라도, 내장 키는 JAR에서 추출할 수 있다.</li>
 * </ol>
 *
 * <p><b>경고 정책</b>: 실제 출력은 {@code crypto.warning.enabled}가 true(기본값)일 때만 한다. false이면 어떤 모드에서도
 * 이 클래스의 WARNING은 0건이다(우회 안내문도 남기지 않음). 이 설정은 안내 로그만 바꾸며, 키·암호문·설정 오류 처리와
 * {@code decrypt}의 확인 절차에는 영향이 없다. 다른 로거·WAS 로그·전역 로깅 설정도 건드리지 않는다. 문구는 설정
 * {@code crypto.lang}의 언어로 만든다(호출 시점의 메시지 언어 범위).</p>
 *
 * <p><b>한 번만 경고</b>: 위험 종류별로 JVM당 한 번만 기록해 DataSource가 여러 개여도 로그가 반복되지 않게 한다.
 * "이미 경고함" 표시는 경고를 실제로 출력할 때만 바뀐다.</p>
 *
 * <p><b>키 비교 방식</b>: 키 원문을 소스에 다시 적지 않도록 공개 기본 키의 SHA-256 지문만 보관하고 비교한다.
 * 키 자체와 지문은 로그에 남기지 않는다.</p>
 */
public final class DefaultKeyWarning {
    /** WAS에서는 WAS 로그(예: Tomcat JULI)로, CLI에서는 표준 오류로 출력되는 java.util.logging 로거. */
    private static final Logger LOG = Logger.getLogger(DefaultKeyWarning.class.getName());
    /** 공개 예제에 포함된 초기 내장 키의 SHA-256 지문(키 자체가 아니다). */
    private static final String PUBLIC_KEY_SHA256 = "351dfcd8784ea44116d96f8ae46dc3ea11dcd51c609e56be70a8165b7b2ea2f7";
    /** 공개 기본 키 경고를 이미 출력했는지. */
    private static final AtomicBoolean PUBLIC_KEY_WARNED = new AtomicBoolean(false);
    /** 교체한 내장 키 경고를 이미 출력했는지. */
    private static final AtomicBoolean EMBEDDED_KEY_WARNED = new AtomicBoolean(false);

    /** 정적 메서드만 제공하므로 인스턴스 생성을 막는다. */
    private DefaultKeyWarning() { }

    /**
     * 키가 공개 기본 키와 같은지 확인한다. 경고 정책과 관계없이 결과를 돌려주므로 {@code info}·{@code doctor} 같은 명시적 진단에 쓴다.
     *
     * @param rawKey 32바이트 원시 키(바꾸거나 보관하지 않는다)
     * @return 공개 기본 키와 같으면 true
     */
    public static boolean isPublicDefaultKey(byte[] rawKey) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(rawKey);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
            return PUBLIC_KEY_SHA256.equals(hex.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

    /**
     * 경고 정책이 켜져 있으면 키 위험을 위험 종류별로 JVM당 한 번 WARNING으로 기록한다.
     *
     * @param settings 검증된 설정(경고 정책, 키 공급 방식, 공급 방식 명시 여부)
     * @param rawKey   검사할 32바이트 원시 키(바꾸거나 보관하지 않는다)
     */
    public static void warnIfNeeded(CryptoSettings settings, byte[] rawKey) {
        // 경고가 꺼져 있으면 아무것도 출력하지 않고, "이미 경고함" 표시도 바꾸지 않는다.
        if (!settings.warningEnabled()) return;
        String source = settings.keySource();
        // 외부 설정이나 JVM 속성으로 다른 항목은 바꾸면서 키 공급 방식은 적지 않아 기본값 embedded가 적용된 경우,
        // 운영자가 외부 키를 쓴다고 오해하지 않도록 덧붙인다.
        boolean customized = settings.externalConfigUsed() || !settings.jvmOverriddenKeys().isEmpty();
        String inheritedNote = customized && !settings.keySourceExplicit() ? Messages.get("warn.inheritedNote") : "";
        if (isPublicDefaultKey(rawKey)) {
            if (PUBLIC_KEY_WARNED.compareAndSet(false, true)) {
                LOG.warning(Messages.TAG + " " + Messages.get("warn.publicKey", source) + inheritedNote);
            }
        } else if ("embedded".equals(source)) {
            if (EMBEDDED_KEY_WARNED.compareAndSet(false, true)) {
                LOG.warning(Messages.TAG + " " + Messages.get("warn.embeddedKey") + inheritedNote);
            }
        }
    }

    /**
     * <b>테스트 전용</b>: "이미 경고함" 표시를 초기화해 테스트 실행 순서와 관계없이 경고 출력 여부를 검증할 수 있게 한다.
     * 운영 코드에서는 호출하지 않는다.
     */
    public static void resetForTests() {
        PUBLIC_KEY_WARNED.set(false);
        EMBEDDED_KEY_WARNED.set(false);
    }
}
