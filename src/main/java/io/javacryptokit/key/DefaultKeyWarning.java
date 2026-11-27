package io.javacryptokit.key;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.i18n.Messages;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 이전 배포본의 공개 예제 키를 지문으로 판별한다. 관리형 키는
 * {@link KeyResolver}에서 해당 지문을 거부한다. 이전 경고 처리의 설정과 동작은 호환 목적으로 유지한다.
 *
 * <p><b>판정</b>: 키 공급 방식(embedded·file·env·vault·aws-kms)과 관계없이 실제 적용된 키 값을 공개 기본 키와 비교한다. 같은 값을
 * 키 파일·환경변수·원격 저장소로 옮겨도 그 키로 만든 암호문은 누구나 복호화할 수 있기 때문이다. 사용자 지정 키(교체한 내장 키
 * 포함)에는 경고하지 않는다.</p>
 *
 * <p><b>정책</b>: {@code crypto.warning.enabled}가 true(기본값)일 때만 출력하고, false이면 0건이다. 이 설정은 이 경고 하나만
 * 바꾸며 키·암호문·설정 오류 처리에는 영향이 없다. 다른 로거·WAS 로그·전역 로깅 설정은 건드리지 않는다. 문구는 설정
 * {@code crypto.lang}의 언어로 만든다(호출 시점의 메시지 언어 범위).</p>
 *
 * <p><b>횟수</b>: JVM(프로세스)당 최대 한 번이다. DataSource가 여러 개이거나 같은 프로세스에서 여러 번 암복호화해도 반복하지 않는다.
 * CLI는 명령마다 새 JVM을 띄우므로 명령을 실행할 때마다 한 번 나올 수 있다. "이미 경고함" 표시는 실제로 출력할 때만 바뀐다.</p>
 *
 * <p><b>명시적 조회</b>: CLI {@code info}·{@code doctor}·{@code fingerprint}처럼 키 상태를 화면에 직접 보여 주는 명령은
 * {@link #quiet()} 범위에서 실행해 같은 사실을 경고로 한 번 더 알리지 않는다.</p>
 *
 * <p><b>키 비교 방식</b>: 키 원문을 소스에 다시 적지 않도록 공개 기본 키의 SHA-256 값만 보관하고 비교한다. 키 자체와 지문은 로그에
 * 남기지 않는다.</p>
 */
public final class DefaultKeyWarning {
    /** WAS에서는 WAS 로그(예: Tomcat JULI)로, CLI에서는 표준 오류로 출력되는 java.util.logging 로거. */
    private static final Logger LOG = Logger.getLogger(DefaultKeyWarning.class.getName());
    /**
     * 공개 기본 키 두 개의 SHA-256 값(키 자체가 아니다): key 유형 {@code default}(이전 형식부터의 공개 AES 키)와 pass 유형
     * {@code pass-default}(공개 예제 Passphrase로 파생한 키).
     */
    private static final java.util.Set<String> PUBLIC_KEY_SHA256 = java.util.Collections.unmodifiableSet(
            new java.util.HashSet<>(java.util.Arrays.asList(
                    "351dfcd8784ea44116d96f8ae46dc3ea11dcd51c609e56be70a8165b7b2ea2f7",
                    "5febb682d5bbd90055236b0c6d3770abc99b3548097c1ac0d2c4a6ff595d3866")));
    /** 이 JVM에서 공개 기본 키 경고를 이미 출력했는지. */
    private static final AtomicBoolean WARNED = new AtomicBoolean(false);
    /** 현재 스레드가 명시적 조회 중이면 TRUE(자동 경고 생략). */
    private static final ThreadLocal<Boolean> QUIET = new ThreadLocal<>();

    /** 정적 메서드만 제공하므로 인스턴스 생성을 막는다. */
    private DefaultKeyWarning() { }

    /**
     * 키가 공개 기본 키와 같은지 확인한다. 경고 정책과 관계없이 결과를 돌려주므로 {@code info}·{@code doctor}·{@code fingerprint}의
     * 키 상태 표시 및 관리형 키 등록·로딩의 이전 공개 키 차단에 쓴다.
     *
     * @param rawKey 32바이트 원시 키(바꾸거나 보관하지 않는다)
     * @return 공개 기본 키와 같으면 true
     */
    public static boolean isPublicDefaultKey(byte[] rawKey) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(rawKey);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
            return PUBLIC_KEY_SHA256.contains(hex.toString());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

    /**
     * 경고 정책이 켜져 있고 키가 공개 기본 키이면 JVM당 한 번 WARNING 한 줄을 기록한다. 명시적 조회({@link #quiet()}) 중에는
     * 기록하지 않는다.
     *
     * @param settings 검증된 설정(경고 정책)
     * @param rawKey   검사할 32바이트 원시 키(바꾸거나 보관하지 않는다)
     */
    public static void warnIfNeeded(CryptoSettings settings, byte[] rawKey) {
        // 경고가 꺼져 있거나 명시적 조회 중이면 아무것도 출력하지 않고 "이미 경고함" 표시도 바꾸지 않는다.
        if (!settings.warningEnabled() || Boolean.TRUE.equals(QUIET.get()) || WARNED.get()) return;
        if (isPublicDefaultKey(rawKey)) warnOnce();
    }

    /**
     * 이전 공개 키 경고를 직접 요청하는 내부 호출용이다. 경고 정책·
     * JVM당 1회 규칙은 자동 경고와 같으며, {@link #quiet()} 범위 안에서 불러도 기록한다(그 범위는 자동 경고만 막는다).
     *
     * @param settings 결과 키의 설정(경고 정책)
     */
    public static void warnPublicKeyInUse(CryptoSettings settings) {
        if (settings.warningEnabled()) warnOnce();
    }

    /** JVM당 한 번만 경고 한 줄을 기록한다. */
    private static void warnOnce() {
        if (WARNED.compareAndSet(false, true)) {
            // WAS 로그에서 다른 로그와 구분되도록 태그를 붙인다(CLI는 태그를 떼고 [WARN] 한 줄로 표시).
            LOG.warning(Messages.TAG + " " + Messages.get("warn.publicKey"));
        }
    }

    /**
     * 현재 스레드에서 자동 경고를 내지 않는 범위를 연다. 키 상태를 화면에 직접 보여 주는 명시적 조회에만 쓴다.
     * {@code try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) { ... }}
     *
     * @return 닫으면 이전 상태로 돌아가는 범위
     */
    public static Quiet quiet() {
        Boolean previous = QUIET.get();
        QUIET.set(Boolean.TRUE);
        return new Quiet(previous);
    }

    /** {@link #quiet()}가 연 범위. 닫으면 이전 상태로 되돌린다. */
    public static final class Quiet implements AutoCloseable {
        private final Boolean previous;

        private Quiet(Boolean previous) {
            this.previous = previous;
        }

        @Override
        public void close() {
            if (previous == null) {
                QUIET.remove();
            } else {
                QUIET.set(previous);
            }
        }
    }

    /**
     * <b>테스트 전용</b>: "이미 경고함" 표시를 초기화해 테스트 실행 순서와 관계없이 경고 출력 여부를 검증할 수 있게 한다.
     * 운영 코드에서는 호출하지 않는다.
     */
    public static void resetForTests() {
        WARNED.set(false);
    }
}
