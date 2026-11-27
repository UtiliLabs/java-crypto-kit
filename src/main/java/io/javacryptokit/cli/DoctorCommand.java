package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.Diagnostic;
import io.javacryptokit.key.KeyResolver;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

/**
 * <b>내부 구현 클래스</b>: {@code doctor} 명령. WAS 기동 전에 설정이 정상 적용되고 키·암복호화가 실제로 동작하는지 한 번에 점검한다.
 * 정책·위험도 평가 도구가 아니다(운영·보안 권고는 사용자 가이드).
 *
 * <p><b>출력</b>: 실제로 실행한 점검만 {@code [PASS]}·{@code [FAIL]}·{@code [SKIP]}로 표시하고, 판단에 필요한 사실만 {@code [INFO]}로
 * 덧붙인다. {@code [WARN]}은 지정한 {@code -D}가 정책 때문에 적용되지 않은 경우처럼 설정이 의도대로 적용되지 않은 경우에만 쓴다.
 * 관리형 공개 키는 키 로딩 단계에서 거부한다. 상태 코드는 언어와 관계없이 같다. FAIL이 하나라도
 * 있으면 종료 코드 1이다.</p>
 *
 * <p><b>키 목록</b>: 등록된 키(pass·key 유형 모두)마다 공급원 준비 상태와 실제 키 조회(외부 키는 고정 지문 확인 포함)를 따로
 * 점검한다. 한 키가 실패해도 다른 키 점검은 계속한다. 암복호화 자체 검증은 읽은 키 하나(가능하면 새 암호화의 기본 키)로 한 번 한다.</p>
 *
 * <p><b>원격 공급원</b>: {@code --offline}이면 Vault·AWS KMS에 연결하지 않고 설정·토큰·SDK·파일 준비 상태만 확인한다(SKIP 표시).
 * 기본은 실제로 연결해 키를 조회한다.</p>
 *
 * <p><b>한계</b>: Tomcat 기동·DB 연결은 점검하지 않으므로 PASS로 표시하지 않는다. 키·토큰·평문은 출력하지 않는다(짧은 키 지문만).</p>
 */
final class DoctorCommand {
    /** 상태 표시({@code [PASS] } 등, 모두 7칸) 다음 열. 조치 줄과 여러 항목은 이 들여쓰기로 쓴다. */
    private static final String DETAIL_INDENT = "       ";
    /** 줄 폭 계산용 상태 표시(모든 상태 코드는 4글자). */
    private static final String STATUS_WIDTH_SAMPLE = "[INFO] ";

    private DoctorCommand() { }

    static int run(CliCommands.Parsed parsed, PrintStream out) {
        boolean offline = parsed.flag("--offline");
        List<Diagnostic> results = new ArrayList<>();

        // [1] JAR 내장 설정 자체(외부 설정 없이)
        try {
            CryptoSettings.fromEmbeddedDefaults(jarDefaults());
            results.add(Diagnostic.pass(Messages.get("doctor.jarSettings")));
        } catch (IOException | RuntimeException e) {
            results.add(Diagnostic.fail(Messages.get("doctor.jarSettingsFail", message(e)), Messages.get("doctor.action.jar")));
        }
        String history = ConfigHistory.describeRunningJar();
        results.add(Diagnostic.info(Messages.get("doctor.history", history)));

        // [2] 실제 적용 설정(외부 Properties·-D 포함). 실패하면 이후 점검은 의미가 없으므로 생략한다.
        CryptoService crypto;
        try {
            crypto = CryptoService.load(parsed.value("--config"));
            results.add(Diagnostic.pass(Messages.get("doctor.settings")));
        } catch (CredentialCryptoException e) {
            results.add(failure(e.getMessage()));
            results.add(Diagnostic.skip(Messages.get("doctor.skipRest")));
            return report(results, out);
        }
        CryptoSettings settings = crypto.settings();
        // 실제로 적용된 외부 설정·-D만 사실로 보여 준다(없으면 줄을 만들지 않음).
        if (settings.externalConfigUsed()) {
            results.add(Diagnostic.info(Messages.get("doctor.external", settings.configFileName(),
                    settings.configOrigin().description())));
        }
        if (!settings.jvmOverriddenKeys().isEmpty()) {
            results.add(Diagnostic.info(names("doctor.jvm", settings.jvmOverriddenKeys())));
        }
        if (!settings.ignoredJvmKeys().isEmpty()) {
            // 정책 권고가 아니라 "지정한 설정이 적용되지 않았다"는 사실이므로 WARN으로 알린다(실행은 계속 가능).
            results.add(Diagnostic.warn(names("doctor.jvmIgnored", settings.ignoredJvmKeys()),
                    Messages.get("doctor.action.jvmIgnored")));
        }
        results.add(Diagnostic.pass(Messages.get("doctor.algorithm", settings.get(CryptoSettings.ALGORITHM))));
        results.add(Diagnostic.info(Messages.get("doctor.keyring", settings.defaultType().code(),
                KeyringView.idOrNone(settings.activeProfile(KeyType.PASS)),
                KeyringView.idOrNone(settings.activeProfile(KeyType.KEY)))));

        // [3] 등록된 키마다: 공급원 준비 상태(네트워크 없이) → 실제 키 조회(지문 고정 확인 포함). --offline이면 원격 조회는 생략한다.
        KeyProfile selfTestKey = null;
        KeyProfile encryptionDefault = crypto.defaultProfile();
        if (encryptionDefault == null) {
            try {
                crypto.select(null, null);
            } catch (CredentialCryptoException e) {
                results.add(failure(e.getMessage()));
            }
        }
        for (KeyProfile profile : settings.profiles()) {
            // 키 한 줄: "키 <ID> (꼬리표): 공급원, 위치". 80열을 넘으면 꼬리표 다음에서 줄을 바꾼다(값은 자르지 않음).
            results.add(Diagnostic.info(KeyringView.wrapAfter(STATUS_WIDTH_SAMPLE,
                    Messages.get("doctor.key", profile.id(), KeyringView.marks(settings, profile)),
                    Messages.get("doctor.keyWhere", profile.source(), crypto.describeKeyLocation(profile)), DETAIL_INDENT)));
            results.addAll(crypto.offlineKeyChecks(profile));
            if (offline && crypto.remoteKeySource(profile)) {
                results.add(Diagnostic.skip(Messages.get("doctor.remoteSkipped", profile.id())));
                continue;
            }
            CryptoService.KeyCheck check = crypto.checkKey(profile);
            if (!check.available()) {
                results.add(failure(check.failure()));
                continue;
            }
            // 키 공급원 로딩에 성공하면 키 상태와 지문을 표시한다.
            results.add(Diagnostic.pass(KeyringView.wrapAfter(STATUS_WIDTH_SAMPLE, Messages.get("doctor.keyOk", profile.id()),
                    Messages.get("doctor.keyOkDetail", CryptoCli.keyStatus(check.publicDefaultKey()),
                            KeyResolver.shortFingerprint(check.fingerprint())), DETAIL_INDENT)));
            if (selfTestKey == null || profile.equals(encryptionDefault)) selfTestKey = profile;
        }

        // [4] 암복호화 자체 검증(읽은 키 하나로, 가능하면 새 암호화의 기본 키). 읽은 키가 없으면 실행하지 않는다(PASS 없음).
        if (selfTestKey != null) results.add(selfTest(crypto, selfTestKey));
        return report(results, out);
    }

    /** 실제 키로 임의 값을 암복호화하고, 변조한 암호문이 거부되는지 확인한다(값·키는 출력하지 않음). */
    private static Diagnostic selfTest(CryptoService crypto, KeyProfile profile) {
        byte[] probe = new byte[32];
        new SecureRandom().nextBytes(probe);
        byte[] back = null;
        try {
            String token = crypto.encryptBytes(probe, null, profile.id());
            back = crypto.decryptBytes(token);
            if (!Arrays.equals(probe, back)) {
                return Diagnostic.fail(Messages.get("doctor.selfTestFail"), Messages.get("doctor.action.provider"));
            }
            // 암호문 본문의 중간 글자 하나를 바꾼다(마지막 글자는 남는 비트일 수 있어 피한다).
            int at = token.startsWith("ENC[") ? token.lastIndexOf(':') + 2 : 6;
            char flipped = token.charAt(at) == 'A' ? 'B' : 'A';
            String tampered = token.substring(0, at) + flipped + token.substring(at + 1);
            if (crypto.verify(tampered)) {
                return Diagnostic.fail(Messages.get("doctor.selfTestFail"), Messages.get("doctor.action.provider"));
            }
            return Diagnostic.pass(Messages.get("doctor.selfTest"));
        } catch (CredentialCryptoException e) {
            return failure(e.getMessage());
        } finally {
            Arrays.fill(probe, (byte) 0);
            if (back != null) Arrays.fill(back, (byte) 0);
        }
    }

    /**
     * 설정 이름 목록 메시지. 이름이 하나이고 한 줄(80열)에 들어가면 {@code 제목: 이름} 한 줄, 아니면 제목 줄 아래에 이름을 한 줄에
     * 하나씩 조치 줄과 같은 들여쓰기로 쓴다.
     *
     * @param key   "제목: {0}" 형식의 메시지 키
     * @param names 설정 이름(비어 있지 않음)
     */
    private static String names(String key, Collection<String> names) {
        if (names.size() == 1) {
            String one = Messages.get(key, names.iterator().next());
            if (CliHelp.width(STATUS_WIDTH_SAMPLE + one) <= CliHelp.LINE_WIDTH) return one;
        }
        StringBuilder text = new StringBuilder(Messages.get(key, "").trim());
        for (String name : names) text.append(System.lineSeparator()).append(DETAIL_INDENT).append(name);
        return text.toString();
    }

    /**
     * 공개 예외 메시지("원인 조치: 확인할 내용", {@code CredentialCryptoException})를 원인과 조치로 나눈 FAIL을 만든다. 조치는 FAIL
     * 바로 아래 한 줄로만 보여 주고 같은 내용의 조치를 한 번 더 붙이지 않는다.
     */
    private static Diagnostic failure(String message) {
        String marker = Messages.get("exception.action", "");
        int at = message == null ? -1 : message.lastIndexOf(marker);
        if (at <= 0) return Diagnostic.fail(message, null);
        return Diagnostic.fail(message.substring(0, at), message.substring(at + marker.length()));
    }

    /**
     * 결과를 출력하고 종료 코드를 돌려준다(FAIL이 있으면 1). 조치는 해당 줄 바로 아래 한 줄. 마지막 줄은
     * {@code 결과: PASS} 또는 {@code 결과: FAIL (n건)}이며 WARN·SKIP이 있으면 개수를 덧붙인다.
     */
    private static int report(List<Diagnostic> results, PrintStream out) {
        int warn = 0;
        int fail = 0;
        int skip = 0;
        for (Diagnostic result : results) {
            out.println("[" + result.status + "] " + result.message);
            if (result.action != null) out.println(DETAIL_INDENT + Messages.get("doctor.actionLabel", result.action));
            switch (result.status) {
                case WARN: warn++; break;
                case FAIL: fail++; break;
                case SKIP: skip++; break;
                default: break;
            }
        }
        // 상태 코드(WARN·SKIP)는 언어와 관계없이 그대로 쓴다.
        List<String> counts = new ArrayList<>();
        if (warn > 0) counts.add("WARN " + warn);
        if (skip > 0) counts.add("SKIP " + skip);
        String extra = counts.isEmpty() ? "" : Messages.get("doctor.result.counts", String.join(", ", counts));
        out.println(fail > 0 ? Messages.get("doctor.result.fail", fail, extra) : Messages.get("doctor.result.pass", extra));
        return fail > 0 ? 1 : 0;
    }

    /** 실행 중인 JAR(클래스패스)의 내부 기본 설정을 읽는다. */
    private static Properties jarDefaults() throws IOException {
        Properties properties = new Properties();
        try (InputStream in = DoctorCommand.class.getResourceAsStream(CryptoSettings.DEFAULT_CONFIG_RESOURCE)) {
            if (in == null) throw new IOException("java-crypto-kit.properties");
            try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
        }
        return properties;
    }

    private static String message(Exception e) {
        return e instanceof io.javacryptokit.config.SafeMessageException ? e.getMessage() : e.getClass().getSimpleName();
    }
}
