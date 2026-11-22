package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.Diagnostic;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * <b>내부 구현 클래스</b>: {@code doctor} 명령. WAS 기동 전에 설정·키·암복호화가 실제로 동작하는지 한 번에 점검한다.
 *
 * <p><b>역할 구분</b>: {@code info}는 적용 설정과 출처를 보여 주고, {@code config show}는 JAR 내부 값만 보여 주며,
 * {@code doctor}는 실제 키를 읽고 암복호화 자체 검증까지 수행해 PASS/WARN/FAIL로 판정한다. 상태 코드는 언어와 관계없이 같다.
 * FAIL이 하나라도 있으면 종료 코드 1이다.</p>
 *
 * <p><b>원격 공급원</b>: {@code --offline}이면 Vault·AWS KMS에 연결하지 않고 설정·토큰·SDK·파일 준비 상태만 확인한다(SKIP 표시).
 * 기본은 실제로 연결해 키를 조회한다.</p>
 *
 * <p><b>한계</b>: doctor PASS는 Tomcat 기동·DB 연결 PASS를 뜻하지 않는다. 키·토큰·평문은 출력하지 않는다(키 지문만).</p>
 */
final class DoctorCommand {
    private DoctorCommand() { }

    static int run(CliCommands.Parsed parsed, PrintStream out) {
        boolean offline = parsed.flag("--offline");
        List<Diagnostic> results = new ArrayList<>();
        out.println(Messages.get("doctor.header", CliHelp.jarName()));

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
            results.add(Diagnostic.fail(e.getMessage(), Messages.get("doctor.action.settings")));
            results.add(Diagnostic.skip(Messages.get("doctor.skipRest")));
            return report(results, out);
        }
        CryptoSettings settings = crypto.settings();
        results.add(Diagnostic.info(settings.externalConfigUsed()
                ? Messages.get("cli.info.external.used", settings.configOrigin().description(), settings.configFileName())
                : Messages.get("cli.info.external.none", settings.configOrigin().description())));
        results.add(Diagnostic.info(Messages.get("doctor.jvm", settings.jvmOverrideEnabled() ? "true" : "false",
                settings.jvmOverriddenKeys().isEmpty() ? Messages.get("cli.info.none") : String.join(", ", settings.jvmOverriddenKeys()))));
        if (!settings.ignoredJvmKeys().isEmpty()) {
            results.add(Diagnostic.warn(Messages.get("doctor.jvmIgnored", String.join(", ", settings.ignoredJvmKeys())),
                    Messages.get("doctor.action.jvmIgnored")));
        }
        results.add(Diagnostic.pass(Messages.get("doctor.algorithm", settings.get(CryptoSettings.ALGORITHM))));
        results.add(Diagnostic.info(Messages.get("doctor.lang", settings.language().code())));
        results.add(Diagnostic.info(Messages.get("doctor.warning", settings.warningEnabled() ? "ON" : "OFF")));
        results.add(Diagnostic.info(Messages.get("doctor.keySource", settings.keySource(), settings.keyId(),
                crypto.describeKeyLocation())));

        // [3] 키 공급원 준비 상태(네트워크 없이)
        results.addAll(crypto.offlineKeyChecks());

        // [4] 실제 키 조회와 암복호화 자체 검증
        if (offline && crypto.remoteKeySource()) {
            results.add(Diagnostic.skip(Messages.get("doctor.remoteSkipped")));
            return report(results, out);
        }
        CryptoService.KeyCheck check = crypto.checkKey();
        if (!check.available()) {
            results.add(Diagnostic.fail(check.failure(), Messages.get("doctor.action.key")));
            return report(results, out);
        }
        results.add(Diagnostic.pass(Messages.get("doctor.keyOk", check.fingerprint())));
        if (check.publicDefaultKey()) {
            results.add(Diagnostic.warn(Messages.get("doctor.publicKey"), Messages.get("doctor.action.publicKey")));
        } else if ("embedded".equals(settings.keySource())) {
            results.add(Diagnostic.info(Messages.get("doctor.embeddedKey")));
        }
        results.add(selfTest(crypto));
        return report(results, out);
    }

    /** 실제 키로 임의 값을 암복호화하고, 변조한 암호문이 거부되는지 확인한다(값·키는 출력하지 않음). */
    private static Diagnostic selfTest(CryptoService crypto) {
        byte[] probe = new byte[32];
        new SecureRandom().nextBytes(probe);
        byte[] back = null;
        try {
            String token = crypto.encryptBytes(probe);
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
            return Diagnostic.fail(e.getMessage(), Messages.get("doctor.action.provider"));
        } finally {
            Arrays.fill(probe, (byte) 0);
            if (back != null) Arrays.fill(back, (byte) 0);
        }
    }

    /** 결과를 출력하고 종료 코드를 돌려준다(FAIL이 있으면 1). */
    private static int report(List<Diagnostic> results, PrintStream out) {
        int pass = 0;
        int warn = 0;
        int fail = 0;
        int skip = 0;
        for (Diagnostic result : results) {
            out.println("[" + result.status + "] " + result.message);
            if (result.action != null) out.println("       " + Messages.get("doctor.actionLabel", result.action));
            switch (result.status) {
                case PASS: pass++; break;
                case WARN: warn++; break;
                case FAIL: fail++; break;
                case SKIP: skip++; break;
                default: break;
            }
        }
        out.println();
        out.println(Messages.get("doctor.summary", pass, warn, fail, skip));
        out.println(Messages.get("doctor.note"));
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
