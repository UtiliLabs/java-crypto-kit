package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.KeyResolver;
import java.io.Console;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/**
 * java-crypto-kit의 명령행 도구(CLI)다. WAS와 무관하게 JAR 하나로 실행하며({@code java -jar}의 Main-Class), 내부적으로 공통 서비스
 * {@link CryptoService}를 사용하므로 Tomcat 어댑터·공개 API와 같은 설정 규칙·암호 엔진으로 동작한다.
 *
 * <p>사용법: {@code java [-D설정=값 ...] -jar java-crypto-kit-<버전>.jar <명령> [옵션] [--lang en|ko]}. 명령·옵션 정의는
 * {@link CliCommands}, 도움말은 {@link CliHelp}(영어·한국어)에 있다.</p>
 *
 * <p><b>메시지 언어</b>: {@code --lang en|ko}를 주면 이번 실행에만 그 언어를 쓴다. 없으면 설정 {@code crypto.lang}
 * (JVM {@code -D} &gt; 외부 Properties &gt; JAR 내부 값, 기본 ko, auto = JVM Locale)을 따른다. 그래서 {@code config set crypto.lang=ko}로
 * 한 번 바꾼 JAR는 매번 {@code --lang}을 쓰지 않아도 그 언어로 동작한다. 설정을 읽지 못해도(잘못된 외부 설정) 도움말은 동작한다.</p>
 *
 * <p><b>출력 규칙</b>: 결과(암호문·보고서·도움말)는 표준 출력, 오류는 표준 오류에 쓴다. 오류는
 * {@code [java-crypto-kit] [사유: 코드] 원인 조치: ...} 한 줄이며 코드는 언어와 관계없이 같다. 종료 코드는 성공 0, 실패 1이다.</p>
 *
 * <p><b>보안 설계</b></p>
 * <ul>
 *   <li>평문 비밀번호와 키는 명령행 인자로 받지 않는다(프로세스 목록·셸 기록 노출 방지).</li>
 *   <li>콘솔 입력이 필요한 명령은 대화형 터미널에서만 동작한다. 파이프·리다이렉트·IDE Debug Console에서는 거부한다.</li>
 *   <li>실패하면 정제된 사유 문구(또는 예외 종류)만 출력한다. JDK 예외 메시지는 경로·입력값이 섞일 수 있어 출력하지 않는다.</li>
 *   <li>{@code crypto.warning.enabled=false}는 안내 WARNING만 끄며 {@code decrypt}의 경고·확인 절차는 끄지 않는다.</li>
 * </ul>
 */
public final class CryptoCli {
    /** decrypt가 평문을 보여 주기 전에 사용자가 직접 입력해야 하는 확인 문구(번역하지 않음). */
    private static final String DECRYPT_CONFIRM_WORD = "SHOW";

    /** 대화형 터미널 입출력. 실제 실행은 {@link System#console()}, 테스트는 가짜 구현을 쓴다. */
    interface Terminal {
        /** 화면에 표시하지 않고 한 줄을 읽는다. */
        char[] readSecret(String prompt);

        /** 화면에 표시하며 한 줄을 읽는다. */
        String readLine(String prompt);

        /** 터미널에 직접 한 줄을 쓴다(표준 오류가 따로 돌려져 있어도 사용자가 보게 하기 위함). */
        void println(String message);
    }

    /** 대화형 터미널 공급자. 대화형 터미널이 아니면 {@link CliException}을 던진다. */
    interface TerminalProvider {
        /** @return 대화형 터미널 */
        Terminal open() throws CliException;
    }

    /** CLI가 직접 만든 고정 문구 오류(사용법 오류, 대화형 터미널 아님 등). 메시지를 그대로 출력해도 안전하다. */
    static final class CliException extends Exception {
        private static final long serialVersionUID = 1L;
        /** 고정 영문 사유 코드: USAGE(명령 사용 방법 문제) 또는 IO_ERROR(파일 입출력 문제). */
        final String code;

        CliException(String fixedMessage) {
            this("USAGE", fixedMessage);
        }

        CliException(String code, String fixedMessage) {
            super(fixedMessage);
            this.code = code;
        }
    }

    /** 실행 진입점만 제공하는 클래스이므로 인스턴스 생성을 막는다. */
    private CryptoCli() { }

    /**
     * JAR 직접 실행 진입점. 실패하면 종료 코드 1로 끝낸다.
     *
     * @param args 명령과 옵션
     */
    public static void main(String[] args) {
        useOneLineLibraryLog(System.err);
        int exitCode = execute(args, CryptoCli::systemTerminal, System.out, System.err, true);
        if (exitCode != 0) System.exit(exitCode);
    }

    /** CLI 프로세스에서 이 라이브러리의 로거를 붙잡아 둔다(JUL 로거는 약한 참조라 붙잡지 않으면 설정이 사라질 수 있다). */
    private static final java.util.logging.Logger LIBRARY_LOG = java.util.logging.Logger.getLogger("io.javacryptokit");

    /**
     * CLI로 실행할 때만({@link #main}): 이 라이브러리의 안내 로그(예: 내장 키 사용 안내)를 JDK 기본 형식(시각·클래스 이름이 붙은
     * 두 줄) 대신 메시지 한 줄로 표준 오류에 쓴다. 비개발자가 Java 오류로 오해하지 않게 하려는 것이다.
     * WAS(Tomcat)에서는 실행되지 않으며 루트 로거·다른 라이브러리 로거는 건드리지 않는다. 안내 정책(crypto.warning.enabled)과
     * 출력 횟수(종류별 JVM당 1회)도 그대로다.
     */
    static void useOneLineLibraryLog(PrintStream err) {
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            private final java.util.logging.SimpleFormatter text = new java.util.logging.SimpleFormatter();

            @Override
            public void publish(java.util.logging.LogRecord record) {
                if (!isLoggable(record)) return;
                err.println(text.formatMessage(record));
                err.flush();
            }

            @Override
            public void flush() {
                err.flush();
            }

            @Override
            public void close() {
                // 표준 오류는 닫지 않는다.
            }
        };
        handler.setLevel(java.util.logging.Level.INFO);
        LIBRARY_LOG.addHandler(handler);
        LIBRARY_LOG.setUseParentHandlers(false);
    }

    /**
     * 명령을 실행하고 종료 코드를 돌려준다(테스트용 진입점: 터미널과 출력 스트림을 바꿔 끼울 수 있다).
     *
     * @return 0: 성공, 1: 실패(사용법 오류, 설정·키·암호문 오류, info 키 확인 실패, doctor FAIL 포함)
     */
    static int execute(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err) {
        return execute(args, terminals, out, err, false);
    }

    private static int execute(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err, boolean console) {
        Messages.Language previous = Messages.processLanguage();
        try {
            String[] rest = applyLanguage(args, console, err);
            return run(rest, terminals, out, err);
        } catch (CliException ex) {
            // 명령 사용 방법 문제(인자·터미널·대상 파일). 메시지에 원인과 해결 방법이 함께 들어 있다.
            err.println(Messages.error(ex.code, ex.getMessage()));
            return 1;
        } catch (CredentialCryptoException ex) {
            // 사유 코드는 공개 API Reason 이름과 같고 원인·조치 문구도 공개 예외의 메시지 그대로다(Java API·Tomcat과 같은 의미).
            err.println(Messages.error(ex.getReason().name(), ex.getMessage()));
            return 1;
        } catch (Exception ex) {
            // JDK 예외 메시지에는 경로·입력값이 들어갈 수 있으므로 종류만 출력한다.
            err.println(Messages.error("IO_ERROR", Messages.get("cli.err.unexpected", ex.getClass().getSimpleName())));
            return 1;
        } finally {
            Messages.setProcessLanguage(previous);
        }
    }

    /**
     * {@code --lang}을 꺼내 이번 실행의 언어를 정하고, 나머지 인자를 돌려준다. {@code --lang}이 없으면 설정
     * ({@code crypto.lang})을 최대한 읽어 정한다(읽지 못하면 JAR 내부 값·Locale).
     */
    private static String[] applyLanguage(String[] args, boolean console, PrintStream err) throws CliException {
        List<String> rest = new ArrayList<>();
        String requested = null;
        boolean langGiven = false;
        String configPath = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (CliCommands.LANG_OPTION.equals(arg) || arg.startsWith(CliCommands.LANG_OPTION + "=")) {
                langGiven = true;
                if (arg.contains("=")) {
                    requested = arg.substring(arg.indexOf('=') + 1);
                } else {
                    requested = i + 1 < args.length ? args[++i] : null;
                }
                continue;
            }
            if ("--config".equals(arg) && i + 1 < args.length) configPath = args[i + 1];
            if (arg.startsWith("--config=")) configPath = arg.substring("--config=".length());
            rest.add(arg);
        }
        Messages.Language fromSettings = settingsLanguage(configPath);
        Messages.setProcessLanguage(fromSettings);
        Messages.Language chosen = fromSettings;
        if (langGiven) {
            chosen = requested == null ? null : Messages.Language.fromCode(requested);
            if (chosen == null) throw new CliException(Messages.get("cli.err.lang"));
        }
        if (console && chosen == Messages.Language.KO && !langGiven && !consoleCanShowKorean()) {
            // 콘솔 문자 인코딩이 한글을 표현할 수 없으면 영어로 바꾼다(언어 설정과 문자 인코딩은 별개이므로 알려 준다).
            err.println(Messages.get(Messages.Language.EN, "cli.note.encodingFallback", consoleCharsetName()));
            chosen = Messages.Language.EN;
        }
        Messages.setProcessLanguage(chosen);
        return rest.toArray(new String[0]);
    }

    /** 설정의 crypto.lang을 최대한 읽는다(키를 읽지 않고, 실패해도 예외를 던지지 않음). */
    private static Messages.Language settingsLanguage(String configPath) {
        try {
            return CryptoSettings.load(configPath).language();
        } catch (Exception | LinkageError e) {
            return CryptoSettings.bootstrapLanguage();
        }
    }

    /** @return 표준 출력 문자 인코딩 이름(Java 19+ stdout.encoding, Windows 콘솔 sun.stdout.encoding, 그 밖에는 기본 인코딩) */
    private static String consoleCharsetName() {
        String name = System.getProperty("stdout.encoding");
        if (name == null) name = System.getProperty("sun.stdout.encoding");
        return name != null ? name : Charset.defaultCharset().name();
    }

    /** @return 표준 출력 인코딩이 한글을 표현할 수 있으면 true */
    private static boolean consoleCanShowKorean() {
        try {
            return Charset.forName(consoleCharsetName()).newEncoder().canEncode("한글");
        } catch (RuntimeException e) {
            return true;
        }
    }

    /** 인자를 해석하고 명령별 처리를 수행한다. 모르는 명령·옵션은 설정을 읽기 전에 거부한다. */
    private static int run(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err) throws Exception {
        // 도움말은 설정·키 파일·외부 Properties·네트워크를 쓰지 않는다(잘못된 외부 설정이 있어도 동작).
        if (args.length == 0 || "help".equals(args[0]) || "--help".equals(args[0]) || "-h".equals(args[0])) {
            return CliHelp.help(Arrays.copyOfRange(args, Math.min(1, args.length), args.length), out);
        }
        String command = args[0];
        CliCommands.Spec spec;
        int start;
        if (CliCommands.GROUPS.contains(command)) {
            String sub = args.length > 1 ? args[1] : null;
            if ("config".equals(command) && (sub == null || "help".equals(sub) || "--help".equals(sub) || "-h".equals(sub))) {
                CliHelp.topic("config", out);
                return 0;
            }
            if (sub == null || "--help".equals(sub) || "-h".equals(sub) || "help".equals(sub)) {
                CliHelp.group(command, out);
                return 0;
            }
            spec = CliCommands.find(command + " " + sub);
            if (spec == null) throw new CliException(Messages.get("cli.err.unknownSub", command, subNames(command)));
            start = 2;
        } else {
            spec = CliCommands.find(command);
            if (spec == null) {
                String suggestion = command.matches("[a-z-]{1,30}")
                        ? CryptoSettings.suggest(command, CliCommands.topLevelNames()) : null;
                throw new CliException(Messages.get("cli.err.unknownCommand",
                        suggestion != null ? Messages.get("cli.hint.command", suggestion) : ""));
            }
            start = 1;
        }
        CliCommands.Parsed parsed = CliCommands.parse(spec, args, start);
        if (parsed.help) {
            CliHelp.topic(spec.topic, out);
            return 0;
        }
        switch (spec.name) {
            case "keygen":
                return keygen(parsed, out);
            case "config show":
            case "config history":
            case "config set":
            case "config embed-key":
                return ConfigCommand.run(parsed, terminals, out);
            case "file encrypt":
            case "file decrypt":
                return FileCommand.run(parsed, out);
            case "fingerprint":
                return KeyCommands.fingerprint(parsed, out);
            case "rekey":
                return KeyCommands.rekey(parsed, terminals, out, err);
            case "kms datakey":
                return KeyCommands.kmsDataKey(parsed, out);
            case "doctor":
                return DoctorCommand.run(parsed, out);
            default:
                break;
        }
        // 설정 로딩(WAS와 같은 규칙): --config가 없으면 JVM 속성 → 환경변수 순서로 외부 설정을 찾고, 없으면 JAR 내부 설정.
        CryptoService crypto = CryptoService.load(parsed.value("--config"));
        switch (spec.name) {
            case "info":
                return printInfo(crypto, out);
            case "encrypt":
                encrypt(crypto, terminals.open(), out);
                return 0;
            case "decrypt":
                decryptInteractively(crypto, terminals.open(), out);
                return 0;
            default: // verify
                verify(crypto, parsed.value("--value"), terminals, out);
                return 0;
        }
    }

    /** @return 그룹의 하위 명령 이름 목록(예: "show, history, set, embed-key") */
    static String subNames(String group) {
        List<String> names = new ArrayList<>();
        for (CliCommands.Spec spec : CliCommands.ALL) {
            if (spec.name.startsWith(group + " ")) names.add(spec.name.substring(group.length() + 1));
        }
        return String.join(", ", names);
    }

    /** keygen: 설정과 기존 키를 읽지 않는다. */
    private static int keygen(CliCommands.Parsed parsed, PrintStream out) throws IOException, CliException {
        String outputPath = parsed.value("--out");
        if (outputPath == null) throw new CliException(Messages.get("cli.err.keygenOut"));
        String fingerprint = generateKeyFile(Paths.get(outputPath));
        out.println(Messages.get("cli.keygen.done", fingerprint));
        // 처음 쓰는 운영자가 다음에 무엇을 할지 바로 알 수 있게 두 가지 사용 방법과 보관 주의를 함께 보여 준다.
        out.println(Messages.get("cli.keygen.next", JarConfigEditor.name(Paths.get(outputPath))));
        return 0;
    }

    /**
     * info 명령: 어떤 설정으로 동작하는지 비밀값 없이 보여 주고, 키를 실제로 읽어 확인한다. 경고 정책이 false여도 이 진단 출력은
     * 그대로다(자동 경고와 명시적 진단은 별개). {@code config show}(JAR 내부 값만)와 달리 최종 적용값과 출처를 보여 준다.
     *
     * @return 0: 키 확인 성공, 1: 키 확인 실패
     */
    private static int printInfo(CryptoService crypto, PrintStream out) {
        CryptoSettings settings = crypto.settings();
        out.println(Messages.get("cli.info.algorithm", settings.get(CryptoSettings.ALGORITHM),
                originOf(settings, CryptoSettings.ALGORITHM)));
        out.println(Messages.get("cli.info.keyId", settings.keyId(), originOf(settings, CryptoSettings.KEY_ID)));
        out.println(Messages.get("cli.info.keySource", settings.keySource(), describeSourceOrigin(settings)));
        out.println(Messages.get("cli.info.keyLocation", crypto.describeKeyLocation(), keyLocationOrigin(settings)));
        out.println(settings.externalConfigUsed()
                ? Messages.get("cli.info.external.used", settings.configOrigin().description(), settings.configFileName())
                : Messages.get("cli.info.external.none", settings.configOrigin().description()));
        out.println(Messages.get("cli.info.jvm", describeJvmOverrides(settings)));
        out.println(Messages.get("cli.info.warning", Messages.get(settings.warningEnabled() ? "cli.info.warning.on"
                : "cli.info.warning.off"), originOf(settings, CryptoSettings.WARNING_ENABLED)));
        out.println(Messages.get("cli.info.output", settings.outputFormat().settingValue(),
                originOf(settings, CryptoSettings.OUTPUT_ENCODING)));
        out.println(Messages.get("cli.info.lang", settings.get(CryptoSettings.LANG).isEmpty() ? SettingCatalog.DEFAULT_LANGUAGE
                : settings.get(CryptoSettings.LANG), settings.language().code(), originOf(settings, CryptoSettings.LANG)));
        out.println(Messages.get("cli.info.pool", settings.poolFactory(), originOf(settings, CryptoSettings.POOL_FACTORY)));
        out.println(Messages.get("cli.info.history", ConfigHistory.describeRunningJar()));
        CryptoService.KeyCheck check = crypto.checkKey();
        if (!check.available()) {
            out.println(Messages.get("cli.info.keyFail", check.failure()));
            return 1;
        }
        out.println(Messages.get("cli.info.keyOk", check.fingerprint())
                + (check.publicDefaultKey() ? Messages.get("cli.info.publicKey") : ""));
        return 0;
    }

    /** 키 공급 방식이 어디서 정해졌는지 설명한다. */
    private static String describeSourceOrigin(CryptoSettings settings) {
        switch (settings.valueOrigin(CryptoSettings.KEY_SOURCE)) {
            case JVM_PROPERTY:
                return Messages.get("cli.info.source.jvm", CryptoSettings.KEY_SOURCE);
            case EXTERNAL_FILE:
                return Messages.get("cli.info.source.external");
            default:
                // 외부 설정이나 JVM 속성으로 다른 항목만 바꾼 경우: 의도치 않게 JAR 내부 키를 쓰는지 운영자가 알아보게 한다.
                if (settings.externalConfigUsed() || !settings.jvmOverriddenKeys().isEmpty()) {
                    return Messages.get("cli.info.source.inherited");
                }
                return Messages.get("cli.info.source.jar");
        }
    }

    /** 최종값의 출처를 " [출처: ...]" 형태로 만든다. 값은 다시 출력하지 않는다. */
    private static String originOf(CryptoSettings settings, String key) {
        return Messages.get("cli.info.origin", settings.valueOrigin(key).description());
    }

    /** 키 위치 설정의 출처(embedded는 위치 설정을 쓰지 않으므로 표시하지 않는다). */
    private static String keyLocationOrigin(CryptoSettings settings) {
        if ("file".equals(settings.keySource())) return originOf(settings, CryptoSettings.KEY_FILE);
        if ("env".equals(settings.keySource())) return originOf(settings, CryptoSettings.KEY_ENV);
        if ("vault".equals(settings.keySource())) return originOf(settings, CryptoSettings.VAULT_PATH);
        if ("aws-kms".equals(settings.keySource())) return originOf(settings, CryptoSettings.AWS_KMS_DATA_KEY_FILE);
        return "";
    }

    /** JVM 개별 속성 정책과 적용 결과를 이름만으로 설명한다(값 미출력). */
    private static String describeJvmOverrides(CryptoSettings settings) {
        StringBuilder text = new StringBuilder(Messages.get(settings.jvmOverrideEnabled() ? "cli.info.jvm.on" : "cli.info.jvm.off"));
        text.append(Messages.get("cli.info.jvm.applied", settings.jvmOverriddenKeys().isEmpty()
                ? Messages.get("cli.info.none") : String.join(", ", settings.jvmOverriddenKeys())));
        if (!settings.ignoredJvmKeys().isEmpty()) {
            text.append(Messages.get("cli.info.jvm.ignored", String.join(", ", settings.ignoredJvmKeys())));
        }
        return text.append(originOf(settings, CryptoSettings.JVM_OVERRIDE_ENABLED)).toString();
    }

    /** encrypt 명령: 가려진 입력으로 받은 값을 암호화해 토큰만 출력한다(표준 출력에는 토큰 한 줄만). */
    private static void encrypt(CryptoService crypto, Terminal terminal, PrintStream out)
            throws CredentialCryptoException, CliException {
        char[] plain = terminal.readSecret(Messages.get("cli.encrypt.prompt") + " ");
        if (plain == null || plain.length == 0) throw new CliException(Messages.get("cli.err.noInput"));
        try {
            out.println(crypto.encryptText(plain));
        } finally {
            Arrays.fill(plain, '\0');
        }
        // 다음 행동 안내는 터미널 화면에만 쓴다(표준 출력은 암호문 한 줄 그대로라 스크립트·리다이렉트 사용에 영향 없음).
        terminal.println(Messages.get("cli.encrypt.next"));
    }

    /**
     * decrypt 명령: 평문을 내보내는 유일한 경로이므로 오용 방지 절차를 거친다(대화형 터미널 필수, 경고 후 {@code SHOW} 입력,
     * 암호문은 화면에 표시하지 않고 입력, 인증 태그 검증에 성공한 경우에만 평문 출력).
     */
    private static void decryptInteractively(CryptoService crypto, Terminal terminal, PrintStream out)
            throws CredentialCryptoException, CliException {
        terminal.println(Messages.get("cli.decrypt.warn1"));
        terminal.println(Messages.get("cli.decrypt.warn2"));
        String answer = terminal.readLine(Messages.get("cli.decrypt.confirm", DECRYPT_CONFIRM_WORD) + " ");
        if (answer == null || !DECRYPT_CONFIRM_WORD.equals(answer.trim())) {
            terminal.println(Messages.get("cli.decrypt.cancel"));
            return;
        }
        char[] input = terminal.readSecret(Messages.get("cli.decrypt.prompt") + " ");
        if (input == null || input.length == 0) throw new CliException(Messages.get("cli.err.noInput"));
        try {
            // 키·인증 태그 검증에 실패하면 예외로 끝나므로 평문은 출력되지 않는다. 평문은 메시지 자리표시자에 넣지 않는다.
            String decrypted = crypto.decryptText(new String(input));
            out.println(Messages.get("cli.decrypt.resultLabel") + " " + decrypted);
            terminal.println(Messages.get("cli.decrypt.cleanup"));
        } finally {
            Arrays.fill(input, '\0');
        }
    }

    /**
     * verify 명령: 복호화가 되는지만 확인하고 평문은 출력하지 않는다. {@code --value}가 없으면 콘솔에서 가려 입력받는다.
     */
    private static void verify(CryptoService crypto, String value, TerminalProvider terminals, PrintStream out)
            throws CredentialCryptoException, CliException {
        String token = value == null ? readHidden(terminals, Messages.get("cli.verify.prompt") + " ") : value;
        byte[] plain = crypto.decryptBytes(token);
        Arrays.fill(plain, (byte) 0);
        out.println(Messages.get("cli.verify.ok"));
    }

    /** 대화형 터미널에서 화면에 표시하지 않고 한 줄을 받는다. */
    static String readHidden(TerminalProvider terminals, String prompt) throws CliException {
        char[] input = terminals.open().readSecret(prompt);
        if (input == null || input.length == 0) throw new CliException(Messages.get("cli.err.noInput"));
        try {
            return new String(input);
        } finally {
            Arrays.fill(input, '\0');
        }
    }

    /**
     * 새 AES-256 키(32바이트 보안 난수)를 표준 Base64 한 줄로 파일에 저장한다. 기존 파일을 덮어쓰지 않고, POSIX에서는 600으로
     * 만들며, 키를 String으로 만들지 않는다. 기록 중 오류가 나면 만들다 만 파일을 지운다.
     *
     * @param destination 만들 키 파일 경로(이미 있으면 실패)
     * @return 새 키의 지문(비밀 아님)
     * @throws CliException 상위 디렉터리가 없거나 파일이 이미 있는 경우
     * @throws IOException  권한 부족 등으로 파일을 만들거나 기록하지 못한 경우
     */
    static String generateKeyFile(Path destination) throws IOException, CliException {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        byte[] encoded = Base64.getEncoder().encode(key);
        try {
            createSecretFile(destination, "cli.err.keygenDir", "cli.err.keygenExists");
            try (OutputStream output = Files.newOutputStream(destination, StandardOpenOption.WRITE)) {
                output.write(encoded);
                output.write('\n');
            } catch (IOException ex) {
                Files.deleteIfExists(destination);
                throw ex;
            }
            return KeyResolver.fingerprint(key);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * 새 파일만 만든다(이미 있으면 덮어쓰지 않음). POSIX는 생성과 동시에 600, Windows는 상위 폴더 ACL을 상속한다.
     *
     * @param destination 경로
     * @param noDirKey    상위 폴더가 없을 때 메시지 키
     * @param existsKey   파일이 있을 때 메시지 키
     */
    static void createSecretFile(Path destination, String noDirKey, String existsKey) throws IOException, CliException {
        Path parent = destination.toAbsolutePath().getParent();
        if (parent == null || !Files.isDirectory(parent)) throw new CliException(Messages.get(noDirKey));
        try {
            try {
                Set<PosixFilePermission> mode = PosixFilePermissions.fromString("rw-------");
                Files.createFile(destination, PosixFilePermissions.asFileAttribute(mode));
            } catch (UnsupportedOperationException ex) {
                Files.createFile(destination);
            }
        } catch (java.nio.file.FileAlreadyExistsException ex) {
            // 경로는 출력하지 않는다. 기존 키를 잃으면 그 키의 암호문을 복구할 수 없으므로 절대 덮어쓰지 않는다.
            throw new CliException(Messages.get(existsKey));
        }
    }

    /**
     * 실제 실행용 터미널: 표준 입출력이 모두 터미널에 연결된 경우에만 {@link System#console()}을 돌려준다.
     *
     * @throws CliException 대화형 터미널이 아닌 경우(예: IDE Debug Console, 파이프, 리다이렉트)
     */
    private static Terminal systemTerminal() throws CliException {
        final Console console = System.console();
        if (console == null || !isInteractiveTerminal(console)) {
            throw new CliException(Messages.get("cli.err.noTerminal"));
        }
        return new Terminal() {
            @Override
            public char[] readSecret(String prompt) {
                return console.readPassword("%s", prompt);
            }

            @Override
            public String readLine(String prompt) {
                return console.readLine("%s", prompt);
            }

            @Override
            public void println(String message) {
                console.printf("%s%n", message);
                console.flush();
            }
        };
    }

    /**
     * Java 22 이상의 {@code Console.isTerminal()}을 리플렉션으로 호출해 실제 터미널인지 확인한다. 메서드가 없는 Java 8~21에서는
     * {@code System.console()}이 null이 아니라는 사실 자체가 터미널 연결을 뜻하므로 true, 호출에 실패하면 false(거부).
     */
    private static boolean isInteractiveTerminal(Console console) {
        Method isTerminal;
        try {
            isTerminal = Console.class.getMethod("isTerminal");
        } catch (NoSuchMethodException ex) {
            return true;
        }
        try {
            return Boolean.TRUE.equals(isTerminal.invoke(console));
        } catch (ReflectiveOperationException | RuntimeException ex) {
            return false;
        }
    }
}
