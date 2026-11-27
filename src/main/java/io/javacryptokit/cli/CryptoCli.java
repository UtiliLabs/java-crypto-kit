package io.javacryptokit.cli;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
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
 * <p><b>출력 규칙</b>: 한 명령 = 입력(필요할 때) → 결과. 결과(암호문·평문·보고서·도움말)는 표준 출력, 오류는 표준 오류에 쓴다.
 * 정상 실행에는 안내·권고·다음 단계 문구를 붙이지 않는다(운영·보안 참고는 사용자 가이드). 오류는
 * {@code [java-crypto-kit] [사유: 코드] 원인 조치: ...} 한 줄이며 코드는 언어와 관계없이 같다. 종료 코드는 성공 0, 실패 1이다.</p>
 *
 * <p><b>키 유형</b>: 관리형 암복호화는 PASS (Passphrase)와 KEY (AES Key)를 지원한다. 이전 공개 키는 로딩 시 거부한다.
 * {@code info}·{@code doctor}·{@code fingerprint}는 키 상태 또는 실패 원인을 출력한다.</p>
 *
 * <p><b>CLI 관리자 비밀번호</b>: 관리자 비밀번호의 최초 설정({@code admin setup})과 공개 조회는 미설정 JAR에서 가능하며,
 * 복호화·키 생성/등록/변경/삭제·키 조회 같은 민감 명령은 실행할 때마다 관리자 비밀번호를 확인한다({@link AdminAccess}). CLI에만
 * 적용되며 Java API·Tomcat은 비밀번호 없이 그대로 동작한다. JAR 자체의 키 추출을 막는 수단은 아니다.</p>
 *
 * <p><b>보안 설계</b></p>
 * <ul>
 *   <li>평문 비밀번호와 키는 명령행 인자로 받지 않는다(프로세스 목록·셸 기록 노출 방지).</li>
 *   <li>콘솔 입력이 필요한 명령은 대화형 터미널에서만 동작하고 입력을 화면에 표시하지 않는다. 파이프·리다이렉트·IDE Debug
 *       Console에서는 거부한다.</li>
 *   <li>{@code decrypt}는 관리자 인증 뒤 인증 태그 검증에 성공한 경우에만 평문을 출력한다. 키 원문은 평소에 출력하지 않고(키
 *       지문만), 예외는 두 가지다: 자동 생성 직후 대화형 터미널에 한 번 보여 주는 생성값, 관리자 인증 뒤 {@code config key show
 *       --show}(노출 경고 후 SHOW 확인, 대화형 터미널만)·{@code --export}(새 파일)로 명시적으로 요청한 키 원문.</li>
 *   <li>실패하면 정제된 사유 문구(또는 예외 종류)만 출력한다. JDK 예외 메시지는 경로·입력값이 섞일 수 있어 출력하지 않는다.</li>
 * </ul>
 */
public final class CryptoCli {
    /** 대화형 터미널 입출력. 실제 실행은 {@link System#console()}, 테스트는 가짜 구현을 쓴다. */
    interface Terminal {
        /** 화면에 표시하지 않고 한 줄을 읽는다. */
        char[] readSecret(String prompt);

        /** 화면에 표시하며 한 줄을 읽는다. */
        String readLine(String prompt);

        /** 터미널에 직접 한 줄을 쓴다(표준 오류가 따로 돌려져 있어도 사용자가 보게 하기 위함). */
        void println(String message);

        /**
         * 자동 생성한 비밀값 한 줄을 대화형 터미널에만 쓴다(표준 출력·표준 오류·로그로 보내지 않는 별도 경로). 라벨·공백 없이
         * 값만 한 줄로 쓰므로 그 줄을 그대로 복사하면 된다.
         */
        default void printSecret(char[] secret) {
            println(new String(secret));
        }
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
        int exitCode = execute(args, CryptoCli::systemTerminal, System.out, System.err, true, AdminAccess.forRunningJar());
        Console console = System.console();
        if (console != null && isInteractiveTerminal(console)) console.printf("%n");
        if (exitCode != 0) System.exit(exitCode);
    }

    /** CLI 프로세스에서 이 라이브러리의 로거를 붙잡아 둔다(JUL 로거는 약한 참조라 붙잡지 않으면 설정이 사라질 수 있다). */
    private static final java.util.logging.Logger LIBRARY_LOG = java.util.logging.Logger.getLogger("io.javacryptokit");
    /** {@link #useOneLineLibraryLog}가 붙인 처리기(여러 번 호출해도 하나만 남긴다). */
    private static java.util.logging.Handler oneLineHandler;

    /**
     * CLI로 실행할 때만({@link #main}): 이 라이브러리의 경고 로그를 JDK 기본 형식(시각·클래스 이름이 붙은 두 줄) 대신
     * 한 줄로 표준 오류에 쓴다. 경고는 WAS 로그용 태그를 떼고 {@code [WARN] <문구>}로 쓴다(표준 출력의 암호문·평문과 섞이지 않음).
     * WAS(Tomcat)에서는 실행되지 않으며 루트 로거·다른 라이브러리 로거는 건드리지 않는다. 경고 정책(crypto.warning.enabled)과
     * 출력 횟수(JVM당 1회)도 그대로다.
     */
    static synchronized void useOneLineLibraryLog(PrintStream err) {
        java.util.logging.Handler handler = new java.util.logging.Handler() {
            private final java.util.logging.SimpleFormatter text = new java.util.logging.SimpleFormatter();

            @Override
            public void publish(java.util.logging.LogRecord record) {
                if (!isLoggable(record)) return;
                String message = text.formatMessage(record);
                if (message.startsWith(Messages.TAG + " ")) message = message.substring(Messages.TAG.length() + 1);
                boolean warning = record.getLevel().intValue() >= java.util.logging.Level.WARNING.intValue();
                err.println(warning ? "[WARN] " + message : message);
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
        if (oneLineHandler != null) LIBRARY_LOG.removeHandler(oneLineHandler);
        oneLineHandler = handler;
        LIBRARY_LOG.addHandler(handler);
        LIBRARY_LOG.setUseParentHandlers(false);
    }

    /**
     * 명령을 실행하고 종료 코드를 돌려준다(테스트용 진입점: 터미널과 출력 스트림을 바꿔 끼울 수 있다).
     *
     * @return 0: 성공, 1: 실패(사용법 오류, 설정·키·암호문 오류, info 키 확인 실패, doctor FAIL 포함)
     */
    static int execute(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err) {
        return execute(args, terminals, out, err, false, AdminAccess.forRunningJar());
    }

    /**
     * {@link #execute(String[], TerminalProvider, PrintStream, PrintStream)}와 같고 관리자 비밀번호 확인 창구를 정한다(시험용: 시험용
     * JAR를 CLI JAR로 쓰거나 명령별 동작만 확인할 때).
     */
    static int execute(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err, AdminGate admin) {
        return execute(args, terminals, out, err, false, admin);
    }

    private static int execute(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err, boolean console,
                               AdminGate admin) {
        Messages.Language previous = Messages.processLanguage();
        try {
            String[] rest = applyLanguage(args, console, err);
            return run(rest, terminals, out, err, admin);
        } catch (CliException ex) {
            // 명령 사용 방법 문제(인자·터미널·대상 파일). 메시지에 원인과 해결 방법이 함께 들어 있다.
            err.println(Messages.error(ex.code, withCleanupMessage(ex)));
            return 1;
        } catch (CredentialCryptoException ex) {
            // 사유 코드는 공개 API Reason 이름과 같고 원인·조치 문구도 공개 예외의 메시지 그대로다(Java API·Tomcat과 같은 의미).
            err.println(errorLine(ex));
            return 1;
        } catch (Exception ex) {
            // JDK 예외 메시지에는 경로·입력값이 들어갈 수 있으므로 종류만 출력한다.
            err.println(Messages.error("IO_ERROR", Messages.get("cli.err.unexpected", ex.getClass().getSimpleName())));
            return 1;
        } finally {
            admin.close();
            Messages.setProcessLanguage(previous);
        }
    }

    private static String withCleanupMessage(Exception failure) {
        StringBuilder message = new StringBuilder(failure.getMessage());
        for (Throwable additional : failure.getSuppressed()) {
            if (additional instanceof CliException) message.append(' ').append(additional.getMessage());
        }
        return message.toString();
    }

    /** 정리 오류가 겹쳐도 사유 코드와 첫 번째 메시지는 최초 오류의 것이다. */
    static String errorLine(CredentialCryptoException failure) {
        StringBuilder message = new StringBuilder(failure.getMessage());
        for (Throwable additional : failure.getSuppressed()) {
            // 내부 close 예외에는 경로가 들어갈 수 있다. 정제된 제품 예외만 표시한다.
            if (additional instanceof CredentialCryptoException) message.append(' ').append(additional.getMessage());
        }
        return Messages.error(failure.getReason().name(), message.toString());
    }

    /**
     * {@code --lang}을 꺼내 이번 실행의 언어를 정하고, 나머지 인자를 돌려준다. {@code --lang}이 없으면 설정
     * ({@code crypto.lang})을 최대한 읽어 정한다(읽지 못하면 JAR 내부 값·Locale).
     */
    private static String[] applyLanguage(String[] args, boolean console, PrintStream err) throws CliException {
        List<String> rest = new ArrayList<>();
        String requested = null;
        boolean langGiven = false;
        boolean duplicateLang = false;
        String configPath = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (CliCommands.LANG_OPTION.equals(arg) || arg.startsWith(CliCommands.LANG_OPTION + "=")) {
                duplicateLang |= langGiven;
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
        Messages.Language fromSettings = rest.isEmpty() || CliHelp.isQuery(rest) || "api".equals(rest.get(0))
                ? CryptoSettings.bootstrapLanguage() : settingsLanguage(configPath);
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
        if (duplicateLang && !rest.isEmpty() && "api".equals(rest.get(0))) {
            throw new CliException(Messages.get("cli.err.duplicate", "--lang", "api"));
        }
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

    /** Route public queries before execution setup and administrator authentication. */
    private static int run(String[] args, TerminalProvider terminals, PrintStream out, PrintStream err, AdminGate admin)
            throws Exception {
        if (args.length == 0) return AdminCommand.startScreen(admin, out);
        if (CliHelp.isQuery(Arrays.asList(args))) return CliHelp.query(args, out, admin.cliJar());
        String command = args[0];
        CliCommands.Spec spec;
        int start;
        if ("api".equals(command)) {
            int options = 1;
            while (options < args.length && !args[options].startsWith("-")) options++;
            String path = String.join(" ", Arrays.copyOfRange(args, 0, options));
            spec = CliCommands.find(path);
            if (spec == null) throw ApiInput.problem("api.err.command");
            start = options;
        } else if (CliCommands.GROUPS.contains(command)) {
            String sub = args.length > 1 ? args[1] : null;
            start = 2;
            String nestedTopic = CliCommands.NESTED_GROUPS.get(command + " " + sub);
            if (nestedTopic != null && args.length > 2) {
                String third = args[2];
                sub = sub + " " + third;
                start = 3;
            }
            spec = CliCommands.find(command + " " + sub);
            if (spec == null) {
                String group = start == 3 ? command + " " + args[1] : command;
                throw new CliException(Messages.get("cli.err.unknownSub", group, subNames(group)));
            }
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
        parsed.admin = admin;
        Integer entered = AdminCommand.enter(spec, terminals, out, err, admin);
        if (entered != null) return entered;
        if (spec.name.startsWith("api ")) ApiInput.precheck(parsed);
        if (spec.access == CliCommands.Access.ADMIN) {
            // 민감 명령: 입력·비밀 자료 없이 하는 사전 검사 → 관리자 인증(여기 한 곳) → 본 처리. 대상 JAR의 키·설정·이력은 인증 뒤에만 읽는다.
            precheck(spec, parsed, terminals);
            authenticate(parsed, terminals, admin);
        }
        int code;
        if (spec.name.startsWith("api ")) {
            try {
                code = ApiCommands.run(parsed, terminals, out, err);
            } catch (io.javacryptokit.jwt.JwtException e) {
                throw new CliException(e.getReason().name(), Messages.get("api.err.jwt." + e.getReason().name()));
            } catch (io.javacryptokit.oauth.OAuthClientException e) {
                String status = e.getStatusCode() < 0 ? "-" : Integer.toString(e.getStatusCode());
                throw new CliException(e.getReason().name(), Messages.get("api.err.oauth." + e.getReason().name(), status,
                        e.getOAuthError() == null ? "-" : e.getOAuthError()));
            } catch (IllegalArgumentException e) {
                throw new CliException("INVALID_INPUT", Messages.get("api.err.commandInput", spec.name));
            }
        } else {
            code = dispatch(spec, parsed, terminals, out, err);
        }
        // 방어적 단언: 민감 명령의 본 처리는 위 인증 뒤에만 실행된다(정책·흐름을 잘못 바꾸면 시험이 이 예외로 잡는다).
        if (code == 0 && CliCommands.needsAdmin(spec) && !admin.authenticated()) {
            throw new IllegalStateException("admin authentication missing");
        }
        return code;
    }

    /**
     * 민감 명령의 사전 검사: 인자·경로·대화형 여부처럼 입력이나 비밀 자료 없이 판단할 수 있는 것만 본다(대상 JAR의 키·설정·이력,
     * 키 파일·암호문 내용은 읽지 않음). 문제가 있으면 관리자 비밀번호를 묻기 전에 끝난다.
     */
    private static void precheck(CliCommands.Spec spec, CliCommands.Parsed parsed, TerminalProvider terminals) throws Exception {
        switch (spec.name) {
            case "decrypt":
                terminals.open(); // 암호문은 대화형 터미널에서만 숨김 입력으로 받는다
                return;
            case "keygen":
                checkKeygen(parsed);
                return;
            case "file decrypt":
                FileCommand.check(parsed);
                return;
            case "rekey":
                KeyCommands.checkRekey(parsed);
                return;
            case "kms datakey":
                KeyCommands.checkKmsDataKey(parsed);
                return;
            case "config history":
                ConfigCommand.checkHistory(parsed);
                return;
            case "config set":
                ConfigCommand.checkSet(parsed);
                return;
            case "config embed-key":
                ConfigCommand.checkEmbedKey(parsed);
                return;
            case "config key add":
                KeyringCommand.checkAdd(parsed, terminals);
                return;
            case "config key use":
            case "config key remove":
                KeyringCommand.checkUseOrRemove(parsed);
                return;
            case "config key show":
                KeyShowCommand.check(parsed, terminals);
                return;
            case "admin password change":
                AdminCommand.checkChange(parsed, terminals);
                return;
            default: // config show: 확인할 인자 없음
        }
    }

    /**
     * 민감 명령의 관리자 인증(본 처리 전 한 곳): 실행 중인 CLI JAR, 그리고 조회·변경 대상 {@code --jar}와 키를 꺼내 쓰는
     * {@code --from-jar}는 그 JAR의 관리자 비밀번호로 확인한다(같은 비밀번호면 한 번). 새 암호문에 키만 쓰는 {@code --to-jar}는
     * 비밀번호를 묻지 않고 무결성(손상 여부)만 확인한다.
     */
    private static void authenticate(CliCommands.Parsed parsed, TerminalProvider terminals, AdminGate admin) throws CliException {
        admin.authenticate(parsed, terminals, jarOption(parsed, "--jar"), jarOption(parsed, "--from-jar"));
        Path to = jarOption(parsed, "--to-jar");
        if (to != null) admin.checkIntact(to);
    }

    /** @return 옵션으로 준 JAR 경로(없으면 null) */
    private static Path jarOption(CliCommands.Parsed parsed, String option) throws CliException {
        String value = parsed.value(option);
        if (value == null) return null;
        try {
            return Paths.get(value);
        } catch (java.nio.file.InvalidPathException e) {
            throw new CliException(Messages.get("cli.err.path", option));
        }
    }

    /** 명령별 처리(관리자 상태 확인을 마친 뒤). */
    private static int dispatch(CliCommands.Spec spec, CliCommands.Parsed parsed, TerminalProvider terminals, PrintStream out,
                                PrintStream err) throws Exception {
        // 키 상태를 화면에 직접 보여 주는 명시적 조회(fingerprint·doctor·info)는 같은 사실을 자동 경고로 한 번 더 알리지 않는다.
        switch (spec.name) {
            case "keygen":
                return keygen(parsed, terminals, out);
            case "admin setup":
            case "admin password change":
                return AdminCommand.run(parsed, terminals, out, parsed.admin);
            case "config show":
            case "config history":
            case "config set":
            case "config embed-key":
            case "config key add":
            case "config key use":
            case "config key remove":
            case "config key show":
                return ConfigCommand.run(parsed, terminals, out);
            case "file encrypt":
            case "file decrypt":
                return FileCommand.run(parsed, out);
            case "fingerprint":
                try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
                    return KeyCommands.fingerprint(parsed, out);
                }
            case "rekey":
                return KeyCommands.rekey(parsed, terminals, out);
            case "kms datakey":
                return KeyCommands.kmsDataKey(parsed, terminals, out);
            case "doctor":
                try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
                    return DoctorCommand.run(parsed, out);
                }
            default:
                break;
        }
        // 설정 로딩(WAS와 같은 규칙): --config가 없으면 JVM 속성 → 환경변수 순서로 외부 설정을 찾고, 없으면 JAR 내부 설정.
        CryptoService crypto = CryptoService.load(parsed.value("--config"));
        switch (spec.name) {
            case "info":
                try (DefaultKeyWarning.Quiet ignored = DefaultKeyWarning.quiet()) {
                    return printInfo(crypto, out, err);
                }
            case "encrypt":
                encrypt(crypto, typeOption(parsed), keyIdOption(parsed), terminals, out);
                return 0;
            case "decrypt":
                // 대화형 터미널 확인(사전 검사) → 관리자 인증 → 설정 로딩·암호문 입력 순서(인증 전에는 설정·키·암호문을 다루지 않음).
                decryptInteractively(crypto, terminals.open(), out);
                return 0;
            default: // verify
                verify(crypto, parsed.value("--value"), terminals, out);
                return 0;
        }
    }

    /** @return 그룹의 하위 명령 이름 목록(예: "show, history, set, embed-key, key"). 한 단계 아래 이름만 한 번씩 쓴다. */
    static String subNames(String group) {
        List<String> names = new ArrayList<>();
        for (CliCommands.Spec spec : CliCommands.ALL) {
            if (!spec.name.startsWith(group + " ")) continue;
            String next = spec.name.substring(group.length() + 1).split(" ")[0];
            if (!names.contains(next)) names.add(next);
        }
        return String.join(", ", names);
    }

    /**
     * {@code --type pass|key}를 읽는다.
     *
     * @return 유형(옵션이 없으면 null)
     * @throws CliException 허용값이 아닌 경우
     */
    static KeyType typeOption(CliCommands.Parsed parsed) throws CliException {
        String value = parsed.value("--type");
        if (value == null) return null;
        KeyType type = KeyType.fromCode(value);
        if (type == null) throw new CliException(Messages.get("cli.err.type"));
        return type;
    }

    /**
     * {@code --key-id}를 읽는다(형식만 검사, 등록 여부는 설정이 확인한다).
     *
     * @return Key ID(옵션이 없으면 null)
     * @throws CliException 형식이 올바르지 않은 경우(값은 출력하지 않음)
     */
    static String keyIdOption(CliCommands.Parsed parsed) throws CliException {
        String value = parsed.value("--key-id");
        if (value == null) return null;
        if (!value.matches("[A-Za-z0-9_-]{1,64}")) throw new CliException(Messages.get("cfg.err.keyIdFormat"));
        return value;
    }

    /**
     * keygen: 설정과 기존 키를 읽지 않는다. 결과는 만든 파일 경로, 키 지문(64자), 사유(·작업자)와 "이력에 저장하지 않음"이다.
     * 사유는 필수다(대화형이면 묻고, 아니면 생성 전에 오류). keygen은 JAR를 바꾸지 않으므로 사유·작업자는 어디에도 저장하지 않는다
     * (config history에 남지 않음). 대화형 터미널이면 키 파일 한 줄과 같은 생성값을 터미널에만 한 번 보여 준다.
     */
    private static int keygen(CliCommands.Parsed parsed, TerminalProvider terminals, PrintStream out)
            throws IOException, CliException {
        String operator = parsed.value("--operator");
        String reason = reasonOption(parsed, terminals);
        Path destination = Paths.get(parsed.value("--out"));
        Terminal terminal = interactive(terminals);
        char[] shown = terminal == null ? null : new char[44];
        try {
            String fingerprint = generateKeyFile(destination, shown);
            out.println(Messages.get("cli.keygen.file", destination.toAbsolutePath().normalize()));
            out.println(Messages.get("cli.keygen.fingerprint", fingerprint));
            out.println(Messages.get("cli.keygen.reason", reason));
            if (operator != null) out.println(Messages.get("cli.keygen.operator", operator));
            out.println(Messages.get("cli.keygen.notRecorded"));
            if (terminal != null) {
                out.flush();
                KeyringView.showGenerated(terminal, KeyType.KEY, null, shown, null, null, KeyringView.Kept.KEY_FILE);
            }
            return 0;
        } finally {
            if (shown != null) Arrays.fill(shown, '\0');
        }
    }

    /** keygen 사전 검사: {@code --out} 필수·경로 형식·기존 파일 없음(덮어쓰지 않음), 작업자 ID 형식. */
    private static void checkKeygen(CliCommands.Parsed parsed) throws CliException {
        String outputPath = parsed.value("--out");
        if (outputPath == null) throw new CliException(Messages.get("cli.err.keygenOut"));
        Path destination = jarOption(parsed, "--out");
        if (Files.exists(destination, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new CliException(Messages.get("cli.err.keygenExists"));
        }
        String operator = parsed.value("--operator");
        if (operator != null) JarConfigEditor.checkOperator(operator);
    }

    /**
     * 사유: {@code --reason} 값. 없으면 대화형 터미널에서 묻고(빈 입력이면 중단), 대화형이 아니면 오류로 멈춘다. 키를 만들거나 바꾸는
     * 명령은 사유 없이 진행하지 않으며 이 확인은 키 생성·KMS 호출·JAR 변경보다 먼저 한다. {@code --yes}는 CHANGE 확인만 생략한다.
     *
     * @return 검사한 사유(1~200자 한 줄)
     */
    static String reasonOption(CliCommands.Parsed parsed, TerminalProvider terminals) throws CliException {
        String reason = parsed.value("--reason");
        if (reason == null) {
            Terminal terminal = interactive(terminals);
            if (terminal == null) throw new CliException(Messages.get("cli.err.reasonNeeded", parsed.spec.name));
            reason = terminal.readLine(Messages.get("cli.reason.prompt") + " ");
            if (reason == null || reason.trim().isEmpty()) throw new CliException(Messages.get("cli.err.reasonEmpty"));
            reason = reason.trim();
        }
        JarConfigEditor.checkReason(reason);
        return reason;
    }

    /** @return 대화형 터미널(표준 입출력이 모두 터미널), 아니면 null */
    static Terminal interactive(TerminalProvider terminals) {
        try {
            return terminals.open();
        } catch (CliException e) {
            return null;
        }
    }

    /** @return 키 상태 표시(공개 기본 키 / 사용자 지정). info·fingerprint·doctor·config show가 같은 문구를 쓴다. */
    static String keyStatus(boolean publicDefaultKey) {
        return Messages.get(publicDefaultKey ? "cli.key.public" : "cli.key.custom");
    }

    /**
     * info 명령: 실제 적용 설정과 각 값의 출처를 비밀값 없이 보여 주고 등록된 키를 모두 실제로 읽어 확인한다. 먼저 기본 유형과 유형별
     * 기본 키를, 이어서 키마다 공급원·위치·(pass는 KDF)·상태(공개 기본 키/사용자 지정)·짧은 지문(앞 12자 + 뒤 8자)·조회 결과를
     * 보여 준다. {@code config show}(JAR 내부 값만)와 달리 외부 Properties·JVM -D를 반영한 최종값이다. 경고 정책
     * (crypto.warning.enabled)과 관계없이 같은 내용을 보여 준다.
     *
     * @return 0: 모든 키 확인 성공, 1: 하나라도 실패(원인은 표준 오류에 키마다 오류 형식 한 줄)
     */
    private static int printInfo(CryptoService crypto, PrintStream out, PrintStream err) {
        CryptoSettings settings = crypto.settings();
        out.println(Messages.get("cli.info.defaultType", settings.defaultType().code(), originOf(settings, CryptoSettings.KEY_TYPE)));
        out.println(Messages.get("cli.info.activePass", KeyringView.idOrNone(settings.activeProfile(KeyType.PASS)),
                originOf(settings, CryptoSettings.KEY_ACTIVE_PASS)));
        String activeKeyOrigin = settings.get(CryptoSettings.KEY_ACTIVE_KEY).isEmpty() ? CryptoSettings.KEY_ID
                : CryptoSettings.KEY_ACTIVE_KEY;
        out.println(Messages.get("cli.info.activeKey", KeyringView.idOrNone(settings.activeProfile(KeyType.KEY)),
                originOf(settings, activeKeyOrigin)));
        List<CryptoService.KeyCheck> failed = new ArrayList<>();
        for (CryptoService.KeyCheck check : crypto.checkKeys()) {
            KeyProfile profile = check.profile();
            out.println();
            out.println(Messages.get("cli.info.key", profile.id(), KeyringView.marks(settings, profile)));
            out.println("  " + Messages.get("cli.info.key.source", profile.source(), sourceOrigin(settings, profile)));
            out.println("  " + Messages.get("cli.info.key.location", crypto.describeKeyLocation(profile),
                    locationOrigin(settings, profile)));
            if (profile.type() == KeyType.PASS) {
                out.println("  " + Messages.get("cli.info.key.kdf", profile.value(KeyProfile.KDF),
                        String.format(java.util.Locale.ROOT, "%,d", profile.iterations())));
            }
            if (check.available()) {
                out.println("  " + Messages.get("cli.info.key.status", keyStatus(check.publicDefaultKey())));
                out.println("  " + Messages.get("cli.info.key.fingerprint", KeyResolver.shortFingerprint(check.fingerprint())));
                out.println("  " + Messages.get("cli.info.key.check", "OK"));
            } else {
                out.println("  " + Messages.get("cli.info.key.check", "FAIL"));
                failed.add(check);
            }
        }
        out.println();
        out.println(Messages.get("cli.info.algorithm", settings.get(CryptoSettings.ALGORITHM),
                originOf(settings, CryptoSettings.ALGORITHM)));
        out.println(Messages.get("cli.info.output", settings.outputFormat().settingValue(),
                originOf(settings, CryptoSettings.OUTPUT_ENCODING)));
        String lang = settings.get(CryptoSettings.LANG).isEmpty() ? SettingCatalog.DEFAULT_LANGUAGE : settings.get(CryptoSettings.LANG);
        String applied = settings.language().code();
        out.println(Messages.get("cli.info.lang", lang.equals(applied) ? lang : lang + " -> " + applied,
                originOf(settings, CryptoSettings.LANG)));
        out.println(Messages.get("cli.info.warning", settings.warningEnabled() ? "true" : "false",
                originOf(settings, CryptoSettings.WARNING_ENABLED)));
        out.println(Messages.get("cli.info.pool", settings.poolFactory(), originOf(settings, CryptoSettings.POOL_FACTORY)));
        out.println(settings.externalConfigUsed()
                ? Messages.get("cli.info.external.used", settings.configOrigin().description(), settings.configFileName())
                : Messages.get("cli.info.external.none"));
        printJvmOverrides(settings, out);
        out.println(Messages.get("cli.info.history", ConfigHistory.describeRunningJar()));
        for (CryptoService.KeyCheck check : failed) err.println(Messages.error(check.failureReason().name(), check.failure()));
        return failed.isEmpty() ? 0 : 1;
    }

    /**
     * 키 공급 방식의 출처(" [JAR 기본값]" 등). crypto.key.* AES 키에서 외부 설정·-D를 쓰면서 공급 방식은 JAR 값을 그대로 쓰는 경우는
     * 그 사실을 덧붙인다.
     */
    private static String sourceOrigin(CryptoSettings settings, KeyProfile profile) {
        if (profile.legacy() && settings.valueOrigin(CryptoSettings.KEY_SOURCE) == CryptoSettings.ValueOrigin.JAR_DEFAULT
                && (settings.externalConfigUsed() || !settings.jvmOverriddenKeys().isEmpty())) {
            return Messages.get("cli.info.origin", Messages.get("cli.info.source.inherited"));
        }
        return originOf(settings, profile.settingName(KeyProfile.SOURCE));
    }

    /** 최종값의 출처를 " [출처: ...]" 형태로 만든다. 값은 다시 출력하지 않는다. */
    private static String originOf(CryptoSettings settings, String key) {
        return Messages.get("cli.info.origin", settings.valueOrigin(key).description());
    }

    /** 키 위치 설정의 출처(embedded는 위치 설정을 쓰지 않으므로 표시하지 않는다). */
    private static String locationOrigin(CryptoSettings settings, KeyProfile profile) {
        switch (profile.source()) {
            case "file": return originOf(settings, profile.settingName(KeyProfile.FILE));
            case "env": return originOf(settings, profile.settingName(KeyProfile.ENV));
            case "vault": return originOf(settings, profile.settingName(KeyProfile.VAULT_PATH));
            case "aws-kms": return originOf(settings, profile.settingName(KeyProfile.AWS_KMS_DATA_KEY_FILE));
            default: return "";
        }
    }

    /**
     * JVM 개별 속성(-D) 정책과 적용 결과를 이름만으로 보여 준다(값 미출력). 정책 줄 다음에 적용한 -D(없으면 "없음")와 무시한 -D(있을
     * 때만)를 한 줄에 하나씩 쓴다.
     */
    private static void printJvmOverrides(CryptoSettings settings, PrintStream out) {
        out.println(Messages.get("cli.info.jvm", Messages.get(settings.jvmOverrideEnabled() ? "cli.info.jvm.on" : "cli.info.jvm.off"),
                originOf(settings, CryptoSettings.JVM_OVERRIDE_ENABLED)));
        List<String> applied = new ArrayList<>(settings.jvmOverriddenKeys());
        if (applied.isEmpty()) applied.add(Messages.get("cli.info.none"));
        CliHelp.printItems(out, Messages.get("cli.info.jvm.applied", ""), applied);
        if (!settings.ignoredJvmKeys().isEmpty()) {
            CliHelp.printItems(out, Messages.get("cli.info.jvm.ignored", ""), new ArrayList<>(settings.ignoredJvmKeys()));
        }
    }

    /**
     * encrypt 명령: 가려진 입력으로 받은 값을 암호화해 토큰만 출력한다(표준 출력에는 완전한 토큰 한 줄만). 키는 입력을 받기 전에
     * 고른다(옵션 없음: 기본 유형의 기본 키, {@code --type}: 그 유형의 기본 키, {@code --key-id}: 그 키, 둘 다: 유형 확인 후 그 키).
     */
    private static void encrypt(CryptoService crypto, KeyType type, String keyId, TerminalProvider terminals, PrintStream out)
            throws CredentialCryptoException, CliException {
        KeyProfile profile = crypto.select(type, keyId);
        char[] plain = terminals.open().readSecret(Messages.get("cli.encrypt.prompt") + " ");
        if (plain == null || plain.length == 0) throw new CliException(Messages.get("cli.err.noInput"));
        try {
            out.println(crypto.encryptText(plain, null, profile.id()));
        } finally {
            Arrays.fill(plain, '\0');
        }
    }

    /**
     * decrypt 명령: 암호문을 화면에 표시하지 않고 한 번 입력받아 바로 평문을 출력한다(대화형 터미널 필수). 키ID·인증 태그 검증에
     * 성공한 경우에만 평문을 출력하며, 실패하면 오류로 끝나 평문은 나오지 않는다. 평문 안의 공백·줄바꿈은 그대로 출력한다.
     */
    private static void decryptInteractively(CryptoService crypto, Terminal terminal, PrintStream out)
            throws CredentialCryptoException, CliException {
        char[] input = terminal.readSecret(Messages.get("cli.decrypt.prompt") + " ");
        if (input == null || input.length == 0) throw new CliException(Messages.get("cli.err.noInput"));
        try {
            // 키·인증 태그 검증에 실패하면 예외로 끝나므로 평문은 출력되지 않는다. 평문은 메시지 자리표시자에 넣지 않는다.
            String decrypted = crypto.decryptText(new String(input));
            out.println(Messages.get("cli.decrypt.resultLabel") + " " + decrypted);
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
        return generateKeyFile(destination, null);
    }

    /**
     * {@link #generateKeyFile(Path)}와 같고, {@code shown}(44칸)을 주면 파일에 쓴 것과 같은 Base64 글자를 담아 돌려준다(대화형
     * 표시용, 호출자가 지운다). 파일에 쓰지 못하면 채우지 않는다.
     */
    static String generateKeyFile(Path destination, char[] shown) throws IOException, CliException {
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
            if (shown != null) {
                for (int i = 0; i < encoded.length && i < shown.length; i++) shown[i] = (char) encoded[i];
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

            @Override
            public void printSecret(char[] secret) {
                console.writer().write(secret);
                console.writer().println();
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
