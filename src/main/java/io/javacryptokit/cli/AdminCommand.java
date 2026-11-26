package io.javacryptokit.cli;

import io.javacryptokit.i18n.Messages;
import java.io.PrintStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * <b>내부 구현 클래스</b>: CLI 관리자 비밀번호의 실행 전 확인과 {@code admin setup}·{@code admin password change}.
 *
 * <ul>
 *   <li><b>실행 전 확인</b>({@link #enter}): 관리자 비밀번호를 설정하지 않은 JAR는 어떤 명령이든 실행하지 않는다. 대화형 터미널이면
 *       바로 최초 설정(작업자 ID → 새 비밀번호 → 확인)을 진행해 설정된 새 JAR를 만들고, 요청한 명령은 실행하지 않은 채 새 JAR로
 *       다시 실행하라고 안내한다(새 JAR로 몰래 이어 실행하지 않음). 비대화형이면 아무것도 바꾸지 않고 실패한다. 검증값이 손상됐으면
 *       Fail Closed다.</li>
 *   <li><b>설정·변경</b>: 결과는 늘 새 JAR다(실행 중인 JAR는 바꾸지 않음). 원본 JAR는 그대로 남으므로 이전 상태(미설정·이전
 *       비밀번호)로 계속 쓸 수 있다. 키·Key ID·KDF·이력은 바뀌지 않고, 이력에 관리자 기록 1건(비밀번호·검증값 없음)이 더해진다.</li>
 * </ul>
 */
final class AdminCommand {
    private AdminCommand() { }

    /**
     * 명령 실행 전 관리자 상태를 확인한다.
     *
     * @return null이면 명령을 계속 실행, 아니면 그 종료 코드로 끝낸다(최초 설정을 대신 진행한 경우)
     */
    static Integer enter(CliCommands.Spec spec, CryptoCli.TerminalProvider terminals, PrintStream out, PrintStream err,
                         AdminGate admin) throws Exception {
        AdminPassword.Status status = admin.status();
        boolean setupCommand = ConfigHistory.ADMIN_SETUP.equals(spec.name);
        switch (status.state) {
            case INITIALIZED:
                if (setupCommand) throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.alreadySet"));
                return null;
            case UNINITIALIZED:
                if (setupCommand) return null;
                CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
                if (terminal == null) {
                    throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.notSet", jarName(admin),
                            AdminPassword.FILE_OPTION));
                }
                Path created = setup(null, terminals, out, admin, spec.name);
                err.println(Messages.error("ADMIN_SETUP", Messages.get("admin.notRun", spec.name,
                        JarConfigEditor.name(created))));
                return 1;
            default:
                throw failure(status, admin);
        }
    }

    /** Only the no-argument startup screen consults setup status. */
    static int startScreen(AdminGate admin, PrintStream out) throws CryptoCli.CliException {
        AdminPassword.Status status = admin.status();
        if (status.state == AdminPassword.State.INITIALIZED) {
            CliHelp.topic("overview", out);
        } else if (status.state == AdminPassword.State.UNINITIALIZED) {
            CliHelp.topic("admin-required", out, jarName(admin));
        } else {
            throw failure(status, admin);
        }
        return 0;
    }

    private static CryptoCli.CliException failure(AdminPassword.Status status, AdminGate admin) {
        if (status.state == AdminPassword.State.NO_JAR) {
            return new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.noJar"));
        }
        String detail = status.detail == null ? Messages.get("admin.damaged.format") : status.detail;
        return new CryptoCli.CliException("INTEGRITY", Messages.get("admin.err.damaged", detail));
    }

    /** {@code admin setup}·{@code admin password change}. */
    static int run(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out, AdminGate admin)
            throws Exception {
        if (ConfigHistory.ADMIN_SETUP.equals(parsed.spec.name)) {
            setup(parsed, terminals, out, admin, null);
            return 0;
        }
        return change(parsed, terminals, out, admin);
    }

    // ===================================================================================================
    // 최초 설정
    // ===================================================================================================

    /**
     * 최초 설정: 작업자 ID → 새 비밀번호 2회(또는 비밀번호 파일) → 설정된 새 JAR. 취소·규칙 위반·불일치·파일 충돌이면 아무것도 만들지
     * 않는다.
     *
     * @param parsed    {@code admin setup}의 인자(다른 명령에서 들어온 최초 설정이면 null: 그 명령의 옵션은 쓰지 않음)
     * @param requested 다른 명령에서 들어왔으면 그 명령 이름, 아니면 null
     * @return 만든 JAR
     */
    private static Path setup(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out, AdminGate admin,
                              String requested) throws Exception {
        Path cliJar = admin.cliJar();
        String file = parsed == null ? null : parsed.value(AdminPassword.FILE_OPTION);
        String operator = parsed == null ? null : parsed.value("--operator");
        CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
        if (file == null && terminal == null) {
            throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.setupNeedsFile", AdminPassword.FILE_OPTION));
        }
        if (operator == null && terminal == null) throw new CryptoCli.CliException(Messages.get("admin.err.operatorNeeded"));
        if (operator != null) JarConfigEditor.checkOperator(operator);
        // 결과 경로는 입력을 받기 전에 정한다(이미 있으면 바로 알림).
        Path output = parsed != null ? ConfigCommand.outputJar(parsed, cliJar) : implicitOutput(cliJar, requested);
        if (terminal != null && (file == null || operator == null)) {
            terminal.println(Messages.get(requested != null ? "admin.setup.titleRequired" : "admin.setup.title"));
            if (requested != null) {
                terminal.println(Messages.get("admin.setup.blocked"));
                terminal.println(Messages.get("admin.setup.newJar", JarConfigEditor.name(output)));
            }
            if (file == null) terminal.println(Messages.get("admin.rules", AdminPassword.MIN_LENGTH, AdminPassword.MAX_LENGTH));
            terminal.println("");
        }
        if (operator == null) operator = readOperator(terminal);
        char[] password = file != null ? newFromFile(file) : readNew(terminal, null);
        try {
            byte[] entry = AdminPassword.create(password);
            JarConfigEditor.Result result = JarConfigEditor.applyAdmin(cliJar, output, ConfigCommand.runningJar(), entry, operator,
                    ConfigHistory.ADMIN_SETUP, Messages.get("admin.reason.setup"), Instant.now());
            if (terminal != null && file == null) terminal.println("");
            out.println(Messages.get("admin.result.setup"));
            out.println(Messages.get("cfg.result.created", result.output.toAbsolutePath()));
            if (JarConfigEditor.posix()) out.println(Messages.get("cfg.result.permission"));
            out.println(Messages.get("admin.result.original.setup", JarConfigEditor.name(cliJar)));
            out.println(Messages.get("admin.result.operator", operator));
            out.println(Messages.get("admin.result.next.setup"));
            out.flush();
            return result.output;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** 다른 명령에서 들어온 최초 설정의 결과 경로: 원본 옆 기본 이름(이미 있으면 그 JAR가 설정된 JAR일 수 있음을 알림). */
    private static Path implicitOutput(Path cliJar, String requested) throws CryptoCli.CliException {
        try {
            return ConfigCommand.defaultOutputJar(cliJar);
        } catch (CryptoCli.CliException e) {
            String taken = ConfigCommand.defaultOutputName(JarConfigEditor.name(cliJar));
            throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.implicitOutExists", taken, requested));
        }
    }

    // ===================================================================================================
    // 변경
    // ===================================================================================================

    /**
     * 변경의 사전 검사(현재 비밀번호 확인 전): 대화형 터미널, 작업자 ID·사유 형식, 결과 파일 자리. 통과하면 제목을 보여 주고,
     * 현재 비밀번호는 {@link CryptoCli}가 다른 민감 명령과 같은 곳에서 확인한다.
     */
    static void checkChange(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals) throws CryptoCli.CliException {
        CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
        if (terminal == null) throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.changeInteractive"));
        String operator = parsed.value("--operator");
        if (operator != null) JarConfigEditor.checkOperator(operator);
        JarConfigEditor.checkReason(parsed.value("--reason"));
        ConfigCommand.outputJar(parsed, parsed.admin.cliJar());
        terminal.println(Messages.get("admin.change.title"));
    }

    /**
     * 변경: (사전 검사·현재 비밀번호 확인 뒤) 작업자 ID·사유(옵션이 없으면 질문) → 새 비밀번호 2회 → 새 JAR. 대화형 전용이다.
     */
    private static int change(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, PrintStream out, AdminGate admin)
            throws Exception {
        CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
        String operator = parsed.value("--operator");
        Path cliJar = admin.cliJar();
        Path output = ConfigCommand.outputJar(parsed, cliJar);
        if (operator == null) operator = readOperator(terminal);
        String reason = CryptoCli.reasonOption(parsed, terminals);
        terminal.println(Messages.get("admin.rules", AdminPassword.MIN_LENGTH, AdminPassword.MAX_LENGTH));
        char[] password = readNew(terminal, admin.verifiedPassword());
        try {
            byte[] entry = AdminPassword.create(password);
            JarConfigEditor.Result result = JarConfigEditor.applyAdmin(cliJar, output, ConfigCommand.runningJar(), entry, operator,
                    ConfigHistory.ADMIN_CHANGE, reason, Instant.now());
            terminal.println("");
            out.println(Messages.get("admin.result.change"));
            out.println(Messages.get("cfg.result.created", result.output.toAbsolutePath()));
            if (JarConfigEditor.posix()) out.println(Messages.get("cfg.result.permission"));
            out.println(Messages.get("admin.result.original.change", JarConfigEditor.name(cliJar)));
            out.println(Messages.get("admin.result.operator", operator));
            out.println(Messages.get("admin.result.reason", reason));
            out.println(Messages.get("admin.result.next.change"));
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ===================================================================================================
    // 입력
    // ===================================================================================================

    /** 작업자 ID 한 줄(화면 표시). 빈 값·공백만이면 중단한다. 형식은 --operator와 같다. */
    private static String readOperator(CryptoCli.Terminal terminal) throws CryptoCli.CliException {
        String operator = terminal.readLine(Messages.get("admin.prompt.operator") + " ");
        if (operator == null || operator.trim().isEmpty()) {
            throw new CryptoCli.CliException(Messages.get("admin.err.operatorEmpty"));
        }
        operator = operator.trim();
        JarConfigEditor.checkOperator(operator);
        return operator;
    }

    /**
     * 새 비밀번호를 두 번 받는다(화면 비표시). 규칙 위반·불일치·현재와 같음이면 이유를 알리고 다시 받는다(실행 1회
     * {@value AdminPassword#ATTEMPTS}번). 빈 입력이면 바로 중단한다.
     *
     * @param current 현재 비밀번호(변경일 때, 같은 값 거부), 최초 설정이면 null
     * @return 확인한 새 비밀번호(호출자가 지운다)
     */
    private static char[] readNew(CryptoCli.Terminal terminal, char[] current) throws CryptoCli.CliException {
        String last = null;
        for (int attempt = 1; attempt <= AdminPassword.ATTEMPTS; attempt++) {
            char[] first = terminal.readSecret(Messages.get("admin.prompt.new") + " ");
            if (first == null || first.length == 0) {
                throw new CryptoCli.CliException("ADMIN_PASSWORD", Messages.get("admin.err.newCancelled"));
            }
            List<String> violations = AdminPassword.violations(first);
            String problem = null;
            if (!violations.isEmpty()) {
                problem = Messages.get("admin.err.rule", AdminPassword.describe(violations));
            } else if (current != null && AdminPassword.same(first, current)) {
                problem = Messages.get("admin.err.sameAsCurrent");
            } else {
                char[] second = terminal.readSecret(Messages.get("admin.prompt.confirm") + " ");
                try {
                    if (second == null || second.length == 0) {
                        Arrays.fill(first, '\0');
                        throw new CryptoCli.CliException("ADMIN_PASSWORD", Messages.get("admin.err.newCancelled"));
                    }
                    if (AdminPassword.same(first, second)) return first;
                    problem = Messages.get("admin.err.mismatch");
                } finally {
                    if (second != null) Arrays.fill(second, '\0');
                }
            }
            Arrays.fill(first, '\0');
            last = problem;
            if (attempt < AdminPassword.ATTEMPTS) {
                terminal.println(Messages.get("admin.retryNew", problem, AdminPassword.ATTEMPTS - attempt));
            }
        }
        throw new CryptoCli.CliException("ADMIN_PASSWORD", Messages.get("admin.err.newFailed", AdminPassword.ATTEMPTS, last));
    }

    /** 비대화형 최초 설정: 비밀번호 파일 한 줄을 읽어 같은 규칙으로 검사한다. */
    private static char[] newFromFile(String file) throws CryptoCli.CliException {
        char[] password = AdminPassword.readFile(file, "ADMIN_PASSWORD");
        List<String> violations = AdminPassword.violations(password);
        if (!violations.isEmpty()) {
            Arrays.fill(password, '\0');
            throw new CryptoCli.CliException("ADMIN_PASSWORD", Messages.get("admin.err.fileRule", AdminPassword.FILE_OPTION,
                    AdminPassword.describe(violations), Messages.get("admin.rules", AdminPassword.MIN_LENGTH, AdminPassword.MAX_LENGTH)));
        }
        return password;
    }

    /** @return 안내에 쓸 실행 중인 JAR 이름 */
    private static String jarName(AdminGate admin) {
        Path jar = admin.cliJar();
        return jar == null ? CliHelp.jarName() : JarConfigEditor.name(jar);
    }
}
