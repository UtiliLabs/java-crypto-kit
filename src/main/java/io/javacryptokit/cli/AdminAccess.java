package io.javacryptokit.cli;

import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <b>내부 구현 클래스</b>: 실제 실행의 관리자 비밀번호 확인({@link AdminGate}). 실행 중인 CLI JAR의 검증값({@link AdminPassword#ENTRY})
 * 으로 비밀번호를 확인하고, 다른 JAR를 바꾸거나 그 JAR의 키를 꺼내 쓰는 명령은 그 JAR의 검증값으로도 확인한다.
 *
 * <p><b>입력</b>: {@value AdminPassword#FILE_OPTION}이 있으면 그 파일(한 줄)을 쓰고, 없으면 대화형 터미널에서 화면에 표시하지 않고
 * 받는다(실행 1회에 {@value AdminPassword#ATTEMPTS}번까지). 둘 다 없으면(비대화형) 아무것도 하지 않고 실패한다. 다른 JAR의 비밀번호가
 * 이미 받은 비밀번호와 같으면 다시 묻지 않는다. 비밀번호 파일로 실행할 때는 그 파일이 모든 대상 JAR와 맞아야 한다.</p>
 *
 * <p><b>한계</b>: 시도 횟수 제한은 이 실행 안에서만이다(새로 실행하면 다시 3번). 영구 잠금·계정 잠금 기능이 아니다.</p>
 */
final class AdminAccess implements AdminGate {
    private final Path cliJar;
    private AdminPassword.Status status;
    private JarConfigEditor.Snapshot snapshot;
    private final List<JarConfigEditor.Snapshot> otherSnapshots = new ArrayList<>();
    private char[] password;
    private boolean authenticated;

    /** @param cliJar 실행 중인 CLI JAR(클래스 폴더에서 실행 중이면 null) */
    AdminAccess(Path cliJar) {
        this.cliJar = cliJar;
    }

    /** @return 지금 실행 중인 JAR 기준의 확인 창구 */
    static AdminAccess forRunningJar() {
        return new AdminAccess(ConfigCommand.runningJar());
    }

    @Override
    public synchronized AdminPassword.Status status() {
        if (status == null) {
            if (cliJar == null) {
                status = new AdminPassword.Status(AdminPassword.State.NO_JAR, null);
            } else {
                try {
                    snapshot = JarConfigEditor.read(cliJar);
                    status = AdminPassword.statusOf(snapshot);
                } catch (CryptoCli.CliException e) {
                    status = new AdminPassword.Status(AdminPassword.State.DAMAGED, e.getMessage());
                }
            }
        }
        return status;
    }

    @Override
    public Path cliJar() {
        return cliJar;
    }

    @Override
    public synchronized void authenticate(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, Path target,
                                          Path source) throws CryptoCli.CliException {
        if (status().state != AdminPassword.State.INITIALIZED) {
            throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.notSetCli"));
        }
        if (!authenticated) {
            AdminPassword.Verifier verifier = AdminPassword.parse(snapshot.adminBytes);
            String prompt = Messages.get(ConfigHistory.ADMIN_CHANGE.equals(parsed.spec.name)
                    ? "admin.prompt.current" : "admin.prompt");
            password = obtain(parsed, terminals, verifier, prompt, true, null);
            authenticated = true;
        }
        List<Path> others = new ArrayList<>();
        List<String> roles = new ArrayList<>();
        if (target != null && !sameFile(target, cliJar)) {
            others.add(target);
            roles.add("admin.role.target");
        }
        if (source != null && !sameFile(source, cliJar) && (target == null || !sameFile(source, target))) {
            others.add(source);
            roles.add("admin.role.source");
        }
        for (int i = 0; i < others.size(); i++) authenticateOther(parsed, terminals, others.get(i), Messages.get(roles.get(i)));
    }

    @Override
    public void checkIntact(Path jar) throws CryptoCli.CliException {
        if (cliJar != null && sameFile(jar, cliJar)) return; // 실행 중인 JAR는 명령 전에 상태를 확인했다
        JarConfigEditor.Snapshot other = JarConfigEditor.read(jar);
        AdminPassword.Status otherStatus = AdminPassword.statusOf(other);
        if (otherStatus.state == AdminPassword.State.DAMAGED) {
            throw new CryptoCli.CliException("INTEGRITY", Messages.get("admin.err.otherDamaged", Messages.get("admin.role.to"),
                    JarConfigEditor.name(jar), otherStatus.detail));
        }
        otherSnapshots.add(other);
    }

    /**
     * 다른 JAR의 관리자 비밀번호 확인. 이전 버전 JAR(관리자 비밀번호 없음)은 실행 중인 CLI JAR의 인증으로 진행하고, 미설정·손상
     * (검증값 또는 변경 이력) JAR은 거부한다. 이미 받은 비밀번호가 맞지 않으면 대화형에서만 그 JAR의 비밀번호를 따로 묻는다.
     */
    private void authenticateOther(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, Path jar, String role)
            throws CryptoCli.CliException {
        JarConfigEditor.Snapshot other = JarConfigEditor.read(jar);
        otherSnapshots.add(other);
        AdminPassword.Status otherStatus = AdminPassword.statusOf(other);
        String name = JarConfigEditor.name(jar);
        switch (otherStatus.state) {
            case LEGACY:
                return;
            case UNINITIALIZED:
                throw new CryptoCli.CliException("ADMIN_SETUP", Messages.get("admin.err.otherNotSet", role, name));
            case DAMAGED:
                throw new CryptoCli.CliException("INTEGRITY", Messages.get("admin.err.otherDamaged", role, name,
                        otherStatus.detail));
            default:
                break;
        }
        AdminPassword.Verifier verifier = AdminPassword.parse(other.adminBytes);
        if (verifier.matches(password)) return;
        if (parsed.value(AdminPassword.FILE_OPTION) != null || CryptoCli.interactive(terminals) == null) {
            throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.otherMismatch", role, name,
                    AdminPassword.FILE_OPTION));
        }
        char[] otherPassword = obtain(parsed, terminals, verifier, Messages.get("admin.prompt.other", role, name), false, role);
        Arrays.fill(otherPassword, '\0');
    }

    /**
     * 비밀번호를 받아 확인한다(파일 또는 대화형 3회).
     *
     * @param useFile 비밀번호 파일 옵션을 쓸지(다른 JAR의 추가 입력은 대화형만)
     * @param role    다른 JAR이면 그 역할(메시지용), 실행 중인 JAR이면 null
     * @return 확인한 비밀번호(호출자가 지운다)
     */
    private static char[] obtain(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, AdminPassword.Verifier verifier,
                                 String prompt, boolean useFile, String role) throws CryptoCli.CliException {
        String file = useFile ? parsed.value(AdminPassword.FILE_OPTION) : null;
        if (file != null) {
            char[] fromFile = AdminPassword.readFile(file, "ADMIN_AUTH");
            if (verifier.matches(fromFile)) return fromFile;
            Arrays.fill(fromFile, '\0');
            throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.fileMismatch", AdminPassword.FILE_OPTION));
        }
        CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
        if (terminal == null) {
            throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.needed", parsed.spec.name,
                    AdminPassword.FILE_OPTION));
        }
        for (int attempt = 1; ; attempt++) {
            char[] typed = terminal.readSecret(prompt + " ");
            if (typed == null || typed.length == 0) {
                throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.cancelled"));
            }
            if (verifier.matches(typed)) return typed;
            Arrays.fill(typed, '\0');
            if (attempt >= AdminPassword.ATTEMPTS) {
                throw new CryptoCli.CliException("ADMIN_AUTH", role == null ? Messages.get("admin.err.failed", AdminPassword.ATTEMPTS)
                        : Messages.get("admin.err.otherFailed", role, AdminPassword.ATTEMPTS));
            }
            terminal.println(Messages.get("admin.retry", AdminPassword.ATTEMPTS - attempt));
        }
    }

    @Override
    public synchronized boolean authenticated() {
        return authenticated;
    }

    @Override
    public synchronized char[] verifiedPassword() {
        return password;
    }

    @Override
    public synchronized void close() {
        if (password != null) Arrays.fill(password, '\0');
        password = null;
    }

    @Override
    public JarConfigEditor.Snapshot snapshot(Path jar) throws CryptoCli.CliException {
        if (snapshot != null && sameFile(jar, cliJar)) return snapshot;
        for (JarConfigEditor.Snapshot other : otherSnapshots) {
            if (sameFile(jar, other.jar)) return other;
        }
        throw new CryptoCli.CliException("ADMIN_AUTH", Messages.get("admin.err.notSetCli"));
    }

    private static boolean sameFile(Path a, Path b) {
        if (a == null || b == null) return false;
        try {
            return Files.exists(a) && Files.exists(b) && Files.isSameFile(a, b);
        } catch (IOException e) {
            return a.toAbsolutePath().normalize().equals(b.toAbsolutePath().normalize());
        }
    }
}
