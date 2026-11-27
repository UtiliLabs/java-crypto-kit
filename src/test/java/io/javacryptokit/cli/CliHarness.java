package io.javacryptokit.cli;

import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.key.DefaultKeyWarning;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * 테스트 전용: CLI를 같은 JVM에서 실행하고 표준 출력·표준 오류를 따로 모은다. 실제 환경의 설정 경로·-D 값이 섞이지 않게
 * 격리하며({@link #close()}에서 원래대로), 대화형 입력은 {@link FakeTerminal}로 대신한다.
 *
 * <p><b>관리자 비밀번호</b>: 기본은 {@link RecordingGate}(설정된 CLI JAR처럼 동작하고 인증 호출만 기록)로 명령별 동작을 확인한다.
 * CLI는 민감 명령이 인증 호출 없이 성공하면 실패로 끝내므로 기존 시험 전체가 "모든 민감 명령이 인증을 거친다"도 함께 확인한다.
 * 실제 인증(최초 설정·비밀번호 확인·다른 JAR 인증)은 {@link #withCliJar}로 시험용 JAR를 CLI JAR로 정해 확인한다.</p>
 */
public final class CliHarness implements AutoCloseable {
    /** 시험용 관리자 비밀번호(규칙: 10자 이상, 영문자·숫자·특수문자). 시험 JAR에만 쓴다. */
    public static final String ADMIN_PASSWORD = "Test-admin-1";
    private final AutoCloseable configPath;
    private final AutoCloseable jvm;
    private ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    private ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    /** 실행마다 새로 만드는 관리자 확인 창구(실제 CLI는 실행마다 새 프로세스). */
    private java.util.function.Supplier<AdminGate> gates = RecordingGate::new;
    /** 마지막 실행의 관리자 확인 창구. */
    private AdminGate lastGate;

    /**
     * 설정된 CLI JAR처럼 동작하는 시험용 창구: 상태는 늘 "설정됨", 인증은 비밀번호를 묻지 않고 호출 횟수만 기록한다(시험 코드에만
     * 있다. 제품 코드에는 인증을 건너뛰는 구현이 없다).
     */
    public static final class RecordingGate implements AdminGate {
        public int calls;
        public final List<String> targets = new ArrayList<>();

        @Override
        public AdminPassword.Status status() {
            return new AdminPassword.Status(AdminPassword.State.INITIALIZED, null);
        }

        @Override
        public java.nio.file.Path cliJar() {
            return null;
        }

        @Override
        public void authenticate(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, java.nio.file.Path target,
                                 java.nio.file.Path source) {
            calls++;
            if (target != null) targets.add("target:" + target.getFileName());
            if (source != null) targets.add("source:" + source.getFileName());
        }

        @Override
        public void checkIntact(java.nio.file.Path jar) {
            targets.add("intact:" + jar.getFileName());
        }

        @Override
        public boolean authenticated() {
            return calls > 0;
        }

        @Override
        public char[] verifiedPassword() {
            return null;
        }

        @Override
        public void close() {
            // 기록만 한다.
        }
    }

    /**
     * 실제 관리자 확인({@link AdminAccess})으로 실행한다: 이 JAR를 실행 중인 CLI JAR로 본다.
     *
     * @param cliJar 시험용 JAR
     * @return 이 하니스
     */
    public CliHarness withCliJar(java.nio.file.Path cliJar) {
        this.gates = () -> new AdminAccess(cliJar);
        return this;
    }

    /** 기본(인증 호출만 기록)으로 되돌린다. */
    public CliHarness recordingGate() {
        this.gates = RecordingGate::new;
        return this;
    }

    /** @return 마지막 실행의 관리자 확인 창구 */
    public AdminGate lastGate() {
        return lastGate;
    }

    /**
     * 시험 JAR를 최초 설정을 마친 JAR로 만든다: 제품의 {@code admin setup}과 같은 경로({@link JarConfigEditor#applyAdmin})로 검증값과
     * 이력의 최초 설정 기록을 함께 넣는다(반복 횟수만 허용 범위의 최솟값으로 낮춤).
     *
     * @param jar      시험용 JAR(그 자리에서 바뀐다)
     * @param password 관리자 비밀번호
     * @return jar
     */
    public static java.nio.file.Path configure(java.nio.file.Path jar, String password) throws java.io.IOException {
        byte[] entry = AdminPassword.create(password.toCharArray(), AdminPassword.MIN_ITERATIONS);
        try {
            JarConfigEditor.applyAdmin(JarConfigEditor.read(jar), entry, "test-setup", ConfigHistory.ADMIN_SETUP,
                    io.javacryptokit.i18n.Messages.get("admin.reason.setup"), java.time.Instant.now(), null);
            return jar;
        } catch (CryptoCli.CliException | io.javacryptokit.CredentialCryptoException e) {
            throw new java.io.IOException(e.getMessage(), e);
        }
    }

    /** Reads the production state view, then falls back to legacy resources. */
    static byte[] effectiveEntry(java.nio.file.Path jar, String name) throws java.io.IOException {
        try (java.util.jar.JarFile file = new java.util.jar.JarFile(jar.toFile())) {
            String format = file.getManifest().getMainAttributes().getValue(io.javacryptokit.config.JarState.ATTRIBUTE);
            if (format != null && isStateEntry(name)) {
                io.javacryptokit.config.JarState.State state = io.javacryptokit.config.JarState.read(jar, format);
                if (state != null) {
                    if (JarConfigEditor.SETTINGS_ENTRY.equals(name)) return state.settings;
                    if (ConfigHistory.ENTRY.equals(name)) return state.history;
                    return state.admin;
                }
            }
            java.util.jar.JarEntry entry = file.getJarEntry(name);
            if (entry == null) return null;
            try (java.io.InputStream in = file.getInputStream(entry);
                 java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                for (int n; (n = in.read(buffer)) != -1; ) bytes.write(buffer, 0, n);
                return bytes.toByteArray();
            }
        }
    }

    private static boolean isStateEntry(String name) {
        return JarConfigEditor.SETTINGS_ENTRY.equals(name) || ConfigHistory.ENTRY.equals(name) ||
                AdminPassword.ENTRY.equals(name);
    }

    private static byte[] valueOrEmpty(byte[] original) {
        return original == null ? new byte[0] : original;
    }

    /**
     * JAR 항목 하나를 바꾸거나(없으면 끝에 추가) 지운다(content가 null). 손상·삭제 시험용.
     *
     * @return jar
     */
    public static java.nio.file.Path replaceEntry(java.nio.file.Path jar, String name, byte[] content) throws java.io.IOException {
        String format;
        try (java.util.jar.JarFile file = new java.util.jar.JarFile(jar.toFile())) {
            format = file.getManifest().getMainAttributes().getValue(io.javacryptokit.config.JarState.ATTRIBUTE);
        }
        if (format != null && isStateEntry(name)) {
            io.javacryptokit.config.JarState.State state = io.javacryptokit.config.JarState.read(jar, format);
            if (state != null) {
                try {
                    io.javacryptokit.config.JarState.update(jar, format, JarConfigEditor.sha256(jar),
                            JarConfigEditor.SETTINGS_ENTRY.equals(name) ? content : state.settings,
                            valueOrEmpty(ConfigHistory.ENTRY.equals(name) ? content : state.history),
                            valueOrEmpty(AdminPassword.ENTRY.equals(name) ? content : state.admin), false);
                } catch (CryptoCli.CliException e) {
                    throw new java.io.IOException(e);
                }
                return jar;
            }
        }
        java.nio.file.Path temp = java.nio.file.Files.createTempFile(jar.toAbsolutePath().getParent(), ".edit", ".jar");
        boolean found = false;
        try (java.util.jar.JarFile in = new java.util.jar.JarFile(jar.toFile(), false);
             java.util.jar.JarOutputStream out = new java.util.jar.JarOutputStream(java.nio.file.Files.newOutputStream(temp))) {
            for (java.util.Enumeration<java.util.jar.JarEntry> e = in.entries(); e.hasMoreElements(); ) {
                java.util.jar.JarEntry entry = e.nextElement();
                if (entry.getName().equals(name)) {
                    found = true;
                    if (content == null) continue;
                    out.putNextEntry(new java.util.jar.JarEntry(name));
                    out.write(content);
                    out.closeEntry();
                    continue;
                }
                java.util.jar.JarEntry copy = new java.util.jar.JarEntry(entry.getName());
                if (entry.getName().startsWith("META-INF/jck-state/")) {
                    copy.setMethod(java.util.zip.ZipEntry.STORED);
                    copy.setSize(0);
                    copy.setCrc(0);
                    copy.setExtra(entry.getExtra());
                }
                out.putNextEntry(copy);
                if (!entry.isDirectory()) {
                    try (java.io.InputStream data = in.getInputStream(entry)) {
                        byte[] buffer = new byte[8192];
                        int read;
                        while ((read = data.read(buffer)) != -1) out.write(buffer, 0, read);
                    }
                }
                out.closeEntry();
            }
            if (!found && content != null) {
                out.putNextEntry(new java.util.jar.JarEntry(name));
                out.write(content);
                out.closeEntry();
            }
        }
        java.nio.file.Files.move(temp, jar, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return jar;
    }

    /**
     * 관리자 비밀번호 파일(한 줄)을 만든다. POSIX에서는 제품 규칙대로 소유자만 읽게(600) 만든다.
     *
     * @return 파일 경로 문자열(--admin-pass-file 값)
     */
    public static String passFile(java.nio.file.Path dir, String password) throws java.io.IOException {
        java.nio.file.Path file = dir.resolve("admin-" + Integer.toHexString(password.hashCode()) + ".pw");
        writeSecret(file, (password + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return file.toString();
    }

    /**
     * 새 JAR를 만든 결과 화면에서 POSIX(Linux·macOS)에만 "생성 JAR" 다음 줄로 나오는 권한 안내(가이드 12.2절의 문서화된 동작).
     * Windows에서는 빈 문자열이다. 결과 화면 전체를 글자 그대로 비교하는 시험이 두 OS에서 같은 기대값을 쓰게 한다.
     */
    public static String permissionLine() {
        return JarConfigEditor.posix()
                ? io.javacryptokit.i18n.Messages.get(io.javacryptokit.i18n.Messages.Language.KO, "cfg.result.permission") + System.lineSeparator()
                : "";
    }

    /**
     * 결과 화면에서 POSIX 권한 안내 줄을 뺀다(줄 위치·개수를 비교하는 시험용). POSIX에서는 그 줄이 정확히 한 번 있어야 한다.
     */
    public static String withoutPermissionLine(String out) {
        String line = permissionLine();
        if (line.isEmpty()) return out;
        int at = out.indexOf(line);
        if (at < 0 || out.indexOf(line, at + 1) >= 0) throw new AssertionError("POSIX 결과 화면에 권한 안내가 한 번 있어야 한다: " + out);
        return out.substring(0, at) + out.substring(at + line.length());
    }

    /** 비밀 파일을 쓰고 POSIX에서는 소유자만 읽고 쓰게(600) 한다. */
    public static java.nio.file.Path writeSecret(java.nio.file.Path file, byte[] content) throws java.io.IOException {
        java.nio.file.Files.write(file, content);
        if (JarConfigEditor.posix()) {
            java.nio.file.Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        }
        return file;
    }

    /** 대화형 터미널 대역: 미리 넣은 입력을 순서대로 돌려주고, 터미널에 쓴 문구를 모은다. */
    public static final class FakeTerminal implements CryptoCli.Terminal {
        public final Deque<String> lines = new ArrayDeque<>();
        public final Deque<String> secrets = new ArrayDeque<>();
        public final List<String> printed = new ArrayList<>();
        public final List<String> prompts = new ArrayList<>();

        @Override
        public char[] readSecret(String prompt) {
            prompts.add(prompt);
            String value = secrets.poll();
            return value == null ? null : value.toCharArray();
        }

        @Override
        public String readLine(String prompt) {
            prompts.add(prompt);
            return lines.poll();
        }

        @Override
        public void println(String message) {
            printed.add(message);
        }
    }

    /**
     * @param jvmPairs 이번 시험에서 쓸 -D 설정("이름=값"). 없으면 모두 지운 상태.
     */
    public CliHarness(String... jvmPairs) {
        this.configPath = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, TestSupport.managedConfig().toString());
        this.jvm = TestSupport.jvmSettings(jvmPairs);
        DefaultKeyWarning.resetForTests();
    }

    /**
     * CLI를 실행한다. 대화형 터미널이 필요하면 terminal을 준다(null이면 "대화형 터미널 아님").
     *
     * @return 종료 코드
     */
    public int run(FakeTerminal terminal, String... args) {
        outBytes = new ByteArrayOutputStream();
        errBytes = new ByteArrayOutputStream();
        try {
            PrintStream out = new PrintStream(outBytes, true, "UTF-8");
            PrintStream err = new PrintStream(errBytes, true, "UTF-8");
            lastGate = gates.get();
            return CryptoCli.execute(args, () -> {
                if (terminal == null) throw new CryptoCli.CliException("NO_TERMINAL");
                return terminal;
            }, out, err, lastGate);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** @return 터미널 없이 실행한 종료 코드 */
    public int run(String... args) {
        return run(null, args);
    }

    /** @return 마지막 실행의 표준 출력 */
    public String out() {
        return new String(outBytes.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    }

    /** @return 마지막 실행의 표준 오류 */
    public String err() {
        return new String(errBytes.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    }

    @Override
    public void close() throws Exception {
        jvm.close();
        configPath.close();
    }
}
