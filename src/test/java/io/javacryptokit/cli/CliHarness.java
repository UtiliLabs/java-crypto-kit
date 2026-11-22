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
 */
public final class CliHarness implements AutoCloseable {
    private final AutoCloseable configPath;
    private final AutoCloseable jvm;
    private ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    private ByteArrayOutputStream errBytes = new ByteArrayOutputStream();

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
        this.configPath = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
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
            return CryptoCli.execute(args, () -> {
                if (terminal == null) throw new CryptoCli.CliException("NO_TERMINAL");
                return terminal;
            }, out, err);
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
