package io.javacryptokit;

import io.javacryptokit.config.CryptoSettings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * 테스트 전용: 빌드 결과(클래스·리소스 폴더)로 배포 JAR와 같은 구조의 실행 가능한 JAR를 만들고, 별도 JVM으로 {@code java -jar}
 * 실행해 결과를 돌려준다(실제 사용자가 내려받은 JAR로 실행하는 상황 재현). AWS SDK·JUnit은 넣지 않는다.
 */
public final class TestJars {
    /** 프로세스 실행 결과. */
    public static final class Run {
        public final int exit;
        public final String out;
        public final String err;

        Run(int exit, String out, String err) {
            this.exit = exit;
            this.out = out;
            this.err = err;
        }

        @Override
        public String toString() {
            return "exit=" + exit + "\n--- out ---\n" + out + "\n--- err ---\n" + err;
        }
    }

    private TestJars() { }

    /**
     * 배포 JAR와 같은 Manifest(Main-Class, Implementation-Title/Version, Build-Time, Settings-Fingerprint)로 JAR를 만든다.
     *
     * @param jar 만들 JAR 경로
     * @return jar
     */
    public static Path build(Path jar) throws IOException {
        Path classes = location(CryptoSettings.class);
        Path resources = location(CryptoSettings.class.getResource("/java-crypto-kit.properties"), "java-crypto-kit.properties");
        Map<String, Path> entries = new TreeMap<>();
        collect(classes, entries);
        collect(resources, entries);
        byte[] settings = Files.readAllBytes(resources.resolve("java-crypto-kit.properties"));
        Manifest manifest = new Manifest();
        Attributes main = manifest.getMainAttributes();
        main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
        main.put(Attributes.Name.MAIN_CLASS, "io.javacryptokit.cli.CryptoCli");
        main.put(Attributes.Name.IMPLEMENTATION_TITLE, "java-crypto-kit");
        main.put(Attributes.Name.IMPLEMENTATION_VERSION, "0.1.0");
        main.putValue("Build-Time", "2026-11-21T00:00:00Z");
        main.putValue("Settings-Fingerprint", "sha256:" + hex(sha256(settings)).substring(0, 16));
        try (OutputStream file = Files.newOutputStream(jar); JarOutputStream out = new JarOutputStream(file, manifest)) {
            for (Map.Entry<String, Path> entry : entries.entrySet()) {
                JarEntry jarEntry = new JarEntry(entry.getKey());
                out.putNextEntry(jarEntry);
                if (!entry.getKey().endsWith("/")) Files.copy(entry.getValue(), out);
                out.closeEntry();
            }
        }
        return jar;
    }

    /**
     * 별도 JVM으로 실행한다(UTF-8 출력, 지정한 언어 Locale). 설정 경로 환경변수는 지운다.
     *
     * @param classpathOrJar null이면 java -jar jar, 아니면 -cp 값
     * @param jar            -jar로 실행할 JAR(classpathOrJar가 null일 때)
     * @param jvmArgs        추가 JVM 인자(-D 등)
     * @param args           명령 인자
     */
    public static Run run(Path jar, List<String> jvmArgs, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-Dfile.encoding=UTF-8");
        command.add("-Dstdout.encoding=UTF-8");
        command.add("-Dstderr.encoding=UTF-8");
        command.add("-Dsun.stdout.encoding=UTF-8");
        command.add("-Dsun.stderr.encoding=UTF-8");
        command.addAll(jvmArgs);
        command.add("-jar");
        command.add(jar.toString());
        command.addAll(Arrays.asList(args));
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.environment().remove(CryptoSettings.CONFIG_FILE_ENV);
        builder.redirectInput(ProcessBuilder.Redirect.PIPE);
        Process process = builder.start();
        process.getOutputStream().close();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread outReader = pump(process.getInputStream(), out);
        Thread errReader = pump(process.getErrorStream(), err);
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("timeout");
        }
        outReader.join();
        errReader.join();
        return new Run(process.exitValue(), new String(out.toByteArray(), StandardCharsets.UTF_8),
                new String(err.toByteArray(), StandardCharsets.UTF_8));
    }

    private static Thread pump(InputStream in, ByteArrayOutputStream sink) {
        Thread thread = new Thread(() -> {
            byte[] buffer = new byte[8192];
            int read;
            try {
                while ((read = in.read(buffer)) != -1) sink.write(buffer, 0, read);
            } catch (IOException ignored) {
                // 프로세스 종료
            }
        });
        thread.start();
        return thread;
    }

    private static Path location(Class<?> type) {
        try {
            return Paths.get(type.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Path location(java.net.URL resource, String name) {
        try {
            return Paths.get(resource.toURI()).getParent();
        } catch (URISyntaxException e) {
            throw new IllegalStateException(name, e);
        }
    }

    private static void collect(Path root, Map<String, Path> entries) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root)) entries.put(root.relativize(dir).toString().replace('\\', '/') + "/", dir);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                entries.put(root.relativize(file).toString().replace('\\', '/'), file);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) text.append(String.format("%02x", b));
        return text.toString();
    }
}
