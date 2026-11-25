package io.javacryptokit;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 시험 전용: 실행 중인 JDK의 keytool로 시험용 CA·서버 인증서를 그때그때 만든다(저장소에 인증서·개인키를 두지 않음). 저장소 비밀번호는
 * 시험용 더미 값이며 임시 폴더 밖으로 나가지 않는다.
 */
public final class TestKeytool {
    /** 시험용 더미 저장소 비밀번호(운영 값 아님). */
    public static final String STORE_PASS = "dummy-store-pass";

    private TestKeytool() { }

    /** 실행 중인 JDK의 keytool 실행(실패하면 예외). */
    public static void run(Path dir, String... args) throws IOException, InterruptedException {
        runWith(System.getProperty("java.home"), dir, args);
    }

    /** 지정한 Java 설치(JAVA_HOME 또는 그 안의 jre)의 keytool 실행(JDK 간 키 저장소 호환 시험용). */
    public static void runWith(String javaHome, Path dir, String... args) throws IOException, InterruptedException {
        File keytool = new File(javaHome, "bin" + File.separator + (isWindows() ? "keytool.exe" : "keytool"));
        if (!keytool.exists()) keytool = new File(new File(javaHome).getParentFile(), "bin" + File.separator + (isWindows() ? "keytool.exe" : "keytool"));
        List<String> command = new ArrayList<>();
        command.add(keytool.getAbsolutePath());
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true).start();
        byte[] output = readAll(process);
        if (!process.waitFor(120, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IOException("keytool failed: " + new String(output, StandardCharsets.UTF_8));
        }
    }

    /**
     * 루트 CA(ca.p12, ca.pem)와 그 CA가 발급한 서버 인증서(server.p12에 키·체인, server.pem)를 만든다.
     *
     * @param dir     작업 폴더
     * @param sanList 서버 인증서 SAN(예: {@code dns:localhost,ip:127.0.0.1})
     */
    public static void caAndServer(Path dir, String sanList) throws IOException, InterruptedException {
        String[] store = {"-storetype", "PKCS12", "-storepass", STORE_PASS, "-keypass", STORE_PASS};
        run(dir, concat(new String[] {"-genkeypair", "-alias", "ca", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=JCK Test Root",
            "-sigalg", "SHA256withRSA", "-ext", "bc:c", "-validity", "3650", "-keystore", "ca.p12"}, store));
        run(dir, concat(new String[] {"-exportcert", "-alias", "ca", "-rfc", "-file", "ca.pem", "-keystore", "ca.p12"}, store));
        run(dir, concat(new String[] {"-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=jck-test-server",
            "-validity", "365", "-keystore", "server.p12"}, store));
        run(dir, concat(new String[] {"-certreq", "-alias", "server", "-file", "server.csr", "-keystore", "server.p12"}, store));
        run(dir, concat(new String[] {"-gencert", "-alias", "ca", "-infile", "server.csr", "-outfile", "server.pem", "-rfc", "-sigalg", "SHA256withRSA",
            "-ext", "SAN=" + sanList, "-ext", "KU=digitalSignature,keyEncipherment", "-ext", "EKU=serverAuth", "-validity", "365",
            "-keystore", "ca.p12"}, store));
        run(dir, concat(new String[] {"-importcert", "-alias", "ca", "-file", "ca.pem", "-noprompt", "-keystore", "server.p12"}, store));
        run(dir, concat(new String[] {"-importcert", "-alias", "server", "-file", "server.pem", "-keystore", "server.p12"}, store));
        Files.deleteIfExists(dir.resolve("server.csr"));
    }

    private static String[] concat(String[] a, String[] b) {
        String[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static byte[] readAll(Process process) throws IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = process.getInputStream().read(buffer)) != -1) out.write(buffer, 0, read);
        return out.toByteArray();
    }
}
