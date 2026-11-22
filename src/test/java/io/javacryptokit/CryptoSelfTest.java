package io.javacryptokit;

import io.javacryptokit.config.CryptoSettings;

import io.javacryptokit.core.CryptoService;

import io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.sql.DataSource;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory;

/**
 * 외부 DB·Tomcat 없이 실행하는 자체 검증 프로그램이다. {@code gradlew check}(및 {@code build})가 {@code selfTest}
 * 태스크로 자동 실행한다.
 *
 * <p>외부 테스트 라이브러리 없이 {@code main}에서 항목을 순서대로 검사한다. 하나라도 실패하면 {@link AssertionError}나
 * 예외로 즉시 종료(종료 코드 1)되어 빌드가 실패한다.</p>
 *
 * <p><b>검증 범위</b></p>
 * <ul>
 *   <li>기존 14개 항목: 암복호화·한글 UTF-8·난수 IV·암호문 변조·버전/평문 오인 거부·JNDI 위임·일반 속성 보존·
 *       원본 Reference 불변·평문 비밀번호 거부·외부 키 파일·키ID 불일치·같은 키ID의 다른 키</li>
 *   <li>보안 보강 항목: IV·인증 태그 변조, 잘린 암호문, 비정상 입력(과도한 길이·Base64 오류·필드 수·빈 IV),
 *       AAD(키ID 바꿔치기), 설정 허용값, 외부 설정·키 누락 시 내장 키로 돌아가지 않음(Fail Closed), 키 길이,
 *       빈 평문, Factory의 비밀번호 누락·사용자명 복호화·타입 검사·예외 정제(원인·입력값 미포함)</li>
 *   <li>Tomcat 방식 로딩: Resource의 {@code factory} 클래스 이름({@code io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory})으로
 *       로딩해도 같은 결과로 위임되는지</li>
 *   <li>JVM 개별 속성: {@code -D} 하나만으로 적용, 정책({@code crypto.jvm.override.enabled=false})이면 무시,
 *       {@code -D}로 정책 우회 불가, 키 원문 {@code -D} 거부(실제 System 속성은 바꾸지 않고 조회 함수를 주입)</li>
 * </ul>
 *
 * <p>실제 Tomcat 기동과 DB 접속은 검증하지 않는다. Tomcat DBCP2 Factory는 같은 이름의 모의 클래스
 * ({@link BasicDataSourceFactory})로 대체한다. 테스트 값은 모두 더미이며, 실패 메시지에는 평문·키·암호문을 넣지 않는다.</p>
 */
public final class CryptoSelfTest {
    /** 통과한 검사 항목 수. 마지막에 요약으로 출력한다. */
    private static int passed = 0;

    /**
     * 모든 검사를 실행한다.
     *
     * @param args 사용하지 않음
     * @throws Exception 검사 실패 또는 예상하지 못한 오류(빌드 실패로 이어진다)
     */
    public static void main(String[] args) throws Exception {
        // ===== 기존 1~3: 기본 암복호화 =====
        CryptoSettings defaultSettings = CryptoSettings.load(null);
        String first = CryptoService.of(defaultSettings).encryptText("비밀번호:Ω!".toCharArray());
        String second = CryptoService.of(defaultSettings).encryptText("비밀번호:Ω!".toCharArray());
        check(!first.equals(second), "난수 IV로 암호문이 매번 달라야 한다");
        check(first.startsWith("ENC[v1:default:"), "암호문 형식/키 식별자");
        check("비밀번호:Ω!".equals(CryptoService.of(defaultSettings).decryptText(first)), "UTF-8 복호화");

        // ===== 기존 4~6: 변조·형식 오류 거부 =====
        // GCM 인증 태그를 변조하면 평문이 반환되지 않아야 한다.
        // Base64URL 마지막 글자의 패딩 비트만 변경하면 실제 바이트가 그대로일 수 있다.
        // 따라서 암호문 필드의 바이너리 첫 바이트를 직접 바꿔 인증 태그가 실패하는지 검사한다.
        String[] envelopeParts = first.substring(4, first.length() - 1).split(":", -1);
        byte[] changedBytes = Base64.getUrlDecoder().decode(envelopeParts[3]);
        changedBytes[0] ^= 0x01;
        envelopeParts[3] = Base64.getUrlEncoder().withoutPadding().encodeToString(changedBytes);
        java.util.Arrays.fill(changedBytes, (byte) 0);
        String tampered = "ENC[" + String.join(":", envelopeParts) + "]";
        fails(() -> CryptoService.of(defaultSettings).decryptText(tampered), "암호문 변조 탐지");
        fails(() -> CryptoService.of(defaultSettings).decryptText("ENC[v0:default:aa:bb]"), "알 수 없는 버전 차단");
        fails(() -> CryptoService.of(defaultSettings).decryptText("plain"), "평문을 암호문으로 오인하지 않음");

        // ===== 기존 7~11: JNDI Factory 위임 =====
        // 실제 운영 DB 접속 대신 모의 DBCP2 Factory로 위임 경로를 확인한다.
        Reference resource = new Reference("javax.sql.DataSource");
        resource.add(new StringRefAddr("username", "appuser"));
        resource.add(new StringRefAddr("password", first));
        resource.add(new StringRefAddr("url", "jdbc:fake:memory"));
        Object dataSource = new EncryptedDataSourceFactory().getObjectInstance(resource, null, null, null);
        check(dataSource instanceof DataSource, "JNDI DataSource 반환");
        check("비밀번호:Ω!".equals(BasicDataSourceFactory.lastPassword), "공식 Pool에 복호화된 비밀번호 위임");
        check("appuser".equals(BasicDataSourceFactory.lastUsername)
                && "jdbc:fake:memory".equals(BasicDataSourceFactory.lastUrl), "일반 Pool 설정 보존");
        check(first.equals(((StringRefAddr) resource.get("password")).getContent()), "원본 JNDI 참조 불변성");

        Reference plainPassword = new Reference("javax.sql.DataSource");
        plainPassword.add(new StringRefAddr("username", "appuser"));
        plainPassword.add(new StringRefAddr("password", "never-accept-plain"));
        fails(() -> new EncryptedDataSourceFactory().getObjectInstance(plainPassword, null, null, null), "평문 비밀번호 차단");

        // ===== 기존 12~14: 외부 키 파일 =====
        // 별도 외부 키 파일을 만들고 기본 키와 혼동하지 않는지 검증한다.
        Path keyFile = Files.createTempFile("java-crypto-kit-test-key", ".key");
        Path props = Files.createTempFile("java-crypto-kit-test-config", ".properties");
        try {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            Files.write(keyFile, Base64.getEncoder().encode(random));
            java.util.Arrays.fill(random, (byte) 0);
            // Properties에서 역슬래시는 이스케이프 문자이므로 Windows 경로는 '/'로 바꿔 기록한다.
            Files.write(props, ("crypto.key.source=file\n"
                    + "crypto.key.id=test01\n"
                    + "crypto.key.file=" + propertiesPath(keyFile) + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            CryptoSettings fileSettings = CryptoSettings.load(props.toString());
            String encrypted = CryptoService.of(fileSettings).encryptText("외부 키 테스트".toCharArray());
            check("외부 키 테스트".equals(CryptoService.of(fileSettings).decryptText(encrypted)), "외부 키 파일 사용");
            fails(() -> CryptoService.of(defaultSettings).decryptText(encrypted), "다른 키 식별자 차단");
            // 동일한 키 식별자를 쓰더라도 실제 키가 다르면 GCM 인증이 실패해야 한다.
            byte[] different = new byte[32];
            new SecureRandom().nextBytes(different);
            Files.write(keyFile, Base64.getEncoder().encode(different));
            java.util.Arrays.fill(different, (byte) 0);
            fails(() -> CryptoService.of(fileSettings).decryptText(encrypted), "동일 키ID의 잘못된 키 차단");
        } finally {
            Files.deleteIfExists(keyFile);
            Files.deleteIfExists(props);
        }

        // ===== Tomcat 방식 로딩: Resource의 factory 클래스 이름으로 찾아 public 기본 생성자로 만든다 =====
        javax.naming.spi.ObjectFactory byName = (javax.naming.spi.ObjectFactory)
                Class.forName("io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory").getConstructor().newInstance();
        BasicDataSourceFactory.lastPassword = null;
        Object byNameDataSource = byName.getObjectInstance(resource, null, null, null);
        check(byNameDataSource instanceof DataSource && "비밀번호:Ω!".equals(BasicDataSourceFactory.lastPassword),
                "factory 클래스 이름으로 로딩해도 같은 위임 동작");

        // ===== 보안 보강 항목 =====
        cipherSecurityChecks(defaultSettings, first);
        settingsAndKeyChecks();
        jvmOverrideChecks();
        factorySecurityChecks(defaultSettings, first);

        System.out.println("CryptoSelfTest PASS: " + passed + "개 항목 (실제 Tomcat/DB 통합 테스트는 별도)");
    }

    /**
     * 암호문 변조와 비정상 입력이 모두 {@link GeneralSecurityException}으로 거부되는지(Fail Closed) 확인한다.
     *
     * @param defaultSettings JAR 기본 설정(공개 내장 키, 키ID default)
     * @param envelope        defaultSettings로 만든 정상 암호문
     */
    private static void cipherSecurityChecks(CryptoSettings defaultSettings, String envelope) throws Exception {
        String[] parts = envelopeParts(envelope);
        // IV를 1비트 바꾸면 다른 IV로 계산되어 인증 태그 검증이 실패해야 한다.
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText(withPart(parts, 2, flipBit(parts[2], 0))), "IV 변조 탐지");
        // 암호문 마지막 바이트(인증 태그 영역)를 바꾸면 태그 검증이 실패해야 한다.
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText(withPart(parts, 3, flipBit(parts[3], -1))), "인증 태그 변조 탐지");
        // 인증 태그(16바이트)보다 짧은 암호문은 복호화를 시도하기 전에 길이 검사에서 거부해야 한다.
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText(withPart(parts, 3, base64Url(new byte[15]))), "잘린 암호문 거부");
        // 16,384자를 넘는 입력은 형식 검사 첫 단계에서 거부해야 한다(자원 낭비 방지).
        StringBuilder huge = new StringBuilder("ENC[v1:default:");
        while (huge.length() <= 16384) huge.append('A');
        huge.append(":AAAA]");
        fails(GeneralSecurityException.class, () -> CryptoService.of(defaultSettings).decryptText(huge.toString()), "과도한 길이 입력 거부");
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText("ENC[v1:default:%%%%:%%%%]"), "Base64 형식 오류 거부");
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText(envelope.replace("]", ":extra]")), "필드 수 오류 거부");
        fails(GeneralSecurityException.class,
                () -> CryptoService.of(defaultSettings).decryptText(withPart(parts, 2, "")), "빈 IV 거부");
        // AAD 검증: 같은 키를 다른 키ID(other01)로 설정한 환경에서 봉투의 키ID만 바꿔치기하면,
        // 키ID 비교는 통과하지만 AAD가 달라 인증 태그 검증에서 실패해야 한다.
        Path aliasConfig = writeProperties("crypto.key.id=other01");
        try {
            CryptoSettings sameKeyOtherId = CryptoSettings.load(aliasConfig.toString());
            fails(GeneralSecurityException.class,
                    () -> CryptoService.of(sameKeyOtherId).decryptText(withPart(parts, 1, "other01")), "키ID 바꿔치기(AAD) 탐지");
        } finally {
            Files.deleteIfExists(aliasConfig);
        }
        // 빈 평문은 암호화하지 않는다.
        fails(CredentialCryptoException.class,
                () -> CryptoService.of(defaultSettings).encryptText(new char[0]), "빈 평문 암호화 거부");
    }

    /**
     * 설정 허용값 검증과, 외부 설정·외부 키 문제 시 내장 키로 돌아가지 않는지(Fail Closed) 확인한다.
     */
    private static void settingsAndKeyChecks() throws Exception {
        // 설정만으로 알고리즘·정책·Pool Factory·키ID 형식·키 공급 방식을 바꿀 수 없어야 한다.
        failsWithConfig(IllegalArgumentException.class, "crypto.algorithm=AES/CBC/PKCS5Padding", "다른 암호 알고리즘 설정 거부");
        failsWithConfig(IllegalArgumentException.class, "crypto.require.encrypted.password=false", "평문 허용 정책 거부");
        failsWithConfig(IllegalArgumentException.class, "crypto.pool.factory=com.example.UnknownFactory", "승인되지 않은 Pool Factory 거부");
        failsWithConfig(IllegalArgumentException.class, "crypto.key.id=bad id!", "잘못된 키ID 형식 거부");
        failsWithConfig(IllegalArgumentException.class, "crypto.key.source=http", "지원하지 않는 키 공급 방식 거부");

        // 지정한 외부 설정 파일이 없으면 내장 기본값으로 진행하지 않고 실패해야 한다.
        Path missingConfig = Files.createTempFile("java-crypto-kit-missing", ".properties");
        Files.delete(missingConfig);
        fails(IOException.class, () -> CryptoSettings.load(missingConfig.toString()), "외부 설정 누락 시 기본값 fallback 없음");

        // file 방식인데 키 파일이 없으면 내장 키로 암호화하지 않고 실패해야 한다.
        Path missingKey = Files.createTempFile("java-crypto-kit-missing", ".key");
        Files.delete(missingKey);
        Path fileConfig = writeProperties("crypto.key.source=file", "crypto.key.file=" + propertiesPath(missingKey));
        try {
            CryptoSettings fileSettings = CryptoSettings.load(fileConfig.toString());
            fails(CredentialCryptoException.class,
                    () -> CryptoService.of(fileSettings).encryptText("dummy".toCharArray()), "키 파일 누락 시 내장 키 fallback 없음");
        } finally {
            Files.deleteIfExists(fileConfig);
        }

        // env 방식인데 환경변수가 없으면 실패해야 한다. 우연히 존재하지 않도록 난수로 변수 이름을 만든다.
        String unsetName = "JAVA_CRYPTO_KIT_SELFTEST_UNSET_" + Integer.toHexString(new SecureRandom().nextInt());
        Path envConfig = writeProperties("crypto.key.source=env", "crypto.key.env=" + unsetName);
        try {
            CryptoSettings envSettings = CryptoSettings.load(envConfig.toString());
            fails(CredentialCryptoException.class,
                    () -> CryptoService.of(envSettings).encryptText("dummy".toCharArray()), "키 환경변수 누락 시 fallback 없음");
        } finally {
            Files.deleteIfExists(envConfig);
        }

        // AES-256만 허용하므로 16바이트(AES-128) 키 파일은 거부해야 한다.
        Path shortKey = Files.createTempFile("java-crypto-kit-short", ".key");
        Path shortConfig = null;
        try {
            Files.write(shortKey, Base64.getEncoder().encode(new byte[16]));
            shortConfig = writeProperties("crypto.key.source=file", "crypto.key.file=" + propertiesPath(shortKey));
            CryptoSettings shortSettings = CryptoSettings.load(shortConfig.toString());
            fails(CredentialCryptoException.class,
                    () -> CryptoService.of(shortSettings).encryptText("dummy".toCharArray()), "32바이트가 아닌 키 거부");
        } finally {
            Files.deleteIfExists(shortKey);
            if (shortConfig != null) Files.deleteIfExists(shortConfig);
        }
    }

    /**
     * JVM 개별 속성(-D) 규칙을 확인한다. 실제 System 속성을 바꾸지 않도록 조회 함수({@code Map::get})를 주입한다.
     */
    private static void jvmOverrideChecks() throws Exception {
        // 외부 Properties 없이 -Dcrypto.warning.enabled=false 하나만으로 경고를 끄고, 키는 기존 embedded를 그대로 쓴다.
        Map<String, String> warningOff = new HashMap<>();
        warningOff.put("crypto.warning.enabled", "false");
        CryptoSettings jvmOnly = CryptoSettings.load(null, warningOff::get, name -> null);
        check(!jvmOnly.warningEnabled() && "embedded".equals(jvmOnly.keySource()), "JVM 속성 하나만으로 경고 끄기");

        // 외부 Properties의 정책 false는 JVM 속성을 막고, -D로 정책 자체를 다시 켤 수도 없다.
        Path policyOff = writeProperties("crypto.jvm.override.enabled=false", "crypto.warning.enabled=true");
        try {
            CryptoSettings blocked = CryptoSettings.load(policyOff.toString(), warningOff::get, name -> null);
            check(blocked.warningEnabled(), "정책 false이면 JVM 속성 무시");
            Map<String, String> bypass = new HashMap<>(warningOff);
            bypass.put("crypto.jvm.override.enabled", "true");
            CryptoSettings stillBlocked = CryptoSettings.load(policyOff.toString(), bypass::get, name -> null);
            check(stillBlocked.warningEnabled() && !stillBlocked.jvmOverrideEnabled(), "-D로 정책 우회 불가");
        } finally {
            Files.deleteIfExists(policyOff);
        }

        // 키 원문은 -D로 받지 않는다(무시하지 않고 오류로 중단).
        Map<String, String> rawKey = new HashMap<>();
        rawKey.put("crypto.key.embedded", base64Url(new byte[32]));
        fails(IllegalArgumentException.class, () -> CryptoSettings.load(null, rawKey::get, name -> null), "키 원문 -D 거부");

        // 지정했지만 비어 있는 설정 경로(-Dcrypto.config.file=)는 내장 키로 바꾸지 않고 실패해야 한다.
        Map<String, String> blankPath = new HashMap<>();
        blankPath.put(CryptoSettings.CONFIG_FILE_PROPERTY, " ");
        fails(IllegalArgumentException.class, () -> CryptoSettings.load(null, blankPath::get, name -> null),
                "빈 외부 설정 경로 거부");

        // 키 공급 이름 오타(-Dcrypto.key.soruce=file)는 무시하면 공개 내장 키로 동작하므로 실패해야 한다.
        Map<String, String> typo = new HashMap<>();
        typo.put("crypto.key.soruce", "file");
        fails(IllegalArgumentException.class, () -> CryptoSettings.load(null, typo::get, name -> null, typo.keySet()),
                "JVM 속성 키 공급 이름 오타 거부");

        // 외부 Properties의 오타 항목은 조용히 무시하지 않고 거부해야 한다(경고를 껐다고 착각하는 사고 방지).
        failsWithConfig(IllegalArgumentException.class, "crypto.warnning.enabled=false", "외부 설정 오타 항목 거부");
    }

    /**
     * Tomcat 연동 Factory의 입력 검증, 사용자명 선택 암호화, 예외 정제를 확인한다.
     *
     * @param defaultSettings JAR 기본 설정
     * @param envelope        defaultSettings로 만든 정상 비밀번호 암호문
     */
    private static void factorySecurityChecks(CryptoSettings defaultSettings, String envelope) throws Exception {
        // password 속성이 없으면 "암호문 필수" 정책을 우회한 것이므로 거부해야 한다.
        fails(NamingException.class, () -> new EncryptedDataSourceFactory()
                .getObjectInstance(dataSourceRef("appuser", null), null, null, null), "password 누락 거부");
        // 사용자명 암호화(선택 기능): 암호문이면 복호화해 Pool에 전달해야 한다.
        String encryptedUser = CryptoService.of(defaultSettings).encryptText("dummy-user".toCharArray());
        new EncryptedDataSourceFactory().getObjectInstance(dataSourceRef(encryptedUser, envelope), null, null, null);
        check("dummy-user".equals(BasicDataSourceFactory.lastUsername), "암호화된 사용자명 복호화 위임");
        // DataSource가 아닌 타입과 Reference가 아닌 객체는 처리하지 않아야 한다.
        Reference wrongType = new Reference("javax.sql.XADataSource");
        wrongType.add(new StringRefAddr("password", envelope));
        fails(NamingException.class, () -> new EncryptedDataSourceFactory()
                .getObjectInstance(wrongType, null, null, null), "DataSource 이외 타입 거부");
        fails(NamingException.class, () -> new EncryptedDataSourceFactory()
                .getObjectInstance("not-a-reference", null, null, null), "Reference 이외 객체 거부");
        // 복호화 실패 예외에는 원인(cause)과 입력 암호문이 들어 있지 않아야 한다(로그 노출 방지).
        String[] parts = envelopeParts(envelope);
        String tampered = withPart(parts, 3, flipBit(parts[3], -1));
        NamingException decryptFailure = expectNamingException(dataSourceRef("appuser", tampered));
        check(decryptFailure.getCause() == null
                && decryptFailure.getMessage().startsWith("[java-crypto-kit]")
                && !decryptFailure.getMessage().contains(tampered), "복호화 실패 예외 정제(원인·입력값 미포함)");
        // 평문 비밀번호를 거부할 때도 예외 메시지에 그 평문이 들어 있지 않아야 한다.
        NamingException plainRejected = expectNamingException(dataSourceRef("appuser", "dummy-plain-password"));
        check(plainRejected.getCause() == null
                && !plainRejected.getMessage().contains("dummy-plain-password"), "평문 거부 예외에 평문 미포함");
    }

    /** 조건이 참이면 통과 수를 늘리고, 거짓이면 설명만 담은 AssertionError로 즉시 실패시킨다. */
    private static void check(boolean good, String description) {
        if (!good) throw new AssertionError("FAIL: " + description);
        passed++;
    }

    /** 검사 대상 작업. 람다로 전달하며 검사 예외를 던질 수 있다. */
    private interface Throwing { void run() throws Exception; }

    /**
     * 작업이 예외(종류 무관)로 실패해야 통과한다. 기존 14개 항목에서 사용하는 원래 검사 방식이다.
     * 예외 없이 끝나면 AssertionError로 실패한다.
     */
    private static void fails(Throwing task, String description) throws Exception {
        try {
            task.run();
            throw new AssertionError("FAIL: " + description);
        } catch (AssertionError e) { throw e; }
        catch (Exception expected) { passed++; }
    }

    /**
     * 작업이 지정한 종류의 예외로 실패해야 통과한다. 엉뚱한 이유(예: 테스트 파일 오류)로 실패한 경우를 통과로
     * 착각하지 않도록 보강 항목에서 사용한다. 실패 메시지에는 예외 종류만 넣는다.
     */
    private static void fails(Class<? extends Exception> expected, Throwing task, String description) throws Exception {
        try {
            task.run();
        } catch (Exception ex) {
            if (!expected.isInstance(ex)) {
                throw new AssertionError("FAIL: " + description + " (예상 " + expected.getSimpleName()
                        + ", 실제 " + ex.getClass().getSimpleName() + ")");
            }
            passed++;
            return;
        }
        throw new AssertionError("FAIL: " + description + " (예외가 발생하지 않음)");
    }

    /** 한 줄짜리 외부 설정이 로딩 단계에서 지정한 예외로 거부되는지 확인한다. */
    private static void failsWithConfig(Class<? extends Exception> expected, String line, String description) throws Exception {
        Path config = writeProperties(line);
        try {
            fails(expected, () -> CryptoSettings.load(config.toString()), description);
        } finally {
            Files.deleteIfExists(config);
        }
    }

    /** Factory가 NamingException으로 거부해야 하는 Reference를 넣고, 발생한 예외를 돌려준다. */
    private static NamingException expectNamingException(Reference reference) throws Exception {
        try {
            new EncryptedDataSourceFactory().getObjectInstance(reference, null, null, null);
        } catch (NamingException expected) {
            return expected;
        }
        throw new AssertionError("FAIL: NamingException이 발생해야 한다");
    }

    /** 테스트용 DataSource Reference를 만든다. null인 속성은 넣지 않는다. */
    private static Reference dataSourceRef(String username, String password) {
        Reference reference = new Reference("javax.sql.DataSource");
        if (username != null) reference.add(new StringRefAddr("username", username));
        if (password != null) reference.add(new StringRefAddr("password", password));
        reference.add(new StringRefAddr("url", "jdbc:fake:memory"));
        return reference;
    }

    /** 주어진 줄들로 임시 외부 설정 파일(UTF-8)을 만든다. 호출자가 삭제한다. */
    private static Path writeProperties(String... lines) throws IOException {
        Path file = Files.createTempFile("java-crypto-kit-test-config", ".properties");
        Files.write(file, (String.join("\n", lines) + "\n").getBytes(StandardCharsets.UTF_8));
        return file;
    }

    /**
     * Properties 파일에 기록할 경로 문자열을 만든다. Properties에서 역슬래시는 이스케이프 문자라서
     * Windows 경로를 그대로 쓰면 {@code C:\Users} 같은 경로가 깨지므로 구분자를 '/'로 바꾼다.
     */
    private static String propertiesPath(Path path) {
        return path.toAbsolutePath().toString().replace(File.separatorChar, '/');
    }

    /** {@code ENC[}와 {@code ]}를 뗀 뒤 ':'로 나눈 네 필드를 돌려준다. */
    private static String[] envelopeParts(String envelope) {
        return envelope.substring(4, envelope.length() - 1).split(":", -1);
    }

    /** 지정한 필드만 바꾼 새 암호문 문자열을 만든다. 원본 배열은 바꾸지 않는다. */
    private static String withPart(String[] parts, int index, String value) {
        String[] copy = parts.clone();
        copy[index] = value;
        return "ENC[" + String.join(":", copy) + "]";
    }

    /**
     * Base64URL 값의 지정 바이트(음수면 끝에서부터)의 최하위 비트를 뒤집는다.
     * 디코딩한 실제 바이트를 바꾸므로 Base64 패딩 비트만 바뀌는 착시가 없다.
     */
    private static String flipBit(String base64Url, int index) {
        byte[] raw = Base64.getUrlDecoder().decode(base64Url);
        int position = index >= 0 ? index : raw.length + index;
        raw[position] ^= 0x01;
        return base64Url(raw);
    }

    /** 바이트 배열을 봉투 형식과 같은 Base64URL(패딩 없음)로 바꾼다. */
    private static String base64Url(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }
}
