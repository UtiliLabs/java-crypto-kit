package io.javacryptokit.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 다국어: 번들 일치, 언어 결정 규칙(기본 ko·auto·미지원 Locale·--lang·-D), 라이브러리 전체 적용(Java API·Tomcat Factory). */
class I18nTest {
    @TempDir
    Path dir;

    private static Properties bundle(String name) throws Exception {
        Properties properties = new Properties();
        try (InputStream in = I18nTest.class.getResourceAsStream("/io/javacryptokit/i18n/" + name + ".properties");
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    @Test
    void englishAndKoreanBundlesHaveTheSameKeysAndPlaceholders() throws Exception {
        Set<String> all = new TreeSet<>();
        for (String base : new String[]{"core", "cli", "settings"}) {
            Properties en = bundle(base);
            Properties ko = bundle(base + "_ko");
            assertEquals(new TreeSet<>(en.stringPropertyNames()), new TreeSet<>(ko.stringPropertyNames()), "키 불일치: " + base);
            Pattern placeholder = Pattern.compile("\\{[0-9]}");
            for (String key : en.stringPropertyNames()) {
                assertEquals(placeholders(placeholder, en.getProperty(key)), placeholders(placeholder, ko.getProperty(key)),
                        "자리표시자 불일치: " + key);
                assertTrue(all.add(key), "번들 사이 중복 키: " + key);
                assertFalse(en.getProperty(key).trim().isEmpty(), "빈 문구: " + key);
            }
        }
    }

    private static Set<String> placeholders(Pattern pattern, String text) {
        Set<String> found = new TreeSet<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) found.add(m.group());
        return found;
    }

    @Test
    void localeSelectionDefaultKoreanAndUnsupportedLocalesFallBackToEnglish() {
        assertEquals(Messages.Language.KO, Messages.Language.fromLocale(Locale.KOREA));
        assertEquals(Messages.Language.KO, Messages.Language.fromLocale(new Locale("ko")));
        assertEquals(Messages.Language.EN, Messages.Language.fromLocale(Locale.US));
        assertEquals(Messages.Language.EN, Messages.Language.fromLocale(Locale.JAPAN), "미지원 언어는 영어");
        assertEquals(Messages.Language.EN, Messages.Language.fromLocale(Locale.FRANCE));
        assertEquals(null, Messages.Language.fromCode("KO"), "대소문자를 추측하지 않는다");
        assertEquals("a b {1}", Messages.format("{0} b {1}", new Object[]{"a"}));
        assertEquals("it's", Messages.format("{0}'s", new Object[]{"it"}), "작은따옴표를 해석하지 않는다");
    }

    @Test
    void settingsLanguageDefaultIsKoreanAndAutoFollowsTheLocale() throws Exception {
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.US);
            CryptoSettings byDefault = TestSupport.isolatedSettings(TestSupport.writeConfig(dir, "empty.properties"));
            assertEquals(Messages.Language.KO, byDefault.language(), "설정이 없으면(기본값 ko) Locale과 무관하게 한국어");
            CryptoSettings auto = TestSupport.isolatedSettings(TestSupport.writeConfig(dir, "auto.properties", "crypto.lang=auto"));
            assertEquals(Messages.Language.EN, auto.language(), "auto + 영어 Locale");
            Locale.setDefault(Locale.JAPAN);
            assertEquals(Messages.Language.EN, TestSupport.isolatedSettings(dir.resolve("auto.properties")).language(),
                    "auto + 미지원 Locale은 영어");
            Locale.setDefault(Locale.KOREA);
            assertEquals(Messages.Language.KO, TestSupport.isolatedSettings(dir.resolve("auto.properties")).language());
            assertEquals(Messages.Language.EN,
                    TestSupport.isolatedSettings(TestSupport.writeConfig(dir, "en.properties", "crypto.lang=en")).language());
            assertThrows(IllegalArgumentException.class,
                    () -> TestSupport.isolatedSettings(TestSupport.writeConfig(dir, "bad.properties", "crypto.lang=jp")));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    void javaApiExceptionsUseTheConfiguredLanguage() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        Path en = TestSupport.writeConfig(dir, "en.properties", "crypto.lang=en");
        CredentialCryptoException english = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(en).decryptText("not-a-token"));
        assertTrue(english.getMessage().contains("The ciphertext format is invalid") && english.getMessage().contains("Action:"),
                english.getMessage());
        assertEquals(CredentialCryptoException.Reason.INVALID_TOKEN, english.getReason(), "사유 코드는 언어와 무관");
        CredentialCryptoException korean = assertThrows(CredentialCryptoException.class,
                () -> TestSupport.managedCrypto().decryptText("not-a-token"));
        assertTrue(korean.getMessage().contains("암호문 형식이 올바르지 않습니다") && korean.getMessage().contains("조치:"),
                korean.getMessage());
        // 설정 오류(설정 언어를 읽은 뒤의 검증 오류)도 그 설정의 언어로 알린다
        Path enBad = TestSupport.writeConfig(dir, "en-bad.properties", "crypto.lang=en", "crypto.key.id=bad id");
        CredentialCryptoException config = assertThrows(CredentialCryptoException.class, () -> CredentialCrypto.fromConfigFile(enBad));
        assertTrue(config.getMessage().contains("The key ID format is invalid"), config.getMessage());
    }

    @Test
    void tomcatFactoryErrorsUseTheConfiguredLanguageWithoutCliInitialisation() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        Path en = TestSupport.writeConfig(dir, "factory-en.properties", "crypto.lang=en");
        Reference plain = new Reference("javax.sql.DataSource");
        plain.add(new StringRefAddr("username", "app"));
        plain.add(new StringRefAddr("password", "plain-password-value"));
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, en.toString());
             AutoCloseable jvm = TestSupport.jvmSettings()) {
            NamingException ex = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(plain, null, null, null));
            assertTrue(ex.getMessage().startsWith("[java-crypto-kit] [reason: PLAINTEXT_PASSWORD]"), ex.getMessage());
            assertFalse(ex.getMessage().contains("plain-password-value"));
        }
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
             AutoCloseable jvm = TestSupport.jvmSettings()) {
            NamingException ex = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(plain, null, null, null));
            assertTrue(ex.getMessage().startsWith("[java-crypto-kit] [사유: PLAINTEXT_PASSWORD]"), "기본값 ko: " + ex.getMessage());
        }
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
             AutoCloseable jvm = TestSupport.jvmSettings("crypto.lang=en")) {
            NamingException ex = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(plain, null, null, null));
            assertTrue(ex.getMessage().startsWith("[java-crypto-kit] [reason: PLAINTEXT_PASSWORD]"), "-Dcrypto.lang=en: " + ex.getMessage());
        }
        assertEquals(null, Messages.processLanguage(), "WAS 경로는 CLI 프로세스 언어를 쓰지 않는다");
    }
}
