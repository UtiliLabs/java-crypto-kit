package io.javacryptokit.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.TestSupport;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.KeyResolver;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** 설정 정의 공통화: 카탈로그·JAR 기본값·도움말 설명·공급원 등록표의 일치와 신규 설정(언어·Vault·AWS) 검증 규칙. */
class SettingCatalogTest {
    @TempDir
    Path dir;

    private static Properties jarDefaults() throws Exception {
        Properties properties = new Properties();
        try (InputStream in = SettingCatalogTest.class.getResourceAsStream("/java-crypto-kit.properties");
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    @Test
    void catalogJarDefaultsAndHelpDescriptionsDescribeExactlyTheSameSettings() throws Exception {
        java.util.Set<String> fixedNames = new java.util.TreeSet<>();
        for (String name : jarDefaults().stringPropertyNames()) {
            if (SettingCatalog.isProfileSetting(name)) continue; // 공개 pass 키(pass-default) 등 키 프로필 항목은 따로 검사
            fixedNames.add(name);
        }
        assertEquals(fixedNames, new java.util.TreeSet<>(SettingCatalog.keys()),
                "JAR 기본 Properties의 고정 설정과 설정 카탈로그의 항목이 정확히 같아야 한다");
        for (String name : jarDefaults().stringPropertyNames()) {
            String[] profile = SettingCatalog.parseProfileName(name);
            if (profile == null) continue;
            assertTrue(SettingCatalog.profileItem(profile[1]) != null, "정의된 키 프로필 항목만: " + name);
            for (Messages.Language language : Messages.Language.values()) {
                assertTrue(Messages.has(language, "setting.profile." + profile[1] + ".purpose"), language + " " + profile[1]);
            }
        }
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            for (Messages.Language language : Messages.Language.values()) {
                for (String part : new String[]{"purpose", "allowed", "example"}) {
                    assertTrue(Messages.has(language, "setting." + setting.key + "." + part), language + " " + setting.key + "." + part);
                }
                // config help 표의 짧은 허용값: 선택형·숫자는 카탈로그에서 만들고, 그 밖의 항목은 .values 문구가 있어야 한다.
                if (setting.choices.isEmpty() && setting.type != SettingCatalog.Type.NUMBER) {
                    assertTrue(Messages.has(language, "setting." + setting.key + ".values"), language + " " + setting.key + ".values");
                }
            }
        }
        assertEquals(new LinkedHashSet<>(SettingCatalog.KEY_SOURCES), KeyResolver.sources(), "공급원 허용값 = 등록표");
        assertEquals(SettingCatalog.jvmOverridableKeys(), CryptoSettings.JVM_OVERRIDABLE_KEYS);
        assertFalse(CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(CryptoSettings.KEY_EMBEDDED), "키 원문은 -D 불가");
        assertFalse(CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(CryptoSettings.JVM_OVERRIDE_ENABLED), "정책 항목은 -D 불가");
        assertEquals(Collections.singleton(CryptoSettings.KEY_EMBEDDED), SettingCatalog.sensitiveKeys());
        assertTrue(SettingCatalog.isSensitive("crypto.keys.pass-default.embedded"), "키 프로필의 내장 값도 비밀 항목");
        assertFalse(SettingCatalog.isSensitive("crypto.keys.pass-default.salt"), "Salt는 비밀이 아니다");
        assertEquals("ko", jarDefaults().getProperty(CryptoSettings.LANG), "기본 메시지 언어는 ko");
    }

    @Test
    void everyHelpExampleValueOfASettingIsAcceptedByTheValidator() throws Exception {
        // 도움말 예제가 "이름=값" 한 줄이면 실제 검증을 통과하는지 확인한다(도움말과 구현의 허용값 일치).
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            String example = Messages.get(Messages.Language.EN, "setting." + setting.key + ".example");
            if (!example.startsWith(setting.key + "=")) continue;
            List<String> lines = new ArrayList<>();
            lines.add(example);
            if (CryptoSettings.KEY_ACTIVE_PASS.equals(setting.key)) {
                for (String value : TestSupport.managedSettings()) {
                    if (value.startsWith("crypto.keys.test-pass.")) lines.add(value.replace("test-pass", "app-pass"));
                }
            }
            if (setting.key.startsWith("crypto.vault.") || setting.key.startsWith("crypto.aws.")
                    || setting.key.startsWith("crypto.key.file")) {
                lines.add("crypto.key.source=" + (setting.key.startsWith("crypto.vault.") ? "vault"
                        : setting.key.startsWith("crypto.aws.") ? "aws-kms" : "file"));
            }
            if (CryptoSettings.KEY_ACTIVE_KEY.equals(setting.key)) lines.add(TestSupport.managedSettings()[0]);
            Path config = TestSupport.writeConfig(dir, "example-" + setting.key + ".properties", lines.toArray(new String[0]));
            TestSupport.isolatedSettings(config);
        }
    }

    @ParameterizedTest(name = "잘못된 원격 설정 \"{0}\"은 거부")
    @ValueSource(strings = {"crypto.vault.url=http://vault.example:8200", "crypto.vault.url=https://vault.example/v1",
            "crypto.vault.url=https://user@vault.example", "crypto.vault.path=../secret", "crypto.vault.path=a/../b",
            "crypto.vault.ver=0", "crypto.vault.ver=latest", "crypto.vault.timeout.ms=0", "crypto.vault.timeout.ms=999999",
            "crypto.vault.token.env=1BAD", "crypto.vault.mount=sec ret", "crypto.aws.region=Seoul",
            "crypto.aws.kms.key.id=key with space", "crypto.aws.kms.timeout.ms=100", "crypto.lang=KO", "crypto.lang="})
    void invalidRemoteAndLanguageValuesAreRejected(String line) throws Exception {
        Path config = TestSupport.writeConfig(dir, "bad.properties", line);
        assertThrows(IllegalArgumentException.class, () -> TestSupport.isolatedSettings(config), line);
    }

    @Test
    void kmsKeyArnRegionMustMatchTheConfiguredRegion() throws Exception {
        Path config = TestSupport.writeConfig(dir, "arn.properties", "crypto.aws.region=ap-northeast-2",
                "crypto.aws.kms.key.id=arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> TestSupport.isolatedSettings(config));
        assertTrue(ex.getMessage().contains("crypto.aws.region"), ex.getMessage());
    }

    @Test
    void remoteSourceSettingsWithoutKeySourceAreAmbiguous() throws Exception {
        Path vault = TestSupport.writeConfig(dir, "vault-only.properties", "crypto.vault.url=https://vault.example:8200",
                "crypto.vault.path=app/prod");
        assertThrows(IllegalArgumentException.class, () -> TestSupport.isolatedSettings(vault));
        Path kms = TestSupport.writeConfig(dir, "kms-only.properties", "crypto.aws.kms.data-key.file=/x.datakey");
        assertThrows(IllegalArgumentException.class, () -> TestSupport.isolatedSettings(kms));
    }

    @Test
    void jvmTyposInNewAreasAndConfigPathNameAreRejectedButUnrelatedNamesAreNot() throws Exception {
        Map<String, String> jvm = new HashMap<>();
        for (String typo : new String[]{"crypto.vault.adress", "crypto.aws.regoin", "crypto.lnag", "crypto.config.fle",
                "crypto.config.path"}) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> CryptoSettings.load(null, jvm::get, name -> null, Collections.singleton(typo)), typo);
            assertTrue(ex.getMessage().contains(typo), ex.getMessage());
        }
        CryptoSettings ok = CryptoSettings.load(null, jvm::get, name -> null,
                java.util.Arrays.asList("crypto.policy", "crypto.config.file", "user.language"));
        assertEquals(CryptoSettings.ConfigOrigin.NONE, ok.configOrigin());
    }

    @Test
    void vaultAndAwsSettingsCanBeGivenAsJvmProperties() throws Exception {
        Map<String, String> jvm = new HashMap<>();
        jvm.put("crypto.key.source", "vault");
        jvm.put("crypto.vault.url", "https://vault.example.internal:8200");
        jvm.put("crypto.vault.path", "app/prod");
        jvm.put("crypto.vault.ver", "4");
        CryptoSettings settings = CryptoSettings.load(null, jvm::get, name -> null, jvm.keySet());
        assertEquals("vault", settings.keySource());
        assertEquals("4", settings.get(CryptoSettings.VAULT_VER));
        assertEquals(CryptoSettings.ValueOrigin.JVM_PROPERTY, settings.valueOrigin(CryptoSettings.VAULT_URL));
        assertEquals(5000, settings.intValue(CryptoSettings.VAULT_TIMEOUT_MS, 1));
    }
}
