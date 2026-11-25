package io.javacryptokit.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 지원하는 모든 설정 항목의 "정의"(이름·자료형·허용값·{@code -D} 규칙·민감 여부·
 * 적용 키 공급원)를 한 곳에 모은 목록이다.
 *
 * <p><b>왜 필요한가</b>: 설정 검증({@link CryptoSettings}), JAR 내부 설정 조회·변경({@code config show/set}), 도움말
 * ({@code config help})이 같은 정의를 써야 도움말의 설정 이름·허용값·{@code -D} 가능 여부가 실제 구현과 어긋나지 않는다.
 * 선택형 값의 허용 목록과 숫자 범위는 여기 값으로 직접 검증한다. 기본값은 JAR 내장 {@code java-crypto-kit.properties}가
 * 정본이며(중복으로 적지 않음), 설명·예제 문구는 언어별 번들 {@code io/javacryptokit/i18n/settings*.properties}의
 * {@code setting.<이름>.*} 키에 있다. 테스트가 이 목록·JAR 기본 Properties·영어/한국어 설명의 항목이 정확히 같은지 검사한다.</p>
 *
 * <p><b>명명 규칙</b>: {@code crypto.} 접두어, 소문자와 점으로 영역 구분, 널리 쓰는 약어({@code lang}, {@code env},
 * {@code url}, {@code id}, {@code ms}), 참/거짓은 {@code .enabled}, 시간은 {@code .timeout.ms}, 파일 경로는 {@code .file}.
 * 이미 배포된 이름({@code crypto.key.file}, {@code crypto.key.env} 등)은 하위 호환을 위해 그대로 둔다.</p>
 *
 * <p><b>새 설정을 추가할 때</b>: ① 이 목록 ② JAR 기본 Properties(주석 포함) ③ 영어·한국어 설명 ④ 필요하면
 * {@link CryptoSettings}의 형식 검증을 함께 바꾼다. 비밀값과 정책 항목은 {@code -D}를 허용하지 않는다. 여러 명령·실행 환경에서
 * 반복해 쓰는 값만 설정으로 만든다(일회성 명령 옵션은 설정으로 만들지 않는다).</p>
 */
public final class SettingCatalog {
    /** 도움말에서 항목을 묶어 보여 주는 단위. */
    public enum Group {
        /** 키 공급·키ID·알고리즘(기존 암호문 복호화에 직접 영향). */
        KEY,
        /** 메시지 언어·경고·출력 형식·JVM 덮어쓰기 정책. */
        BEHAVIOR,
        /** Tomcat JDBC Factory 전용. */
        TOMCAT,
        /** HashiCorp Vault KV v2 키 공급원({@code crypto.key.source=vault}). */
        VAULT,
        /** AWS KMS Envelope Encryption 키 공급원({@code crypto.key.source=aws-kms}). */
        AWS_KMS
    }

    /** 값의 자료형(도움말 표시와 공통 검증에 쓴다). */
    public enum Type {
        /** 정해진 값 중 하나({@link Setting#choices}). */
        CHOICE,
        /** 소문자 true/false. */
        BOOLEAN,
        /** 정수({@link Setting#min} ~ {@link Setting#max}). */
        NUMBER,
        /** 식별자·이름 등 형식이 정해진 문자열(형식은 {@link CryptoSettings}가 검증). */
        TEXT,
        /** 파일 경로(존재 여부는 사용할 때 확인). */
        FILE,
        /** HTTPS 주소. */
        URL
    }

    /** JVM 개별 속성({@code -D이름=값})을 받았을 때의 처리. */
    public enum JvmRule {
        /** 덮어쓰기 정책({@code crypto.jvm.override.enabled})이 true면 적용한다. */
        ALLOWED,
        /** 적용하지 않고 이름만 진단에 표시한다(정책 항목 자체: 우회 방지). */
        IGNORED,
        /** 오류로 중단한다(키 원문: 프로세스 목록·기동 로그 노출 방지). */
        REJECTED
    }

    /** 설정 항목 하나의 정의(불변). */
    public static final class Setting {
        /** 설정 이름(Properties 키이자 -D 이름). */
        public final String key;
        /** 묶음. */
        public final Group group;
        /** 자료형. */
        public final Type type;
        /** CHOICE의 허용값(대소문자 구분, 정해진 순서). 그 밖의 자료형은 빈 목록. */
        public final List<String> choices;
        /** NUMBER의 최솟값. */
        public final int min;
        /** NUMBER의 최댓값. */
        public final int max;
        /** -D 처리 규칙. */
        public final JvmRule jvmRule;
        /** 값을 화면·이력·오류에 보여 주지 않는 비밀 항목. {@code config set}으로 바꿀 수 없다. */
        public final boolean sensitive;
        /** 바꾸면 기존 암호문 복호화에 영향을 줄 수 있는 항목(변경 전 영향 안내·확인 필요). */
        public final boolean keyAffecting;
        /** 이 항목을 쓰는 키 공급원({@link #KEY_SOURCES} 값). 빈 목록이면 모든 공급원에 적용된다. */
        public final List<String> sources;

        private Setting(String key, Group group, Type type, List<String> choices, int min, int max, JvmRule jvmRule,
                        boolean sensitive, boolean keyAffecting, List<String> sources) {
            this.key = key;
            this.group = group;
            this.type = type;
            this.choices = choices;
            this.min = min;
            this.max = max;
            this.jvmRule = jvmRule;
            this.sensitive = sensitive;
            this.keyAffecting = keyAffecting;
            this.sources = sources;
        }
    }

    /** {@code crypto.key.source} 허용값(명시적으로 허용한 공급원만. 클래스 이름으로 임의 공급원을 로딩하지 않는다). */
    public static final List<String> KEY_SOURCES = Collections.unmodifiableList(Arrays.asList(
            "embedded", "file", "env", "vault", "aws-kms"));

    /** {@code crypto.lang} 허용값(기본 ko). auto는 JVM Locale이 한국어면 ko, 그 밖(미지원 언어 포함)에는 en. */
    public static final List<String> LANGUAGES = Collections.unmodifiableList(Arrays.asList("ko", "en", "auto"));

    /** {@code crypto.lang}이 아예 없을 때(이전 형식 설정) 쓰는 기본 언어 코드. JAR 내장 기본값과 같다. */
    public static final String DEFAULT_LANGUAGE = "ko";

    /** 전체 설정 정의(도움말에 보이는 순서). */
    public static final List<Setting> ALL;

    /** KDF 반복 횟수 최솟값. */
    public static final int KDF_MIN_ITERATIONS = 100_000;
    /** KDF 반복 횟수 최댓값. */
    public static final int KDF_MAX_ITERATIONS = 5_000_000;
    /** KDF 반복 횟수 기본값(새 pass 키). */
    public static final int KDF_DEFAULT_ITERATIONS = 600_000;

    /** 키 프로필 항목 정의(도움말 표시 순서). */
    public static final List<ProfileItem> PROFILE_ITEMS;

    /** {@code crypto.key.type}과 프로필 {@code type}의 허용값(pass가 기본). */
    public static final List<String> KEY_TYPES = Collections.unmodifiableList(Arrays.asList("pass", "key"));

    /** 프로필 {@code kdf}의 허용값(PBKDF2-HMAC-SHA256 하나). */
    public static final List<String> KDF_NAMES = Collections.singletonList("pbkdf2-sha256");

    static {
        List<Setting> all = new ArrayList<>();
        // ---- 키 선택(유형 생략 시 기본 유형, 유형별 기본 Key ID) ----
        all.add(choice(CryptoSettings.KEY_TYPE, Group.KEY, KEY_TYPES, true));
        all.add(text(CryptoSettings.KEY_ACTIVE_PASS, Group.KEY, Type.TEXT, JvmRule.ALLOWED, true));
        all.add(text(CryptoSettings.KEY_ACTIVE_KEY, Group.KEY, Type.TEXT, JvmRule.ALLOWED, true));
        // ---- 레거시 AES 슬롯(crypto.key.*)·알고리즘 ----
        all.add(choice(CryptoSettings.KEY_SOURCE, Group.KEY, KEY_SOURCES, true));
        all.add(text(CryptoSettings.KEY_ID, Group.KEY, Type.TEXT, JvmRule.ALLOWED, true));
        all.add(text(CryptoSettings.KEY_FILE, Group.KEY, Type.FILE, JvmRule.ALLOWED, true, "file"));
        all.add(text(CryptoSettings.KEY_ENV, Group.KEY, Type.TEXT, JvmRule.ALLOWED, true, "env"));
        all.add(new Setting(CryptoSettings.KEY_EMBEDDED, Group.KEY, Type.TEXT, Collections.<String>emptyList(), 0, 0,
                JvmRule.REJECTED, true, true, Collections.singletonList("embedded")));
        all.add(choice(CryptoSettings.ALGORITHM, Group.KEY, Collections.singletonList("AES/GCM/NoPadding"), true));
        // ---- 동작·정책 ----
        all.add(choice(CryptoSettings.LANG, Group.BEHAVIOR, LANGUAGES, false));
        all.add(bool(CryptoSettings.WARNING_ENABLED, JvmRule.ALLOWED));
        all.add(choice(CryptoSettings.OUTPUT_ENCODING, Group.BEHAVIOR, Arrays.asList("enc", "base64"), false));
        all.add(bool(CryptoSettings.JVM_OVERRIDE_ENABLED, JvmRule.IGNORED));
        // ---- Tomcat ----
        all.add(choice(CryptoSettings.POOL_FACTORY, Group.TOMCAT,
                Arrays.asList(CryptoSettings.DBCP2_FACTORY, CryptoSettings.TOMCAT_JDBC_FACTORY), false));
        all.add(choice(CryptoSettings.REQUIRE_ENCRYPTED_PASSWORD, Group.TOMCAT, Collections.singletonList("true"), false));
        // ---- Vault KV v2 (토큰 원문은 설정에 두지 않는다: 토큰 환경변수 이름 또는 토큰 파일 경로만) ----
        all.add(text(CryptoSettings.VAULT_URL, Group.VAULT, Type.URL, JvmRule.ALLOWED, true, "vault"));
        all.add(text(CryptoSettings.VAULT_MOUNT, Group.VAULT, Type.TEXT, JvmRule.ALLOWED, true, "vault"));
        all.add(text(CryptoSettings.VAULT_PATH, Group.VAULT, Type.TEXT, JvmRule.ALLOWED, true, "vault"));
        all.add(text(CryptoSettings.VAULT_FIELD, Group.VAULT, Type.TEXT, JvmRule.ALLOWED, true, "vault"));
        all.add(text(CryptoSettings.VAULT_VER, Group.VAULT, Type.TEXT, JvmRule.ALLOWED, true, "vault"));
        all.add(text(CryptoSettings.VAULT_TOKEN_ENV, Group.VAULT, Type.TEXT, JvmRule.ALLOWED, false, "vault"));
        all.add(text(CryptoSettings.VAULT_TOKEN_FILE, Group.VAULT, Type.FILE, JvmRule.ALLOWED, false, "vault"));
        all.add(text(CryptoSettings.VAULT_CA_FILE, Group.VAULT, Type.FILE, JvmRule.ALLOWED, false, "vault"));
        all.add(number(CryptoSettings.VAULT_TIMEOUT_MS, Group.VAULT, 100, 60000, "vault"));
        // ---- AWS KMS (자격증명은 설정에 두지 않는다: AWS SDK 표준 자격증명 체계) ----
        all.add(text(CryptoSettings.AWS_REGION, Group.AWS_KMS, Type.TEXT, JvmRule.ALLOWED, false, "aws-kms"));
        all.add(text(CryptoSettings.AWS_KMS_KEY_ID, Group.AWS_KMS, Type.TEXT, JvmRule.ALLOWED, true, "aws-kms"));
        all.add(text(CryptoSettings.AWS_KMS_DATA_KEY_FILE, Group.AWS_KMS, Type.FILE, JvmRule.ALLOWED, true, "aws-kms"));
        all.add(number(CryptoSettings.AWS_KMS_TIMEOUT_MS, Group.AWS_KMS, 500, 120000, "aws-kms"));
        ALL = Collections.unmodifiableList(all);

        List<ProfileItem> items = new ArrayList<>();
        // 키 정체성 항목(바깥 계층·-D로 바꿀 수 없음: 같은 Key ID에 다른 키가 생기는 것을 막는다)
        items.add(new ProfileItem(KeyProfile.TYPE, Type.CHOICE, KEY_TYPES, 0, 0, false, false));
        items.add(new ProfileItem(KeyProfile.SOURCE, Type.CHOICE, KEY_SOURCES, 0, 0, false, false));
        items.add(new ProfileItem(KeyProfile.EMBEDDED, Type.TEXT, Collections.<String>emptyList(), 0, 0, false, true));
        // 위치 항목(서버마다 다를 수 있으므로 외부 Properties·-D로 바꿀 수 있음)
        items.add(new ProfileItem(KeyProfile.FILE, Type.FILE, Collections.<String>emptyList(), 0, 0, true, false));
        items.add(new ProfileItem(KeyProfile.ENV, Type.TEXT, Collections.<String>emptyList(), 0, 0, true, false));
        items.add(new ProfileItem(KeyProfile.VAULT_PATH, Type.TEXT, Collections.<String>emptyList(), 0, 0, true, false));
        items.add(new ProfileItem(KeyProfile.VAULT_FIELD, Type.TEXT, Collections.<String>emptyList(), 0, 0, true, false));
        items.add(new ProfileItem(KeyProfile.VAULT_VER, Type.TEXT, Collections.<String>emptyList(), 0, 0, true, false));
        items.add(new ProfileItem(KeyProfile.AWS_KMS_DATA_KEY_FILE, Type.FILE, Collections.<String>emptyList(), 0, 0, true,
                false));
        // 키 파생 메타데이터(pass만)와 외부 공급 키의 고정 지문(키 정체성 항목)
        items.add(new ProfileItem(KeyProfile.KDF, Type.CHOICE, KDF_NAMES, 0, 0, false, false));
        items.add(new ProfileItem(KeyProfile.KDF_ITERATIONS, Type.NUMBER, Collections.<String>emptyList(),
                KDF_MIN_ITERATIONS, KDF_MAX_ITERATIONS, false, false));
        items.add(new ProfileItem(KeyProfile.SALT, Type.TEXT, Collections.<String>emptyList(), 0, 0, false, false));
        items.add(new ProfileItem(KeyProfile.FINGERPRINT, Type.TEXT, Collections.<String>emptyList(), 0, 0, false, false));
        PROFILE_ITEMS = Collections.unmodifiableList(items);
    }

    /**
     * 키 프로필 항목 하나의 정의({@code crypto.keys.<Key ID>.<항목>}). Key ID마다 같은 정의를 쓴다.
     * 위치 항목만 외부 Properties·{@code -D}로 덮어쓸 수 있고, 나머지(유형·공급원·비밀·KDF·지문)는 키의 정체성이라 처음 정한
     * 계층에서만 정한다({@code -D}로 지정하면 오류).
     */
    public static final class ProfileItem {
        /** 항목 이름(예: {@code type}, {@code vault.path}). */
        public final String name;
        /** 자료형. */
        public final Type type;
        /** CHOICE 허용값. */
        public final List<String> choices;
        /** NUMBER 최솟값. */
        public final int min;
        /** NUMBER 최댓값. */
        public final int max;
        /** 위치 항목이면 true(외부 Properties·-D 덮어쓰기 가능). */
        public final boolean location;
        /** 비밀 항목이면 true(값을 화면·이력·오류에 보여 주지 않음). */
        public final boolean sensitive;

        private ProfileItem(String name, Type type, List<String> choices, int min, int max, boolean location,
                            boolean sensitive) {
            this.name = name;
            this.type = type;
            this.choices = choices;
            this.min = min;
            this.max = max;
            this.location = location;
            this.sensitive = sensitive;
        }
    }

    /** 템플릿 프로필 설정 이름 형식: crypto.keys.&lt;Key ID&gt;.&lt;항목&gt; (Key ID 규칙은 crypto.key.id와 같다). */
    private static final java.util.regex.Pattern PROFILE_NAME =
            java.util.regex.Pattern.compile("crypto\\.keys\\.([A-Za-z0-9_-]{1,64})\\.([a-z.-]{1,32})");

    /**
     * @param item 항목 이름
     * @return 정의, 없으면 null
     */
    public static ProfileItem profileItem(String item) {
        for (ProfileItem candidate : PROFILE_ITEMS) {
            if (candidate.name.equals(item)) return candidate;
        }
        return null;
    }

    /**
     * 설정 이름을 템플릿 프로필 이름으로 해석한다.
     *
     * @param name 설정 이름
     * @return {Key ID, 항목} 또는 형식이 아니면 null(항목이 정의에 없어도 형식만 맞으면 돌려준다)
     */
    public static String[] parseProfileName(String name) {
        java.util.regex.Matcher m = PROFILE_NAME.matcher(name);
        return m.matches() ? new String[]{m.group(1), m.group(2)} : null;
    }

    /** @return 이 이름이 정의된 항목을 쓰는 템플릿 프로필 설정 이름이면 true */
    public static boolean isProfileSetting(String name) {
        String[] parts = parseProfileName(name);
        return parts != null && profileItem(parts[1]) != null;
    }

    /** @return 값을 보여 주지 않는 비밀 설정이면 true(고정 항목과 프로필 항목 모두) */
    public static boolean isSensitive(String name) {
        if (sensitiveKeys().contains(name)) return true;
        String[] parts = parseProfileName(name);
        ProfileItem item = parts == null ? null : profileItem(parts[1]);
        return item != null && item.sensitive;
    }

    /**
     * 변경 이력에 값 대신 고정 표시(비공개·없음)만 남기는 항목: 비밀 설정(내장 키 값)뿐이다. pass 키의 Salt는 비밀이 아닌 관리정보라
     * 값 그대로 남긴다(이전 형식의 이력에는 Salt 줄이 고정 표시로 남아 있으며 그대로 읽는다).
     *
     * @return 이력에서 값을 감추는 항목이면 true
     */
    public static boolean isHistoryMasked(String name) {
        return isSensitive(name);
    }

    /** @return pass 키 프로필의 Salt 항목({@code crypto.keys.<id>.salt})이면 true */
    public static boolean isSaltSetting(String name) {
        String[] parts = parseProfileName(name);
        return parts != null && KeyProfile.SALT.equals(parts[1]);
    }

    /** @return 바꾸면 실제 사용 키나 기존 암호문 복호화에 영향을 주는 설정이면 true(프로필 항목은 모두 해당) */
    public static boolean isKeyAffecting(String name) {
        return keyAffectingKeys().contains(name) || isProfileSetting(name);
    }

    private SettingCatalog() { }

    private static Setting choice(String key, Group group, List<String> choices, boolean keyAffecting) {
        return new Setting(key, group, Type.CHOICE, Collections.unmodifiableList(choices), 0, 0, JvmRule.ALLOWED, false,
                keyAffecting, Collections.<String>emptyList());
    }

    private static Setting bool(String key, JvmRule rule) {
        return new Setting(key, Group.BEHAVIOR, Type.BOOLEAN, Collections.unmodifiableList(Arrays.asList("true", "false")),
                0, 0, rule, false, false, Collections.<String>emptyList());
    }

    private static Setting text(String key, Group group, Type type, JvmRule rule, boolean keyAffecting, String... sources) {
        return new Setting(key, group, type, Collections.<String>emptyList(), 0, 0, rule, false, keyAffecting,
                Collections.unmodifiableList(Arrays.asList(sources)));
    }

    private static Setting number(String key, Group group, int min, int max, String... sources) {
        return new Setting(key, group, Type.NUMBER, Collections.<String>emptyList(), min, max, JvmRule.ALLOWED, false, false,
                Collections.unmodifiableList(Arrays.asList(sources)));
    }

    /**
     * @param key 설정 이름
     * @return 정의(지원하지 않는 이름이면 null)
     */
    public static Setting find(String key) {
        for (Setting setting : ALL) {
            if (setting.key.equals(key)) return setting;
        }
        return null;
    }

    /** @return 지원하는 모든 설정 이름(정의 순서) */
    public static Set<String> keys() {
        Set<String> keys = new LinkedHashSet<>();
        for (Setting setting : ALL) keys.add(setting.key);
        return Collections.unmodifiableSet(keys);
    }

    /** @return -D로 덮어쓸 수 있는 설정 이름(정의 순서) */
    public static List<String> jvmOverridableKeys() {
        List<String> keys = new ArrayList<>();
        for (Setting setting : ALL) {
            if (setting.jvmRule == JvmRule.ALLOWED) keys.add(setting.key);
        }
        return Collections.unmodifiableList(keys);
    }

    /** @return 값을 보여 주지 않는 비밀 항목 이름 */
    public static Set<String> sensitiveKeys() {
        Set<String> keys = new LinkedHashSet<>();
        for (Setting setting : ALL) {
            if (setting.sensitive) keys.add(setting.key);
        }
        return Collections.unmodifiableSet(keys);
    }

    /** @return 기존 암호문 복호화에 영향을 주는 항목 이름 */
    public static Set<String> keyAffectingKeys() {
        Set<String> keys = new LinkedHashSet<>();
        for (Setting setting : ALL) {
            if (setting.keyAffecting) keys.add(setting.key);
        }
        return Collections.unmodifiableSet(keys);
    }
}
