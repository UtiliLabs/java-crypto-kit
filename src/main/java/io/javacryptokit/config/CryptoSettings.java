package io.javacryptokit.config;

import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 암복호화 설정을 읽고 허용된 안전한 값만 통과시키는 설정 클래스다(생성 후 변경 불가).
 * 패키지 사이에서 쓰기 위해 public이지만, 애플리케이션은 {@code io.javacryptokit.CredentialCrypto}를 사용한다.
 *
 * <p><b>공통 설정(유일한 설정 로더)</b>: CLI, 공개 Java API, Tomcat 연동 어댑터, Vault/AWS KMS 어댑터가 모두 이 클래스로 같은
 * 규칙에 따라 설정을 읽는다. 다른 클래스는 설정 원본(파일·JVM 속성)을 직접 읽지 않고 이 객체의 최종값만 사용한다. 지원 항목의
 * 정의(이름·자료형·허용값·-D 규칙)는 {@link SettingCatalog}에 있다. {@code crypto.pool.factory}는 Tomcat 어댑터 전용이지만
 * 문자열만 검사하므로 Tomcat이 없는 환경에서도 영향이 없다.</p>
 *
 * <p><b>최종값 우선순위</b>: JVM 개별 속성({@code -Dcrypto.*}, 허용 항목만) &gt; 외부 Properties 파일 &gt; JAR 내장 기본값.
 * CLI의 일회성 옵션({@code --lang} 등)은 해당 실행에만 적용되며 이 클래스의 값을 바꾸지 않는다. 그래서 JAR를 다시 빌드하지
 * 않고 WAS 실행 옵션·외부 파일·{@code config set}으로 바꾼 JAR 내부 값만으로 동작을 정할 수 있다.</p>
 *
 * <p><b>설정을 읽는 순서</b></p>
 * <ol>
 *   <li>JAR의 활성 예약 영역을 읽고, 미설정 배포본이면 기본 {@code /java-crypto-kit.properties}를 사용한다.</li>
 *   <li>외부 설정 파일이 지정되어 있으면 그 파일에 적힌 항목만 기본값을 덮어쓴다. 외부 파일을 쓴다고 외부 키가 강제되지는
 *       않는다. 경로는 ① 직접 지정(CLI {@code --config}, 공개 API {@code fromConfigFile}) ② JVM 속성
 *       {@code -Dcrypto.config.file} ③ 환경변수 {@code CRYPTO_CONFIG_FILE} 순서로 처음 값이 있는 단계 하나만 쓴다(별칭 없음).
 *       이 경로 지정 속성은 아래 JVM 덮어쓰기 정책과 관계없이 항상 동작한다(부트스트랩 옵션).</li>
 *   <li>JVM 개별 속성 덮어쓰기 정책 {@code crypto.jvm.override.enabled}를 JAR 기본값과 외부 파일만으로 정한다(기본 true).
 *       {@code -Dcrypto.jvm.override.enabled}는 읽지 않으므로 JVM 옵션 하나로 운영 정책(false)을 우회할 수 없다.</li>
 *   <li>정책이 true이면 {@link #JVM_OVERRIDABLE_KEYS}의 항목을 같은 이름의 JVM 속성 값으로 덮어쓴다.</li>
 *   <li>메시지 언어({@code crypto.lang})를 정하고, 이후 검증 오류는 그 언어로 만든다.</li>
 *   <li>합쳐진 최종값을 검증한다. 검증을 통과하지 못한 설정 객체는 만들어지지 않는다.</li>
 * </ol>
 *
 * <p><b>JVM 속성으로 받지 않는 값</b>: 키 원문 {@code crypto.key.embedded}는 {@code -D}로 받지 않는다(지정하면 오류).
 * JVM 인자는 프로세스 목록·Tomcat 기동 로그·모니터링 도구에 그대로 보이기 때문이다. Vault 토큰·AWS 자격증명은 아예 설정
 * 항목이 없다(토큰은 환경변수·파일, AWS는 SDK 표준 자격증명 체계).</p>
 *
 * <p><b>Fail Closed</b>: 외부 설정 경로를 지정했는데 파일이 없거나, 읽을 수 없거나, UTF-8이 아니거나, 형식이 깨졌거나, 지정했지만
 * 비어 있으면 내장 기본값으로 조용히 진행하지 않고 예외로 중단한다. JVM 속성 값이 허용 범위를 벗어난 경우도 같다.</p>
 *
 * <p><b>오타 방지</b>: 외부 설정 파일에 지원하지 않는 항목 이름이 있으면 오류로 중단한다. JVM 속성은 다른 프로그램과 함께 쓰는
 * 이름 공간이므로 이 라이브러리 설정 영역({@code crypto.key.*}·{@code crypto.vault.*}·{@code crypto.aws.*}·{@code crypto.lang}
 * 등, 지원 항목 이름의 첫 단어)의 모르는 이름이나 정식 이름과 거의 같은 이름(편집 거리 2 이하)만 오타로 보고 중단한다
 * ({@code -Dcrypto.policy} 같은 무관한 이름은 영향 없음). {@code -Dcrypto.config.fle}처럼 외부 설정 경로 이름의 오타도 같은 규칙으로 중단한다. 이 검사는 경고·덮어쓰기 정책과 관계없이 항상 적용한다.</p>
 *
 * <p><b>모호한 키 설정 방지</b>: 외부 설정이나 JVM 속성에 키 공급원 설정(키 파일 경로·키 환경변수 이름·Vault 주소·Secret 경로·
 * KMS 키·데이터 키 파일)이 있는데 {@code crypto.key.source}가 어디에도 없으면 오류로 중단한다.</p>
 *
 * <p><b>반영 시점</b>: 설정은 객체를 만들 때 한 번 읽는다(Tomcat은 DataSource를 만들 때, CLI는 명령을 실행할 때). 실행 중인
 * WAS에서 파일이나 JVM 옵션을 바꿔도 자동 반영되지 않으므로 WAS 재기동(또는 DataSource 재생성)이 필요하다.</p>
 */
public final class CryptoSettings {
    /** JAR 내부 기본 설정 리소스 경로. 공개 내장 키와 각 항목의 기본값이 들어 있다. */
    public static final String DEFAULT_CONFIG_RESOURCE = "/java-crypto-kit.properties";
    /** 외부 설정 파일 경로 JVM 속성(-Dcrypto.config.file=경로). 설정 파일 안에는 쓰지 않는다(부트스트랩 전용). */
    public static final String CONFIG_FILE_PROPERTY = "crypto.config.file";
    /** 외부 설정 파일 경로 환경변수(CRYPTO_CONFIG_FILE=경로). JVM 속성이 없을 때만 쓴다. */
    public static final String CONFIG_FILE_ENV = "CRYPTO_CONFIG_FILE";
    /** Tomcat 기본 DBCP2 Pool Factory. */
    public static final String DBCP2_FACTORY = "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory";
    /** Tomcat JDBC Pool Factory(선택). */
    public static final String TOMCAT_JDBC_FACTORY = "org.apache.tomcat.jdbc.pool.DataSourceFactory";

    /** 암호화 알고리즘(AES/GCM/NoPadding 고정). */
    public static final String ALGORITHM = "crypto.algorithm";
    /** 키 공급 방식. */
    public static final String KEY_SOURCE = "crypto.key.source";
    /** 키 식별자(암호문에 기록). */
    public static final String KEY_ID = "crypto.key.id";
    /** 내장 키(표준 Base64, 비밀 항목). */
    public static final String KEY_EMBEDDED = "crypto.key.embedded";
    /** 키 파일 경로(file). 이미 배포된 이름이라 하위 호환을 위해 유지한다. */
    public static final String KEY_FILE = "crypto.key.file";
    /** 키 환경변수 이름(env). 이미 배포된 이름이라 하위 호환을 위해 유지한다. */
    public static final String KEY_ENV = "crypto.key.env";
    /** 유형을 생략한 새 암호화의 유형(pass·key, 기본 pass). 이 항목이 없는 설정(이전 형식 JAR)은 레거시 단일 키(key)로 본다. */
    public static final String KEY_TYPE = "crypto.key.type";
    /** pass 유형의 기본 Key ID(템플릿 pass 프로필). */
    public static final String KEY_ACTIVE_PASS = "crypto.key.active.pass";
    /** key 유형의 기본 Key ID. 비우면 레거시 AES 슬롯({@code crypto.key.*})이 key 유형의 기본 키다. */
    public static final String KEY_ACTIVE_KEY = "crypto.key.active.key";
    /** [Tomcat] 위임할 공식 Pool Factory. */
    public static final String POOL_FACTORY = "crypto.pool.factory";
    /** [Tomcat] 평문 비밀번호 거부 정책(true 고정). */
    public static final String REQUIRE_ENCRYPTED_PASSWORD = "crypto.require.encrypted.password";
    /** 이전 설정 호환용 경고 정책. 관리형 공개 키 차단에는 영향이 없다. */
    public static final String WARNING_ENABLED = "crypto.warning.enabled";
    /** 암호문 출력 표현(enc/base64). */
    public static final String OUTPUT_ENCODING = "crypto.output.encoding";
    /** JVM 개별 속성 덮어쓰기 허용 정책. */
    public static final String JVM_OVERRIDE_ENABLED = "crypto.jvm.override.enabled";
    /** 라이브러리 메시지 언어(기본 ko, en, auto). CLI·Java API·Tomcat·Vault/KMS 어댑터 공통. */
    public static final String LANG = "crypto.lang";
    /** [Vault] 서버 주소(https://호스트[:포트]). */
    public static final String VAULT_URL = "crypto.vault.url";
    /** [Vault] KV v2 마운트 경로. */
    public static final String VAULT_MOUNT = "crypto.vault.mount";
    /** [Vault] Secret 경로(마운트 아래). */
    public static final String VAULT_PATH = "crypto.vault.path";
    /** [Vault] 키가 들어 있는 필드 이름. */
    public static final String VAULT_FIELD = "crypto.vault.field";
    /** [Vault] Secret 버전(비우면 최신). */
    public static final String VAULT_VER = "crypto.vault.ver";
    /** [Vault] 토큰 환경변수 이름(토큰 값 아님). */
    public static final String VAULT_TOKEN_ENV = "crypto.vault.token.env";
    /** [Vault] 토큰 파일 경로(지정하면 환경변수 대신 사용). */
    public static final String VAULT_TOKEN_FILE = "crypto.vault.token.file";
    /** [Vault] 서버 인증서를 검증할 CA PEM 파일(비우면 JVM 기본 신뢰 저장소). */
    public static final String VAULT_CA_FILE = "crypto.vault.ca.file";
    /** [Vault] 연결·응답 제한 시간(밀리초). */
    public static final String VAULT_TIMEOUT_MS = "crypto.vault.timeout.ms";
    /** [AWS] 리전(비우면 AWS SDK 기본 리전 공급 체계). */
    public static final String AWS_REGION = "crypto.aws.region";
    /** [AWS KMS] KMS 키 ID·ARN·별칭. */
    public static final String AWS_KMS_KEY_ID = "crypto.aws.kms.key.id";
    /** [AWS KMS] 암호화된 데이터 키(CiphertextBlob Base64) 파일. */
    public static final String AWS_KMS_DATA_KEY_FILE = "crypto.aws.kms.data-key.file";
    /** [AWS KMS] 요청 제한 시간(밀리초, 재시도 포함 전체). */
    public static final String AWS_KMS_TIMEOUT_MS = "crypto.aws.kms.timeout.ms";

    /**
     * JVM 개별 속성({@code -D이름=값})으로 덮어쓸 수 있는 항목(허용 목록, {@link SettingCatalog} 정의 순서).
     * 키 원문({@link #KEY_EMBEDDED})과 덮어쓰기 정책 자체({@link #JVM_OVERRIDE_ENABLED})는 제외한다.
     */
    public static final List<String> JVM_OVERRIDABLE_KEYS = SettingCatalog.jvmOverridableKeys();

    /** 외부 설정 파일 경로를 어디에서 얻었는지. CLI {@code info}가 경로 대신 이 출처를 보여 준다. */
    public enum ConfigOrigin {
        NONE(null),
        EXPLICIT_PATH(null),
        JVM_PROPERTY(CONFIG_FILE_PROPERTY),
        ENVIRONMENT(CONFIG_FILE_ENV);

        private final String name;

        ConfigOrigin(String name) {
            this.name = name;
        }

        /** @return 사람이 읽는 출처 설명(현재 메시지 언어, 경로는 들어 있지 않다) */
        public String description() {
            return Messages.get("origin." + name(), name);
        }
    }

    /** 최종 설정값 하나가 어느 단계에서 정해졌는지(CLI {@code info} 진단용). 값 자체는 들어 있지 않다. */
    public enum ValueOrigin {
        /** JAR 내장 기본값(또는 config set으로 바꾼 JAR 내부 값). */
        JAR_DEFAULT,
        /** 외부 설정 파일에 적힌 값. */
        EXTERNAL_FILE,
        /** JVM 개별 속성(-D)으로 지정한 값. */
        JVM_PROPERTY;

        /** @return 사람이 읽는 출처 설명(현재 메시지 언어) */
        public String description() {
            return Messages.get("value." + name());
        }
    }

    /** 암호문 출력 표현. 설정값 {@code crypto.output.encoding}의 허용값과 1:1로 대응한다. 암호화 방식과는 무관하다. */
    public enum OutputFormat {
        /** 기본값: {@code ENC[v1:...]} 그대로. */
        ENC("enc"),
        /** 선택값: {@code B64[...]} 추가 포장(인코딩일 뿐 암호화가 아님). */
        BASE64("base64");

        private final String settingValue;

        OutputFormat(String settingValue) {
            this.settingValue = settingValue;
        }

        /** @return 설정 파일에 쓰는 값(enc 또는 base64) */
        public String settingValue() {
            return settingValue;
        }

        /**
         * 설정값을 출력 표현으로 바꾼다. 대소문자·공백 변형을 추측하지 않는다.
         *
         * @param value 앞뒤 공백을 제거한 설정값
         * @return 대응하는 표현, 허용값이 아니면 null
         */
        static OutputFormat fromSetting(String value) {
            for (OutputFormat format : values()) {
                if (format.settingValue.equals(value)) return format;
            }
            return null;
        }
    }

    /** 이 라이브러리와 무관하지만 {@code crypto.}로 시작해 흔히 보이는 JVM 속성 이름(오타 진단에서 제외). */
    private static final Set<String> FOREIGN_JVM_NAMES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "crypto.policy")));
    /** 메시지·진단에 그대로 보여 줘도 되는 설정 이름 형식. 이 형식이 아니면 이름도 출력하지 않는다. */
    private static final String SAFE_NAME = "[A-Za-z0-9._-]{1,80}";
    /** 환경변수 이름 형식. */
    private static final String ENV_NAME = "[A-Za-z_][A-Za-z0-9_]{0,127}";
    /** JAR 내부 기본 설정 캐시(언어 결정용, 내용은 JVM 실행 중 바뀌지 않는다). */
    private static volatile Properties cachedDefaults;

    /** JAR 기본값 → 외부 설정 → JVM 개별 속성 순서로 합친 최종값. 외부로 노출하지 않는다. */
    private final Properties properties;
    /** 외부 설정 파일에 실제로 적힌 항목 이름(기본값 상속 여부·값 출처 판단용). */
    private final Set<String> externalKeys;
    /** JVM 개별 속성으로 실제 적용된 항목 이름(허용 목록 순서). 값은 따로 보관하지 않는다. */
    private final Set<String> jvmKeys;
    /** 지정됐지만 적용하지 않은 JVM 속성 이름(정책 false이거나 정책 항목 자체). 진단용이며 값은 보관하지 않는다. */
    private final Set<String> ignoredJvmKeys;
    /** 지원하는 설정 항목 이름(JAR 기본 설정에 들어 있는 이름이 곧 전체 목록이다). */
    private final Set<String> knownKeys;
    /** 외부 설정 경로를 얻은 곳. */
    private final ConfigOrigin origin;
    /** 외부 설정 파일 이름(경로 제외). 외부 설정이 없으면 null. */
    private final String configFileName;
    /** crypto.jvm.override.enabled 해석 결과(JAR 기본값·외부 파일 기준). */
    private final boolean jvmOverrideEnabled;
    /** crypto.lang 해석 결과(auto는 생성 시점의 JVM Locale로 결정). */
    private final Messages.Language language;
    /** crypto.warning.enabled 해석 결과(최종값 기준). */
    private final boolean warningEnabled;
    /** crypto.output.encoding 해석 결과. */
    private final OutputFormat outputFormat;
    /** 등록된 키 프로필(레거시 AES 슬롯이 먼저, 그다음 템플릿 프로필을 Key ID 순서로). */
    private final List<KeyProfile> profiles;
    /** Key ID → 프로필. */
    private final java.util.Map<String, KeyProfile> profilesById;
    /** 유형을 생략한 새 암호화의 유형. */
    private final io.javacryptokit.KeyType defaultType;
    /** pass 유형의 기본 키(없을 수 있음). */
    private final KeyProfile activePass;
    /** key 유형의 기본 키(없을 수 있음). */
    private final KeyProfile activeKey;

    /**
     * 기본값·외부 설정·JVM 개별 속성을 정해진 순서로 합치고 모든 규칙을 즉시 검증한다.
     *
     * @param defaults         JAR 내장 기본값
     * @param external         외부 설정 파일 내용(없으면 빈 Properties)
     * @param jvmProperties    JVM 속성 조회 함수(이름 → 값, 없으면 null)
     * @param origin           외부 설정 경로의 출처
     * @param configFileName   외부 설정 파일 이름(경로 제외, 없으면 null)
     * @param jvmPropertyNames 현재 JVM에 지정된 시스템 속성 이름 전체(라이브러리 설정 오타 검사용)
     * @throws IllegalArgumentException 허용되지 않은 설정값, 외부 파일의 모르는 항목, -D로 받을 수 없는 항목,
     *                                  모호한 키 설정이 있는 경우
     */
    private CryptoSettings(Properties defaults, Properties external, Function<String, String> jvmProperties,
                           ConfigOrigin origin, String configFileName, Iterable<String> jvmPropertyNames) {
        this.knownKeys = Collections.unmodifiableSet(new HashSet<>(defaults.stringPropertyNames()));

        // [1] JAR 기본값 위에 외부 파일에 적힌 항목만 덮어쓴다.
        Properties merged = new Properties();
        merged.putAll(defaults);
        merged.putAll(external);
        this.externalKeys = Collections.unmodifiableSet(new HashSet<>(external.stringPropertyNames()));
        this.origin = origin;
        this.configFileName = configFileName;

        // [2] JVM 덮어쓰기 허용 정책은 JVM 속성을 적용하기 "전"의 값(외부 파일 → JAR 기본값)으로만 정한다.
        //     -Dcrypto.jvm.override.enabled는 아예 읽지 않으므로 JVM 옵션으로 운영 정책(false)을 다시 켤 수 없다.
        this.jvmOverrideEnabled = parseStrictBoolean(merged.getProperty(JVM_OVERRIDE_ENABLED), JVM_OVERRIDE_ENABLED);

        // [3] 허용 목록 항목만 JVM 속성 값으로 덮어쓴다. 빈 값(-Dcrypto.key.id=)도 "지정한 값"으로 보고 아래 검증에서 거부한다.
        Set<String> applied = new LinkedHashSet<>();
        Set<String> ignored = new LinkedHashSet<>();
        for (String key : JVM_OVERRIDABLE_KEYS) {
            String value = jvmProperties.apply(key);
            if (value == null) continue;
            if (jvmOverrideEnabled) {
                merged.setProperty(key, value);
                applied.add(key);
            } else {
                // 정책 false: 값은 쓰지 않고 이름만 남긴다(CLI info에서 "무시됨"으로 확인).
                ignored.add(key);
            }
        }
        if (jvmProperties.apply(JVM_OVERRIDE_ENABLED) != null) {
            // 정책 항목을 -D로 지정해도 적용하지 않는다(운영 정책 우회 방지). 진단에서 보이도록 이름만 남긴다.
            ignored.add(JVM_OVERRIDE_ENABLED);
        }
        // [3-1] 키 프로필(crypto.keys.<id>.*): -D는 이미 등록된 프로필의 위치 항목만 덮어쓴다(서버마다 다른 경로·변수 이름).
        //       유형·공급원·비밀·KDF·지문은 키의 정체성이라 -D로 받지 않는다(정책과 관계없이 오류, 아래 [6]).
        String rejectedProfileJvm = null;
        for (String id : profileIds(merged)) {
            for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
                String name = KeyProfile.PREFIX + id + "." + item.name;
                String value = jvmProperties.apply(name);
                if (value == null) continue;
                if (!item.location) {
                    if (rejectedProfileJvm == null) rejectedProfileJvm = name;
                } else if (jvmOverrideEnabled) {
                    merged.setProperty(name, value);
                    applied.add(name);
                } else {
                    ignored.add(name);
                }
            }
        }
        this.jvmKeys = Collections.unmodifiableSet(applied);
        this.ignoredJvmKeys = Collections.unmodifiableSet(ignored);
        this.properties = merged;

        // [4] 메시지 언어를 먼저 정한다. 이후 검증 오류는 이 설정의 언어로 만든다(WAS·Java API에서도 같은 언어).
        this.language = parseLanguage(merged.getProperty(LANG));

        Messages.Scope scope = Messages.use(language);
        try {
            // [5] 외부 파일의 모르는 항목(오타)과 이 라이브러리 설정의 오타로 보이는 -D 이름을 거부한다.
            rejectUnknownExternalKeys(external);
            rejectMisspelledJvmKeys(jvmPropertyNames);
            // [6] 키 원문을 -D로 넘긴 경우는 정책과 관계없이 거부한다. 무시하면 운영자가 키를 설정했다고 착각한 채 다른 키로
            //     동작할 수 있고, 이미 명령행에 키가 노출된 상태이므로 즉시 알려야 한다. 메시지에는 값을 넣지 않는다.
            if (jvmProperties.apply(KEY_EMBEDDED) != null) {
                throw new SafeMessageException(Messages.get("config.err.embeddedJvm", KEY_EMBEDDED));
            }
            if (rejectedProfileJvm != null) {
                throw new SafeMessageException(Messages.get("config.err.profileJvm", rejectedProfileJvm));
            }
            // [7] 최종값 검증. 값의 출처(JAR·외부 파일·JVM)와 관계없이 같은 규칙을 적용한다.
            validateCatalogValues();
            validateFormats();
            validateKeySourceIntent();
            this.warningEnabled = parseStrictBoolean(properties.getProperty(WARNING_ENABLED), WARNING_ENABLED);
            this.outputFormat = parseOutputFormat();
            // [8] Keyring: 레거시 AES 슬롯 + 템플릿 프로필(계층 간 합집합), 유형별 기본 키.
            KeyProfile legacy = "embedded".equals(get(KEY_SOURCE)) && get(KEY_EMBEDDED).isEmpty()
                    ? null : legacyProfile(properties);
            java.util.Map<String, KeyProfile> byId = new java.util.LinkedHashMap<>();
            if (legacy != null) byId.put(legacy.id(), legacy);
            java.util.TreeMap<String, KeyProfile> templates = new java.util.TreeMap<>();
            for (String id : profileIds(merged)) {
                checkProfileLayers(id, defaults, external);
                KeyProfile profile = templateProfile(id);
                if (legacy != null && profile.id().equals(legacy.id())) {
                    throw new SafeMessageException(Messages.get("config.err.profileIdConflict", id, KEY_ID));
                }
                templates.put(id, profile);
            }
            byId.putAll(templates);
            List<KeyProfile> ordered = new java.util.ArrayList<>(byId.values());
            this.profiles = Collections.unmodifiableList(ordered);
            this.profilesById = Collections.unmodifiableMap(byId);
            String typeValue = properties.getProperty(KEY_TYPE);
            // 이 항목이 없는 설정은 이전 형식 JAR의 내장 설정(레거시 단일 키)이므로 key가 기본이다. 새 JAR·외부 설정은 JAR 기본값 pass.
            this.defaultType = typeValue == null ? io.javacryptokit.KeyType.KEY
                    : io.javacryptokit.KeyType.fromCode(typeValue.trim());
            this.activePass = activeFor(io.javacryptokit.KeyType.PASS, get(KEY_ACTIVE_PASS), null);
            this.activeKey = activeFor(io.javacryptokit.KeyType.KEY, get(KEY_ACTIVE_KEY), legacy);
        } finally {
            scope.close();
        }
    }

    /** @return 설정 이름에서 찾은 템플릿 프로필 Key ID(정렬, 중복 없음) */
    private static Set<String> profileIds(Properties source) {
        Set<String> ids = new java.util.TreeSet<>();
        for (String name : source.stringPropertyNames()) {
            String[] parts = SettingCatalog.parseProfileName(name);
            if (parts != null && SettingCatalog.profileItem(parts[1]) != null) ids.add(parts[0]);
        }
        return ids;
    }

    /**
     * 계층 규칙: JAR에 등록된 프로필은 외부 설정이 위치 항목만 덮어쓸 수 있다(같은 Key ID에 다른 키가 생기지 않게). 외부 설정은
     * 새 프로필을 더할 수 있지만 JAR 프로필을 지우거나 정체성 항목을 바꿀 수 없다. 같은 값을 다시 적는 것은 허용한다.
     */
    private static void checkProfileLayers(String id, Properties defaults, Properties external) {
        boolean jarProfile = defaults.getProperty(KeyProfile.PREFIX + id + "." + KeyProfile.TYPE) != null;
        if (!jarProfile) return;
        for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
            if (item.location) continue;
            String name = KeyProfile.PREFIX + id + "." + item.name;
            String outer = external.getProperty(name);
            if (outer != null && !trimToEmpty(outer).equals(trimToEmpty(defaults.getProperty(name)))) {
                throw new SafeMessageException(Messages.get("config.err.profileImmutable", name));
            }
        }
    }

    /** 레거시 AES 슬롯의 프로필 항목 → 실제 설정 이름(이전 형식와 같은 자리). 이력의 유형 분류도 이 표를 쓴다. */
    private static final String[][] LEGACY_SLOT_MAPPING = {
            {KeyProfile.SOURCE, KEY_SOURCE}, {KeyProfile.EMBEDDED, KEY_EMBEDDED}, {KeyProfile.FILE, KEY_FILE},
            {KeyProfile.ENV, KEY_ENV}, {KeyProfile.VAULT_PATH, VAULT_PATH}, {KeyProfile.VAULT_FIELD, VAULT_FIELD},
            {KeyProfile.VAULT_VER, VAULT_VER}, {KeyProfile.AWS_KMS_DATA_KEY_FILE, AWS_KMS_DATA_KEY_FILE}};

    /**
     * 레거시 AES 슬롯({@code crypto.key.*})의 키를 정하는 설정 이름: Key ID와 공급원·내장 값·위치 항목. 바꾸면 그 슬롯의 AES 키가
     * 바뀐다(변경 이력의 key 유형 분류에 쓴다).
     */
    public static final Set<String> LEGACY_SLOT_SETTINGS;

    static {
        Set<String> names = new java.util.LinkedHashSet<>();
        names.add(KEY_ID);
        for (String[] pair : LEGACY_SLOT_MAPPING) names.add(pair[1]);
        LEGACY_SLOT_SETTINGS = Collections.unmodifiableSet(names);
    }

    /** 레거시 AES 슬롯({@code crypto.key.*})을 key 유형 프로필로 만든다(이름·의미는 이전 형식와 같다). */
    private static KeyProfile legacyProfile(Properties merged) {
        java.util.Map<String, String> values = new java.util.LinkedHashMap<>();
        java.util.Map<String, String> names = new java.util.LinkedHashMap<>();
        for (String[] pair : LEGACY_SLOT_MAPPING) {
            values.put(pair[0], trimToEmpty(merged.getProperty(pair[1])));
            names.put(pair[0], pair[1]);
        }
        values.put(KeyProfile.TYPE, io.javacryptokit.KeyType.KEY.code());
        return new KeyProfile(trimToEmpty(merged.getProperty(KEY_ID)), io.javacryptokit.KeyType.KEY, true, values, names);
    }

    /** 템플릿 프로필 하나를 검증해 만든다(값은 오류 메시지에 넣지 않는다). */
    private KeyProfile templateProfile(String id) {
        java.util.Map<String, String> values = new java.util.LinkedHashMap<>();
        for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
            String name = KeyProfile.PREFIX + id + "." + item.name;
            String raw = properties.getProperty(name);
            if (raw == null) continue;
            if (hasControl(raw)) throw new SafeMessageException(Messages.get("config.err.control", name));
            values.put(item.name, raw.trim());
        }
        String typeName = KeyProfile.PREFIX + id + "." + KeyProfile.TYPE;
        String typeValue = values.get(KeyProfile.TYPE);
        if (typeValue == null || typeValue.isEmpty()) {
            throw new SafeMessageException(Messages.get("config.err.profileType", typeName));
        }
        io.javacryptokit.KeyType type = io.javacryptokit.KeyType.fromCode(typeValue);
        if (type == null) {
            throw new SafeMessageException(Messages.get("config.err.profileValue", typeName,
                    String.join(", ", SettingCatalog.KEY_TYPES)));
        }
        String source = values.containsKey(KeyProfile.SOURCE) ? values.get(KeyProfile.SOURCE) : "";
        if (!SettingCatalog.KEY_SOURCES.contains(source)) {
            throw new SafeMessageException(Messages.get("config.err.profileValue", KeyProfile.PREFIX + id + "." + KeyProfile.SOURCE,
                    String.join(", ", SettingCatalog.KEY_SOURCES)));
        }
        // 공급원마다 필요한 위치 항목. 다른 공급원의 위치 항목이 섞여 있으면 의도와 다르게 동작할 수 있으므로 거부한다.
        String required = requiredItem(source);
        for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) {
            boolean sourceItem = item.location || KeyProfile.EMBEDDED.equals(item.name);
            if (!sourceItem || !values.containsKey(item.name) || values.get(item.name).isEmpty()) continue;
            if (!belongsTo(item.name, source)) {
                throw new SafeMessageException(Messages.get("config.err.profileItemSource",
                        KeyProfile.PREFIX + id + "." + item.name, source));
            }
        }
        if (value(values, required).isEmpty()) {
            throw new SafeMessageException(Messages.get("config.err.profileRequired", id, source,
                    KeyProfile.PREFIX + id + "." + required));
        }
        checkProfileFormat(id, values, KeyProfile.ENV, ENV_NAME);
        checkProfileFormat(id, values, KeyProfile.VAULT_PATH, "[A-Za-z0-9_.-]{1,128}(/[A-Za-z0-9_.-]{1,128}){0,15}");
        checkProfileFormat(id, values, KeyProfile.VAULT_FIELD, "[A-Za-z0-9_.-]{1,128}");
        checkProfileFormat(id, values, KeyProfile.VAULT_VER, "[1-9][0-9]{0,8}");
        if (value(values, KeyProfile.VAULT_PATH).matches("(.*/)?\\.{1,2}(/.*)?")) {
            throw new SafeMessageException(Messages.get("config.err.profileValue", KeyProfile.PREFIX + id + "." + KeyProfile.VAULT_PATH,
                    "secret/path"));
        }
        // 외부 공급 키는 등록할 때 확인한 지문을 고정한다(외부 비밀값이 바뀌면 같은 Key ID로 조용히 받지 않음).
        String pin = value(values, KeyProfile.FINGERPRINT);
        if (!"embedded".equals(source) && pin.isEmpty()) {
            throw new SafeMessageException(Messages.get("config.err.profileRequired", id, source,
                    KeyProfile.PREFIX + id + "." + KeyProfile.FINGERPRINT));
        }
        if (!pin.isEmpty() && !pin.matches("[0-9a-f]{64}")) {
            throw new SafeMessageException(Messages.get("config.err.profilePin", KeyProfile.PREFIX + id + "." + KeyProfile.FINGERPRINT));
        }
        // Passphrase 파생 메타데이터: pass는 모두 필요하고 key에는 쓰지 않는다.
        String[] kdfItems = {KeyProfile.KDF, KeyProfile.KDF_ITERATIONS, KeyProfile.SALT};
        for (String item : kdfItems) {
            String name = KeyProfile.PREFIX + id + "." + item;
            if (type == io.javacryptokit.KeyType.KEY) {
                if (!value(values, item).isEmpty()) throw new SafeMessageException(Messages.get("config.err.profilePassOnly", name));
            } else if (value(values, item).isEmpty()) {
                throw new SafeMessageException(Messages.get("config.err.profileRequired", id, source, name));
            }
        }
        if (type == io.javacryptokit.KeyType.PASS) {
            if (!SettingCatalog.KDF_NAMES.contains(value(values, KeyProfile.KDF))) {
                throw new SafeMessageException(Messages.get("config.err.profileValue", KeyProfile.PREFIX + id + "." + KeyProfile.KDF,
                        String.join(", ", SettingCatalog.KDF_NAMES)));
            }
            String iterations = value(values, KeyProfile.KDF_ITERATIONS);
            boolean inRange = iterations.matches("[0-9]{1,9}") && Integer.parseInt(iterations) >= SettingCatalog.KDF_MIN_ITERATIONS
                    && Integer.parseInt(iterations) <= SettingCatalog.KDF_MAX_ITERATIONS;
            if (!inRange) {
                throw new SafeMessageException(Messages.get("config.err.number", KeyProfile.PREFIX + id + "." + KeyProfile.KDF_ITERATIONS,
                        SettingCatalog.KDF_MIN_ITERATIONS, SettingCatalog.KDF_MAX_ITERATIONS));
            }
            byte[] salt;
            try {
                salt = java.util.Base64.getDecoder().decode(value(values, KeyProfile.SALT));
            } catch (IllegalArgumentException e) {
                salt = new byte[0];
            }
            if (salt.length != 16) {
                throw new SafeMessageException(Messages.get("config.err.profileSalt", KeyProfile.PREFIX + id + "." + KeyProfile.SALT));
            }
        }
        return new KeyProfile(id, type, false, values, Collections.<String, String>emptyMap());
    }

    /** @return 공급원이 반드시 써야 하는 위치 항목(embedded는 내장 키) */
    private static String requiredItem(String source) {
        switch (source) {
            case "file": return KeyProfile.FILE;
            case "env": return KeyProfile.ENV;
            case "vault": return KeyProfile.VAULT_PATH;
            case "aws-kms": return KeyProfile.AWS_KMS_DATA_KEY_FILE;
            default: return KeyProfile.EMBEDDED;
        }
    }

    /** @return 위치·내장 항목이 그 공급원에서 쓰이면 true(설정 검증과 CLI의 위치 항목 지정이 같은 규칙을 쓴다) */
    public static boolean belongsTo(String item, String source) {
        switch (item) {
            case KeyProfile.EMBEDDED: return "embedded".equals(source);
            case KeyProfile.FILE: return "file".equals(source);
            case KeyProfile.ENV: return "env".equals(source);
            case KeyProfile.VAULT_PATH:
            case KeyProfile.VAULT_FIELD:
            case KeyProfile.VAULT_VER: return "vault".equals(source);
            case KeyProfile.AWS_KMS_DATA_KEY_FILE: return "aws-kms".equals(source);
            default: return true;
        }
    }

    private static String value(java.util.Map<String, String> values, String item) {
        String value = values.get(item);
        return value == null ? "" : value;
    }

    private static void checkProfileFormat(String id, java.util.Map<String, String> values, String item, String regex) {
        String value = value(values, item);
        if (!value.isEmpty() && !value.matches(regex)) {
            throw new SafeMessageException(Messages.get("config.err.profileFormat", KeyProfile.PREFIX + id + "." + item));
        }
    }

    /**
     * 유형별 기본 키를 정한다. 지정한 Key ID가 없거나 유형이 다르면 오류다(다른 키로 바꾸지 않음).
     *
     * @param type     유형
     * @param id       설정한 Key ID(빈 값이면 fallback)
     * @param fallback 빈 값일 때의 기본 키(key는 레거시 AES 슬롯, pass는 없음)
     */
    private KeyProfile activeFor(io.javacryptokit.KeyType type, String id, KeyProfile fallback) {
        String setting = type == io.javacryptokit.KeyType.PASS ? KEY_ACTIVE_PASS : KEY_ACTIVE_KEY;
        if (id.isEmpty()) return fallback;
        KeyProfile profile = profilesById.get(id);
        if (profile == null) throw new SafeMessageException(Messages.get("config.err.activeMissing", setting, id));
        if (profile.type() != type) {
            throw new SafeMessageException(Messages.get("config.err.activeType", setting, id, type.code()));
        }
        return profile;
    }

    /**
     * 내장 기본 설정, (지정되었다면) 외부 설정 파일, (정책이 허용하면) JVM 개별 속성을 합쳐 검증된 설정 객체를 만든다.
     * 실제 JVM 시스템 속성과 환경변수에서 외부 설정 경로와 개별 설정값을 찾는다.
     *
     * @param explicitConfigPath 직접 지정한 외부 설정 경로(CLI {@code --config}, 공개 API {@code fromConfigFile}).
     *                           null이면 JVM 속성 → 환경변수 순서로 찾는다(WAS 연동과 {@code fromDefaultConfiguration}).
     * @return 검증을 통과한 설정
     * @throws IOException              JAR 내부 기본 설정이 없거나, 지정한 외부 설정 파일이 없거나 읽을 수 없거나,
     *                                  UTF-8이 아닌 경우
     * @throws IllegalArgumentException 설정값이 허용 범위를 벗어났거나, 설정 경로가 충돌하거나, 키 설정이 모호하거나,
     *                                  키 원문을 JVM 속성으로 넘겼거나, 경로 문자열 자체가 잘못된 경우
     *                                  ({@link java.nio.file.InvalidPathException} 포함)
     */
    public static CryptoSettings load(String explicitConfigPath) throws IOException {
        return load(explicitConfigPath, System::getProperty, System::getenv, System.getProperties().stringPropertyNames());
    }

    /**
     * {@link #load(String)}와 같지만, JVM 속성·환경변수 조회 방법을 주입받는다(테스트에서 실제 환경을 바꾸지 않고 경로 우선순위·
     * 충돌 규칙·JVM 덮어쓰기 정책을 검증하기 위한 진입점).
     *
     * @param explicitConfigPath 직접 지정 경로(없으면 null)
     * @param jvmProperties      JVM 속성 조회 함수(이름 → 값, 없으면 null)
     * @param environment        환경변수 조회 함수(이름 → 값, 없으면 null). 설정 경로만 여기서 읽는다.
     * @return 검증을 통과한 설정
     * @throws IOException              {@link #load(String)}와 같다
     */
    public static CryptoSettings load(String explicitConfigPath, Function<String, String> jvmProperties,
                                      Function<String, String> environment) throws IOException {
        return load(explicitConfigPath, jvmProperties, environment, Collections.<String>emptySet());
    }

    /**
     * {@link #load(String, Function, Function)}에 더해, 현재 JVM의 시스템 속성 이름 목록을 받아 이 라이브러리 설정의
     * 오타로 보이는 {@code -Dcrypto.*} 이름이 있으면 오류로 중단한다. 이름만 쓰고 값은 읽지 않는다.
     *
     * @param explicitConfigPath 직접 지정 경로(없으면 null, 빈 문자열·공백은 오류)
     * @param jvmProperties      JVM 속성 조회 함수
     * @param environment        환경변수 조회 함수
     * @param jvmPropertyNames   JVM 시스템 속성 이름 전체
     * @return 검증을 통과한 설정
     * @throws IOException {@link #load(String)}와 같다
     */
    public static CryptoSettings load(String explicitConfigPath, Function<String, String> jvmProperties,
                                      Function<String, String> environment, Iterable<String> jvmPropertyNames)
            throws IOException {
        Properties defaults = readDefaults();

        // [1] 외부 설정 경로 선택: 직접 지정 → JVM 속성 → 환경변수(각 이름 하나, 별칭 없음).
        //     "지정하지 않음(null)"과 "지정했지만 비어 있음"을 구분한다. 빈 경로를 미지정으로 보면 운영자는 외부 설정을
        //     쓴다고 믿는데 공개 내장 키로 동작하므로, 빈 값은 오류로 중단한다(Fail Closed).
        ConfigOrigin origin = ConfigOrigin.NONE;
        String path = null;
        String[] candidates = {explicitConfigPath, jvmProperties.apply(CONFIG_FILE_PROPERTY),
                environment.apply(CONFIG_FILE_ENV)};
        ConfigOrigin[] origins = {ConfigOrigin.EXPLICIT_PATH, ConfigOrigin.JVM_PROPERTY, ConfigOrigin.ENVIRONMENT};
        for (int i = 0; i < candidates.length; i++) {
            if (candidates[i] == null) continue; // 이 단계는 지정하지 않음
            path = trimToNull(candidates[i]);
            if (path == null) {
                // -Dcrypto.config.file= 처럼 지정했지만 비어 있음: 미지정으로 취급하면 내장 키로 바뀌므로 거부한다.
                throw new SafeMessageException(Messages.get("config.err.pathBlank", origins[i].description()));
            }
            origin = origins[i];
            break;
        }

        // [2] 외부 설정 읽기: 지정했는데 읽지 못하면 예외로 끝난다(내장 기본값으로 대체하지 않음).
        Properties external = new Properties();
        String fileName = null;
        if (path != null) {
            Path externalPath = Paths.get(path);
            Path name = externalPath.getFileName();
            fileName = name == null ? null : SecretFiles.fileName(externalPath);
            // 파일이 없으면 NoSuchFileException, UTF-8이 아니면 MalformedInputException이 발생한다.
            try (Reader reader = Files.newBufferedReader(externalPath, StandardCharsets.UTF_8)) {
                external.load(reader);
            }
        }
        // [3] 생성자에서 JVM 덮어쓰기 정책 적용, 언어 결정, 모르는 항목 검사, 허용값·모호성 검증을 한다.
        return new CryptoSettings(defaults, external, jvmProperties, origin, fileName, jvmPropertyNames);
    }

    /**
     * <b>내부 전용</b>: 공개 API로 직접 준 키 하나만 가진 메모리 안 설정({@code CredentialCrypto.fromRawKey}·{@code fromPassphrase}).
     * JAR 내부 설정·외부 설정 파일·JVM 속성·환경변수를 전혀 읽지 않고, 키 목록·이력·공개 기본 키 경고와 무관하다. 그 키가 유형의 기본
     * 키이자 유일한 키이며(다른 Key ID는 등록되지 않음), 출력 형식은 {@code ENC[v1:...]}다. 키 값은 들어 있지 않다.
     *
     * @param profile  직접 주입 키의 프로필({@link KeyProfile#direct})
     * @param language 메시지 언어
     * @return 설정
     */
    public static CryptoSettings direct(KeyProfile profile, Messages.Language language) {
        return new CryptoSettings(profile, language);
    }

    private CryptoSettings(KeyProfile profile, Messages.Language language) {
        this.properties = new Properties();
        this.externalKeys = Collections.emptySet();
        this.jvmKeys = Collections.emptySet();
        this.ignoredJvmKeys = Collections.emptySet();
        this.knownKeys = Collections.emptySet();
        this.origin = ConfigOrigin.NONE;
        this.configFileName = null;
        this.jvmOverrideEnabled = false;
        this.language = language;
        this.warningEnabled = false;
        this.outputFormat = OutputFormat.ENC;
        this.profiles = Collections.singletonList(profile);
        this.profilesById = Collections.singletonMap(profile.id(), profile);
        this.defaultType = profile.type();
        this.activePass = profile.type() == io.javacryptokit.KeyType.PASS ? profile : null;
        this.activeKey = profile.type() == io.javacryptokit.KeyType.KEY ? profile : null;
    }

    /**
     * JAR 내부 기본 설정(Properties) "그 자체"만으로 검증된 설정 객체를 만든다. 외부 설정 파일·JVM 속성·환경변수는 전혀
     * 읽지 않는다. CLI {@code config show}(JAR 내부 원본 조회), {@code config set}·{@code config embed-key}(대상 JAR에 갱신할
     * 설정의 재검증), {@code rekey --from-jar/--to-jar}가 실행 환경의 설정과 섞이지 않게 하기 위한 진입점이다.
     *
     * @param embeddedDefaults JAR 안의 {@code java-crypto-kit.properties} 내용(지원 항목 목록도 이 이름들로 정해진다)
     * @return 검증을 통과한 설정(모든 값의 출처는 JAR 기본값)
     * @throws IllegalArgumentException 허용되지 않은 값이 있는 경우(고정 문구, 값은 넣지 않음)
     */
    public static CryptoSettings fromEmbeddedDefaults(Properties embeddedDefaults) {
        Properties copy = new Properties();
        copy.putAll(embeddedDefaults);
        return new CryptoSettings(copy, new Properties(), name -> null, ConfigOrigin.NONE, null,
                Collections.<String>emptySet());
    }

    /**
     * 설정을 읽기 "전"에 만들어지는 메시지의 언어를 정한다(예: 외부 설정 파일이 없다는 오류). 예외를 던지지 않으며 메시지를
     * 만들지 않는다(무한 재귀 방지). 순서: {@code -Dcrypto.lang}(JAR 내장 덮어쓰기 정책이 허용할 때) → JAR 내장
     * {@code crypto.lang} → 기본 ko. 값이 auto면 JVM 기본 Locale(한국어 외에는 영어)이다. 외부 설정 파일은 아직 읽지 않은
     * 상태이므로 보지 않는다. 잘못된 값은 여기서는 기본 ko로 보고, 실제 설정을 읽을 때 오류로 알린다.
     *
     * @return 메시지 언어
     */
    public static Messages.Language bootstrapLanguage() {
        Properties jar = cachedDefaultsQuietly();
        String value = null;
        boolean jvmAllowed = jar == null || !"false".equals(trimToEmpty(jar.getProperty(JVM_OVERRIDE_ENABLED)));
        if (jvmAllowed) {
            try {
                value = System.getProperty(LANG);
            } catch (SecurityException ignored) {
                value = null;
            }
        }
        if (value == null && jar != null) value = jar.getProperty(LANG);
        String code = value == null ? SettingCatalog.DEFAULT_LANGUAGE : value.trim();
        if ("auto".equals(code)) return Messages.Language.fromLocale(Locale.getDefault());
        Messages.Language fixed = Messages.Language.fromCode(code);
        return fixed != null ? fixed : Messages.Language.fromCode(SettingCatalog.DEFAULT_LANGUAGE);
    }

    /** JAR 내부 기본 설정을 UTF-8로 읽는다(복사본). 없으면 배포 JAR가 손상된 것이므로 즉시 실패한다. */
    private static Properties readDefaults() throws IOException {
        Properties cached = cachedDefaults;
        if (cached == null) {
            Properties defaults = new Properties();
            try (InputStream in = defaultsStream()) {
                if (in == null) throw new IOException("java-crypto-kit.properties");
                // Properties.load(InputStream)는 기본 ISO-8859-1이므로 Reader를 명시한다.
                try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                    defaults.load(reader);
                }
            }
            cachedDefaults = defaults;
            cached = defaults;
        }
        Properties copy = new Properties();
        copy.putAll(cached);
        return copy;
    }

    private static InputStream defaultsStream() throws IOException {
        java.security.CodeSource source = CryptoSettings.class.getProtectionDomain().getCodeSource();
        if (source != null && "file".equals(source.getLocation().getProtocol())) {
            try {
                Path path = Paths.get(source.getLocation().toURI());
                if (java.nio.file.Files.isRegularFile(path)) {
                    try (java.util.jar.JarFile jar = new java.util.jar.JarFile(path.toFile(), false)) {
                        java.util.jar.Manifest manifest = jar.getManifest();
                        String format = manifest == null ? null : manifest.getMainAttributes().getValue(JarState.ATTRIBUTE);
                        if (format != null) {
                            JarState.State state = JarState.read(path, format);
                            if (state != null) return new java.io.ByteArrayInputStream(state.settings);
                        }
                    }
                }
            } catch (java.net.URISyntaxException e) {
                throw new IOException("jar location", e);
            }
        }
        return CryptoSettings.class.getResourceAsStream(DEFAULT_CONFIG_RESOURCE);
    }

    /** {@link #readDefaults()}와 같지만 실패하면 null(언어 결정용). */
    private static Properties cachedDefaultsQuietly() {
        try {
            return readDefaults();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * {@code crypto.lang}을 해석한다. 항목이 없으면(이전 형식 설정) 기본 ko, auto는 JVM Locale(한국어 외에는 영어)이다.
     *
     * @throws IllegalArgumentException ko/en/auto가 아닌 값(빈 값 포함). 아직 설정 언어가 정해지기 전이므로 부트스트랩 언어로 알린다.
     */
    private static Messages.Language parseLanguage(String raw) {
        String value = raw == null ? SettingCatalog.DEFAULT_LANGUAGE : raw.trim();
        if (!SettingCatalog.LANGUAGES.contains(value)) {
            throw new SafeMessageException(Messages.get("config.err.choice." + LANG));
        }
        Messages.Language fixed = Messages.Language.fromCode(value);
        return fixed != null ? fixed : Messages.Language.fromLocale(Locale.getDefault());
    }

    /**
     * 카탈로그에 정의된 선택형·참거짓·숫자 항목을 공통 규칙으로 검증한다(값 앞뒤 공백만 제거, 대소문자 추측 없음).
     *
     * <ul>
     *   <li>{@code crypto.algorithm}: AES/GCM/NoPadding만(무인증·약한 방식으로의 다운그레이드 방지).</li>
     *   <li>{@code crypto.key.source}: 명시적으로 허용한 공급원 이름만(임의 클래스 로딩 없음).</li>
     *   <li>{@code crypto.require.encrypted.password}: true만(평문 비밀번호 허용으로의 우회 방지).</li>
     *   <li>{@code crypto.pool.factory}: Tomcat 공식 Factory 두 개만(설정으로 임의 클래스 생성 방지).</li>
     *   <li>숫자(제한 시간): 정해진 범위의 정수만(무한 대기·0 방지).</li>
     * </ul>
     * 출력 형식·언어·참거짓 항목은 항목이 아예 없으면(이전 버전 설정) 기본 동작을 쓰고, 그 밖의 필수 항목은 없으면 거부한다.
     *
     * @throws IllegalArgumentException 규칙을 어긴 경우(설정값은 메시지에 넣지 않는다)
     */
    private void validateCatalogValues() {
        for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
            String raw = properties.getProperty(setting.key);
            if (raw != null && hasControl(raw)) {
                throw new SafeMessageException(Messages.get("config.err.control", setting.key));
            }
            switch (setting.type) {
                case CHOICE:
                    // 이전 버전 설정에 없던 항목은 기본 동작을 쓴다(crypto.key.type이 없으면 이전 형식 단일 키 설정).
                    if (raw == null && (LANG.equals(setting.key) || OUTPUT_ENCODING.equals(setting.key)
                            || KEY_TYPE.equals(setting.key))) {
                        break;
                    }
                    if (!setting.choices.contains(trimToEmpty(raw))) {
                        String specific = "config.err.choice." + setting.key;
                        throw new SafeMessageException(Messages.has(Messages.current(), specific) ? Messages.get(specific)
                                : Messages.get("config.err.choice", setting.key, String.join(", ", setting.choices)));
                    }
                    break;
                case BOOLEAN:
                    parseStrictBoolean(raw, setting.key);
                    break;
                case NUMBER:
                    if (raw != null) parseNumber(setting, raw);
                    break;
                default:
                    break;
            }
        }
    }

    /** 자유 형식 문자열 항목의 형식을 검사한다(비어 있으면 검사하지 않음, 필수 여부는 키를 읽을 때 각 공급원과 doctor가 확인한다. */
    private void validateFormats() {
        if (!get(KEY_ID).matches("[A-Za-z0-9_-]{1,64}")) {
            throw new SafeMessageException(Messages.get("config.err.keyId"));
        }
        for (String active : new String[]{KEY_ACTIVE_PASS, KEY_ACTIVE_KEY}) {
            if (!get(active).isEmpty() && !get(active).matches("[A-Za-z0-9_-]{1,64}")) {
                throw new SafeMessageException(Messages.get("config.err.activeId", active));
            }
        }
        checkFormat(VAULT_URL, "https://([A-Za-z0-9.-]{1,253}|\\[[0-9A-Fa-f:]{2,45}\\])(:[0-9]{1,5})?/?");
        checkFormat(VAULT_MOUNT, "[A-Za-z0-9_-]{1,64}(/[A-Za-z0-9_-]{1,64}){0,7}");
        checkFormat(VAULT_PATH, "[A-Za-z0-9_.-]{1,128}(/[A-Za-z0-9_.-]{1,128}){0,15}");
        if (get(VAULT_PATH).matches("(.*/)?\\.{1,2}(/.*)?")) {
            throw new SafeMessageException(Messages.get("config.err.format." + VAULT_PATH));
        }
        checkFormat(VAULT_FIELD, "[A-Za-z0-9_.-]{1,128}");
        checkFormat(VAULT_VER, "[1-9][0-9]{0,8}");
        checkFormat(VAULT_TOKEN_ENV, ENV_NAME);
        checkFormat(AWS_REGION, "[a-z]{2}(-[a-z]+){1,3}-[0-9]{1,2}");
        checkFormat(AWS_KMS_KEY_ID, "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                + "|mrk-[0-9a-fA-F]{32}|alias/[A-Za-z0-9/_-]{1,250}"
                + "|arn:aws[a-z-]{0,16}:kms:[a-z]{2}(-[a-z]+){1,3}-[0-9]{1,2}:[0-9]{12}:(key/[A-Za-z0-9-]{1,64}|alias/[A-Za-z0-9/_-]{1,250}))");
        String keyArnRegion = arnRegion(get(AWS_KMS_KEY_ID));
        if (keyArnRegion != null && !get(AWS_REGION).isEmpty() && !keyArnRegion.equals(get(AWS_REGION))) {
            throw new SafeMessageException(Messages.get("config.err.awsArnRegion"));
        }
    }

    /** 값이 있으면 정규식과 정확히 일치해야 한다. */
    private void checkFormat(String key, String regex) {
        String value = get(key);
        if (!value.isEmpty() && !value.matches(regex)) {
            throw new SafeMessageException(Messages.get("config.err.format." + key));
        }
    }

    /** KMS 키 ARN에서 리전을 꺼낸다(ARN이 아니면 null). */
    private static String arnRegion(String keyId) {
        if (!keyId.startsWith("arn:")) return null;
        String[] parts = keyId.split(":", -1);
        return parts.length > 3 ? parts[3] : null;
    }

    /**
     * true/false 정책 항목을 해석한다. 오타를 조용히 기본값으로 바꾸지 않도록 소문자 true/false만 허용한다(앞뒤 공백만 제거).
     *
     * @param raw  설정값(항목이 없으면 null)
     * @param name 항목 이름(오류 메시지용)
     * @return 해석 결과. 항목 자체가 없으면(이전 설정 파일 호환) 기본값 true
     * @throws IllegalArgumentException 빈 값이거나 true/false가 아닌 경우
     */
    private static boolean parseStrictBoolean(String raw, String name) {
        if (raw == null) return true;
        String value = raw.trim();
        if ("true".equals(value)) return true;
        if ("false".equals(value)) return false;
        throw new SafeMessageException(Messages.get("config.err.boolean", name));
    }

    /** 숫자 항목을 범위 안의 정수로 해석한다. */
    private static int parseNumber(SettingCatalog.Setting setting, String raw) {
        String value = raw.trim();
        if (value.matches("[0-9]{1,9}")) {
            int number = Integer.parseInt(value);
            if (number >= setting.min && number <= setting.max) return number;
        }
        throw new SafeMessageException(Messages.get("config.err.number", setting.key, setting.min, setting.max));
    }

    /**
     * crypto.output.encoding을 해석한다. 출력 표현만 바꾸며 암호화 방식에는 영향이 없다.
     *
     * @return 출력 표현. 항목 자체가 없으면 기본 ENC
     */
    private OutputFormat parseOutputFormat() {
        String raw = properties.getProperty(OUTPUT_ENCODING);
        if (raw == null) return OutputFormat.ENC;
        OutputFormat format = OutputFormat.fromSetting(raw.trim());
        if (format == null) {
            throw new SafeMessageException(Messages.get("config.err.choice." + OUTPUT_ENCODING));
        }
        return format;
    }

    /**
     * 모호한 키 설정 검사: 외부 설정이나 JVM 속성에 외부 키를 쓰려는 흔적이 있는데 {@code crypto.key.source}를 어디에도 적지
     * 않았으면, 기본값 embedded로 조용히 동작하지 않도록 오류로 중단한다. JAR 내부 값(config set 포함)은 사용자가
     * 실행 환경에서 지정한 값이 아니므로 흔적으로 보지 않는다.
     */
    private void validateKeySourceIntent() {
        if (keySourceExplicit()) return;
        for (String key : new String[]{KEY_FILE, KEY_ENV, VAULT_URL, VAULT_PATH, AWS_KMS_KEY_ID,
                AWS_KMS_DATA_KEY_FILE}) {
            if (userSpecifiedNonEmpty(key)) {
                throw new SafeMessageException(Messages.get("config.err.ambiguousSource"));
            }
        }
    }

    /** 외부 파일이나 JVM 속성으로 지정한 값이 있고 비어 있지 않으면 true(JAR 기본값은 제외). */
    private boolean userSpecifiedNonEmpty(String key) {
        return valueOrigin(key) != ValueOrigin.JAR_DEFAULT && !get(key).isEmpty();
    }

    /**
     * 외부 설정 파일에 지원하지 않는 항목 이름이 있으면 오류로 중단한다. 이름만 보여 주고 값은 출력하지 않는다.
     * 비슷한 정식 이름이 하나뿐이면 함께 안내한다(예: crypto.warnning.enabled → crypto.warning.enabled).
     */
    private void rejectUnknownExternalKeys(Properties external) {
        Set<String> unknown = new java.util.TreeSet<>();
        for (String name : external.stringPropertyNames()) {
            // 키 프로필(crypto.keys.<Key ID>.<항목>)은 Key ID가 자유이므로 항목 이름이 정의에 있으면 지원 항목이다.
            if (!knownKeys.contains(name) && !SettingCatalog.isProfileSetting(name)) unknown.add(name);
        }
        if (unknown.isEmpty()) return;
        String first = unknown.iterator().next();
        String count = unknown.size() > 1 ? Messages.get("config.more", unknown.size() - 1) : "";
        if (!first.matches(SAFE_NAME)) {
            // 형식이 깨진 줄(예: '=' 없이 값까지 붙은 줄)은 이름에 값이 섞였을 수 있으므로 이름도 보여 주지 않는다.
            throw new SafeMessageException(Messages.get("config.err.unknownExternalUnsafe", count));
        }
        if (CONFIG_FILE_PROPERTY.equals(first)) {
            throw new SafeMessageException(Messages.get("config.err.configFileInFile", CONFIG_FILE_PROPERTY, CONFIG_FILE_ENV));
        }
        String suggestion = suggestKnownKey(first);
        throw new SafeMessageException(Messages.get("config.err.unknownExternal", first, count,
                suggestion != null ? Messages.get("config.hint.didYouMean", suggestion) : Messages.get("config.hint.seeHelp")));
    }

    /**
     * 이 라이브러리 설정의 오타로 보이는 JVM 속성 이름이 있으면 오류로 중단한다. 판단 기준은 두 가지다.
     * <ol>
     *   <li>이 라이브러리 설정 영역 안의 모르는 이름: {@code crypto.<영역>.}의 영역이 지원 항목의 영역과 같다
     *       (예: {@code crypto.key.soruce}, {@code crypto.vault.adress}).</li>
     *   <li>정식 이름과 거의 같은 이름(편집 거리 2 이하): 예 {@code crypto.keys.source}</li>
     * </ol>
     * 그 밖의 {@code crypto.*}(예: {@code crypto.policy})는 다른 프로그램의 속성일 수 있으므로 건드리지 않는다.
     */
    private void rejectMisspelledJvmKeys(Iterable<String> jvmPropertyNames) {
        Set<String> names = new HashSet<>(knownKeys);
        names.add(CONFIG_FILE_PROPERTY);
        // 등록된 키 프로필의 정식 항목 이름은 알려진 이름이다(위치 항목은 적용, 나머지는 [6]에서 오류). 등록되지 않은 Key ID의
        // crypto.keys.* 는 -D로 새 키를 만들려는 것이므로 오타와 같이 거부한다(암시적 등록 금지).
        for (String id : profileIds(properties)) {
            for (SettingCatalog.ProfileItem item : SettingCatalog.PROFILE_ITEMS) names.add(KeyProfile.PREFIX + id + "." + item.name);
        }
        Set<String> areas = new HashSet<>();
        for (String known : names) {
            if (known.startsWith("crypto.")) areas.add(areaOf(known));
        }
        Set<String> suspicious = new java.util.TreeSet<>();
        for (String name : jvmPropertyNames) {
            if (!name.startsWith("crypto.") || names.contains(name) || FOREIGN_JVM_NAMES.contains(name)) continue;
            if (areas.contains(areaOf(name)) || suggestKnownKey(name) != null) suspicious.add(name);
        }
        if (suspicious.isEmpty()) return;
        String first = suspicious.iterator().next();
        String count = suspicious.size() > 1 ? Messages.get("config.more", suspicious.size() - 1) : "";
        if (!first.matches(SAFE_NAME)) {
            throw new SafeMessageException(Messages.get("config.err.jvmTypoUnsafe", count));
        }
        String suggestion = suggest(first, names);
        throw new SafeMessageException(Messages.get("config.err.jvmTypo", first, count,
                suggestion != null ? Messages.get("config.hint.didYouMean", suggestion) : Messages.get("config.hint.seeHelp")));
    }

    /** {@code crypto.<영역>.나머지}에서 영역 이름을 돌려준다(예: crypto.key.source → key). */
    private static String areaOf(String name) {
        String rest = name.substring("crypto.".length());
        int dot = rest.indexOf('.');
        return dot < 0 ? rest : rest.substring(0, dot);
    }

    /**
     * 오타로 보이는 이름과 가장 가까운 정식 설정 이름을 찾는다. 편집 거리 2 이하이고 후보가 하나뿐일 때만 돌려준다
     * (확신할 수 없으면 추측하지 않는다).
     *
     * @param name 확인할 이름
     * @return 정식 설정 이름 또는 null
     */
    String suggestKnownKey(String name) {
        return suggest(name, knownKeys);
    }

    /**
     * 후보 중 편집 거리 2 이하이고 유일하게 가장 가까운 이름을 찾는다(CLI의 명령·설정 이름 안내에도 쓴다).
     *
     * @param name       확인할 이름
     * @param candidates 정식 이름 후보
     * @return 정식 이름 또는 null
     */
    public static String suggest(String name, Iterable<String> candidates) {
        String best = null;
        int bestDistance = Integer.MAX_VALUE;
        boolean tie = false;
        for (String known : candidates) {
            int distance = editDistance(name, known);
            if (distance < bestDistance) {
                best = known;
                bestDistance = distance;
                tie = false;
            } else if (distance == bestDistance) {
                tie = true;
            }
        }
        return bestDistance <= 2 && !tie ? best : null;
    }

    /** 두 문자열의 편집 거리(삽입·삭제·교체 횟수). 설정 이름 오타 안내에만 쓴다. */
    private static int editDistance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) previous[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }

    /**
     * 설정값을 앞뒤 공백을 제거해 반환한다. 항목이 없으면 빈 문자열을 돌려준다.
     * 내장 키 문자열({@code crypto.key.embedded})도 이 메서드로 읽히므로 반환값을 로그·화면에 그대로 출력하지 않는다.
     *
     * @param key 설정 항목 이름
     * @return 공백을 제거한 값 또는 빈 문자열(null을 돌려주지 않는다)
     */
    public String get(String key) {
        return trimToEmpty(properties.getProperty(key));
    }

    /**
     * 숫자 항목(제한 시간)을 돌려준다. 항목이 없으면(이전 버전 설정) 대신 쓸 값을 돌려준다.
     *
     * @param key      숫자 설정 이름
     * @param fallback 항목이 없을 때 쓸 값
     * @return 검증된 정수
     */
    public int intValue(String key, int fallback) {
        String raw = properties.getProperty(key);
        return raw == null ? fallback : Integer.parseInt(raw.trim());
    }

    /** @return 레거시 AES 슬롯의 키 식별자({@code crypto.key.id}). 실제 암호화에 쓰는 키는 {@link #select}로 정한다. */
    public String keyId() { return get(KEY_ID); }

    /** @return 레거시 AES 슬롯의 키 공급 방식({@code crypto.key.source}): {@link SettingCatalog#KEY_SOURCES} 중 하나 */
    public String keySource() { return get(KEY_SOURCE); }

    /** @return 등록된 키 프로필(레거시 AES 슬롯이 먼저, 그다음 템플릿 프로필을 Key ID 순서로, 변경 불가) */
    public List<KeyProfile> profiles() { return profiles; }

    /**
     * @param id Key ID
     * @return 그 Key ID의 프로필, 등록되지 않았으면 null
     */
    public KeyProfile profile(String id) { return id == null ? null : profilesById.get(id); }

    /** @return 레거시 AES 슬롯 프로필({@code crypto.key.*}) */
    public KeyProfile legacyProfile() { KeyProfile slot = profilesById.get(keyId());
        return slot != null && slot.legacy() ? slot : null; }

    /** @return 유형을 생략한 새 암호화의 유형({@code crypto.key.type}, 이전 형식 설정은 key) */
    public io.javacryptokit.KeyType defaultType() { return defaultType; }

    /**
     * @param type 유형
     * @return 그 유형의 기본 키, 없으면 null(그 유형을 지정한 암호화는 실패한다)
     */
    public KeyProfile activeProfile(io.javacryptokit.KeyType type) {
        return type == io.javacryptokit.KeyType.PASS ? activePass : activeKey;
    }

    /**
     * 새 암호화에 쓸 키를 고른다. 규칙: Key ID를 주면 그 키(유형도 주면 같아야 함), 유형만 주면 그 유형의 기본 키, 둘 다 없으면
     * 기본 유형({@code crypto.key.type})의 기본 키. 고르지 못하면 다른 키로 바꾸지 않고 오류로 끝낸다.
     *
     * @param type  유형(없으면 null)
     * @param keyId Key ID(없으면 null)
     * @return 고른 프로필
     * @throws IllegalArgumentException 등록되지 않은 Key ID, 유형 불일치, 그 유형의 기본 키 없음({@link SafeMessageException})
     */
    public KeyProfile select(io.javacryptokit.KeyType type, String keyId) {
        if (keyId != null) {
            KeyProfile profile = profilesById.get(keyId);
            if (profile == null) throw new SafeMessageException(Messages.get("config.err.keyIdUnknown", safeId(keyId)));
            if (type != null && profile.type() != type) {
                throw new SafeMessageException(Messages.get("config.err.keyTypeMismatch", keyId, profile.type().code(), type.code()));
            }
            return profile;
        }
        io.javacryptokit.KeyType chosen = type == null ? defaultType : type;
        KeyProfile active = activeProfile(chosen);
        if (active == null) {
            boolean pass = chosen == io.javacryptokit.KeyType.PASS;
            String label = pass ? "PASS (Passphrase)" : "KEY (AES Key)";
            String setting = pass ? KEY_ACTIVE_PASS : KEY_ACTIVE_KEY;
            String message = profilesById.isEmpty() ? "config.err.noActiveKey.initial" : "config.err.noActiveKey";
            throw new SafeMessageException(Messages.get(message, label, setting, chosen.code()));
        }
        return active;
    }

    /** Key ID 형식이면 그대로, 아니면 표시하지 않는다(입력값이 메시지에 섞이지 않게). */
    private static String safeId(String id) {
        return id.matches("[A-Za-z0-9_-]{1,64}") ? id : "?";
    }

    /** @return [Tomcat 연동] XML에서 Pool 선택을 생략한 경우 위임할 공식 클래스 이름({@code crypto.pool.factory}) */
    public String poolFactory() { return get(POOL_FACTORY); }

    /** @return 키 공급 방식을 외부 설정 파일이나 JVM 속성으로 직접 지정했으면 true, JAR 내부 값을 물려받았으면 false */
    public boolean keySourceExplicit() { return valueOrigin(KEY_SOURCE) != ValueOrigin.JAR_DEFAULT; }

    /**
     * 설정 항목의 최종값이 어디에서 왔는지 알려 준다(우선순위: JVM 속성 &gt; 외부 파일 &gt; JAR 내부 값). 값은 돌려주지 않는다.
     *
     * @param key 설정 항목 이름
     * @return 값의 출처
     */
    public ValueOrigin valueOrigin(String key) {
        if (jvmKeys.contains(key)) return ValueOrigin.JVM_PROPERTY;
        if (externalKeys.contains(key)) return ValueOrigin.EXTERNAL_FILE;
        return ValueOrigin.JAR_DEFAULT;
    }

    /** @return JVM 개별 속성 덮어쓰기 허용 여부({@code crypto.jvm.override.enabled}, JAR 기본값·외부 파일 기준) */
    public boolean jvmOverrideEnabled() { return jvmOverrideEnabled; }

    /** @return JVM 개별 속성으로 실제 적용된 항목 이름(허용 목록 순서, 변경 불가). 값은 들어 있지 않다. */
    public Set<String> jvmOverriddenKeys() { return jvmKeys; }

    /** @return 지정됐지만 적용하지 않은 JVM 속성 이름(정책 false, 또는 -D로 바꿀 수 없는 정책 항목). 값은 들어 있지 않다. */
    public Set<String> ignoredJvmKeys() { return ignoredJvmKeys; }

    /** @return 외부 설정 파일 경로의 출처 */
    public ConfigOrigin configOrigin() { return origin; }

    /** @return 외부 설정 파일 사용 여부 */
    public boolean externalConfigUsed() { return origin != ConfigOrigin.NONE; }

    /** @return 외부 설정 파일 이름(경로 제외). 외부 설정이 없으면 null */
    public String configFileName() { return configFileName; }

    /** @return 이전 설정 호환용 경고 옵션(crypto.warning.enabled) */
    public boolean warningEnabled() { return warningEnabled; }

    /** @return 암호문 출력 표현(crypto.output.encoding) */
    public OutputFormat outputFormat() { return outputFormat; }

    /** @return 라이브러리 메시지 언어(crypto.lang, 기본 ko. auto는 설정을 읽은 시점의 JVM Locale로 결정) */
    public Messages.Language language() { return language; }

    /** null이면 빈 문자열, 아니면 앞뒤 공백을 제거한 값. */
    private static String trimToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    /** null이거나 공백뿐이면 null, 아니면 앞뒤 공백을 제거한 값. */
    private static String trimToNull(String value) {
        String trimmed = trimToEmpty(value);
        return trimmed.isEmpty() ? null : trimmed;
    }

    /** 제어문자(줄바꿈 포함)가 있으면 true. */
    private static boolean hasControl(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (Character.isISOControl(text.charAt(i))) return true;
        }
        return false;
    }
}
