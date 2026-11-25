package io.javacryptokit.i18n;

import io.javacryptokit.config.CryptoSettings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 라이브러리 전체(CLI·공개 Java API·Tomcat JDBC Factory·Vault/AWS KMS 어댑터)가
 * 사용자에게 보여 주는 메시지를 한 곳에서 관리한다. 영어({@code en})와 한국어({@code ko})를 지원한다.
 *
 * <p><b>메시지 원본</b>: Java 8 표준 {@link ResourceBundle}(Properties 형식)을 사용한다. 기본(영어) 번들과 한국어 번들이
 * 같은 키를 가져야 하며 테스트가 이를 검사한다. 파일은 UTF-8로 저장하고 아래 {@link #UTF8_CONTROL}이 UTF-8로 읽는다
 * (Java 8의 기본 ResourceBundle은 ISO-8859-1로 읽어 한글이 깨지므로 직접 읽는다). 긴 도움말 문서는
 * {@code io/javacryptokit/i18n/help/<언어>/<주제>.txt}에 두고 {@link #text(Language, String)}로 읽는다.</p>
 *
 * <p><b>언어 결정 순서</b>(앞이 우선)</p>
 * <ol>
 *   <li>CLI의 일시 지정({@code --lang en|ko}) 또는 CLI가 설정에서 정한 프로세스 언어({@link #setProcessLanguage}).
 *       CLI 프로세스에서만 쓰며 WAS·Java API는 이 값을 쓰지 않는다.</li>
 *   <li>현재 스레드의 설정 범위({@link #use}): {@code CryptoService}·Tomcat Factory가 검증된 설정의
 *       {@code crypto.lang}으로 작업 동안 지정한다. 그래서 WAS에서도 CLI 초기화 없이 설정이 적용된다.</li>
 *   <li>설정을 읽기 전(외부 설정 파일 없음 등) 메시지: {@code -Dcrypto.lang} &gt; JAR 내장 값 &gt; 기본 ko
 *       ({@link CryptoSettings#bootstrapLanguage()}).</li>
 * </ol>
 * <p>설정 기본값은 {@code ko}(한국어)다. {@code auto}는 JVM 기본 Locale의 언어가 한국어면 {@code ko}, 그 밖의 모든 Locale
 * (지원하지 않는 언어 포함)은 {@code en}이다.</p>
 *
 * <p><b>보안</b>: 메시지 자리표시자({@code {0}})에는 설정 "이름"·개수·파일 이름처럼 고정된 안전한 값만 넣는다. 사용자 입력값·
 * 키·토큰·비밀번호·평문은 넣지 않는다. 자리표시자 치환은 {@link java.text.MessageFormat}을 쓰지 않는 단순 치환이라
 * 작은따옴표 같은 특수 문자를 해석하지 않는다(번역문 작성 실수로 문장이 깨지지 않게 하기 위함).</p>
 *
 * <p><b>번역 대상이 아닌 것</b>: CLI 명령·옵션 이름, Properties 설정 키, 키ID, 암호문·파일 형식, 오류 코드
 * ({@code CONFIGURATION} 등), 상태 코드({@code PASS/WARN/FAIL}), Java API 이름. 외부 제품(Tomcat·JDBC 드라이버·AWS SDK)이
 * 직접 출력하는 메시지도 번역하지 않는다.</p>
 */
public final class Messages {
    /** 지원 언어. 설정값·{@code --lang} 값은 {@link #code()}와 정확히 같아야 한다(소문자). */
    public enum Language {
        /** 영어(기본 번들, 지원하지 않는 Locale의 폴백). */
        EN("en", Locale.ROOT),
        /** 한국어. */
        KO("ko", Locale.KOREAN);

        private final String code;
        private final Locale bundleLocale;

        Language(String code, Locale bundleLocale) {
            this.code = code;
            this.bundleLocale = bundleLocale;
        }

        /** @return 설정·옵션에 쓰는 언어 코드(en 또는 ko) */
        public String code() {
            return code;
        }

        /**
         * 언어 코드를 해석한다. 대소문자·공백 변형을 추측하지 않는다.
         *
         * @param code 언어 코드
         * @return 대응하는 언어, 지원하지 않는 값이면 null
         */
        public static Language fromCode(String code) {
            for (Language language : values()) {
                if (language.code.equals(code)) return language;
            }
            return null;
        }

        /**
         * Locale에서 언어를 고른다. 한국어 Locale만 {@link #KO}, 그 밖의 모든 Locale(미지원 포함)은 {@link #EN}이다.
         *
         * @param locale JVM·OS Locale(null이면 영어)
         * @return 언어
         */
        public static Language fromLocale(Locale locale) {
            return locale != null && "ko".equals(locale.getLanguage()) ? KO : EN;
        }
    }

    /** 메시지 번들 이름(모두 이 패키지에 있다). 영역별로 나누되 키는 전체에서 고유해야 한다(테스트가 검사). */
    public static final List<String> BUNDLES = Collections.unmodifiableList(Arrays.asList(
            "io.javacryptokit.i18n.core", "io.javacryptokit.i18n.cli", "io.javacryptokit.i18n.settings"));

    /** 도움말 문서 위치(언어별 폴더). */
    public static final String HELP_ROOT = "io/javacryptokit/i18n/help/";

    /**
     * 이 라이브러리가 직접 출력하는 로그·오류 메시지의 공통 태그(언어와 관계없이 같다). 운영 로그 검색에 쓴다.
     * 공통 기능 전체에 쓰므로 프로젝트 이름을 그대로 쓴다(JDBC 전용 이름을 쓰지 않음).
     */
    public static final String TAG = "[java-crypto-kit]";

    /** 현재 스레드의 설정 언어 범위. 작업이 끝나면 반드시 원래 값으로 돌린다(WAS 스레드 풀에 값이 남지 않게). */
    private static final ThreadLocal<Language> SCOPE = new ThreadLocal<>();
    /** CLI 프로세스 언어(CLI만 지정). */
    private static volatile Language processLanguage;
    /** 언어별 번들 목록 캐시. */
    private static final Map<Language, List<ResourceBundle>> CACHE = Collections.synchronizedMap(new EnumMap<>(Language.class));

    /**
     * UTF-8로 Properties 번들을 읽고, 요청한 언어가 없을 때 JVM 기본 Locale로 넘어가지 않게 하는 로더.
     * (기본 ResourceBundle은 요청 Locale이 없으면 기본 Locale 번들을 먼저 찾으므로, 한국어 PC에서 미지원 Locale을 요청하면
     * 영어 대신 한국어가 나올 수 있다. 여기서는 언어를 직접 고르므로 그 동작을 끈다.)
     */
    private static final ResourceBundle.Control UTF8_CONTROL = new ResourceBundle.Control() {
        @Override
        public List<String> getFormats(String baseName) {
            return FORMAT_PROPERTIES;
        }

        @Override
        public Locale getFallbackLocale(String baseName, Locale locale) {
            return null;
        }

        @Override
        public ResourceBundle newBundle(String baseName, Locale locale, String format, ClassLoader loader, boolean reload)
                throws IOException {
            String resource = toResourceName(toBundleName(baseName, locale), "properties");
            InputStream in = loader.getResourceAsStream(resource);
            if (in == null) return null;
            try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
                return new PropertyResourceBundle(reader);
            }
        }
    };

    private Messages() { }

    /**
     * 지금 메시지를 만들 언어를 돌려준다(위 "언어 결정 순서").
     *
     * @return 언어
     */
    public static Language current() {
        Language process = processLanguage;
        if (process != null) return process;
        Language scoped = SCOPE.get();
        if (scoped != null) return scoped;
        return CryptoSettings.bootstrapLanguage();
    }

    /**
     * CLI 프로세스 전체의 언어를 정한다. CLI 진입점만 호출한다(WAS·Java API는 호출하지 않음).
     *
     * @param language 언어(null이면 지정 해제)
     */
    public static void setProcessLanguage(Language language) {
        processLanguage = language;
    }

    /** @return CLI가 지정한 프로세스 언어(없으면 null) */
    public static Language processLanguage() {
        return processLanguage;
    }

    /** 현재 스레드의 언어 범위. {@code try-with-resources}로 닫으면 이전 값으로 돌아간다. */
    public static final class Scope implements AutoCloseable {
        private final Language previous;

        private Scope(Language previous) {
            this.previous = previous;
        }

        /** 범위를 끝내고 이전 언어로 돌린다. */
        @Override
        public void close() {
            if (previous == null) {
                SCOPE.remove();
            } else {
                SCOPE.set(previous);
            }
        }
    }

    /**
     * 현재 스레드에서 작업하는 동안 쓸 언어를 지정한다.
     *
     * @param language 언어(null이면 범위를 바꾸지 않는다)
     * @return 닫으면 이전 값으로 돌아가는 범위
     */
    public static Scope use(Language language) {
        Language previous = SCOPE.get();
        if (language != null) SCOPE.set(language);
        return new Scope(previous);
    }

    /**
     * 현재 언어로 메시지를 만든다.
     *
     * @param key  메시지 키
     * @param args 자리표시자 {@code {0}}, {@code {1}} ... 에 넣을 안전한 값(설정 이름·개수 등. 비밀값·입력값 금지)
     * @return 메시지(키가 없으면 {@code !키!})
     */
    public static String get(String key, Object... args) {
        return get(current(), key, args);
    }

    /**
     * 지정한 언어로 메시지를 만든다.
     *
     * @param language 언어
     * @param key      메시지 키
     * @param args     자리표시자 값
     * @return 메시지(키가 없으면 {@code !키!})
     */
    public static String get(Language language, String key, Object... args) {
        String pattern = lookup(language, key);
        if (pattern == null) return "!" + key + "!";
        return args == null || args.length == 0 ? pattern : format(pattern, args);
    }

    /**
     * 사용자에게 보여 줄 오류 한 줄을 만든다: {@code [java-crypto-kit] [사유: 코드] 원인 조치: ...}(영어는 {@code [reason: 코드]}).
     * CLI·Tomcat Factory가 같은 형식을 쓰도록 이 한 곳에서만 만든다. 코드는 번역하지 않는다.
     *
     * @param code    사유 코드(공개 API {@code Reason} 이름 또는 USAGE·IO_ERROR·PLAINTEXT_PASSWORD 등)
     * @param message 정제된 원인·조치 문구
     * @return 오류 한 줄
     */
    public static String error(String code, String message) {
        return TAG + " " + get("format.reason", code) + " " + singleLine(message);
    }

    /** 표시용 한 줄 문자열. 경로 계산·파일 쓰기·비밀값 입력에 사용하지 않는다. */
    public static String singleLine(String text) {
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) || c == 0x2028 || c == 0x2029
                    || c == 0x061C || c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E)
                    || (c >= 0x2066 && c <= 0x2069)) {
                result.append(String.format(java.util.Locale.ROOT, "\\u%04X", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * 키가 정의되어 있는지 확인한다(테스트·도움말 생성용).
     *
     * @param language 언어
     * @param key      메시지 키
     * @return 정의되어 있으면 true
     */
    public static boolean has(Language language, String key) {
        return lookup(language, key) != null;
    }

    /**
     * 언어별 도움말 문서를 읽는다. 키 파일·외부 설정·네트워크를 쓰지 않는다.
     *
     * @param language 언어
     * @param topic    주제 이름(예: {@code encrypt}, {@code config-set})
     * @return UTF-8 문서 내용(줄바꿈은 \n). 없으면 null
     */
    public static String text(Language language, String topic) {
        if (!topic.matches("[a-z0-9-]{1,40}")) return null;
        String resource = HELP_ROOT + language.code() + "/" + topic + ".txt";
        try (InputStream in = loader().getResourceAsStream(resource)) {
            if (in == null) return null;
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) bytes.write(buffer, 0, read);
            return new String(bytes.toByteArray(), StandardCharsets.UTF_8).replace("\r\n", "\n");
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * 자리표시자 {@code {n}}을 인자로 바꾼다. 인자 개수를 넘는 번호와 그 밖의 중괄호는 그대로 둔다.
     *
     * @param pattern 메시지 원문
     * @param args    인자
     * @return 치환한 문장
     */
    static String format(String pattern, Object[] args) {
        StringBuilder out = new StringBuilder(pattern.length() + 32);
        int i = 0;
        while (i < pattern.length()) {
            char c = pattern.charAt(i);
            if (c == '{') {
                int close = pattern.indexOf('}', i);
                if (close > i + 1 && close - i <= 3) {
                    String number = pattern.substring(i + 1, close);
                    if (number.matches("[0-9]{1,2}")) {
                        int index = Integer.parseInt(number);
                        if (index < args.length) {
                            Object value = args[index];
                            out.append(value instanceof java.nio.file.Path ? singleLine(value.toString()) : value);
                            i = close + 1;
                            continue;
                        }
                    }
                }
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    /** 번들에서 키를 찾는다(영역별 번들을 차례로 확인). */
    private static String lookup(Language language, String key) {
        for (ResourceBundle bundle : bundles(language)) {
            if (bundle.containsKey(key)) {
                try {
                    return bundle.getString(key);
                } catch (MissingResourceException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    /** 언어별 번들 목록(한 번 읽은 뒤 캐시). 이 라이브러리를 로딩한 클래스로더에서만 읽는다(웹앱 리소스로 바꿔치기 방지). */
    private static List<ResourceBundle> bundles(Language language) {
        List<ResourceBundle> cached = CACHE.get(language);
        if (cached != null) return cached;
        List<ResourceBundle> loaded = new ArrayList<>();
        for (String name : BUNDLES) {
            try {
                loaded.add(ResourceBundle.getBundle(name, language.bundleLocale, loader(), UTF8_CONTROL));
            } catch (MissingResourceException ignored) {
                // 번들 파일이 빠진 잘못된 빌드: 키 대신 !키!가 보이며 테스트에서 드러난다.
            }
        }
        List<ResourceBundle> result = Collections.unmodifiableList(loaded);
        CACHE.put(language, result);
        return result;
    }

    private static ClassLoader loader() {
        ClassLoader loader = Messages.class.getClassLoader();
        return loader != null ? loader : ClassLoader.getSystemClassLoader();
    }
}
