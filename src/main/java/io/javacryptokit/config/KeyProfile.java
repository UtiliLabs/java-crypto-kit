package io.javacryptokit.config;

import io.javacryptokit.KeyType;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: Keyring에 등록된 키 하나(Key ID·유형·공급원·위치·KDF 메타데이터)의 설정 정보다.
 * 키 재료(원문 키·Passphrase)는 들어 있지 않다. 내장 공급원의 비밀 값({@code embedded})만 설정 문자열로 들고 있으며 화면·로그에
 * 출력하지 않는다. 생성 후 바뀌지 않는다.
 *
 * <p><b>두 가지 출처</b></p>
 * <ul>
 *   <li><b>레거시 AES 슬롯</b>: 기존 단일 키 설정 {@code crypto.key.*}(+ {@code crypto.vault.path/field/ver},
 *       {@code crypto.aws.kms.data-key.file})이 정의하는 key 유형 프로필 하나. ID는 {@code crypto.key.id}이며 의미는 이전 형식와 같다.</li>
 *   <li><b>템플릿 프로필</b>: {@code crypto.keys.<Key ID>.<항목>}으로 정의하는 프로필. Passphrase 키와 추가 AES 키는 모두 이 형식이다.</li>
 * </ul>
 */
public final class KeyProfile {
    /** 템플릿 프로필 설정 이름 접두사. */
    public static final String PREFIX = "crypto.keys.";
    /** 항목: 유형(pass·key). */
    public static final String TYPE = "type";
    /** 항목: 공급원(embedded·file·env·vault·aws-kms). */
    public static final String SOURCE = "source";
    /** 항목: 내장 키(표준 Base64 32바이트, pass는 파생 키). 비밀. */
    public static final String EMBEDDED = "embedded";
    /** 항목: 키 파일 또는 Passphrase 파일 경로. */
    public static final String FILE = "file";
    /** 항목: 키 또는 Passphrase 환경변수 이름. */
    public static final String ENV = "env";
    /** 항목: Vault Secret 경로. */
    public static final String VAULT_PATH = "vault.path";
    /** 항목: Vault 필드 이름. */
    public static final String VAULT_FIELD = "vault.field";
    /** 항목: Vault Secret 버전. */
    public static final String VAULT_VER = "vault.ver";
    /** 항목: KMS로 감싼 데이터 키 파일. */
    public static final String AWS_KMS_DATA_KEY_FILE = "aws.kms.data-key.file";
    /** 항목: 키 파생 방식(pass만, pbkdf2-sha256). */
    public static final String KDF = "kdf";
    /** 항목: 키 파생 반복 횟수(pass만). */
    public static final String KDF_ITERATIONS = "kdf.iterations";
    /** 항목: 키 파생 Salt(pass만, 표준 Base64 16바이트). */
    public static final String SALT = "salt";
    /** 항목: 외부 공급 키의 고정 지문(64자). 실행 중 공급받은 키와 다르면 사용하지 않는다. */
    public static final String FINGERPRINT = "fingerprint";

    private final String id;
    private final KeyType type;
    private final boolean legacy;
    /** 항목 이름 → 값(앞뒤 공백 제거). */
    private final Map<String, String> values;
    /** 항목 이름 → 실제 설정 이름(진단·오류 메시지용). */
    private final Map<String, String> settingNames;

    KeyProfile(String id, KeyType type, boolean legacy, Map<String, String> values, Map<String, String> settingNames) {
        this.id = id;
        this.type = type;
        this.legacy = legacy;
        this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
        this.settingNames = Collections.unmodifiableMap(new LinkedHashMap<>(settingNames));
    }

    /** @return Key ID(암호문·파일 헤더에 기록되는 식별자) */
    /**
     * <b>내부 전용</b>: {@code config key add}·{@code config embed-key}가 키를 등록하기 전에 공급원을 한 번 읽어 지문을 계산할 때 쓰는
     * 임시 프로필이다. 설정 검증(지문 고정 필수 등)을 거치지 않으므로 실제 암복호화 설정에는 쓰지 않는다.
     *
     * @param id    Key ID
     * @param type  유형
     * @param items 항목 이름(예: {@code source}, {@code file}, {@code salt}) → 값
     * @return 임시 프로필
     */
    public static KeyProfile probe(String id, KeyType type, Map<String, String> items) {
        Map<String, String> names = new LinkedHashMap<>();
        for (String item : items.keySet()) names.put(item, PREFIX + id + "." + item);
        return new KeyProfile(id, type, false, items, names);
    }

    /** 개발자가 공개 API로 직접 준 키의 공급 방식 이름({@code CredentialCrypto.fromRawKey}·{@code fromPassphrase}). 설정으로는 지정할 수 없다. */
    public static final String DIRECT = "direct";

    /**
     * <b>내부 전용</b>: 공개 API로 직접 준 키의 프로필. 키 값은 들어 있지 않으며(키는 그 객체만 메모리에 보관) 공급 방식만
     * {@link #DIRECT}다. JAR·설정 파일·키 목록·이력에 등록되지 않는다.
     *
     * @param id   Key ID
     * @param type 유형
     * @return 프로필
     */
    public static KeyProfile direct(String id, KeyType type) {
        Map<String, String> items = new LinkedHashMap<>();
        items.put(SOURCE, DIRECT);
        Map<String, String> names = new LinkedHashMap<>();
        names.put(SOURCE, PREFIX + id + "." + SOURCE);
        return new KeyProfile(id, type, false, items, names);
    }

    public String id() { return id; }

    /** @return 유형(pass·key). 레거시 슬롯은 항상 key */
    public KeyType type() { return type; }

    /** @return 레거시 AES 슬롯({@code crypto.key.*})이면 true */
    public boolean legacy() { return legacy; }

    /** @return 공급원 이름(embedded·file·env·vault·aws-kms) */
    public String source() { return value(SOURCE); }

    /**
     * @param item 항목 이름(이 클래스의 상수)
     * @return 값(앞뒤 공백 제거), 없으면 빈 문자열. {@link #EMBEDDED}는 비밀이므로 출력하지 않는다.
     */
    public String value(String item) {
        String value = values.get(item);
        return value == null ? "" : value;
    }

    /**
     * @param item 항목 이름
     * @return 이 프로필에서 그 항목을 정하는 설정 이름(레거시 슬롯은 {@code crypto.key.file} 같은 기존 이름)
     */
    public String settingName(String item) {
        String name = settingNames.get(item);
        return name != null ? name : PREFIX + id + "." + item;
    }

    /** @return 키 파생 반복 횟수(pass만, 검증된 값) */
    public int iterations() {
        return Integer.parseInt(value(KDF_ITERATIONS));
    }

    /** @return 키 파생 Salt 복사본(pass만, 검증된 값) */
    public byte[] salt() {
        return Base64.getDecoder().decode(value(SALT));
    }

    /** @return 고정 지문(64자 소문자 16진수), 없으면 null */
    public String pinnedFingerprint() {
        String pin = value(FINGERPRINT);
        return pin.isEmpty() ? null : pin;
    }

    /** @return 원문 Passphrase를 실행 중 외부 공급원(file·env·vault)에서 받아 파생해야 하면 true */
    public boolean derivesAtRuntime() {
        return type == KeyType.PASS && ("file".equals(source()) || "env".equals(source()) || "vault".equals(source()));
    }
}
