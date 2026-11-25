package io.javacryptokit.cli;

import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.DefaultKeyWarning;
import io.javacryptokit.key.KeyResolver;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <b>내부 구현 클래스</b>: 등록된 키(키 목록)를 화면에 보여 주는 공통 형식이다. {@code info}·{@code doctor}·{@code config show}와
 * 변경 이력의 키 요약 줄이 같은 표현을 쓴다. 관리자 인증 뒤 보는 {@code config show}·{@code config history}·{@code config key show}는
 * 관리정보(전체 지문·KDF·반복 횟수·Salt·Salt SHA-256)를 마스킹 없이 보여 주고, {@code info}·{@code doctor}는 짧은 지문을 쓴다. 키
 * 원문·Passphrase는 자동 생성 직후 표시와 {@code config key show --show}(SHOW 확인 뒤)에서만 다룬다.
 */
final class KeyringView {
    private KeyringView() { }

    /**
     * 키 표시 꼬리표: 유형, 그 유형의 기본 키면 "기본", 레거시 AES 슬롯이면 {@code crypto.key.*}.
     *
     * @param settings 검증된 설정
     * @param profile  키
     * @return 예: {@code pass, 기본}
     */
    static String marks(CryptoSettings settings, KeyProfile profile) {
        List<String> marks = new ArrayList<>();
        marks.add(profile.type().code());
        if (isActive(settings, profile)) marks.add(Messages.get("cli.key.default"));
        if (profile.legacy()) marks.add("crypto.key.*");
        return String.join(", ", marks);
    }

    /** @return 이 키가 그 유형의 기본 키이면 true */
    static boolean isActive(CryptoSettings settings, KeyProfile profile) {
        KeyProfile active = settings.activeProfile(profile.type());
        return active != null && active.id().equals(profile.id());
    }

    /** @return 유형별 기본 키 요약(예: {@code pass=pass-default, key=default}, 없으면 "없음") */
    static String actives(CryptoSettings settings) {
        return "pass=" + idOrNone(settings.activeProfile(KeyType.PASS)) + ", key=" + idOrNone(settings.activeProfile(KeyType.KEY));
    }

    /** @return Key ID, 없으면 "없음" */
    static String idOrNone(KeyProfile profile) {
        return profile == null ? Messages.get("cli.info.none") : profile.id();
    }

    /**
     * JAR 안의 정보만으로 키 하나를 요약한다(외부 키를 읽지 않음): 유형·공급원, 내장 키는 상태(공개 기본 키/사용자 지정), 외부 키는
     * "외부 키". 지문·KDF는 {@link #profileDetails}가 다음 줄에 보여 준다. {@code config show}가 쓴다.
     *
     * @param settings JAR 내부 설정
     * @param profile  키
     * @return 예: {@code pass, embedded, 공개 기본 키}
     */
    static String jarSummary(CryptoSettings settings, KeyProfile profile) {
        List<String> parts = new ArrayList<>();
        parts.add(profile.type().code());
        parts.add(profile.source());
        parts.add(status(profile));
        // 기본 키 여부는 바로 위 "기본 키" 줄이 보여 주므로 여기서는 crypto.key.* AES 키만 표시한다(80열 유지).
        if (profile.legacy()) parts.add("crypto.key.*");
        return String.join(", ", parts);
    }

    /** @return 키 상태: 내장 키는 공개 기본 키/사용자 지정(형식 오류면 그 사유), 외부 키는 "외부 키" */
    static String status(KeyProfile profile) {
        if (!"embedded".equals(profile.source())) return Messages.get("cfg.key.external");
        byte[] key = null;
        try {
            key = KeyResolver.decodeEmbedded(profile.value(KeyProfile.EMBEDDED));
            return CryptoCli.keyStatus(DefaultKeyWarning.isPublicDefaultKey(key));
        } catch (IllegalArgumentException e) {
            return Messages.get("cfg.key.invalid", e.getMessage());
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /**
     * JAR에 등록된 키의 관리정보 줄(마스킹 없음, 키 원문 없음): 전체 지문(내장 키는 값에서 계산, 외부 키는 고정 지문·없으면 "모름"),
     * pass는 KDF·반복 횟수, Salt, Salt SHA-256.
     *
     * @param profile 키
     * @param indent  줄 앞 들여쓰기
     * @return 화면 줄(80열을 넘는 항목은 이름 다음 줄에 값)
     */
    static List<String> profileDetails(KeyProfile profile, String indent) {
        List<String> lines = new ArrayList<>();
        String fingerprint = jarFingerprint(profile);
        String shown;
        if (fingerprint == null) {
            shown = Messages.get("keys.detail.unknown");
        } else if (!"embedded".equals(profile.source())) {
            shown = Messages.get("keys.detail.pinned", fingerprint);
        } else {
            shown = fingerprint;
        }
        detail(lines, indent, Messages.get("keys.detail.fingerprint"), shown);
        if (profile.type() == KeyType.PASS) {
            detail(lines, indent, "KDF", Messages.get("keys.detail.kdfValue", profile.value(KeyProfile.KDF),
                    rounds(profile.value(KeyProfile.KDF_ITERATIONS))));
            String salt = emptyToNull(profile.value(KeyProfile.SALT));
            detail(lines, indent, "Salt", salt == null ? Messages.get("keys.detail.notRecorded") : salt);
            String saltSha256 = salt == null ? null : saltSha256(salt);
            detail(lines, indent, "Salt SHA-256", saltSha256 == null ? Messages.get("keys.detail.notRecorded") : saltSha256);
        }
        return lines;
    }

    /**
     * 이력 키 기록의 관리정보 줄(기록된 값 그대로): 전체 지문, pass는 KDF·반복 횟수와 Salt SHA-256. 기록에 없는 항목은 "기록 없음"으로
     * 구분한다(이전 형식 기록의 값을 지어내지 않음).
     */
    static List<String> recordDetails(ConfigHistory.KeyRecord record, String indent) {
        List<String> lines = new ArrayList<>();
        String missing = Messages.get("keys.detail.notRecorded");
        detail(lines, indent, Messages.get("keys.detail.fingerprint"), record.fingerprint == null ? missing : record.fingerprint);
        if (KeyType.PASS.code().equals(record.type)) {
            detail(lines, indent, "KDF", record.kdf == null || record.iterations == null ? missing
                    : Messages.get("keys.detail.kdfValue", record.kdf, rounds(record.iterations)));
            detail(lines, indent, "Salt SHA-256", record.saltSha256 == null ? missing : record.saltSha256);
        }
        return lines;
    }

    /** 이름: 값 한 줄. 80열을 넘으면 이름 줄 다음에 값을 2칸 더 들여 쓴다(값은 자르지 않음). */
    private static void detail(List<String> lines, String indent, String label, String value) {
        String line = indent + label + ": " + value;
        if (CliHelp.width(line) <= CliHelp.LINE_WIDTH) {
            lines.add(line);
        } else {
            lines.add(indent + label + ":");
            lines.add(indent + "  " + value);
        }
    }

    /** @return 반복 횟수 표시(예: 600,000). 숫자가 아니면 그대로 */
    static String rounds(String iterations) {
        try {
            return String.format(java.util.Locale.ROOT, "%,d", Long.parseLong(iterations.trim()));
        } catch (RuntimeException e) {
            return String.valueOf(iterations);
        }
    }

    /**
     * JAR 안의 정보만으로 키 지문을 구한다(외부 키를 읽지 않음).
     *
     * @param profile 키
     * @return 내장 키는 값에서 계산한 지문, 외부 키는 고정 지문, 알 수 없으면 null
     */
    static String jarFingerprint(KeyProfile profile) {
        if (!"embedded".equals(profile.source())) return profile.pinnedFingerprint();
        byte[] key = null;
        try {
            key = KeyResolver.decodeEmbedded(profile.value(KeyProfile.EMBEDDED));
            return KeyResolver.fingerprint(key);
        } catch (IllegalArgumentException e) {
            return null;
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /** 이력 기록의 출처 값(번역하지 않는 고정 이름). */
    static final java.util.Set<String> ORIGINS = java.util.Collections.unmodifiableSet(new java.util.LinkedHashSet<>(
            java.util.Arrays.asList("generated", "restored", "copied", "file", "input", "external", "moved")));

    /**
     * 등록·제거하는 키의 이력 기록(키 원문·Passphrase·Salt 값 없음, 전체 지문과 Salt의 SHA-256만).
     *
     * @param type        유형
     * @param source      공급원
     * @param origin      출처({@link #ORIGINS}, 모르면 null)
     * @param fingerprint 전체 키 지문(64자, 모르면 null)
     * @param items       pass 키 항목(kdf, kdf.iterations, salt), 없으면 null
     * @param publicKey   공개 기본 키이면 true
     * @param slot        레거시 AES 슬롯({@code crypto.key.*})의 키이면 true
     */
    static ConfigHistory.KeyRecord record(KeyType type, String source, String origin, String fingerprint,
                                          java.util.Map<String, String> items, boolean publicKey, boolean slot) {
        String kdf = items == null ? null : emptyToNull(items.get(KeyProfile.KDF));
        String iterations = items == null ? null : emptyToNull(items.get(KeyProfile.KDF_ITERATIONS));
        String salt = items == null ? null : emptyToNull(items.get(KeyProfile.SALT));
        return new ConfigHistory.KeyRecord(type.code(), source, origin, fingerprint, kdf, iterations,
                salt == null ? null : saltSha256(salt), publicKey, slot);
    }

    /** 등록된 키(프로필)의 이력 기록. 외부 키는 고정 지문(없으면 지문 모름). */
    static ConfigHistory.KeyRecord record(KeyProfile profile, String origin) {
        java.util.Map<String, String> items = new java.util.HashMap<>();
        if (profile.type() == KeyType.PASS) {
            items.put(KeyProfile.KDF, profile.value(KeyProfile.KDF));
            items.put(KeyProfile.KDF_ITERATIONS, profile.value(KeyProfile.KDF_ITERATIONS));
            items.put(KeyProfile.SALT, profile.value(KeyProfile.SALT));
        }
        return record(profile.type(), profile.source(), origin, jarFingerprint(profile), items, isPublic(profile), profile.legacy());
    }

    /** @return 내장 키가 공개 기본 키이면 true(외부 키·읽을 수 없는 값은 false) */
    static boolean isPublic(KeyProfile profile) {
        if (!"embedded".equals(profile.source())) return false;
        byte[] key = null;
        try {
            key = KeyResolver.decodeEmbedded(profile.value(KeyProfile.EMBEDDED));
            return DefaultKeyWarning.isPublicDefaultKey(key);
        } catch (IllegalArgumentException e) {
            return false;
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
        }
    }

    /** @return Salt(표준 Base64)의 SHA-256 16진수. Salt를 이력에 남기지 않고 같은 Salt인지만 확인할 때 쓴다 */
    static String saltSha256(String saltBase64) {
        byte[] salt;
        try {
            salt = java.util.Base64.getDecoder().decode(saltBase64.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
        return ConfigHistory.hex(ConfigHistory.sha256(salt));
    }

    /**
     * 이력 값 표시: 키 기록이면 번역한 요약(유형, 공급원, crypto.key.*, 공개 기본 키, 출처), 고정 표시·예전 형식이면 그대로. 기록된
     * 전체 지문·KDF·반복 횟수·Salt SHA-256은 {@link #recordDetails}가 다음 줄에 보여 준다.
     */
    static String displayRecord(String stored) {
        ConfigHistory.KeyRecord record = ConfigHistory.KeyRecord.parse(stored);
        if (record == null) return ConfigHistory.display(stored);
        List<String> parts = new ArrayList<>();
        parts.add(record.type);
        if (record.source != null) parts.add(record.source);
        if (record.slot) parts.add("crypto.key.*");
        if (record.publicKey) parts.add(CryptoCli.keyStatus(true));
        if (record.origin != null) {
            parts.add(ORIGINS.contains(record.origin) ? Messages.get("history.origin." + record.origin) : record.origin);
        }
        return String.join(", ", parts);
    }

    /** 생성값을 어디에 두었는지(대화형 표시의 마지막 안내 줄을 고른다). */
    enum Kept {
        /** keygen: 키 파일에 같은 값이 있다. */
        KEY_FILE,
        /** --export로 내보낸 파일에도 있다. */
        EXPORT,
        /** 화면에만 있다(지금 보관하지 않으면 원문을 다시 볼 수 없음). */
        NONE
    }

    /**
     * 자동 생성한 값을 대화형 터미널에만 한 번 보여 준다(표준 출력·표준 오류·로그로 보내지 않음). 유형, Key ID(등록하지 않았으면
     * 미등록), 값의 형식, 값 한 줄(라벨·공백 없음: 그 줄을 그대로 복사), pass는 복원 정보(KDF·반복 횟수·Salt)와 전체 지문, 마지막에
     * 보관 안내 한 줄. 호출자는 작업이 모두 성공한 뒤에만 부른다.
     *
     * @param terminal    대화형 터미널
     * @param type        유형
     * @param keyId       등록한 Key ID(keygen처럼 등록하지 않았으면 null)
     * @param secret      생성값(pass: Passphrase 글자, key: 표준 Base64 44자 = 키 파일 한 줄)
     * @param items       pass 키 항목(kdf, kdf.iterations, salt), key면 null
     * @param fingerprint pass 키의 전체 지문(복원 확인용), 없으면 null
     * @param kept        생성값을 둔 곳
     */
    static void showGenerated(CryptoCli.Terminal terminal, KeyType type, String keyId, char[] secret,
                              java.util.Map<String, String> items, String fingerprint, Kept kept) {
        terminal.println(""); // 앞의 결과 줄(생성 JAR·키 파일 등)과 생성값 묶음을 빈 줄 하나로 구분한다.
        terminal.println(Messages.get("gen.type", type.code()));
        terminal.println(keyId == null ? Messages.get("gen.keyIdNone") : Messages.get("gen.keyId", keyId));
        terminal.println(type == KeyType.PASS ? Messages.get("gen.format.pass", secret.length) : Messages.get("gen.format.key"));
        terminal.printSecret(secret);
        if (type == KeyType.PASS && items != null) {
            terminal.println(Messages.get("gen.restore", items.get(KeyProfile.KDF), items.get(KeyProfile.KDF_ITERATIONS),
                    items.get(KeyProfile.SALT)));
            if (fingerprint != null) terminal.println(Messages.get("gen.fingerprint", fingerprint));
        }
        String kind = kept.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
        // 안내는 80열 안에서 한두 줄(메시지의 줄바꿈 위치를 그대로 따른다).
        String notice = Messages.get("gen.kept." + kind + (type == KeyType.PASS && kept != Kept.KEY_FILE ? ".pass" : ""));
        for (String line : notice.split("\n")) terminal.println(line);
    }

    /**
     * 관리자 인증과 SHOW 확인을 마친 뒤 등록된 키의 원문을 대화형 터미널에만 보여 준다({@code config key show --show}, 표준 출력·
     * 표준 오류·로그로 보내지 않음). 유형, Key ID, 형식, 값 한 줄(그 줄 전체가 값), pass는 복원 정보, 전체 지문, 주의 안내.
     *
     * @param secret      원문(pass: 공급원에 보관된 Passphrase 글자, key: 표준 Base64 44자 = 키 파일 한 줄)
     * @param items       pass 키 항목(kdf, kdf.iterations, salt), key면 null
     * @param fingerprint 전체 지문
     */
    static void showSecret(CryptoCli.Terminal terminal, KeyType type, String keyId, char[] secret,
                           java.util.Map<String, String> items, String fingerprint) {
        terminal.println("");
        terminal.println(Messages.get("gen.type", type.code()));
        terminal.println(Messages.get("gen.keyId", keyId));
        terminal.println(type == KeyType.PASS ? Messages.get("keyshow.format.pass", secret.length)
                : Messages.get("keyshow.format.key"));
        terminal.printSecret(secret);
        if (type == KeyType.PASS && items != null) {
            terminal.println(Messages.get("gen.restore", items.get(KeyProfile.KDF), items.get(KeyProfile.KDF_ITERATIONS),
                    items.get(KeyProfile.SALT)));
        }
        terminal.println(Messages.get("gen.fingerprint", fingerprint));
        for (String line : Messages.get("keyshow.shownNote").split("\n")) terminal.println(line);
    }

    private static String emptyToNull(String value) {
        return value == null || value.trim().isEmpty() ? null : value.trim();
    }

    /**
     * 머리말 다음에 값을 붙인 한 줄. 80열을 넘으면 머리말 다음에서 줄을 바꾸고 다음 줄은 {@code continuation}으로 들여 쓴다(값은 자르지
     * 않음).
     *
     * @param lead         줄 앞부분(폭 계산용, 결과에는 포함하지 않음)
     * @param head         머리말(예: {@code pass-default:})
     * @param tail         값
     * @param continuation 넘긴 줄의 들여쓰기
     * @return head + 공백 + tail, 또는 head + 줄바꿈 + continuation + tail
     */
    static String wrapAfter(String lead, String head, String tail, String continuation) {
        if (CliHelp.width(lead + head + " " + tail) <= CliHelp.LINE_WIDTH) return head + " " + tail;
        return head + System.lineSeparator() + continuation + tail;
    }
}
