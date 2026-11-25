package io.javacryptokit.key;

import io.javacryptokit.KeyType;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 네트워크 없이 같은 서버 안에서 키 재료를 읽는 기본 공급원 세 가지
 * ({@code embedded}, {@code file}, {@code env})다. 기본 설치(JAR 하나)는 이 세 공급원만으로 동작하며 추가 의존성이 없다.
 * 재료는 읽을 때마다 공급원에서 읽는다(파일·환경변수 읽기는 빠르다. pass 유형의 파생 결과는 {@link PassKdf}가 JVM 안에 한 번만
 * 계산한다).
 */
final class LocalKeyProviders {
    /** 키 파일 최대 크기(바이트). keygen 출력 45바이트에 공백·CRLF 여유를 둔 값이다. */
    static final int MAX_KEY_FILE_BYTES = 512;

    private LocalKeyProviders() { }

    /**
     * JAR(또는 설정 파일) 안의 표준 Base64 키. pass 유형은 등록할 때 파생한 키를 저장한다. JAR을 가진 누구나 꺼낼 수 있으므로
     * 키를 내장한 JAR는 비밀 파일이다.
     */
    static final class Embedded implements KeyProvider {
        @Override
        public String source() {
            return "embedded";
        }

        @Override
        public byte[] loadMaterial(CryptoSettings settings, KeyProfile profile) {
            return KeyResolver.decodeEmbedded(profile.value(KeyProfile.EMBEDDED));
        }

        @Override
        public boolean textMaterial() {
            return false;
        }

        @Override
        public String describe(CryptoSettings settings, KeyProfile profile) {
            // 키 값이 외부 설정 파일에서 왔으면 "JAR 내장"이라고 표시하지 않는다(진단할 때 엉뚱한 곳을 보지 않게).
            // -D는 키 원문을 받지 않으므로 출처는 JAR 내부 값 또는 외부 설정 파일 둘 중 하나다.
            String name = profile.settingName(KeyProfile.EMBEDDED);
            boolean external = settings.valueOrigin(name) == CryptoSettings.ValueOrigin.EXTERNAL_FILE;
            return Messages.get(external ? "key.describe.embeddedExternal" : "key.describe.embedded", name);
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings, KeyProfile profile) {
            // 내장 키는 따로 준비할 것이 없다(키 형식은 키 로딩에서 확인).
            return Collections.emptyList();
        }
    }

    /** 파일 한 줄: key 유형은 표준 Base64({@code keygen} 출력 형식), pass 유형은 Passphrase(UTF-8). */
    static final class File implements KeyProvider {
        @Override
        public String source() {
            return "file";
        }

        @Override
        public byte[] loadMaterial(CryptoSettings settings, KeyProfile profile) throws IOException {
            String name = profile.settingName(KeyProfile.FILE);
            String path = profile.value(KeyProfile.FILE);
            if (path.isEmpty()) {
                throw new SafeMessageException(Messages.get("key.err.filePathEmpty", name));
            }
            // 비정상적으로 큰 파일(또는 끝없는 장치 파일)을 읽어 메모리를 소모하지 않도록 상한 + 1바이트까지만 읽는다.
            int limit = profile.type() == KeyType.PASS ? PassKdf.MAX_FILE_BYTES : MAX_KEY_FILE_BYTES;
            return SecretFiles.readBytes(Paths.get(path), limit, name);
        }

        @Override
        public boolean textMaterial() {
            return true;
        }

        @Override
        public String describe(CryptoSettings settings, KeyProfile profile) {
            String path = profile.value(KeyProfile.FILE);
            if (path.isEmpty()) return Messages.get("key.describe.fileNone");
            return Messages.get("key.describe.file", SecretFiles.fileName(path));
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings, KeyProfile profile) {
            return SecretFiles.check(profile.settingName(KeyProfile.FILE), profile.value(KeyProfile.FILE));
        }
    }

    /** 환경변수 값: key 유형은 표준 Base64, pass 유형은 Passphrase. 설정에는 변수 "이름"만 적는다. */
    static final class Env implements KeyProvider {
        @Override
        public String source() {
            return "env";
        }

        @Override
        public byte[] loadMaterial(CryptoSettings settings, KeyProfile profile) {
            String envName = checkedName(profile);
            String value = System.getenv(envName);
            // 변수가 없으면 다른 키로 바꾸지 않고 중단한다(Fail Closed). WAS 서비스 계정에 변수가 전달됐는지 확인할 것.
            if (value == null || value.trim().isEmpty()) {
                throw new SafeMessageException(Messages.get("key.err.envMissing", profile.settingName(KeyProfile.ENV)));
            }
            return value.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public boolean textMaterial() {
            return true;
        }

        @Override
        public String describe(CryptoSettings settings, KeyProfile profile) {
            return Messages.get("key.describe.env", profile.value(KeyProfile.ENV));
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings, KeyProfile profile) {
            List<Diagnostic> results = new ArrayList<>();
            String envName;
            try {
                envName = checkedName(profile);
            } catch (SafeMessageException e) {
                results.add(Diagnostic.fail(e.getMessage(), Messages.get("key.action.envName", profile.settingName(KeyProfile.ENV))));
                return results;
            }
            String value = System.getenv(envName);
            if (value == null || value.trim().isEmpty()) {
                results.add(Diagnostic.fail(Messages.get("key.check.envMissing", envName),
                        Messages.get("key.action.envExport", envName)));
            } else {
                // 값은 출력하지 않고 존재 여부와 길이만 알린다.
                results.add(Diagnostic.pass(Messages.get("key.check.envOk", envName,
                        value.getBytes(StandardCharsets.UTF_8).length)));
            }
            return results;
        }

        /** 환경변수 이름 형식을 제한해 오타·이상한 값으로 엉뚱한 변수를 읽지 않게 한다. */
        private static String checkedName(KeyProfile profile) {
            String envName = profile.value(KeyProfile.ENV);
            if (!envName.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) {
                throw new SafeMessageException(Messages.get("key.err.envName", profile.settingName(KeyProfile.ENV)));
            }
            return envName;
        }
    }
}
