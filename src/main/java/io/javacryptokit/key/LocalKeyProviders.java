package io.javacryptokit.key;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 네트워크 없이 같은 서버 안에서 키를 읽는 기본 공급원 세 가지
 * ({@code embedded}, {@code file}, {@code env})다. 기본 설치(JAR 하나)는 이 세 공급원만으로 동작하며 추가 의존성이 없다.
 * 키 값은 읽을 때마다 공급원에서 읽는다(파일·환경변수 읽기는 빠르고, 원격 공급원과 달리 캐시가 필요 없다).
 */
final class LocalKeyProviders {
    /** 키 파일 최대 크기(바이트). keygen 출력 45바이트에 공백·CRLF 여유를 둔 값이다. */
    static final int MAX_KEY_FILE_BYTES = 512;

    private LocalKeyProviders() { }

    /** JAR 안 {@code crypto.key.embedded}의 표준 Base64 키. JAR을 가진 누구나 꺼낼 수 있으므로 비밀키가 아니다. */
    static final class Embedded implements KeyProvider {
        @Override
        public String source() {
            return "embedded";
        }

        @Override
        public byte[] loadKey(CryptoSettings settings) {
            return KeyResolver.decodeKey(settings.get(CryptoSettings.KEY_EMBEDDED));
        }

        @Override
        public String describe(CryptoSettings settings) {
            // 키 값이 외부 설정 파일에서 왔으면 "JAR 내장"이라고 표시하지 않는다(진단할 때 엉뚱한 곳을 보지 않게).
            // -D는 키 원문을 받지 않으므로 출처는 JAR 내부 값 또는 외부 설정 파일 둘 중 하나다.
            boolean external = settings.valueOrigin(CryptoSettings.KEY_EMBEDDED) == CryptoSettings.ValueOrigin.EXTERNAL_FILE;
            return Messages.get(external ? "key.describe.embeddedExternal" : "key.describe.embedded", CryptoSettings.KEY_EMBEDDED);
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings) {
            return Collections.singletonList(Diagnostic.info(Messages.get("key.check.embedded")));
        }
    }

    /** {@code crypto.key.file} 파일 안의 표준 Base64 한 줄({@code keygen} 출력 형식). */
    static final class File implements KeyProvider {
        @Override
        public String source() {
            return "file";
        }

        @Override
        public byte[] loadKey(CryptoSettings settings) throws IOException {
            String path = settings.get(CryptoSettings.KEY_FILE);
            if (path.isEmpty()) {
                throw new SafeMessageException(Messages.get("key.err.filePathEmpty", CryptoSettings.KEY_FILE));
            }
            // 비정상적으로 큰 파일(또는 끝없는 장치 파일)을 읽어 메모리를 소모하지 않도록 상한(512바이트 + 1)까지만 읽는다.
            return KeyResolver.decodeKey(SecretFiles.readText(Paths.get(path), MAX_KEY_FILE_BYTES, CryptoSettings.KEY_FILE));
        }

        @Override
        public String describe(CryptoSettings settings) {
            String path = settings.get(CryptoSettings.KEY_FILE);
            if (path.isEmpty()) return Messages.get("key.describe.fileNone");
            return Messages.get("key.describe.file", SecretFiles.fileName(path));
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings) {
            return SecretFiles.check(CryptoSettings.KEY_FILE, settings.get(CryptoSettings.KEY_FILE), true);
        }
    }

    /** {@code crypto.key.env}가 가리키는 환경변수의 표준 Base64 값. 설정에는 변수 "이름"만 적는다. */
    static final class Env implements KeyProvider {
        @Override
        public String source() {
            return "env";
        }

        @Override
        public byte[] loadKey(CryptoSettings settings) {
            String envName = checkedName(settings);
            String encoded = System.getenv(envName);
            // 변수가 없으면 내장 키로 바꾸지 않고 중단한다(Fail Closed). WAS 서비스 계정에 변수가 전달됐는지 확인할 것.
            if (encoded == null || encoded.trim().isEmpty()) {
                throw new SafeMessageException(Messages.get("key.err.envMissing", CryptoSettings.KEY_ENV));
            }
            return KeyResolver.decodeKey(encoded);
        }

        @Override
        public String describe(CryptoSettings settings) {
            return Messages.get("key.describe.env", settings.get(CryptoSettings.KEY_ENV));
        }

        @Override
        public boolean remote() {
            return false;
        }

        @Override
        public List<Diagnostic> offlineChecks(CryptoSettings settings) {
            List<Diagnostic> results = new ArrayList<>();
            String envName;
            try {
                envName = checkedName(settings);
            } catch (SafeMessageException e) {
                results.add(Diagnostic.fail(e.getMessage(), Messages.get("key.action.envName", CryptoSettings.KEY_ENV)));
                return results;
            }
            String value = System.getenv(envName);
            if (value == null || value.trim().isEmpty()) {
                results.add(Diagnostic.fail(Messages.get("key.check.envMissing", envName),
                        Messages.get("key.action.envExport", envName)));
            } else {
                // 값은 출력하지 않고 존재 여부와 길이 형식만 알린다.
                results.add(Diagnostic.pass(Messages.get("key.check.envOk", envName,
                        value.trim().getBytes(StandardCharsets.US_ASCII).length)));
            }
            return results;
        }

        /** 환경변수 이름 형식을 제한해 오타·이상한 값으로 엉뚱한 변수를 읽지 않게 한다. */
        private static String checkedName(CryptoSettings settings) {
            String envName = settings.get(CryptoSettings.KEY_ENV);
            if (!envName.matches("[A-Za-z_][A-Za-z0-9_]{0,127}")) {
                throw new SafeMessageException(Messages.get("key.err.envName", CryptoSettings.KEY_ENV));
            }
            return envName;
        }
    }
}
