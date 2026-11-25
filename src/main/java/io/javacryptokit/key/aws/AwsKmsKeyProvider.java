package io.javacryptokit.key.aws;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.Diagnostic;
import io.javacryptokit.key.KeyProvider;
import io.javacryptokit.key.SecretFiles;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: AWS KMS <b>Envelope Encryption</b> 방식의 키 공급원({@code crypto.key.source=aws-kms}).
 *
 * <p><b>구조</b>: KMS 마스터 키(KMS 밖으로 나오지 않음)가 AES-256 <b>데이터 키</b>를 암호화해 둔다. 암호화된 데이터 키
 * (CiphertextBlob, Base64)는 {@code crypto.aws.kms.data-key.file}에 보관하고, 실행 시 KMS {@code Decrypt}로 평문 데이터 키를
 * 복원해 기존 AES-GCM 엔진에 넘긴다. 데이터 키 파일은 {@code kms datakey} 명령으로 한 번 만들고 계속 재사용한다(WAS를
 * 다시 시작할 때마다 새 데이터 키를 만들지 않는다. 새로 만들면 기존 암호문을 복호화할 수 없다).</p>
 *
 * <p><b>Encryption Context</b>: {@code java-crypto-kit:key-id = <Key ID>}를 항상 함께 보낸다(설정 불필요). 데이터 키가
 * 다른 Key ID용으로 만들어졌거나 파일이 바뀌면 KMS가 복원을 거부한다. 그래서 Key ID를 바꾸면 데이터 키도 새로 만들어야 한다
 * (rekey로 기존 암호문을 다시 암호화). 레거시 슬롯의 Key ID는 {@code crypto.key.id}다.</p>
 *
 * <p><b>pass 유형</b>: 등록할 때 Passphrase로 파생한 32바이트 키를 같은 방식(KMS Encrypt, 같은 컨텍스트)으로 감싸 같은 형식의
 * 데이터 키 파일에 둔다. 실행 중에는 KMS Decrypt만 하므로 기존 데이터 키 파일과 형식이 같다(KDF 메타데이터는 프로필에 기록).</p>
 *
 * <p><b>의존성 격리</b>: 이 클래스는 AWS SDK 형식을 필드·메서드 형식에 쓰지 않는다. SDK 호출은 {@link AwsKmsSupport}에만 있고,
 * 실제로 이 공급원을 쓸 때만 로딩된다. 그래서 기본 설치(JAR 하나, SDK 없음)의 embedded/file/env/vault 동작에 영향이 없다.
 * SDK가 없으면 설치 방법을 안내하는 오류로 끝난다(다른 키로 바꾸지 않음).</p>
 *
 * <p><b>자격증명</b>: AWS SDK 2.x 표준 자격증명 체계(환경변수, 웹 ID 토큰(EKS IRSA), 프로필, 컨테이너(ECS·EKS Pod Identity),
 * EC2 인스턴스 프로필)를 그대로 쓴다. Access Key·Secret Key를 이 라이브러리 설정에 두지 않으며, JVM 명령행
 * ({@code -Daws.secretAccessKey})에 두면 {@code doctor}가 경고한다.</p>
 */
public final class AwsKmsKeyProvider implements KeyProvider {
    /** SDK 설치 여부를 확인하는 고정 클래스 이름(설정 값으로 클래스를 고르지 않는다). */
    private static final String[] SDK_MARKERS = {"software.amazon.awssdk.services.kms.KmsClient",
            "software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient"};
    /** 데이터 키 파일 최대 크기(바이트). */
    private static final int MAX_DATA_KEY_FILE_BYTES = 16 * 1024;
    /** Encryption Context 키 이름. */
    static final String CONTEXT_KEY = "java-crypto-kit:key-id";

    @Override
    public String source() {
        return "aws-kms";
    }

    @Override
    public boolean remote() {
        return true;
    }

    @Override
    public String describe(CryptoSettings settings, KeyProfile profile) {
        String region = settings.get(CryptoSettings.AWS_REGION);
        return Messages.get("key.describe.aws", SecretFiles.fileName(profile.value(KeyProfile.AWS_KMS_DATA_KEY_FILE)),
                settings.get(CryptoSettings.AWS_KMS_KEY_ID),
                region.isEmpty() ? Messages.get("key.aws.regionDefault") : region);
    }

    @Override
    public List<Diagnostic> offlineChecks(CryptoSettings settings, KeyProfile profile) {
        List<Diagnostic> results = new ArrayList<>();
        results.add(sdkAvailable() ? Diagnostic.pass(Messages.get("key.check.awsSdk"))
                : Diagnostic.fail(Messages.get("key.aws.err.sdkMissing"), Messages.get("key.action.awsSdk")));
        if (settings.get(CryptoSettings.AWS_KMS_KEY_ID).isEmpty()) {
            results.add(Diagnostic.fail(Messages.get("config.err.required", "aws-kms", CryptoSettings.AWS_KMS_KEY_ID),
                    Messages.get("key.action.awsSettings")));
        }
        String file = profile.value(KeyProfile.AWS_KMS_DATA_KEY_FILE);
        List<Diagnostic> fileChecks = SecretFiles.check(profile.settingName(KeyProfile.AWS_KMS_DATA_KEY_FILE), file);
        results.addAll(fileChecks);
        if (fileChecks.size() == 1 && fileChecks.get(0).status == Diagnostic.Status.PASS) {
            try {
                readBlob(profile);
                results.add(Diagnostic.pass(Messages.get("key.check.awsDataKeyFormat")));
            } catch (IOException | IllegalArgumentException e) {
                results.add(Diagnostic.fail(Messages.get("key.aws.err.dataKeyFormat"), Messages.get("key.action.awsDataKey")));
            }
        }
        String region = settings.get(CryptoSettings.AWS_REGION);
        results.add(Diagnostic.info(region.isEmpty() ? Messages.get("key.check.awsRegionDefault")
                : Messages.get("key.check.awsRegion", region)));
        // 엔드포인트를 바꾼 사실만 알린다(값은 출력하지 않음). 엔드포인트·자격증명 운영 방식은 사용자 가이드의 운영·보안 참고.
        for (String env : new String[]{"AWS_ENDPOINT_URL_KMS", "AWS_ENDPOINT_URL"}) {
            String endpoint = System.getenv(env);
            if (endpoint != null && !endpoint.trim().isEmpty()) {
                results.add(Diagnostic.info(Messages.get("key.check.awsEndpoint", env)));
            }
        }
        return results;
    }

    @Override
    public boolean textMaterial() {
        return false;
    }

    @Override
    public byte[] loadMaterial(CryptoSettings settings, KeyProfile profile) throws IOException {
        requireKeyId(settings);
        byte[] blob = readBlob(profile);
        requireSdk();
        return AwsKmsSupport.decrypt(settings, profile.id(), blob);
    }

    /**
     * 레거시 AES 슬롯({@code crypto.key.id})용 새 데이터 키를 KMS {@code GenerateDataKey}로 만든다({@code kms datakey}).
     *
     * @param settings 검증된 설정(리전·KMS 키·제한 시간)
     * @return 평문 데이터 키와 암호화된 데이터 키(호출자가 {@link DataKey#wipe()}로 지운다)
     */
    public static DataKey generate(CryptoSettings settings) {
        return generate(settings, settings.keyId());
    }

    /**
     * 새 AES-256 데이터 키를 KMS {@code GenerateDataKey}로 만든다(지정한 Key ID에 묶음).
     *
     * @param settings 검증된 설정(리전·KMS 키·제한 시간)
     * @param keyId    데이터 키를 묶을 Key ID(Encryption Context)
     * @return 평문 데이터 키와 암호화된 데이터 키(호출자가 {@link DataKey#wipe()}로 지운다)
     */
    public static DataKey generate(CryptoSettings settings, String keyId) {
        requireKeyId(settings);
        requireSdk();
        return AwsKmsSupport.generate(settings, keyId);
    }

    /**
     * 이미 쓰고 있는 32바이트 키를 KMS {@code Encrypt}로 감싸 데이터 키 파일 내용을 만든다(기존 암호문·키ID 유지 이전용).
     *
     * @param settings 검증된 설정(레거시 AES 슬롯의 Key ID에 묶음)
     * @param key      32바이트 키(바꾸지 않는다)
     * @return 암호화된 데이터 키(CiphertextBlob)
     */
    public static byte[] wrap(CryptoSettings settings, byte[] key) {
        return wrap(settings, settings.keyId(), key);
    }

    /**
     * 32바이트 키를 KMS {@code Encrypt}로 감싸 데이터 키 파일 내용을 만든다(지정한 Key ID에 묶음).
     *
     * @param settings 검증된 설정
     * @param keyId    데이터 키를 묶을 Key ID(Encryption Context)
     * @param key      32바이트 키(바꾸지 않는다)
     * @return 암호화된 데이터 키(CiphertextBlob)
     */
    public static byte[] wrap(CryptoSettings settings, String keyId, byte[] key) {
        requireKeyId(settings);
        requireSdk();
        return AwsKmsSupport.wrap(settings, keyId, key);
    }

    /**
     * KMS로 복원해 평문 데이터 키를 돌려준다({@code kms datakey}의 왕복 검증용).
     *
     * @param settings 검증된 설정
     * @param keyId    데이터 키를 묶은 Key ID(Encryption Context)
     * @param blob     암호화된 데이터 키
     * @return 평문 데이터 키(호출자가 지운다)
     */
    public static byte[] unwrap(CryptoSettings settings, String keyId, byte[] blob) {
        requireKeyId(settings);
        requireSdk();
        return AwsKmsSupport.decrypt(settings, keyId, blob);
    }

    /** @return AWS SDK(KMS·URLConnection HTTP 클라이언트)가 이 라이브러리와 같은 클래스로더에 설치되어 있으면 true */
    public static boolean sdkAvailable() {
        ClassLoader loader = AwsKmsKeyProvider.class.getClassLoader();
        try {
            for (String marker : SDK_MARKERS) Class.forName(marker, false, loader);
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /** 데이터 키 파일(CiphertextBlob 표준 Base64 한 줄)을 읽는다. 비밀은 아니지만 바뀌면 복원이 실패한다. */
    static byte[] readBlob(KeyProfile profile) throws IOException {
        String name = profile.settingName(KeyProfile.AWS_KMS_DATA_KEY_FILE);
        String file = profile.value(KeyProfile.AWS_KMS_DATA_KEY_FILE);
        if (file.isEmpty()) {
            throw new SafeMessageException(Messages.get("config.err.required", "aws-kms", name));
        }
        String text = SecretFiles.readText(Paths.get(file), MAX_DATA_KEY_FILE_BYTES, name);
        byte[] blob;
        try {
            blob = Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw new SafeMessageException(Messages.get("key.aws.err.dataKeyFormat"));
        }
        if (blob.length < 16 || blob.length > 6144) {
            Arrays.fill(blob, (byte) 0);
            throw new SafeMessageException(Messages.get("key.aws.err.dataKeyFormat"));
        }
        return blob;
    }

    private static void requireKeyId(CryptoSettings settings) {
        if (settings.get(CryptoSettings.AWS_KMS_KEY_ID).isEmpty()) {
            throw new SafeMessageException(Messages.get("config.err.required", "aws-kms", CryptoSettings.AWS_KMS_KEY_ID));
        }
    }

    private static void requireSdk() {
        if (!sdkAvailable()) throw new SafeMessageException(Messages.get("key.aws.err.sdkMissing"));
    }

    /** KMS가 만든 데이터 키(평문 + 암호문). 평문은 사용 후 반드시 지운다. */
    public static final class DataKey {
        /** 평문 데이터 키(32바이트). */
        public final byte[] plaintext;
        /** 암호화된 데이터 키(CiphertextBlob). 비밀은 아니며 데이터 키 파일에 보관한다. */
        public final byte[] ciphertextBlob;

        DataKey(byte[] plaintext, byte[] ciphertextBlob) {
            this.plaintext = plaintext;
            this.ciphertextBlob = ciphertextBlob;
        }

        /** 평문 데이터 키를 지운다. */
        public void wipe() {
            Arrays.fill(plaintext, (byte) 0);
        }
    }
}
