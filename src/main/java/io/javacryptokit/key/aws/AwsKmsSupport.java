package io.javacryptokit.key.aws;

import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import javax.net.ssl.SSLException;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;

/**
 * <b>내부 구현 클래스</b>: AWS SDK for Java 2.x를 직접 호출하는 유일한 클래스다(SDK 의존을 이 클래스로 격리).
 * {@link AwsKmsKeyProvider}가 SDK 설치를 확인한 뒤에만 호출한다.
 *
 * <p><b>클라이언트 구성</b>(호출마다 만들고 닫는다. WAS 기동 시 Resource당 한 번이라 비용이 작고, 연결·스레드를 남기지 않는다)</p>
 * <ul>
 *   <li>HTTP: 경량 {@code UrlConnectionHttpClient}를 명시한다(서비스 로더 자동 탐색을 쓰지 않아 웹앱의 다른 HTTP 클라이언트가
 *       섞이지 않음).</li>
 *   <li>자격증명: SDK 표준 {@code DefaultCredentialsProvider}(자격증명을 이 라이브러리 설정에 두지 않음).</li>
 *   <li>리전: {@code crypto.aws.region}, 비우면 SDK 기본 리전 공급 체계(AWS_REGION, 프로필, EC2 메타데이터).</li>
 *   <li>엔드포인트: SDK 표준 설정(AWS_ENDPOINT_URL_KMS 등)을 따른다(VPC 엔드포인트·FIPS·시험용 에뮬레이터).</li>
 *   <li>제한 시간: {@code crypto.aws.kms.timeout.ms}가 재시도를 포함한 전체 호출 시간이다(SDK 표준 재시도, 무한 대기 없음).</li>
 *   <li>스레드 컨텍스트 클래스로더: 호출 동안 이 라이브러리를 로딩한 클래스로더로 바꾼다. Tomcat에서 웹앱 클래스로더가 같은 이름의
 *       SDK 구성요소(인터셉터 등)를 끼워 넣어 평문 데이터 키에 접근하는 것을 막는다(Pool Factory와 같은 신뢰 경계 원칙).</li>
 * </ul>
 *
 * <p><b>오류</b>: SDK 예외 메시지(ARN·요청 ID 포함)는 출력하지 않고, AWS 오류 코드(고정 영문 이름)로 원인을 나눠 안내한다.
 * 평문 데이터 키는 로그·예외에 넣지 않는다. SDK가 돌려주는 {@code SdkBytes} 내부 버퍼는 지울 수 없다(SDK 한계).</p>
 */
final class AwsKmsSupport {
    /** 기본 제한 시간(설정 항목이 없는 이전 설정 대비). */
    private static final int DEFAULT_TIMEOUT_MS = 10000;
    /**
     * <b>테스트 전용</b>: 지정하면 실제 클라이언트 대신 이 함수가 만든 클라이언트를 쓴다(모의 KMS 서버 연결용). 운영 코드는 쓰지 않는다.
     */
    static volatile Function<CryptoSettings, KmsClient> clientFactoryForTests;

    private AwsKmsSupport() { }

    /** KMS Decrypt로 평문 데이터 키를 복원한다. */
    static byte[] decrypt(CryptoSettings settings, byte[] blob) {
        return call(settings, kms -> kms.decrypt(DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(blob))
                .keyId(settings.get(CryptoSettings.AWS_KMS_KEY_ID))
                .encryptionContext(context(settings))
                .build()).plaintext().asByteArray());
    }

    /** KMS GenerateDataKey(AES_256)로 새 데이터 키를 만든다. */
    static AwsKmsKeyProvider.DataKey generate(CryptoSettings settings) {
        return call(settings, kms -> {
            GenerateDataKeyResponse response = kms.generateDataKey(GenerateDataKeyRequest.builder()
                    .keyId(settings.get(CryptoSettings.AWS_KMS_KEY_ID))
                    .keySpec(DataKeySpec.AES_256)
                    .encryptionContext(context(settings))
                    .build());
            return new AwsKmsKeyProvider.DataKey(response.plaintext().asByteArray(), response.ciphertextBlob().asByteArray());
        });
    }

    /** KMS Encrypt로 기존 키를 감싼다. */
    static byte[] wrap(CryptoSettings settings, byte[] key) {
        return call(settings, kms -> kms.encrypt(EncryptRequest.builder()
                .keyId(settings.get(CryptoSettings.AWS_KMS_KEY_ID))
                .plaintext(SdkBytes.fromByteArray(key))
                .encryptionContext(context(settings))
                .build()).ciphertextBlob().asByteArray());
    }

    /** 고정 Encryption Context: 데이터 키를 키ID에 묶는다(암호화·복호화에서 항상 같다). */
    static Map<String, String> context(CryptoSettings settings) {
        return Collections.singletonMap(AwsKmsKeyProvider.CONTEXT_KEY, settings.keyId());
    }

    /** 클라이언트를 만들어 한 번 호출하고 닫는다. SDK 예외는 정제된 고정 문구로 바꾼다. */
    private static <T> T call(CryptoSettings settings, Function<KmsClient, T> operation) {
        Thread thread = Thread.currentThread();
        ClassLoader previous = thread.getContextClassLoader();
        thread.setContextClassLoader(AwsKmsSupport.class.getClassLoader());
        try {
            Function<CryptoSettings, KmsClient> testFactory = clientFactoryForTests;
            if (testFactory != null) {
                return operation.apply(testFactory.apply(settings));
            }
            int timeout = settings.intValue(CryptoSettings.AWS_KMS_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
            try (SdkHttpClient http = UrlConnectionHttpClient.builder()
                    .connectionTimeout(Duration.ofMillis(Math.min(timeout, 5000)))
                    .socketTimeout(Duration.ofMillis(timeout))
                    .build();
                 DefaultCredentialsProvider credentials = DefaultCredentialsProvider.builder().build()) {
                KmsClientBuilder builder = KmsClient.builder()
                        .httpClient(http)
                        .credentialsProvider(credentials)
                        .overrideConfiguration(ClientOverrideConfiguration.builder()
                                .apiCallTimeout(Duration.ofMillis(timeout))
                                .build());
                String region = settings.get(CryptoSettings.AWS_REGION);
                if (!region.isEmpty()) builder.region(Region.of(region));
                try (KmsClient kms = builder.build()) {
                    return operation.apply(kms);
                }
            }
        } catch (KmsException e) {
            String code = e.awsErrorDetails() == null ? null : e.awsErrorDetails().errorCode();
            throw new SafeMessageException(serviceMessage(code));
        } catch (ApiCallTimeoutException | ApiCallAttemptTimeoutException e) {
            throw new SafeMessageException(Messages.get("key.aws.err.timeout"));
        } catch (SdkClientException e) {
            throw new SafeMessageException(clientMessage(e));
        } catch (SdkException e) {
            throw new SafeMessageException(Messages.get("key.aws.err.client", e.getClass().getSimpleName()));
        } finally {
            thread.setContextClassLoader(previous);
        }
    }

    /** AWS KMS 오류 코드별 안내. 오류 코드는 고정 영문 이름이므로 형식을 확인한 뒤에만 표시한다. */
    static String serviceMessage(String code) {
        String safe = code != null && code.matches("[A-Za-z0-9]{1,64}") ? code : "?";
        switch (safe) {
            case "AccessDeniedException":
                return Messages.get("key.aws.err.accessDenied");
            case "IncorrectKeyException":
                return Messages.get("key.aws.err.incorrectKey");
            case "InvalidCiphertextException":
                return Messages.get("key.aws.err.invalidCiphertext");
            case "NotFoundException":
                return Messages.get("key.aws.err.notFound");
            case "DisabledException":
            case "KMSInvalidStateException":
                return Messages.get("key.aws.err.disabled");
            case "InvalidKeyUsageException":
                return Messages.get("key.aws.err.keyUsage");
            case "UnrecognizedClientException":
            case "InvalidSignatureException":
            case "ExpiredTokenException":
            case "InvalidClientTokenId":
                return Messages.get("key.aws.err.auth");
            case "KeyUnavailableException":
            case "KMSInternalException":
            case "DependencyTimeoutException":
            case "ThrottlingException":
                return Messages.get("key.aws.err.unavailable", safe);
            default:
                return Messages.get("key.aws.err.service", safe);
        }
    }

    /** SDK 클라이언트 쪽 오류(자격증명·리전·네트워크)를 구분한다. 메시지는 분류에만 쓰고 출력하지 않는다. */
    private static String clientMessage(SdkClientException e) {
        String message = String.valueOf(e.getMessage());
        if (message.contains("Unable to load credentials")) return Messages.get("key.aws.err.credentials");
        if (message.contains("Unable to load region")) return Messages.get("key.aws.err.region");
        for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
            if (cause instanceof SSLException) return Messages.get("key.aws.err.tls");
            if (cause instanceof SocketTimeoutException) return Messages.get("key.aws.err.timeout");
            if (cause instanceof UnknownHostException || cause instanceof ConnectException) {
                return Messages.get("key.aws.err.network");
            }
            if (cause instanceof IOException) return Messages.get("key.aws.err.network");
        }
        return Messages.get("key.aws.err.client", e.getClass().getSimpleName());
    }
}
