package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestSupport;
import io.javacryptokit.key.aws.MockKms;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** CLI kms datakey(모의 KMS): 데이터 키 파일 생성·덮어쓰기 금지·평문 미출력, 기존 키 감싸기 후 기존 암호문 유지, doctor 연동. */
class KmsDataKeyCliTest {
    @TempDir
    Path dir;
    private MockKms kms;
    private CliHarness cli;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        kms = new MockKms();
        kms.install();
        cli = new CliHarness();
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
        kms.close();
    }

    @Test
    void createsDataKeyFileThenTheKmsSourceWorksEndToEnd() throws Exception {
        Path base = TestSupport.writeConfig(dir, "kms-base.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1",
                "crypto.aws.kms.key.id=alias/test");
        Path dataKey = dir.resolve("prod01.datakey");
        // 사유가 없으면 KMS를 부르기 전에 멈춘다(요청 0건, 파일 없음).
        assertEquals(1, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString()));
        assertTrue(cli.err().contains("[사유: USAGE]") && cli.err().contains("--reason"), cli.err());
        assertTrue(kms.requests.isEmpty(), "사유 확인 전에 KMS를 호출하면 안 된다: " + kms.requests);
        assertFalse(Files.exists(dataKey));
        assertEquals(0, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString(),
                "--reason", "운영 데이터 키 준비"), cli.err());
        // 결과: 파일(설정에 쓸 경로)·방식·키 ID·데이터 키 지문, 사유와 이력에 남지 않는다는 사실. 다음 명령·보관 안내 장문은 없다.
        String[] lines = cli.out().trim().split("\\r?\\n");
        assertEquals(6, lines.length, cli.out());
        assertEquals("사유      : 운영 데이터 키 준비", lines[4]);
        assertEquals("이력      : 저장 안 함(JAR를 바꾸지 않는 명령이라 config history에 없음)", lines[5]);
        assertEquals("파일      : " + dataKey.toAbsolutePath().normalize().toString().replace('\\', '/'), lines[0]);
        assertEquals("방식      : 새 데이터 키(KMS GenerateDataKey)", lines[1]);
        assertEquals("키 ID     : prod01", lines[2]);
        assertTrue(lines[3].matches("키 지문   : [0-9a-f]{64}"), lines[3]);
        assertEquals(1, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString(), "--reason", "x"));
        assertTrue(cli.err().contains("덮어쓰지 않습니다"), cli.err());

        Path kmsConfig = TestSupport.writeConfig(dir, "kms.properties", "crypto.key.type=key", "crypto.key.source=aws-kms",
                "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1", "crypto.aws.kms.key.id=alias/test",
                "crypto.aws.kms.data-key.file=" + TestSupport.propertiesPath(dataKey));
        assertEquals(0, cli.run("doctor", "--config", kmsConfig.toString()), cli.out());
        assertTrue(cli.out().contains("[PASS] 키 로딩 정상: prod01, 사용자 지정"), cli.out());
        String token = CredentialCrypto.fromConfigFile(kmsConfig).encryptText("dummy-pw");
        assertEquals(0, cli.run("verify", "--config", kmsConfig.toString(), "--value", token), cli.err());
    }

    @Test
    void wrappingTheCurrentFileKeyKeepsExistingCiphertextValid() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "current.key");
        Path fileConfig = TestSupport.writeConfig(dir, "file.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.id=prod01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        String existing = CredentialCrypto.fromConfigFile(fileConfig).encryptText("dummy-existing-pw");
        Path base = TestSupport.writeConfig(dir, "kms-base.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1",
                "crypto.aws.kms.key.id=alias/test");
        Path dataKey = dir.resolve("wrapped.datakey");
        assertEquals(0, cli.run("kms", "datakey", "--from-file", key.toString(), "--out", dataKey.toString(),
                "--config", base.toString(), "--reason", "기존 키 KMS 보호"), cli.err());
        String keyText = new String(Files.readAllBytes(key), StandardCharsets.US_ASCII).trim();
        assertFalse(cli.out().contains(keyText), "키를 출력하면 안 된다");
        Path kmsConfig = TestSupport.writeConfig(dir, "kms.properties", "crypto.key.type=key", "crypto.key.source=aws-kms",
                "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1", "crypto.aws.kms.key.id=alias/test",
                "crypto.aws.kms.data-key.file=" + TestSupport.propertiesPath(dataKey));
        assertEquals("dummy-existing-pw", CredentialCrypto.fromConfigFile(kmsConfig).decryptText(existing),
                "같은 키·키ID라 기존 암호문을 그대로 쓴다");
    }

    @Test
    void kmsErrorsAreReportedAsKeySourceWithoutCreatingAFile() throws Exception {
        Path base = TestSupport.writeConfig(dir, "kms-base.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1",
                "crypto.aws.kms.key.id=alias/test");
        kms.forcedError = "AccessDeniedException";
        Path dataKey = dir.resolve("denied.datakey");
        assertEquals(1, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString(), "--reason", "x"));
        assertTrue(cli.err().contains("[사유: KEY_SOURCE]") && cli.err().contains("AccessDeniedException"), cli.err());
        assertFalse(Files.exists(dataKey), "실패하면 데이터 키 파일을 만들지 않는다");
        assertEquals(1, cli.run("kms", "datakey", "--config", base.toString()));
        assertTrue(cli.err().contains("--out"), cli.err());
    }
}
