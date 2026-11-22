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
        assertEquals(0, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString()), cli.err());
        assertTrue(cli.out().contains("[PASS]") && cli.out().contains("crypto.aws.kms.data-key.file="), cli.out());
        assertEquals(1, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString()));
        assertTrue(cli.err().contains("덮어쓰지 않습니다"), cli.err());

        Path kmsConfig = TestSupport.writeConfig(dir, "kms.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1", "crypto.aws.kms.key.id=alias/test",
                "crypto.aws.kms.data-key.file=" + TestSupport.propertiesPath(dataKey));
        assertEquals(0, cli.run("doctor", "--config", kmsConfig.toString()), cli.out());
        assertTrue(cli.out().contains("[PASS] 키 읽기 정상"), cli.out());
        String token = CredentialCrypto.fromConfigFile(kmsConfig).encryptText("dummy-pw");
        assertEquals(0, cli.run("verify", "--config", kmsConfig.toString(), "--value", token), cli.err());
    }

    @Test
    void wrappingTheCurrentFileKeyKeepsExistingCiphertextValid() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "current.key");
        Path fileConfig = TestSupport.writeConfig(dir, "file.properties", "crypto.key.source=file", "crypto.key.id=prod01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        String existing = CredentialCrypto.fromConfigFile(fileConfig).encryptText("dummy-existing-pw");
        Path base = TestSupport.writeConfig(dir, "kms-base.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
                "crypto.aws.region=us-east-1",
                "crypto.aws.kms.key.id=alias/test");
        Path dataKey = dir.resolve("wrapped.datakey");
        assertEquals(0, cli.run("kms", "datakey", "--from-file", key.toString(), "--out", dataKey.toString(),
                "--config", base.toString()), cli.err());
        String keyText = new String(Files.readAllBytes(key), StandardCharsets.US_ASCII).trim();
        assertFalse(cli.out().contains(keyText), "키를 출력하면 안 된다");
        Path kmsConfig = TestSupport.writeConfig(dir, "kms.properties", "crypto.key.source=aws-kms", "crypto.key.id=prod01",
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
        assertEquals(1, cli.run("kms", "datakey", "--out", dataKey.toString(), "--config", base.toString()));
        assertTrue(cli.err().contains("[사유: KEY_SOURCE]") && cli.err().contains("AccessDeniedException"), cli.err());
        assertFalse(Files.exists(dataKey), "실패하면 데이터 키 파일을 만들지 않는다");
        assertEquals(1, cli.run("kms", "datakey", "--config", base.toString()));
        assertTrue(cli.err().contains("--out"), cli.err());
    }
}
