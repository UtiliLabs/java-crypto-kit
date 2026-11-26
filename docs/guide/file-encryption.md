# 파일 암복호화

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

CSV, PDF, JSON, 이미지 등 파일을 내용 형식에 관계없이 보호합니다. 일회성 작업 또는 배치에서는 CLI를, 애플리케이션 처리 흐름에서는 Java API를 선택합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[CLI와 Java API 중 선택하기](#guide-section-1) · [파일 암복호화에서 키와 출력 선택](#guide-section-2) · [파일 처리 절차·명령·Java API](#topic-file-encryption)

---

<a name="guide-section-1"></a>
## CLI와 Java API 중 선택하기

JCKF를 스트리밍으로 처리할 때는 이 문서의 관리형 파일 명령을 사용합니다. 외부 AES·RSA·Hybrid 형식과 교차 검증하는 제한 크기 데이터는 [독립 암복호화 CLI](java-encryption.md#api-aes)를 사용합니다.

| 작업 | 권장 방식 |
|---|---|
| 수동으로 파일 한 개를 보호하거나 복원 | CLI `file encrypt` / `file decrypt` |
| 스케줄러에서 파일 단위 반복 처리 | CLI 명령 및 종료 코드 활용, 민감 명령은 비대화형 관리자 인증 |
| 업무 서비스 내부에서 파일 처리 | `CredentialCrypto.encryptFile` / `decryptFile` |

CLI를 처음 쓰면 [관리자 인증](cli.md#topic-admin)을 준비합니다. 운영 키를 사용하고 복원할 때 같은 키 ID와 키를 유지해야 합니다. 애플리케이션이 직접 키를 보유한 경우 [직접 키 주입 API](java-encryption.md#topic-direct-key)를 사용합니다.

> [!IMPORTANT]
출력 폴더에서 하드 링크를 만들 수 있어야 합니다. 같은 경로에 동시에 쓰면 먼저 공개한 파일 한 개만 남습니다. 네트워크 공유나 이동식 저장장치는 실제 출력 폴더의 권한과 하드 링크 지원 여부를 확인하세요.

<a name="file-result"></a>

| 실행 결과 | 파일 상태와 조치 |
|---|---|
| 완료 메시지 | 최종 경로에 완성된 파일이 있습니다. |
| 결과 파일이 완성됐지만 임시 파일을 지우지 못했다는 메시지 | **결과 파일을 보관**하세요. 출력 폴더에서 메시지에 나온 임시 이름(`.jck-tmp`)만 삭제합니다. 두 이름이 같은 내용을 가리키므로 임시 파일의 내용을 지우거나 덮어쓰면 정상 결과도 손상됩니다. |
| 키·무결성·입출력·이름 충돌 오류 | 이번 실행은 최종 파일을 공개하지 못했습니다. 기존 대상은 보존하세요. 최초 오류를 먼저 해결합니다. 임시 파일 삭제까지 실패하면 CLI 오류 줄에는 최초 사유 코드와 원인 뒤에 남은 임시 파일 이름과 삭제 방법이 표시됩니다. Java에서는 `getSuppressed()`로 정리 오류를 확인합니다. 남은 임시 파일에는 평문이 있을 수 있으므로 해당 이름만 삭제하세요. |

CLI에서 정리 실패는 종료 코드 1이며, 파일명의 제어문자는 `\u000A` 같은 코드값으로 표시합니다. 실제 파일을 정리할 때는 출력 폴더의 항목을 확인하세요.

이전 빌드에서 파일 완성 여부 없이 정리 오류만 표시한다면 메시지만으로 결과를 판정할 수 없습니다. 기존 결과를 보존하고, 보호된 별도 경로에서 원본과 대조한 뒤 남은 임시 이름을 정리하세요.

<a name="guide-section-2"></a>
## 파일 암복호화에서 키와 출력 선택

파일 예제는 `file enc`와 `file dec`를 사용합니다. 정식 명령은 `file encrypt`와 `file decrypt`입니다.

CLI는 암호화와 복호화 모두 `--out <경로>`를 요구합니다. 생략하거나 빈 값을 주면 `USAGE`로 종료하며 작업 파일을 만들지 않습니다. 스크립트의 기존 자동 이름은 `--out`에 직접 지정하세요.

파일 형식은 JCKF이며 관리형·직접 키 주입 모두 AES-256-GCM입니다. `pass`와 `key`는 키 준비 방법이며 CSV·PDF·ZIP 등 파일 종류와 무관합니다. JAR 자체의 공개 키 두 개는 시험용입니다.

| 입력 상황 | 선택 |
|---|---|
| 관리형 Passphrase 업무 키 | CLI `file encrypt --type pass` 또는 해당 `--key-id`; Java `encryptFile`의 `KeyType.PASS` |
| 관리형 AES 업무 키 | CLI `file encrypt --type key` 또는 해당 `--key-id`; Java `KeyType.KEY` |
| 서비스에서 가진 키 | `CredentialCrypto.fromRawKey` 또는 `fromPassphrase` 후 `encryptFile` |
| 원시 AES·RSA·Hybrid | 메모리 데이터용 API이며 JCKF 스트리밍과 호환되지 않음 |

원본과 출력은 다른 경로를 사용합니다. 암호화 결과 파일을 받은 쪽은 같은 키 ID와 실제 키를 확보해야 합니다. 키 변경을 위해 파일을 처리할 경우 원본과 검증된 백업을 유지합니다. 복호화는 파일 헤더 키 ID를 선택하므로 유형을 다시 입력하지 않습니다. [키 선택과 복구](key-management.md#choose-key-material).

<a name="topic-file-encryption"></a>

## 파일 처리 절차·명령·Java API

<a name="topic-file-encryption--파일-암복호화"></a>
<a name="topic-file-encryption--7-파일-암복호화"></a>
### 파일 암복호화 (7)

문자열 `ENC`/`B64`와 파일 `JCKF`는 다른 형식입니다. CSV·PDF·JSON·이미지 등 **내용 형식을 해석하지 않고 바이너리로 암호화**하며, 큰 파일도 한 번에 메모리에 올리지 않고 스트리밍으로 처리합니다.

| 하려는 작업 | 명령 | 기본 결과·주의 |
|---|---|---|
| 파일 암호화 | `file encrypt --in <원본> --out <암호화 파일>` | 명시한 경로에 JCKF v2 생성. 키 옵션을 생략하면 기본 유형의 기본 키 |
| 파일 복호화 | `file decrypt --in <암호화 파일> --out <복원 파일>` | 인증이 모두 끝나면 지정한 경로에 복원. 기존 출력 파일 보호 |

```powershell
java -jar .\java-crypto-kit-0.2.0-cfg-2.jar file enc --in 'C:/data/report.pdf' --out 'C:/data/report.pdf.jck'
java -jar .\java-crypto-kit-0.2.0-cfg-2.jar file dec --in 'C:/data/report.pdf.jck' --out 'C:/restore/report.pdf'
```

복호화는 파일 헤더의 키 ID로 키를 고르며, 전체 인증이 끝나기 전에는 최종 평문 파일을 만들지 않습니다. 실패하면 `INTEGRITY`(변조·키 불일치), `KEY_ID_MISMATCH`(다른 키ID), 파일 존재 오류(다른 출력 경로 지정)를 확인합니다.

결과 평문 파일은 접근이 제한된 폴더에 저장하고 권한을 확인합니다. 파일 암복호화 작업마다 서로 다른 출력 경로를 지정하세요. 동일 경로를 여러 작업이 동시에 사용하지 않도록 합니다.

옵션과 Linux 예제는 [2.15절](#topic-file-encryption--215-file-encrypt--파일-암호화)·[2.16절](#topic-file-encryption--216-file-decrypt--파일-복호화), Java 코드는 [6장](java-encryption.md#topic-java-api--6-java-api)의 `encryptFile`·`decryptFile`을 봅니다.

<a name="topic-file-encryption--215-file-encrypt--파일-암호화"></a>
### `file encrypt` — 파일 암호화 (2.15)

**사용 상황:** CSV·PDF·JSON·이미지·압축 파일 등 내용 형식과 관계없이 파일 전체를 암호화할 때. 자세한 형식은 [7장](#topic-file-encryption--7-파일-암복호화).

```text
java -jar <JAR> file encrypt --in <원본 파일> --out <출력 파일> [--type pass|key] [--key-id <키 ID>]
    [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--in <경로>` | 예 | 암호화할 일반 파일 |
| `--out <경로>` | 예 | 결과 파일 경로. 기존 파일은 덮어쓰지 않음 |
| `--type pass\|key` | 아니요 | 키 유형(`encrypt`와 같은 규칙, 생략하면 기본 유형의 기본 키) |
| `--key-id <ID>` | 아니요 | 등록된 키 ID로 선택(유형 자동) |
| `--config <경로>` | 아니요 | 외부 키 공급 설정을 쓸 때 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.2.0-cfg-2.jar file enc --in 'C:/data/report.pdf' --out 'C:/data/report.pdf.jck'
```

```bash
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar file enc --in /data/export/users.csv --out /secure/users.csv.jck
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar file enc --in /data/export/users.csv --out /secure/users-aes.jck --type key
```

정식 명령으로 실행하려면 `java -jar ./java-crypto-kit-0.2.0-cfg-2.jar file encrypt --in /data/export/users.csv --out /secure/users.csv.jck`를 사용합니다.

**결과:** 예를 들어 `report.pdf.jck`가 만들어지고 원본 `report.pdf`는 그대로 남습니다.

화면에는 `암호화 완료: report.pdf -> report.pdf.jck (키 ID key01, 1049071바이트)` 한 줄이 나옵니다(쓴 키의 키 ID). 키 ID는 파일 헤더에 기록되어 복호화할 때 키를 자동으로 고릅니다.

출력 파일은 청크 기반 바이너리 `JCKF v2`이며, 큰 파일도 스트리밍으로 처리합니다. v2는 파일별 난수 식별자를 각 청크 인증에 사용해 다른 파일의 청크가 섞이면 복호화를 거부합니다. [JCKF 기술 명세](../reference/technical-specification.md#jckf-v2)

**오류·주의:** 출력 파일이 이미 있거나 입력이 없거나 입력과 출력이 같으면 거부합니다. 처리 중에는 입력 파일을 바꾸지 않습니다. 복호화에는 같은 키·키ID가 필요하므로 키(또는 키 내장 JAR)를 백업합니다. 평문 원본은 별도 보관·폐기 정책에 따라 관리합니다.

<a name="topic-file-encryption--216-file-decrypt--파일-복호화"></a>
### `file decrypt` — 파일 복호화 (2.16)

**사용 상황:** `file encrypt`(또는 Java API `encryptFile`)로 만든 `JCKF v1` 또는 `v2` 파일을 원래 파일로 되돌릴 때.

기존 v1 파일도 읽을 수 있습니다. v1의 청크 인증은 같은 키를 쓴 다른 파일의 청크를 구분하지 못합니다. 출처와 무결성을 별도로 확인한 v1 파일만 복호화하고, 기존 파일과 다른 경로에 다시 암호화하면 v2가 생성됩니다. v1 전용 이전 JAR는 새 v2 파일을 읽을 수 없습니다.

```text
java -jar <JAR> file decrypt --in <암호화 파일> --out <복원 파일> [--config <외부 Properties>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--in <경로>` | 예 | `JCKF v1` 또는 `v2` 암호화 파일(보통 `.jck`) |
| `--out <경로>` | 예 | 결과 파일 경로. 기존 파일은 덮어쓰지 않음 |
| `--config <경로>` | 아니요 | 파일 암호화에 쓴 키 공급 설정 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 원본 report.pdf가 같은 폴더에 아직 있으면 실패하므로 다른 복원 경로를 지정합니다.
java -jar .\java-crypto-kit-0.2.0-cfg-2.jar file dec --in 'C:/data/report.pdf.jck' --out 'C:/restore/report.pdf'
```

```bash
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar file dec --in /secure/users.csv.jck --out /restore/users.csv
```

정식 명령으로 실행하려면 `java -jar ./java-crypto-kit-0.2.0-cfg-2.jar file decrypt --in /secure/users.csv.jck --out /restore/users.csv`를 사용합니다.

**결과:** 먼저 관리자 비밀번호를 확인합니다(`--admin-pass-file`이면 묻지 않음, 실패하면 키를 읽거나 파일을 만들지 않음). 파일 헤더의 키 ID로 등록된 키(pass·key 모두)를 고르고, 모든 청크의 인증이 끝난 파일만 최종 경로에 만들어 `복호화 완료: report.pdf.jck -> report.pdf (1048576바이트)` 한 줄을 출력합니다.

인증 실패 시 임시 파일 삭제를 시도합니다. 정리 중 오류가 겹친 경우에는 [파일 상태별 조치](#file-result)를 따르세요.

**오류·주의:** `INTEGRITY`는 손상·변조 또는 다른 키, `KEY_ID_MISMATCH`는 이 설정에 등록되지 않은 키ID(키 파일을 읽기 전에 거부), `INVALID_TOKEN`은 `JCKF` 형식이 아닌 파일입니다.

**결과는 평문**이므로 보호된 출력 폴더를 고릅니다(Linux/macOS는 소유자 전용 600으로 만들고, Windows는 출력 폴더의 권한을 상속). 사용이 끝난 평문 파일의 정리는 [12.3절](../reference/security.md#123-평문을-다루는-명령)을 봅니다.

<a name="topic-file-encryption--a13-파일-암복호화"></a>
### 파일 암복호화 (A.13)

```powershell
java -jar .\app-pass.jar file enc --in .\report.csv --out .\report.csv.jck
java -jar .\app-pass.jar file dec --in .\report.csv.jck --out .\report-restored.csv
```

```bash
java -jar ./app-pass.jar file enc --in ./report.csv --out ./report.csv.jck
java -jar ./app-pass.jar file dec --in ./report.csv.jck --out ./report-restored.csv
```

```text
암호화 완료: report.csv -> report.csv.jck (키 ID app-pass, 65바이트)
관리자 비밀번호(입력 숨김):                  ← file decrypt만(file encrypt는 묻지 않음)
복호화 완료: report.csv.jck -> report-restored.csv (18바이트)
```


<a name="topic-file-encryption--실행-예제--임시-파일-암복호화-왕복"></a>
### 실행 예제 — 임시 파일 암복호화 왕복

`FileExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.security.SecureRandoms;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class FileExample {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("jck-example-");
        Path input = dir.resolve("sample.txt");
        Path sealed = dir.resolve("sample.jck");
        Path restored = dir.resolve("restored.txt");
        try {
            Files.write(input, "sample".getBytes(StandardCharsets.UTF_8));
            CredentialCrypto crypto = CredentialCrypto.fromRawKey("demo", SecureRandoms.bytes(32));
            crypto.encryptFile(input, sealed);
            crypto.decryptFile(sealed, restored);
            System.out.println(Arrays.equals(Files.readAllBytes(input), Files.readAllBytes(restored)));
        } finally {
            Files.deleteIfExists(restored);
            Files.deleteIfExists(sealed);
            Files.deleteIfExists(input);
            Files.deleteIfExists(dir);
        }
    }
}
```

**예상 결과**

```text
true
```

예제는 임시 폴더만 사용합니다. 실제 파일은 업무 키와 별도의 출력 경로를 사용하세요.

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
