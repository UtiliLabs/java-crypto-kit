# 외부 키 관리 서비스 연동

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

이미 외부 키 관리 체계를 운용하고 있다면 관리형 암복호화에 Vault KV v2 또는 AWS KMS를 연결할 수 있습니다. 독립 Java 보안 API와 달리 관리형 키 공급원을 설정하는 기능입니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[공급원 선택 및 연결 흐름](#guide-section-1) · [외부 공급원에서도 pass/key를 구분합니다](#guide-section-2) · [HashiCorp Vault KV v2](#topic-vault) · [AWS KMS 데이터 키 및 연동](#topic-aws-kms)

---

<a name="guide-section-1"></a>
## 공급원 선택 및 연결 흐름

Vault와 AWS KMS는 관리형 키를 공급합니다. `api` 명령은 입력받은 키만 사용하며 이 공급원을 호출하지 않습니다.

| 상황 | 선택 | 사용하는 도구 |
|---|---|---|
| Vault KV v2에 등록한 업무용 키를 읽음 | [Vault](#topic-vault) | 외부 Properties·환경 설정, CLI `info`·`doctor` |
| KMS로 보호된 데이터 키 사용 | [AWS KMS](#topic-aws-kms) | 선택 SDK와 데이터 키 파일, CLI `kms datakey` |

외부 서비스 권한과 TLS 신뢰를 먼저 준비하고, JCK 설정을 지정한 후 `info`·`doctor`로 점검합니다. Tomcat에서 사용할 경우 [Tomcat JDBC 연동](tomcat-jdbc.md)의 JNDI 설정과 실제 DB 연결 확인까지 수행합니다. 외부 키를 읽지 못하면 공개 키로 대체하지 않습니다.

<a name="guide-section-2"></a>
## 외부 공급원에서도 pass/key를 구분합니다

외부 공급원은 관리형 키를 JAR 밖에 두는 방법이며 암호화 알고리즘은 바뀌지 않습니다. Vault에서는 pass 유형이면 Passphrase를 읽어 등록된 Salt/KDF로 파생하고, key 유형이면 AES 키를 읽습니다. AWS KMS에서는 보호된 데이터 키 파일에서 AES 키를 복원하며 pass 등록은 파생된 키를 KMS로 보호합니다. KMS가 매 업무 데이터 자체를 암복호화하는 방식은 아닙니다.

| 선택 기준 | Vault KV v2 | AWS KMS |
|---|---|---|
| 기존 운영 환경 | Secret 경로와 접근 토큰을 관리하는 환경 | IAM 역할과 KMS 키를 관리하는 환경 |
| 배포 시 준비 | Vault 주소·TLS·권한·Secret 위치 | 선택 SDK·리전·IAM 권한·보호된 데이터 키 파일 |
| 실행 시 | 지정 Secret에서 키 재료 조회 | KMS를 이용해 보호된 데이터 키 복원 |
| 변경 시 | 새 키 ID 등록, 이전 키 유지 후 교체 | 이전 데이터 키 파일과 접근 권한 유지 후 교체 |

**어떤 값을 준비하나요?** Vault의 pass 프로필에는 Passphrase 원문, key 프로필에는 정확히 32바이트인 키의 표준 Base64 한 줄을 둡니다. AWS KMS를 쓰는 서비스에는 KMS가 보호한 데이터 키 파일과 복호화 권한이 함께 필요합니다. 같은 서버에서 `info`가 키 ID를 표시해도 원격 접근이 된다는 보장은 없습니다. 원격 조회까지 확인할 때는 `doctor`에서 `--offline`을 생략하세요.

키 목록에 등록한 외부 키는 지문이 달라지면 실패합니다. 같은 위치의 값을 조용히 덮어쓰지 말고 새 키 ID로 등록한 후 이전 암호문을 이전합니다. CLI `info`·`doctor`를 실제 서비스와 같은 설정 및 권한으로 확인하고 Tomcat에서는 실제 DB 연결까지 점검합니다.

<a name="topic-vault"></a>

## HashiCorp Vault KV v2

<a name="topic-vault--hashicorp-vault-연동"></a>
<a name="topic-vault--8-vault와-aws-kms-선택"></a>
### Vault와 AWS KMS (선택) (8)

**중앙 키 관리 체계를 이미 쓰는 경우에만 필요합니다.** 키 내장 JAR나 파일·환경변수 키로 운영한다면 이 장은 건너뜁니다.

| 방식 | 실제 동작 | 주의 |
|---|---|---|
| Vault KV v2 | Vault Secret에 저장한 AES 키 또는 Passphrase를 조회 | 버전 고정, TLS·토큰 권한. Transit 직접 암호화가 아님 |
| AWS KMS | KMS가 보호한 **암호화 데이터 키**(pass는 파생한 AES 키)를 복원 | KMS 마스터 키는 반출하지 않음. 선택형 SDK 설치 필요 |

<a name="topic-vault--81-vault-kv-v2"></a>
### Vault KV v2 (8.1)

**이럴 때:** 여러 WAS가 중앙 Secret에서 같은 키를 읽어야 하고 Vault의 TLS·토큰·권한 정책이 이미 있을 때. **Vault Transit 직접 암복호화는 지원하지 않습니다.**

| 준비 항목 | 설정·선택 기준 |
|---|---|
| Vault 위치 | `crypto.vault.url=https://...`, `crypto.vault.mount=secret`, `crypto.vault.path=java-crypto-kit/prod` |
| 키 필드 | `crypto.vault.field=key`. 값은 `keygen` 형식의 Base64 AES-256 키 |
| 키 버전 | `crypto.vault.ver=1`처럼 **버전 고정 권장**. 생략하면 최신 버전을 읽으므로 재기동 때 키가 바뀔 위험 |
| 인증 | `crypto.vault.token.file=/run/secrets/vault-token` 또는 `crypto.vault.token.env=VAULT_TOKEN`. **토큰 값은 Properties·`-D`에 적지 않음** |
| 사설 CA | 필요하면 `crypto.vault.ca.file=/etc/.../vault-ca.pem`. TLS 인증서·호스트 이름 검증은 끌 수 없음 |
| 제한 시간 | `crypto.vault.timeout.ms=5000`(100~60000ms) |

**Vault 준비 예(권한 있는 Vault 운영자):**

```bash
# 이미 KV v2 마운트가 있으면 'secrets enable'은 다시 하지 않습니다.
vault secrets enable -path=secret kv-v2
# keygen으로 만든 키 파일을 Secret에 저장합니다.
vault kv put secret/java-crypto-kit/prod key=@example.key
```

**pass 키·추가 키를 Vault에서 읽기:** `crypto.key.*` 대신 키 목록 항목으로 등록할 수 있습니다.

Secret 필드에 AES 키(key 유형) 또는 Passphrase(pass 유형)를 두고 `config key add --key-id vault-pass --source vault --location java-crypto-kit/prod#pass --operator <ID>`로 등록합니다(연결 설정 `crypto.vault.url`·토큰 등은 위와 같고, 등록할 때 한 번 읽어 지문을 고정). 버전을 고정하려면 `config set crypto.keys.vault-pass.vault.ver=1`처럼 위치 항목을 지정합니다.

연결 설정만 외부 Properties에 두고 `crypto.key.*`는 JAR의 내장 키를 그대로 쓴다면 `crypto.key.source=embedded`도 함께 적습니다.

공급원 없이 Vault 설정만 있으면 어느 키의 설정인지 모호해 `CONFIGURATION`으로 중단합니다.

Vault 읽기 정책의 대상 경로 예는 `secret/data/java-crypto-kit/prod`이고 필요한 권한은 `read`입니다. Secret 쓰기와 토큰 발급은 권한이 있는 Vault 운영자가 합니다.

**외부 설정 예(토큰 값 없음):**

```properties
crypto.key.source=vault
crypto.key.id=key01
crypto.vault.url=https://vault.example.internal:8200
crypto.vault.mount=secret
crypto.vault.path=java-crypto-kit/prod
crypto.vault.field=key
crypto.vault.ver=1
crypto.vault.token.file=/run/secrets/vault-token
crypto.vault.timeout.ms=5000
```

```bash
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar doctor --config /etc/java-crypto-kit/vault.properties --offline
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar doctor --config /etc/java-crypto-kit/vault.properties
java -jar ./java-crypto-kit-0.2.0-cfg-2.jar fingerprint --config /etc/java-crypto-kit/vault.properties
```

**결과 판단:** `--offline`은 네트워크 확인을 건너뜁니다(SKIP). `--offline` 없는 `doctor`는 TLS·토큰·KV v2 키 조회까지 확인합니다. 403이면 토큰 권한뿐 아니라 **mount·path 오타**도 확인합니다(정책 밖 경로도 Vault는 권한 부족으로 답함). 404면 Secret·버전·KV v2 여부를 확인합니다.

토큰·CA·네트워크 문제는 내장 키로 대체하지 않고 실패합니다. Tomcat은 **실제 서비스 계정**으로 Secret을 읽어야 하며, 키는 DataSource를 만들 때 조회하므로 설정·Secret을 바꾸면 재시작합니다.

재시도는 연결 실패·시간 초과·429/5xx에만 하고 리다이렉트는 따르지 않습니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-aws-kms"></a>

## AWS KMS 데이터 키 및 연동

<a name="topic-aws-kms--aws-kms-연동"></a>
<a name="topic-aws-kms--217-kms-datakey--aws-kms-데이터-키-파일-만들기"></a>
### `kms datakey` — AWS KMS 데이터 키 파일 만들기 (2.17)

**사용 상황:** `crypto.key.*` AES 키의 키 공급원 `aws-kms`를 처음 준비할 때 한 번(이전 형식와 같은 AES 전용 명령). pass 키나 추가 키를 KMS로 보호하려면 `config key add --source aws-kms`([2.18절](key-management.md#topic-key-registration--218-config-key-add--키-추가))를 씁니다.

기본 JAR만으로는 AWS SDK를 쓸 수 없으므로 선택형 `aws-kms-lib/*.jar`를 실행 클래스패스에 함께 넣습니다(Tomcat에서도 같음). 자세한 준비는 [8.2절](#topic-aws-kms--82-aws-kms).

```text
java -cp '<JAR>;aws-kms-lib/*' io.javacryptokit.cli.CryptoCli kms datakey --out <데이터 키 파일> --reason <사유> [--from-file <기존 키 파일>] [--config <KMS Properties>] [--operator <작업자>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--out <경로>` | 예 | KMS로 암호화된 데이터 키 파일 위치. 기존 파일은 덮어쓰지 않음 |
| `--from-file <키 파일>` | 아니요 | 기존 AES 키를 KMS `Encrypt`로 감싸 **계속 쓸 때**(기존 암호문 유지). 생략하면 KMS `GenerateDataKey`로 새 키 생성 |
| `--config <경로>` | 조건부 | KMS 키 ID·리전·`crypto.key.id` 등을 외부 파일로 줄 때. JAR 내장 설정에 모두 있으면 생략 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 **KMS를 호출하기 전에** `USAGE`로 끝남. 결과 화면에만 표시하며 저장하지 않음 |
| `--operator <ID>` | 아니요 | 결과 화면에 함께 표시할 작업자 식별자(저장하지 않음) |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**클래스패스 변수 `CP`:** `java -jar`는 `-cp`를 무시하므로 JAR와 SDK 묶음을 `-cp`로 함께 지정하고 진입점 `io.javacryptokit.cli.CryptoCli`를 적습니다.

같은 값을 여러 번 쓰므로 변수 `CP`에 담아 두면 편합니다(도움말 `kms datakey --help`·`help aws-kms`의 `$CP`). 아래는 JAR와 `aws-kms-lib` 폴더가 현재 폴더에 있다고 가정합니다.

구분자는 Windows `;`, Linux `:`이고, `aws-kms-lib/*`는 그 폴더의 모든 JAR를 뜻하는 Java 클래스패스 표기라 셸이 펼치지 않도록 따옴표로 감쌉니다.

| 셸 | 변수 만들기 | 사용 |
|---|---|---|
| Windows PowerShell | `$CP = "java-crypto-kit-0.2.0-cfg-2.jar;aws-kms-lib/*"` | `java -cp "$CP" io.javacryptokit.cli.CryptoCli <명령>` |
| Windows 명령 프롬프트 | `set "CP=java-crypto-kit-0.2.0-cfg-2.jar;aws-kms-lib/*"` | `java -cp "%CP%" io.javacryptokit.cli.CryptoCli <명령>` |
| Linux(bash) | `CP="java-crypto-kit-0.2.0-cfg-2.jar:aws-kms-lib/*"` | `java -cp "$CP" io.javacryptokit.cli.CryptoCli <명령>` |

변수는 만든 터미널 창에서만 유지되므로 새 창에서는 다시 만듭니다.

**예제**(아래 두 명령 중 하나만 실행합니다. 결과 파일은 덮어쓰지 않습니다.)

```powershell
# Windows PowerShell
$CP = "java-crypto-kit-0.2.0-cfg-2.jar;aws-kms-lib/*"
# 새 데이터 키 만들기(새 키이므로 기존 암호문은 rekey 필요)
java -cp "$CP" io.javacryptokit.cli.CryptoCli kms datakey --out C:/secure/prod.datakey --config C:/secure/kms.properties --reason "KMS 데이터 키 준비"
# 이미 쓰는 키(keygen 형식)를 KMS로 감싸기(키·키 ID가 그대로라 기존 암호문을 계속 씀)
java -cp "$CP" io.javacryptokit.cli.CryptoCli kms datakey --from-file C:/secure/example.key --out C:/secure/prod.datakey --config C:/secure/kms.properties --reason "기존 키를 KMS로 보호"
```

```bash
# Linux
CP="java-crypto-kit-0.2.0-cfg-2.jar:aws-kms-lib/*"
java -cp "$CP" io.javacryptokit.cli.CryptoCli kms datakey --out /secure/prod.datakey --config /secure/kms.properties --reason "KMS 데이터 키 준비"
java -cp "$CP" io.javacryptokit.cli.CryptoCli kms datakey --from-file /secure/example.key --out /secure/prod.datakey --config /secure/kms.properties --reason "기존 키를 KMS로 보호"
```

**결과:** 관리자 비밀번호를 확인한 뒤에만 KMS를 부릅니다.

암호화된 데이터 키 파일만 만들고, KMS `Decrypt`로 복원까지 확인한 뒤 결과 줄(파일·방식·키 ID·64자 키 지문·사유, `--operator`를 주면 작업자, `이력 : 저장 안 함`)을 출력합니다.

`파일`의 경로를 설정 `crypto.aws.kms.data-key.file`에 그대로 씁니다(예: `config set crypto.key.source=aws-kms crypto.aws.kms.data-key.file=<경로> crypto.aws.kms.key.id=<KMS 키> --operator <ID> --reason <사유>` 또는 외부 Properties).

```text
파일      : /secure/prod.datakey
방식      : 새 데이터 키(KMS GenerateDataKey)
키 ID     : key01
키 지문   : 9d2e...(64자)
사유      : KMS 데이터 키 준비
이력      : 저장 안 함(JAR를 바꾸지 않는 명령이라 config history에 없음)
```

새 데이터 키(`--from-file` 없음)는 새 키이므로 기존 암호문은 `rekey`로 다시 암호화해야 하고, 기존 키 감싸기(`--from-file`)는 키·키 ID가 같아 기존 암호문을 그대로 씁니다.

**WAS를 재기동할 때마다 다시 실행하지 않습니다.** 같은 파일에서 같은 데이터 키를 복원해야 기존 암호문이 유지되므로 데이터 키 파일은 지우지 말고 보관합니다.

데이터 키 파일은 KMS가 암호화한 형식이라 `keygen` 키 파일(표준 Base64 한 줄)·pass 복원 백업과 다른 파일이며, `--from-file`로 다시 등록하는 키 원문이 아닙니다.

이 명령은 이전 형식처럼 데이터 키 파일만 만들고 데이터 키 원문을 화면에 보여 주지 않습니다(KMS 마스터 키를 보여 주거나 내보내는 기능도 없음). 복구는 같은 데이터 키 파일과 KMS 키·권한으로 합니다. 사유는 결과 화면에만 나오고 저장되지 않습니다.

**권한·오류:** 새 키 생성은 `kms:GenerateDataKey`·`kms:Decrypt`, 기존 키 감싸기는 `kms:Encrypt`·`kms:Decrypt`가 필요합니다.

SDK가 없으면 클래스패스를, `AccessDenied`면 IAM·키 정책을, 자격증명·리전·키 ID 누락이면 설정을 확인합니다. 실제 AWS 연동은 사용하는 계정·IAM·네트워크에서 따로 검증해야 합니다.

<a name="topic-aws-kms--82-aws-kms"></a>
### AWS KMS (8.2)

**이럴 때:** IAM 역할과 KMS 운영 정책이 준비되어 있고, 키 평문 파일을 계속 두기보다 **KMS가 보호한 데이터 키 파일**을 재사용하려는 경우. java-crypto-kit은 KMS 마스터 키를 반출하지 않습니다.

1. AWS SDK 2.x 선택형 묶음(`aws-kms-lib/*.jar`)을 준비합니다. **기본 JAR에는 AWS SDK가 없습니다.**
2. KMS 키 ID·ARN·alias, 리전, 키ID(`crypto.key.id`)를 설정합니다. 자격증명은 AWS SDK 표준 체계(IAM 역할 우선)를 씁니다.
3. [`kms datakey`](#topic-aws-kms--217-kms-datakey--aws-kms-데이터-키-파일-만들기)를 **처음 한 번** 실행해 데이터 키 파일을 만듭니다.

기존 암호문을 유지하려면 `--from-file`로 **현재 AES 키를 KMS로 감쌉니다.** 생략하면 새 키가 만들어져 기존 암호문과 맞지 않습니다.
4. WAS에는 데이터 키 파일, `crypto.key.source=aws-kms` 설정, SDK 묶음을 배포합니다. WAS는 기동할 때 KMS `Decrypt`로 **같은 키**를 복원합니다.

```properties
crypto.key.source=aws-kms
crypto.key.id=key01
crypto.aws.region=ap-northeast-2
crypto.aws.kms.key.id=alias/java-crypto-kit-prod
crypto.aws.kms.data-key.file=/etc/java-crypto-kit/prod.datakey
crypto.aws.kms.timeout.ms=10000
```

```bash
# Linux: 배포 JAR와 aws-kms-lib 폴더가 현재 폴더에 있다고 가정(변수 CP: 2.17절)
CP="java-crypto-kit-0.2.0-cfg-2.jar:aws-kms-lib/*"
# 새 데이터 키를 만드는 예입니다. 이미 쓰는 AES 키가 있으면 --from-file /secure/example.key를 붙여야 기존 ENC가 유지됩니다.
java -cp "$CP" io.javacryptokit.cli.CryptoCli kms datakey --out /etc/java-crypto-kit/prod.datakey --config /etc/java-crypto-kit/kms.properties --reason "KMS 데이터 키 준비"
java -cp "$CP" io.javacryptokit.cli.CryptoCli doctor --offline --config /etc/java-crypto-kit/kms.properties
java -cp "$CP" io.javacryptokit.cli.CryptoCli doctor --config /etc/java-crypto-kit/kms.properties
```

Windows PowerShell은 `$CP = "java-crypto-kit-0.2.0-cfg-2.jar;aws-kms-lib/*"`처럼 세미콜론으로 만들고 같은 `java -cp "$CP" ...` 명령을 씁니다(셸별 방법: [2.17절](#topic-aws-kms--217-kms-datakey--aws-kms-데이터-키-파일-만들기)). AWS SDK가 필요한 실행에서는 `java -jar`와 `-cp`를 함께 쓰지 않습니다.

필요한 권한은 새 키 생성 `kms:GenerateDataKey`+`kms:Decrypt`, 기존 키 감싸기 `kms:Encrypt`+`kms:Decrypt`, WAS 복원 `kms:Decrypt`입니다.

암호화 컨텍스트는 `java-crypto-kit:key-id=<crypto.key.id>`로 고정됩니다.

**pass 키·추가 키를 KMS로 보호:** `config key add --key-id kms-pass --source aws-kms --location /etc/java-crypto-kit/kms-pass.datakey --operator <ID> --reason <사유>`(Passphrase 숨김 입력) 또는 `--type key --generate`(대화형이면 KMS가 만든 데이터 키를 한 번 보여 줌, [2.18절](key-management.md#topic-key-registration--218-config-key-add--키-추가))로 데이터 키 파일을 새로 만듭니다. pass 유형은 Passphrase로 파생한 AES 키를 **기존과 같은 데이터 키 형식**으로 KMS가 감싸며, 암호화 컨텍스트는 그 키의 키 ID(`java-crypto-kit:key-id=<키 ID>`)입니다.

SDK가 필요하므로 `java -cp "$CP" io.javacryptokit.cli.CryptoCli config key add ...`로 실행합니다.

**장애 시:** `AccessDenied`는 IAM·키 정책, `InvalidCiphertext`는 데이터 키 파일 손상 또는 키ID(암호화 컨텍스트) 불일치, `NotFound`는 KMS 키·리전, SDK 누락은 선택형 라이브러리 설치를 확인합니다.

데이터 키 파일과 KMS 키를 잃거나 삭제하면 기존 암호문을 복구할 수 없습니다. 실제 AWS 계정에서의 KMS 연동은 로컬 모의 시험과 따로 검증해야 합니다.

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
