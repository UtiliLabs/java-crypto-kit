# 암호화 키 관리

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

관리형 암복호화, Tomcat 및 파일 처리에서 사용하는 키의 준비부터 등록·선택·백업·복구·교체까지 다룹니다. 같은 키 ID와 실제 키를 유지해야 기존 암호문을 복호화할 수 있습니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[키를 준비하기 전에 결정할 것](#choose-key-material) · [키의 전체 생애주기](#guide-section-2) · [공개 예제 키와 업무용 키 준비](#topic-key-selection) · [키 공급원과 설정 적용](#topic-key-management) · [AES 키 생성 및 내장](#topic-key-generation) · [새 키 및 기존 키 등록](#topic-key-registration) · [기본 키 선택 및 제거](#topic-key-defaults) · [키 관리정보 조회 및 백업](#topic-key-export) · [키 복구 및 다른 JAR로 이전](#topic-key-recovery) · [키 교체 및 암호문 이전](#topic-key-rotation) · [설정 변경 이력](#topic-history)

---

<a name="choose-key-material"></a>
## 키를 준비하기 전에 결정할 것

키의 **유형(무엇으로 AES 키를 준비하는가)**, **공급원(어디에서 읽는가)**, **키 ID(어떤 키를 찾는가)**를 별도로 결정합니다. 데이터 암호화 방식 자체는 두 유형 모두 AES-256-GCM입니다.

| 구분 | `pass` | `key` |
|---|---|---|
| 등록 시 입력 | 비밀 문자열, 생성값 또는 복원 백업 | 기존 32바이트 AES 키 또는 새 난수 키 |
| 내부 처리 | PBKDF2-SHA256으로 파생. Salt·반복 횟수 필요 | 입력 AES 키 직접 사용 |
| 사용자 지정 키 생성 | `config key add --type pass --generate` 또는 숨김 입력 | `config key add --type key --generate` 또는 `keygen` |
| 암호화 선택 | `--type pass`, `KeyType.PASS` | `--type key`, `KeyType.KEY` |
| 복구 | 원본 복원 백업·동일 키 JAR 또는 동일한 외부 Passphrase와 KDF 정보 | 같은 실제 AES 키 및 같은 ID |

새로운 기계 관리 키가 필요하면 무작위 AES 키를 생성하는 `key`가 단순합니다. Passphrase가 필요한 경우 충분히 강한 비밀 문자열과 복구 정보를 함께 보관하세요. `pass`라고 더 강하거나 `key`라고 무조건 더 안전한 것은 아니며 실제 키 재료의 강도와 보관 정책이 중요합니다.

| 제공되는 키 관리 기능 | 실제 활용 |
|---|---|
| 공개 기본 키 2개 | 새 JAR 동작 확인. 실제 비밀값에는 사용하지 않음 |
| 여러 유형·키 ID 동시 등록 | 업무별 암호화 키 구분, 키 교체 기간의 이전 암호문 복호화 |
| 기본 유형과 유형별 기본 키 | 명령·API마다 키를 지정하지 않을 때 선택할 키 결정 |
| 명시적 `--key-id` | 지정 업무 키 사용. `--type`도 있으면 유형 일치 필요 |
| 지문·설정 조회 | CLI와 WAS, 다른 서버의 실제 키가 동일한지 확인 |
| 원본/결과 JAR 분리 및 이력 | 변경 전후 파일 관리와 변경 이유 추적. 이력이 작업자 신원을 인증하는 것은 아님 |

키를 등록만 해서는 암호문이 자동 변환되지 않습니다. 기존 암호문은 그 키 ID의 키가 필요하며, 키 교체는 이전 키를 유지한 채 `rekey` 후 확인하는 별도 작업입니다. 직접 키 API에는 관리형 키 등록·이력 기능을 적용하지 않습니다.

<a name="guide-section-2"></a>
## 키의 전체 생애주기

| 단계 | CLI 명령 또는 선택 | 결과 |
|---|---|---|
| [준비](#topic-key-selection) | `admin setup`, `keygen` 또는 `config key add` | 관리자 인증, 업무용 키 확보 |
| [등록](#topic-key-registration) | `config key add`, `config embed-key` | 새 키를 등록한 JAR |
| [사용](#topic-key-defaults) | `config key use`, `encrypt --key-id` | 기본 키 또는 명시적 키로 암호화 |
| [확인](#topic-key-management--54-지금-쓰는-키-확인) | `info`, `doctor`, `fingerprint`, `config key show` | 실제 설정·키 지문 확인 |
| [보관·복구](#topic-key-recovery) | `config key show --key-id <ID> --export <새 파일>`, `config key add --from-file` | 기존 키와 ID 복원 |
| [교체](#topic-key-rotation) | 새 키 등록 → `rekey` → 검증 → 필요 시 이전 키 제거 | 기존 암호문 이전 |
| [추적](#topic-history) | `config history` | JAR 변경 이력 확인 |

**CLI는 키 관리의 주 사용 방식**입니다. 실행 전 [CLI 관리자 인증·공통 규칙](cli.md)을 확인합니다. 키 등록·변경 명령은 새 JAR를 생성하므로 결과 JAR를 이후 명령과 실제 배포에 사용합니다. 공개 예제 키는 실습에만 사용합니다. 직접 키 주입·범용 API의 키 수명주기는 호출자가 관리하며 이 CLI 키 목록에 자동 등록되지 않습니다.

<a name="topic-key-selection"></a>

## 공개 예제 키와 업무용 키 준비

<a name="topic-key-selection--사용자-지정-키-준비"></a>
<a name="topic-key-selection--13-체험용-내장-키와-운영용-사용자-지정-키"></a>
### 체험용 내장 키와 운영용 사용자 지정 키 (1.3)

공개 JAR에는 체험용 **공개 기본 키 두 개**가 들어 있어 키를 만들지 않고 바로 실행해 볼 수 있습니다. 두 키는 소스와 함께 공개된 값이므로 누구나 복호화할 수 있습니다.

| 키 ID | 유형 | 용도 |
|---|---|---|
| `pass-default` | `pass` | 유형을 정하지 않은 새 암호화의 기본 키(공개 예제 Passphrase로 파생한 키) |
| `default` | `key` | `--type key`(Java `KeyType.KEY`)의 기본 키. 이전 형식의 공개 AES 키와 같은 값·같은 키 ID라 기존 암호문이 그대로 복호화됨 |

| 구분 | 체험(기능 확인) | 운영(실제 비밀번호·비밀값) |
|---|---|---|
| 키 | 공개 기본 키 `pass-default`·`default` | 사용자 지정 키(JAR 내장 또는 `file`·`env`·`vault`·`aws-kms`) |
| 준비 | 없음(`keygen` 불필요) | pass: `config key add --active`(Passphrase 입력). key: 새 키가 필요할 때만 `keygen` → `config embed-key`(또는 `config key add --type key`) |
| 알아보는 법 | 암호문의 키ID가 `pass-default`·`default`, `info`·`doctor`의 키 상태 `공개 기본 키`, 실행할 때 `[WARN] 공개 기본 키 사용 중` 한 줄 | 지정한 키ID(예: `app-pass`·`key01`), 키 상태 `사용자 지정`, 경고 없음 |
| 쓸 수 있는 데이터 | 시험 데이터만 | 실제 DB 비밀번호·비밀값 |

**새 암호화가 쓰는 키:** 유형·키 ID를 정하지 않으면 `crypto.key.type`(기본 `pass`)의 **기본 키**를 씁니다. pass 기본 키는 `crypto.key.active.pass`(공식 JAR `pass-default`), key 기본 키는 `crypto.key.active.key`(비우면 `crypto.key.*`의 AES 키)입니다.

그래서 AES 키만 내장해도(`config embed-key`) 유형을 정하지 않은 `encrypt`는 여전히 공개 `pass-default`를 씁니다.

운영에서는 **사용자 지정 pass 키를 기본으로 정하거나**(아래 A) **AES 키를 내장한 뒤 key 유형으로 암호화합니다**(아래 B). 자세한 선택 규칙은 [5.5절](#topic-key-management--55-키-목록과-유형-선택)에 있습니다.

**A. 운영 준비 - Passphrase(pass) 키를 JAR에 내장**

1. [`config key add`](#topic-key-registration--218-config-key-add--키-추가)로 키를 추가하고 `--active`로 pass 기본 키로 정합니다. Passphrase는 화면에 보이지 않게 두 번 입력하며, JAR에는 파생한 키만 들어갑니다.

실제 키 변경이므로 변경 사유(`--reason`, 빠지면 물어봄)를 받고 `CHANGE`를 입력해 확인합니다.

Passphrase를 직접 정하지 않으려면 `--generate`로 만들게 합니다(생성값은 화면에 한 번만 나오므로 [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)대로 보관).
2. 결과 JAR로 [`config show`](cli.md#topic-cli-settings--210-config-show--jar-내장값-조회)·[`doctor`](cli.md#topic-cli-settings--214-doctor--설정과-키-진단)(`결과: PASS`)를 확인합니다.
3. 결과 JAR로 [`encrypt`](cli.md#topic-cli-encryption--23-encrypt--문자열-암호화)를 실행해 DB 비밀번호 암호문(`ENC[v1:app-pass:...]`)을 만듭니다.
4. **같은 결과 JAR**를 WAS에 배포합니다([3장](tomcat-jdbc.md#topic-tomcat--3-tomcat-jndi-연동)).

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass --active --operator example-admin --reason "운영 pass 키 등록"
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config show
java -jar .\java-crypto-kit-0.1.0-configured-2.jar doctor
java -jar .\java-crypto-kit-0.1.0-configured-2.jar encrypt
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass --active --operator example-admin --reason "운영 pass 키 등록"
java -jar ./java-crypto-kit-0.1.0-configured-2.jar doctor
java -jar ./java-crypto-kit-0.1.0-configured-2.jar encrypt
```

**B. 운영 준비 - AES 키(key)를 JAR에 내장**

1. 새 키가 필요하면 [`keygen`](#topic-key-generation--26-keygen--새-키-파일-만들기)으로 키 파일을 만듭니다. 이미 쓰는 키가 있으면 이 단계는 없습니다.
2. [`config embed-key`](#topic-key-generation--27-config-embed-key--사용자-지정-키-내장)로 키 내장 JAR를 만듭니다(사유 입력·`CHANGE` 확인). 원본 JAR는 그대로 남고, 이전 AES 키(`default`)는 같은 키 ID로 키 목록에 남습니다.

JAR 대신 키를 외부에 두려면 [5장](#topic-key-management--5-키-공급원과-설정-적용)을 봅니다.
3. 결과 JAR로 [`config show`](cli.md#topic-cli-settings--210-config-show--jar-내장값-조회)·[`fingerprint --type key`](#topic-key-generation--28-fingerprint--키가-같은지-비교)(JAR와 키 파일의 지문 일치)·[`doctor`](cli.md#topic-cli-settings--214-doctor--설정과-키-진단)(`결과: PASS`)를 확인합니다.

지금 쓰는 키를 확인하는 방법은 [5.4절](#topic-key-management--54-지금-쓰는-키-확인)에 있습니다.
4. 결과 JAR로 `encrypt --type key`를 실행해 DB 비밀번호 암호문(`ENC[v1:key01:...]`)을 만듭니다. 유형을 매번 적지 않으려면 `config set crypto.key.type=key`로 기본 유형을 key로 바꿉니다.
5. **같은 결과 JAR**를 WAS에 배포합니다([3장](tomcat-jdbc.md#topic-tomcat--3-tomcat-jndi-연동)).

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\jck-secure" | Out-Null
java -jar .\java-crypto-kit-0.1.0-configured.jar keygen --out "$HOME\jck-secure\example.key" --reason "운영 AES 키 준비"
java -jar .\java-crypto-kit-0.1.0-configured.jar config embed-key --from-file "$HOME\jck-secure\example.key" --key-id key01 --operator example-admin --reason "운영 AES 키 내장"
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config show
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --type key
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-file "$HOME\jck-secure\example.key"
java -jar .\java-crypto-kit-0.1.0-configured-2.jar doctor
java -jar .\java-crypto-kit-0.1.0-configured-2.jar encrypt --type key
```

```bash
mkdir -p -m 700 ~/jck-secure
java -jar ./java-crypto-kit-0.1.0-configured.jar keygen --out ~/jck-secure/example.key --reason "운영 AES 키 준비"
java -jar ./java-crypto-kit-0.1.0-configured.jar config embed-key --from-file ~/jck-secure/example.key --key-id key01 --operator example-admin --reason "운영 AES 키 내장"
java -jar ./java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-file ~/jck-secure/example.key
java -jar ./java-crypto-kit-0.1.0-configured-2.jar doctor
java -jar ./java-crypto-kit-0.1.0-configured-2.jar encrypt --type key
```

키 파일·Passphrase와 키 내장 JAR는 비밀 파일입니다.

Git 저장소 밖의 보호된 곳에 보관·백업하고, 둘 다 잃으면 그 키로 만든 암호문을 복구할 수 없습니다(보관·재등록·복구 방법: [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)). 공개 기본 키는 자동으로 지우거나 막지 않습니다.

더 쓰지 않으려면 기존 암호문을 `rekey`로 옮긴 뒤 [`config key remove`](#topic-key-defaults--220-config-key-remove--키-제거)로 직접 제거합니다(그 유형의 기본 키는 먼저 바꿔야 함).

<a name="topic-key-selection--a3-운영-passphrasepass-키를-jar에-넣고-기본-키로"></a>
### 운영: Passphrase(pass) 키를 JAR에 넣고 기본 키로 (A.3)

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass --active --operator example-admin --reason "운영 pass 키 등록" --out app-pass.jar
java -jar .\app-pass.jar config show
java -jar .\app-pass.jar doctor
java -jar .\app-pass.jar encrypt
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass --active --operator example-admin --reason "운영 pass 키 등록" --out app-pass.jar
java -jar ./app-pass.jar config show
java -jar ./app-pass.jar doctor
java -jar ./app-pass.jar encrypt
```

```text
관리자 비밀번호(입력 숨김):                   ← 관리자 비밀번호
Passphrase(입력 숨김):                        ← Passphrase 입력
Passphrase 확인(입력 숨김):                   ← 같은 값 다시 입력
키를 추가합니다(기존 암호문은 그대로):
  결과: 새 JAR app-pass.jar (원본은 그대로)
  사유: 운영 pass 키 등록
  crypto.keys.app-pass.type ((없음) -> pass)
  crypto.keys.app-pass.source ((없음) -> embedded)
  crypto.keys.app-pass.embedded (비공개)
  crypto.keys.app-pass.kdf ((없음) -> pbkdf2-sha256)
  crypto.keys.app-pass.kdf.iterations ((없음) -> 600000)
  crypto.keys.app-pass.salt ((없음) -> bpdlnvXfo8nRHG1JQmKL8Q==)
  crypto.key.active.pass (pass-default -> app-pass)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
생성 JAR  : C:\work\app-pass.jar
변경 항목 : crypto.keys.app-pass.type ((없음) -> pass)
            ...
            crypto.key.active.pass (pass-default -> app-pass)
추가 키   : app-pass (pass, embedded, 지문 e87f0d656730...3db05eaa)
```

`config show`의 `기본 키   : pass=app-pass, key=default`와 키 목록, `doctor`의 `결과: PASS`(키마다 `[PASS] 키 로딩 정상`)를 확인한 뒤 `encrypt`로 만든 `ENC[v1:app-pass:...]`를 Tomcat Resource에 넣습니다.

이 JAR를 그대로 Tomcat `lib`에 배포합니다.

<a name="topic-key-selection--a4-운영-aes-키key를-jar에-넣기"></a>
### 운영: AES 키(key)를 JAR에 넣기 (A.4)

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar keygen --out "$SECURE\example.key" --reason "운영 AES 키 준비"
java -jar .\java-crypto-kit-0.1.0-configured.jar config embed-key --from-file "$SECURE\example.key" --key-id key01 --operator example-admin --reason "운영 AES 키 내장" --out app-aes.jar
java -jar .\app-aes.jar fingerprint --type key
java -jar .\app-aes.jar fingerprint --key-file "$SECURE\example.key"
java -jar .\app-aes.jar encrypt --type key
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar keygen --out "$SECURE/example.key" --reason "운영 AES 키 준비"
java -jar ./java-crypto-kit-0.1.0-configured.jar config embed-key --from-file "$SECURE/example.key" --key-id key01 --operator example-admin --reason "운영 AES 키 내장" --out app-aes.jar
java -jar ./app-aes.jar fingerprint --type key
java -jar ./app-aes.jar fingerprint --key-file "$SECURE/example.key"
java -jar ./app-aes.jar encrypt --type key
```

```text
관리자 비밀번호(입력 숨김):                                ← keygen(관리자 비밀번호 먼저)
키 파일   : C:\Users\me\jck-secure\example.key
키 지문   : 5186b17515455bfcbac7e0f19799dc0ea985e30845d29ab860ec35dbfe8a3a18
사유      : 운영 AES 키 준비
이력      : 저장 안 함(JAR를 바꾸지 않는 명령이라 config history에 없음)

유형      : key
키 ID     : 미등록(키 파일만 만듦)
생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값
<생성 결과: 키 파일과 같은 표준 Base64 44자>
안내      : 키 파일 내용과 같은 값입니다. 키 파일을 안전하게 보관하세요.

관리자 비밀번호(입력 숨김):                                ← embed-key
AES 키(crypto.key.*)를 교체합니다(이전 키가 남아 기존 암호문은 그대로):
  결과: 새 JAR app-aes.jar (원본은 그대로)
  사유: 운영 AES 키 내장
  crypto.key.embedded (비공개)
  crypto.key.id (default -> key01)
  crypto.keys.default.type ((없음) -> key)
  crypto.keys.default.source ((없음) -> embedded)
  crypto.keys.default.embedded (비공개)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
...
키 지문   : 5186b1751545...fe8a3a18

키 ID     : key01                            ← fingerprint --type key
키 유형   : key
키 지문   : 5186b17515455bfcbac7e0f19799dc0ea985e30845d29ab860ec35dbfe8a3a18
키 지문   : 5186b17515455bfcbac7e0f19799dc0ea985e30845d29ab860ec35dbfe8a3a18   ← --key-file(같아야 함)

ENC[v1:key01:...]                            ← encrypt --type key
```

`keygen`의 사유는 화면에만 나오고 어디에도 저장되지 않습니다(`이력 : 저장 안 함`). 스크립트·CI처럼 대화형 터미널이 아니면 생성값 묶음(`유형`부터 `안내`까지)은 나오지 않고 키 파일이 유일한 사본입니다.

이전 공개 AES 키(`default`)는 키 목록에 남아 기존 `ENC[v1:default:...]`도 계속 복호화됩니다. 유형을 정하지 않은 `encrypt`도 이 AES 키를 쓰게 하려면 기본 유형을 바꿉니다.

```powershell
java -jar .\app-aes.jar config set crypto.key.type=key --operator example-admin --reason "기본 유형 key" --yes --out app-aes-key.jar
java -jar .\app-aes-key.jar encrypt
```

```bash
java -jar ./app-aes.jar config set crypto.key.type=key --operator example-admin --reason "기본 유형 key" --yes --out app-aes-key.jar
java -jar ./app-aes-key.jar encrypt
```

```text
관리자 비밀번호(입력 숨김):                  ← config set
생성 JAR  : C:\work\app-aes-key.jar
변경 항목 : crypto.key.type (pass -> key)
ENC[v1:key01:...]                            ← 유형을 정하지 않아도 key01
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-management"></a>

## 키 공급원과 설정 적용

<a name="topic-key-management--키-공급원과-설정"></a>
<a name="topic-key-management--5-키-공급원과-설정-적용"></a>
<a name="topic-key-management--51-키-공급원-선택"></a>
### 키 공급원 선택 (5.1)

| 공급원 | 이럴 때 | 준비·주의 |
|---|---|---|
| `embedded` | **키 내장 JAR 하나로 배포**(기본값) | 키를 JAR에서 추출할 수 있으므로 JAR 파일 권한·배포를 통제 |
| `file` | JAR와 키를 분리할 때 | 보호된 키 파일, Tomcat 서비스 계정의 읽기 권한 |
| `env` | 배포 환경이 환경변수로 비밀값을 안전하게 넣어 줄 때 | 실제 키 값을 `.properties`나 `-D`에 적지 않음 |
| `vault` | Vault KV v2 운영 체계가 이미 있을 때 | TLS·권한·토큰, Secret 버전 고정([8.1절](external-key-providers.md#topic-vault--81-vault-kv-v2)) |
| `aws-kms` | AWS IAM·KMS로 데이터 키를 보호할 때 | 선택형 SDK, 암호화된 데이터 키 파일 보존([8.2절](external-key-providers.md#topic-aws-kms--82-aws-kms)) |

**AES 키가 꼭 필요한가요?** 복호화할 수 있는 AES-256-GCM 암호화에는 비밀키가 필요하지만, **키 파일을 매번 만들거나 명령마다 입력할 필요는 없습니다.** 키는 AES 키(`key` 유형)로 두거나 Passphrase(`pass` 유형, 키를 파생)로 둘 수 있고, 각 키의 공급원은 아래 표에서 고릅니다.

이미 준비된 키를 위 공급원 중 하나로 씁니다. `keygen`은 *새 AES 키가 필요할 때만* 실행합니다. 공개 JAR의 예제 키는 동작 확인용이며 실제 비밀값 보호에는 쓰지 않습니다.

| 질문 | 답 |
|---|---|
| 키 파일 없이 쓸 수 있나요? | 예. JAR에 사용자 지정 키가 이미 내장되어 있거나 환경변수·Vault·KMS가 키를 주면 키 파일을 따로 만들 필요가 없습니다. |
| Salt만으로 암호화·복호화할 수 있나요? | 아니요. Salt는 비밀키가 아닙니다. 비밀번호 기반 암호화(PBE)는 *비밀번호 + Salt + 키 파생 함수*로 실제 AES 키를 만드는 방식입니다. |
| 비밀번호와 Salt로 키를 만드는 기능이 있나요? | 예. `pass` 유형이 Passphrase에서 **PBKDF2-HMAC-SHA256**(키마다 16바이트 난수 Salt, 반복 600,000회, 허용 100,000~5,000,000회)으로 AES-256 키를 파생합니다([5.5절](#topic-key-management--55-키-목록과-유형-선택)). 다른 키 파생 함수(Argon2·scrypt 등)는 **미지원**입니다. |
| 사용자 로그인 비밀번호를 보관하려면? | 원문 복원이 필요 없으므로 AES 양방향 암호화가 아니라 Salt를 쓰는 **단방향 비밀번호 해시**를 별도 인증 모듈에서 씁니다. |

**키를 가져오지 못하면 다른 키로 자동 전환하지 않습니다(Fail Closed).** 키 파일·환경변수·Vault·KMS 설정이 있는데 `crypto.key.source`가 없으면 오류로 중단합니다. 키 목록의 외부 키는 등록할 때 고정한 지문과 다르면 실패합니다.

<a name="topic-key-management--52-설정을-두는-곳과-우선순위"></a>
### 설정을 두는 곳과 우선순위 (5.2)

**최종값 우선순위:** CLI 1회 옵션(`--lang`) → 허용된 JVM `-D` → 외부 Properties → JAR 내장값. `crypto.jvm.override.enabled=false`이면 개별 `-D`는 무시합니다(설정 파일 경로 `-Dcrypto.config.file`은 예외로 항상 동작). 설정은 객체(또는 DataSource)를 만들 때 한 번 읽으므로, 실행 중인 WAS에 반영하려면 재시작합니다.

| 두는 곳 | 바꾸는 방법 | 언제 쓰나 | 반영 |
|---|---|---|---|
| JAR 내장값 | `config set ... --operator <ID>`, 키는 `config embed-key` | 여러 서버·실행에 같은 기본값을 영구 적용 | **결과 JAR**를 CLI·WAS에 다시 배포 |
| 외부 Properties | `.properties` 파일([5.3절](#topic-key-management--53-외부-properties-지정)) | 서버마다 키 공급원·키 경로·Vault 경로를 다르게 둘 때 | WAS에 설정 경로 전달 후 재시작 |
| JVM `-D` | `-Dcrypto.<이름>=<값>`(허용된 이름만) | 운영 정책이 허용하고 **프로세스 전체**에 같은 값을 줄 때 | 그 JVM 재시작 |
| Tomcat `<Resource>` 속성 | Context XML의 `maxTotal`·`validationQuery` 등 | 그 JNDI Resource의 연결·Pool 옵션 | 해당 앱·Tomcat 재시작 |
| CLI 1회 옵션 | `--lang`, `--in`, `--out` 등 | 그 명령 한 번 | 그 실행에만 |

키 목록 항목(`crypto.keys.<ID>.*`)은 JAR·외부 Properties 어느 쪽에서도 등록할 수 있고(합쳐서 하나의 키 목록), 바깥 계층은 JAR에 등록된 키의 **위치 항목**만 바꿀 수 있습니다.

`-D`로는 이미 등록된 키의 위치 항목, `crypto.key.type`, `crypto.key.active.*`만 바꿀 수 있습니다([5.5절](#topic-key-management--55-키-목록과-유형-선택)).

`cryptoPool`·`auth`·`maxTotal` 같은 Resource 속성은 `crypto.*` 설정이 아니고, 반대로 `crypto.key.source`·`crypto.lang`·`crypto.pool.factory`는 XML 속성이 아닙니다.

키 원문 `crypto.key.embedded`는 `-D`로 지정하면 오류로 중단합니다(프로세스 목록·로그 노출 방지). JAR 내장값은 `config embed-key`로만 바꾸며, 외부 Properties에 적어 공급할 수도 있지만 키 원문이 파일에 남으므로 권장하지 않습니다(키를 JAR 밖에 두려면 `file`·`env`를 씁니다).

| 확인 명령 | 보여 주는 것 |
|---|---|
| `config show` | **JAR 내장값만**(외부 Properties·`-D` 미반영) |
| `config history` | JAR 설정 변경 이력(기록용, 신원 인증 아님) |
| `info` | 이번 실행에서 최종 적용된 값과 출처, 적용·무시한 `-D` |
| `doctor` | 설정·키·암복호화 자체 진단(**DB 연결 시험 아님**) |

**기본 언어:** `crypto.lang=ko`(허용 `ko`·`en`·`auto`). 출력 형식 `crypto.output.encoding=enc|base64`는 ENC/B64 **표현만** 바꿉니다. 전체 설정과 키 목록 항목의 이름·허용값·기본값은 [10장](../reference/configuration.md#10-설정-사전)에 있습니다.

<a name="topic-key-management--53-외부-properties-지정"></a>
### 외부 Properties 지정 (5.3)

외부 설정 파일의 경로는 다음 순서로 하나를 고릅니다. 아무것도 지정하지 않으면 JAR 내장값만 씁니다.

1. CLI `--config <파일>`(Java API는 `CredentialCrypto.fromConfigFile(path)`)
2. JVM 속성 `-Dcrypto.config.file=<파일>`
3. 환경변수 `CRYPTO_CONFIG_FILE`

경로를 지정했는데 비어 있으면(빈 `--config`·빈 `-D`·빈 환경변수) 미지정으로 보지 않고 오류로 중단합니다.

외부 파일에 없는 설정 이름(오타)이나 `crypto.config.file`이 있으면 오류로 중단하고, 비슷한 정식 이름이 확실하면 함께 안내합니다(값은 출력하지 않음). 이 라이브러리 영역의 `-Dcrypto.*` 오타(예: `crypto.key.soruce`)도 같은 이유로 오류로 중단합니다.

예제 파일: [java-crypto-kit.example.properties](../config/java-crypto-kit.example.properties). 이 예제는 Linux 경로의 파일 키(예 1)가 켜진 상태이므로, 그대로 쓰면 키 파일이 없는 서버에서 `KEY_SOURCE` 오류가 나는 것이 정상입니다.

자신의 OS 경로·키ID·실제 키 파일로 바꾼 뒤 `doctor`로 확인합니다. Windows 경로는 `C:/secure/app.key`처럼 `/`로 적습니다.

<a name="topic-key-management--54-지금-쓰는-키-확인"></a>
### 지금 쓰는 키 확인 (5.4)

등록된 키의 원문은 일반 조회로 볼 수 없습니다(예외: 자동 생성 직후 대화형 터미널에 한 번 나오는 생성값([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)), 관리자 인증 뒤의 [`config key show`](#topic-key-export--224-config-key-show--키-관리정보원문-확인): 화면 표시 `--show`는 `SHOW` 확인까지, 파일 내보내기 `--export`는 관리자 인증만). 대신 키 공급원·키 ID·키 상태·키 지문으로 **지금 어떤 키가 적용됐는지, 다른 곳의 키와 같은지**를 확인합니다.

| 확인하려는 것 | 명령 | 보여 주는 것 |
|---|---|---|
| 이 JAR 파일에 들어 있는 키 | `config show`(관리자 인증) | 기본 유형·유형별 기본 키·키 목록(키마다 유형·공급원·상태 `공개 기본 키`/`사용자 지정`/`외부 키`, 64자 전체 지문, pass는 KDF·Salt). 외부 설정·`-D`는 반영하지 않고 외부 키는 읽지 않음 |
| 키 하나의 관리정보·원문 | `config key show --key-id <ID>`(관리자 인증) | 관리정보 전체, `--show`(SHOW 확인)·`--export`로 원문(pass는 공급원에 원문이 있을 때만) |
| 실행할 때 실제로 쓰는 키 | `info` | 외부 Properties·`-D`·환경변수를 반영한 기본 유형·기본 키와 등록된 키마다 공급원·위치·키 상태·짧은 지문·조회 결과 |
| 두 키가 정확히 같은지 | `fingerprint` | 64자 전체 지문(키 파일은 `--key-file`). 양쪽 지문이 같으면 같은 키 |

**지문 표기:** `info`·`doctor`와 변경 결과 화면은 `ab12cd34ef56...7890abcd`(앞 12자 + 뒤 8자), `fingerprint`와 관리자 인증 뒤의 `config show`·`config history`·`config key show`는 64자 전체입니다.

둘 다 키 원문이 아니라 `SHA-256("java-crypto-kit/key-fingerprint/v1" || 0x00 || 키)`의 16진수입니다. `config show`의 `설정 지문`(`sha256:...`)은 설정 파일 내용의 식별값이며 키 지문과 무관합니다.

**자주 헷갈리는 점**

- `config set`으로 키 ID·언어 등을 바꿔도 키 자체는 그대로입니다. 키를 바꾸려면 `config embed-key`(AES 키)·`config key add`(pass 키·추가 키) 또는 외부 키 공급 설정을 씁니다. 키 ID만 바꾸고 공개 기본 키를 계속 쓰면 공개 키 경고도 그대로 나옵니다.
- AES 키를 내장해도 유형을 정하지 않은 새 암호화의 기본 유형은 `pass`입니다. `info`의 `기본 유형`·`pass 기본`·`key 기본` 줄로 새 암호화가 실제로 쓰는 키를 확인합니다.
- 외부 설정·`-D`로 다른 키 공급원을 쓰면 `config show`의 내장 키와 `info`의 실행 키가 다를 수 있습니다. WAS 기준은 항상 WAS와 같은 계정·설정으로 실행한 `info`·`fingerprint`입니다.
- 여러 서버의 키가 같은지는 각 서버에서 `fingerprint`를 실행해 64자 지문을 비교합니다.

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config show
java -jar .\java-crypto-kit-0.1.0-configured-2.jar info
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint
```

```bash
java -Dcrypto.config.file=/etc/java-crypto-kit/app.properties -jar ./java-crypto-kit-0.1.0-configured-2.jar info
java -jar ./java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-file /etc/java-crypto-kit/example.key
```

<a name="topic-key-management--55-키-목록과-유형-선택"></a>
### 키 목록과 유형 선택 (5.5)

한 JAR(또는 설정)은 **여러 키를 함께 등록한 키 목록**을 가집니다. 키마다 키 ID·유형·공급원이 있고, 암호문(파일은 헤더)에는 키 ID가 들어 있어 복호화할 때 그 키를 찾습니다.

| 구성 | 설정 | 설명 |
|---|---|---|
| `crypto.key.*` AES 키 | `crypto.key.source`·`crypto.key.id`·`crypto.key.embedded`·`crypto.key.file`·`crypto.key.env`, Vault·KMS 위치 설정 | 이전 형식와 같은 자리·같은 의미의 key 유형 키 하나(공식 JAR: 공개 키 `default`). 고정 지문은 쓰지 않음 |
| 키 목록 항목 | `crypto.keys.<키 ID>.<항목>`([10.5절](../reference/configuration.md#105-키-목록-항목)) | pass 키와 추가 key 키. `config key add`가 만들고, 외부 Properties에 직접 적어 등록할 수도 있음(공식 JAR: 공개 키 `pass-default`) |
| 기본 유형 | `crypto.key.type`(`pass`·`key`, 기본 `pass`) | 유형·키 ID를 정하지 않은 새 암호화의 유형. JAR 설정에 이 항목이 없으면(이전 형식 JAR) `key` |
| pass 기본 키 | `crypto.key.active.pass`(공식 JAR `pass-default`) | `--type pass`와 기본 유형 pass가 쓰는 키. 등록된 pass 키여야 함 |
| key 기본 키 | `crypto.key.active.key`(기본 빈 값) | `--type key`가 쓰는 키. 비우면 `crypto.key.*` AES 키, 지정하면 등록된 key 키 |

**새 암호화의 키 선택:** 옵션 없음 → 기본 유형의 기본 키, `--type`(Java `KeyType`) → 그 유형의 기본 키, `--key-id`(Java `withKeyId`) → 그 키(유형 자동), 둘 다 → 유형을 확인한 뒤 그 키. 기본 키는 `crypto.key.active.*`로 **명시한 키 ID만** 쓰며 "목록의 첫 키" 같은 암묵 규칙은 없습니다.

키를 추가해도 기본 키는 바뀌지 않고(`--active`·`config key use`로만 바꿈), 한 유형의 기본 키를 바꿔도 다른 유형은 그대로입니다.

**복호화:** 암호문의 키 ID로 등록된 키를 찾습니다. 등록되지 않은 키 ID는 다른 키로 시도하지 않고 `KEY_ID_MISMATCH`, 키를 읽지 못하거나 외부 키의 지문이 고정값과 다르면 `KEY_SOURCE`, 변조·다른 키면 `INTEGRITY`로 실패합니다.

**설정 계층과 키 목록:** 키 목록은 JAR 내장값과 외부 Properties의 합집합입니다(어느 계층이든 `crypto.keys.<ID>.type`이 있으면 등록). 바깥 계층은 JAR에 등록된 키의 **위치 항목**(`file`·`env`·`vault.path`·`vault.field`·`vault.ver`·`aws.kms.data-key.file`)만 바꿀 수 있고, 유형·공급원·내장 값·KDF·Salt·고정 지문을 바꾸려 하면 오류입니다.

`-D`는 등록된 키의 위치 항목만 받으며(서버마다 다른 경로·환경변수 이름), 정체 항목이나 등록되지 않은 키 ID의 `-D`는 오류입니다. 템플릿 키 ID가 `crypto.key.id`와 같으면 같은 키 ID가 두 키를 가리키므로 오류입니다.

**키 ID 규칙:** 영문·숫자·`_`·`-`, 1~64자(설정 이름 소문자 규칙의 예외). 한 번 쓴 키 ID는 다른 키에 다시 쓰지 않습니다(같은 키 ID가 다른 키를 가리키면 예전 암호문의 실패 원인을 구분할 수 없음). 그래서 CLI는 JAR 이력에 나온 키 ID에 키를 다시 등록할 때 **이력에 기록된 그 키와 같은지**(유형·64자 전체 지문, pass는 KDF·반복 횟수·Salt까지) 확인하고 같은 키를 되살리는 경우에만 허용합니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)). `pass-default`·`default`는 공개 기본 키 전용입니다.

Passphrase·Salt·반복 횟수를 바꾸는 것은 **새 키**이므로 새 키 ID로 추가합니다.

**외부 키의 지문 고정:** `crypto.keys.<ID>.*`로 등록한 외부 공급원 키(`file`·`env`·`vault`·`aws-kms`)는 `crypto.keys.<ID>.fingerprint`(64자)가 필수입니다.

실행할 때 읽은 키의 지문이 다르면 실패하므로, 파일·환경변수·Vault 값이 바뀌어도 다른 키로 조용히 암복호화하지 않습니다. `config key add`가 등록할 때 한 번 읽어 이 값을 채웁니다.

**한 JVM 안에서:** pass·key 키는 같은 객체·같은 JAR 안에서 동시에 독립적으로 동작합니다(여러 스레드 공유 가능). Passphrase 파생은 비용이 큰 계산이라(JDK 8에서 첫 파생 약 1초) JVM 안에서 키마다 한 번만 계산해 재사용합니다.

<a name="topic-key-management--a12-지금-쓰는-키-확인"></a>
### 지금 쓰는 키 확인 (A.12)

```powershell
java -jar .\app-pass.jar info
java -jar .\app-pass.jar doctor
```

```bash
java -jar ./app-pass.jar info
java -jar ./app-pass.jar doctor
```

```text
기본 유형 : pass [JAR 기본값]
pass 기본 : app-pass [JAR 기본값]
key 기본  : default [JAR 기본값]

키 app-pass (pass, 기본)
  공급원 : embedded [JAR 기본값]
  위치   : JAR 내장(crypto.keys.app-pass.embedded)
  KDF    : pbkdf2-sha256, 반복 600,000회
  상태   : 사용자 지정
  지문   : e87f0d656730...3db05eaa
  조회   : OK
...
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-generation"></a>

## AES 키 생성 및 내장

<a name="topic-key-generation--aes-키-생성-및-내장"></a>
<a name="topic-key-generation--26-keygen--새-키-파일-만들기"></a>
### `keygen` — 새 키 파일 만들기 (2.6)

**사용 상황:** 운영용 새 AES-256 키(`key` 유형)가 필요할 때만 씁니다. **암복호화의 필수 선행 단계가 아닙니다**(체험은 내장 예제 키로, 이미 키가 있으면 그 키로 합니다). Passphrase(`pass` 유형)는 만들지 않습니다.

운영 키를 잃었다고 새 키를 만들어도 **기존 암호문은 복구되지 않습니다**.

```text
java -jar <JAR> keygen --out <새 키 파일> [--reason <사유>] [--operator <작업자>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--out <경로>` | 예 | 32바이트 난수 키를 표준 Base64 한 줄로 저장할 **새 파일**. 상위 폴더가 있어야 하고, 같은 이름의 파일이 있으면 덮어쓰지 않음 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 생성 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 키 파일을 만들기 전에 `USAGE`로 끝남. **결과 화면에만 표시하며 JAR 이력이나 다른 곳에 저장하지 않음** |
| `--operator <ID>` | 아니요 | 결과 화면에 함께 표시할 작업자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자). 저장하지 않음 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# Windows PowerShell: 상위 폴더를 먼저 만듭니다. example.key는 새로 만들 파일 이름이지 키 값이 아닙니다.
New-Item -ItemType Directory -Force -Path "$HOME\jck-secure" | Out-Null
java -jar .\java-crypto-kit-0.1.0-configured.jar keygen --out "$HOME\jck-secure\example.key" --reason "운영 AES 키 준비"
```

```bash
# Linux(키 내장용, 본인 폴더)
mkdir -p -m 700 ~/jck-secure
java -jar ./java-crypto-kit-0.1.0-configured.jar keygen --out ~/jck-secure/example.key --reason "운영 AES 키 준비"
# Linux 서버(파일 키로 사용, Tomcat 실행 계정이 읽음 - root로 실행, 계정 이름은 환경에 맞게)
install -d -m 750 -g tomcat /etc/java-crypto-kit
java -jar ./java-crypto-kit-0.1.0-configured.jar keygen --out /etc/java-crypto-kit/example.key --reason "운영 AES 키 준비"
chown tomcat:tomcat /etc/java-crypto-kit/example.key
```

**결과:** 관리자 비밀번호를 확인한 뒤(키를 만들기 전), 표준 출력에 만든 파일의 전체 경로, 64자 키 지문, 사유(`--operator`를 주면 작업자도)와 `이력 : 저장 안 함`을 씁니다.

대화형 터미널에서는 이어서 빈 줄 하나 뒤에 생성한 키 원문을 **한 번** 보여 줍니다.

그 값은 키 파일 내용과 같은 표준 Base64 한 줄(32바이트 키, 44자)이며 `생성값` 다음 줄에 값만 있습니다(라벨·공백 없음). 스크립트·CI에서는 원문을 보여 주지 않으며 키 파일이 유일한 사본입니다.

```text
관리자 비밀번호(입력 숨김):
키 파일   : C:\Users\me\jck-secure\example.key
키 지문   : 3f9a...(64자)
사유      : 운영 AES 키 준비
이력      : 저장 안 함(JAR를 바꾸지 않는 명령이라 config history에 없음)

유형      : key
키 ID     : 미등록(키 파일만 만듦)
생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값
<생성 결과: 표준 Base64 44자>
안내      : 키 파일 내용과 같은 값입니다. 키 파일을 안전하게 보관하세요.
```

키 파일을 잃어도 화면에서 옮겨 둔 값으로 같은 키 파일을 다시 만들 수 있습니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구) (b)). 사유는 이 화면에만 남으므로 변경 관리 기록이 필요하면 조직의 절차(작업 티켓 등)에 따로 남깁니다.

Linux·macOS에서는 파일을 소유자 전용 권한(600)으로 만들고, Windows에서는 저장 폴더의 NTFS 권한을 그대로 물려받습니다.

사용자 프로필 아래 폴더는 기본으로 본인·관리자만 접근하지만, `C:\` 바로 아래에 만든 폴더(예: `C:\secure`)는 기본 상속으로 다른 로컬 사용자도 읽을 수 있으므로 `icacls`로 상속을 끊고 필요한 계정(운영자, Tomcat 서비스 계정)만 허용합니다([12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관)).

**다음 단계:** `crypto.key.*` AES 키로 내장하려면 [`config embed-key`](#topic-key-generation--27-config-embed-key--사용자-지정-키-내장), 추가 key 키로 등록하려면 [`config key add --type key --from-file`](#topic-key-registration--218-config-key-add--키-추가), 외부 파일 키로 쓰려면 `crypto.key.source=file`과 `crypto.key.file`을 설정합니다([5장](#topic-key-management--5-키-공급원과-설정-적용)).

**`keygen`·`kms datakey`와 키 목록 명령의 차이:** 두 명령은 이전 형식와 같은 **AES 키(`key` 유형) 전용**입니다.

`keygen`은 키 파일만 만들고 JAR·설정을 바꾸지 않으며, `kms datakey`는 `crypto.key.*` AES 키(키 ID `crypto.key.id`)의 데이터 키 파일을 만듭니다.

Passphrase 키를 새로 만들거나 키를 여러 개 두려면 `config key add`를 씁니다(`--generate`는 pass면 32자 Passphrase, key면 32바이트 키를 만들어 대화형 터미널에 한 번 보여 주고, `--export`로 파일에도 저장: pass는 복원 백업, key는 keygen과 같은 키 파일). 기본값도 다릅니다: `keygen`이 만든 키는 그 자체로는 아무 기본 키도 바꾸지 않고, `config key add`도 `--active`를 줄 때만 기본 키를 바꿉니다.

**오류·주의:** 폴더가 없거나 같은 이름의 파일이 있으면 다른 출력 경로를 지정합니다. 스크립트·CI에서 `--reason`이 빠지면 키 파일을 만들기 전에 `[사유: USAGE] keygen에는 사유가 필요합니다. ...`로 끝납니다.

키 파일은 운영 환경의 보안 정책에 따라 보관·백업합니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)).

<a name="topic-key-generation--27-config-embed-key--사용자-지정-키-내장"></a>
### `config embed-key` — 사용자 지정 키 내장 (2.7)

**사용 상황:** 외부 키 파일을 따로 배포하지 않고 **사용자 지정 AES 키를 `crypto.key.*` 자리에 내장한 JAR**로 운영할 때. JAR에서 키를 추출할 수 있으므로 결과 JAR도 비밀 파일로 관리합니다.

이 명령은 AES 키(`key` 유형)만 바꾸며 pass 키와 다른 키 ID의 키는 건드리지 않습니다. 키를 하나 더 두거나 pass 키를 추가하려면 [`config key add`](#topic-key-registration--218-config-key-add--키-추가)를 씁니다.

```text
java -jar <입력 JAR> config embed-key --from-file <키 파일> --key-id <새 키ID> --operator <수정자> [--reason <사유>]
    [--source embedded] [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--from-file <경로>` | 예 | `keygen`으로 만든 AES-256 키 파일. 키 문자열을 인자로 받지 않음 |
| `--key-id <ID>` | 예 | 영문·숫자·`_`·`-`, 1~64자. **현재 키ID, 키 목록에 등록된 키ID, 공개 기본 키 ID(`pass-default`·`default`)는 쓸 수 없음.** 이 JAR 이력에 나온 키ID는 **같은 키를 되살릴 때만**(이력에 기록된 유형·64자 전체 지문과 같을 때) 쓸 수 있음 |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자). 기록용이며 본인 인증이 아님 |
| `--source embedded` | 조건부 | 대상 JAR의 `crypto.key.source`가 `embedded`가 아닐 때만 필요: `embedded`로 **명시적으로 전환**하며 키를 내장. 이미 `embedded`(기본값)이면 생략해도 진행되고, `embedded`가 아닌데 생략하면 오류로 멈추며 JAR는 바뀌지 않음 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 이력에 남길 변경 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 바꾸기 전에 오류. `--yes`로 생략되지 않음 |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로. 생략하면 `<이름>-configured.jar`, 이미 바꾼 JAR면 `-configured-2.jar` 등. 기존 파일은 덮어쓰지 않음 |
| `--replace` | 아니요 | 새 파일 대신 `<이름>.bak-<UTC>` 백업 후 원본 교체. `--out`과 함께 쓸 수 없고, 실행 중인 JAR는 교체하지 않음 |
| `--yes` | 아니요 | `CHANGE` 확인을 생략(무인 자동화). 키 변경이므로 새 JAR를 만들 때도 확인하며, 대화형 터미널이 없으면 `--yes`가 필요함 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config embed-key --from-file "$HOME\jck-secure\example.key" --key-id key01 --operator example-admin --reason "운영 AES 키 내장"
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config show
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --type key
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-file "$HOME\jck-secure\example.key"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config embed-key --from-file ~/jck-secure/example.key --key-id key01 --operator example-admin --reason "운영 AES 키 내장"
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config history
```

**확인:** 관리자 비밀번호를 확인한 뒤에만 키 파일을 읽습니다. 실제 키 변경이므로 사유를 받은 뒤(옵션이 없으면 질문) 새 JAR를 만들 때도 기존 암호문 영향(제목)·결과 JAR·사유·바꿀 내용을 보여 주고 `CHANGE` 입력(또는 `--yes`)을 받습니다.

이전 AES 키는 **같은 키 ID의 키 목록 항목**(`crypto.keys.<이전 ID>.*`)으로 옮겨져 기존 암호문을 계속 복호화합니다.

```text
관리자 비밀번호(입력 숨김):
AES 키(crypto.key.*)를 교체합니다(이전 키가 남아 기존 암호문은 그대로):
  결과: 새 JAR java-crypto-kit-0.1.0-configured-2.jar (원본은 그대로)
  사유: 운영 AES 키 내장
  crypto.key.embedded (비공개)
  crypto.key.id (default -> key01)
  crypto.keys.default.type ((없음) -> key)
  crypto.keys.default.source ((없음) -> embedded)
  crypto.keys.default.embedded (비공개)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소):
```

**결과:** 원본 JAR는 그대로 두고 **결과 JAR**를 만듭니다(관리자 비밀번호 검증값은 그대로 옮겨져 같은 비밀번호로 씀). 출력은 결과 JAR, 변경 항목(설정마다 한 줄), 짧은 키 지문입니다(`--replace`면 `교체 JAR`·`백업`·`변경 항목`·`키 지문`).

```text
생성 JAR  : C:\work\java-crypto-kit-0.1.0-configured-2.jar
변경 항목 : crypto.key.embedded (비공개)
            crypto.key.id (default -> key01)
            crypto.keys.default.type ((없음) -> key)
            crypto.keys.default.source ((없음) -> embedded)
            crypto.keys.default.embedded (비공개)
키 지문   : ab12cd34ef56...7890abcd
```

이후 key 유형의 기본 키는 새 `crypto.key.*` 키입니다(`crypto.key.active.key`가 비어 있을 때). 유형을 정하지 않은 새 암호화의 기본은 그대로 pass이므로 새 AES 키로 암호화하려면 `encrypt --type key`를 쓰거나 `config set crypto.key.type=key`로 기본 유형을 바꿉니다.

이전 키로 만든 암호문은 그대로 복호화되므로 계획에 따라 [`rekey`](#topic-key-rotation--29-rekey--기존-암호문을-새-키로-바꾸기)로 옮기고, 다 옮긴 뒤 이전 키를 [`config key remove`](#topic-key-defaults--220-config-key-remove--키-제거)로 제거할 수 있습니다.

`config show`의 키 목록, `config history`의 변경 기록, **결과 JAR와 키 파일의 지문 일치**를 확인합니다.

**외부 공급원 키에서 전환할 때(`--source embedded`):** 지금 `crypto.key.*`가 `file`·`env`·`vault`·`aws-kms`이면 이전 키를 지금 한 번 읽어 지문을 고정한 뒤 같은 키 ID로 남깁니다.

위치가 JAR 밖(실행 시 `-D`·외부 Properties)에서 정해지거나 지금 읽을 수 없으면 지문을 고정할 수 없으므로 **남기지 않고** 확인 화면과 결과에 `이전 키 <ID>(<공급원>)는 지금 읽을 수 없어 키 목록에 남기지 않습니다(그 키의 암호문은 rekey 필요).`를 보여 주고, 확인 제목도 `내장 키를 교체합니다(기존 암호문은 rekey로 재암호화 필요):`로 바뀝니다(이전 형식와 같은 결과).

**이전 버전 JAR:** 키 목록을 지원하지 않는 이전 형식 JAR를 대상으로 하면 그 버전이 모르는 항목을 쓰지 않도록 이전 형식와 같이 `crypto.key.*`만 바꿉니다(확인 제목 `내장 키를 교체합니다(기존 암호문은 rekey로 재암호화 필요):`).

**오류·주의:** 키ID가 겹치면 새 ID를 씁니다(이력의 키 ID를 같은 키로 되살리는 경우는 [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)). `--source embedded`를 요구하면 그대로 붙입니다.

공개 예제 키, 현재와 같은 키, 키 목록에 이미 있는 키는 내장할 수 없습니다. 결과 JAR(이름을 `--out`으로 정한 경우 포함)와 키 파일은 Git·공개 저장소에 올리지 않습니다.

<a name="topic-key-generation--28-fingerprint--키가-같은지-비교"></a>
### `fingerprint` — 키가 같은지 비교 (2.8)

**사용 상황:** 키 파일과 키 내장 JAR, 또는 여러 서버의 키가 같은지 키 원문 없이 비교할 때.

```text
java -jar <JAR> fingerprint [--type pass|key] [--key-id <키 ID>] [--config <외부 Properties>] [--lang ko|en]
java -jar <JAR> fingerprint --key-file <키 파일> [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--type pass\|key` | 아니요 | 그 유형의 기본 키. 생략하면 유형을 정하지 않은 새 암호화가 쓰는 키 |
| `--key-id <ID>` | 아니요 | 등록된 키 ID의 키(유형 자동). `--type`과 함께 쓰면 유형 확인 |
| `--config <경로>` | 아니요 | 그 설정이 실제로 쓰는 키의 지문. Vault·KMS면 원격 키를 실제로 조회할 수 있음 |
| `--key-file <경로>` | 아니요 | `keygen` 형식 키 파일 자체의 지문. `--config`·`--type`·`--key-id`와 함께 쓸 수 없음 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --type key
java -jar .\java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-file "$HOME\jck-secure\example.key"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured-2.jar fingerprint --key-id app-pass --config /etc/java-crypto-kit/app.properties
```

**결과:** 키 공급원·위치·키 ID·유형·키 상태와 **64자 전체 키 지문**을 출력합니다. pass 유형은 Passphrase에서 파생한 AES 키의 지문입니다. 비교할 양쪽의 `키 지문` 줄이 같으면 같은 키입니다. `--key-file`이면 키 파일 이름·키 상태·키 지문만 나옵니다.

```text
키 공급원 : embedded
키 위치   : JAR 내장(crypto.key.embedded)
키 ID     : key01
키 유형   : key
키 상태   : 사용자 지정
키 지문   : 5b1c...(64자)
```

키 지문은 `SHA-256("java-crypto-kit/key-fingerprint/v1" || 0x00 || 키)`의 16진수 64자로, 키 원문이 아니라 키를 비교하기 위한 값입니다.

인증·키 보관 수단이 아니며, 같은 키라도 키ID가 다르면 이전 암호문과 맞지 않을 수 있습니다. `info`·`config show`는 같은 지문을 앞 12자와 뒤 8자만 보여 줍니다([5.4절](#topic-key-management--54-지금-쓰는-키-확인)).

**오류·주의:** 키를 읽지 못하면 실제 사유 코드(`KEY_SOURCE` 등)와 원인으로 실패합니다. 실제 키 공급원과 실행 계정의 권한을 확인합니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-registration"></a>

## 새 키 및 기존 키 등록

<a name="topic-key-registration--키-등록"></a>
<a name="topic-key-registration--218-config-key-add--키-추가"></a>
### `config key add` — 키 추가 (2.18)

**사용 상황:** JAR에 사용자 지정 **pass 키**(Passphrase)나 **추가 key 키**를 넣을 때, 외부 공급원(파일·환경변수·Vault·AWS KMS)의 키를 키 목록에 등록할 때, 다른 JAR의 키를 같은 키 ID로 가져올 때. 결과는 새 JAR이며(원본 그대로) JAR 하나에 여러 키를 함께 둡니다.

키를 추가해도 **기본 키는 바뀌지 않습니다**(`--active` 또는 [`config key use`](#topic-key-defaults--219-config-key-use--기본-키-변경)로만 바꿈).

```text
java -jar <입력 JAR> config key add --key-id <새 키 ID> --operator <수정자> [--reason <사유>]
    [--type pass|key] [--generate [--export <파일>] | --from-file <파일> | --from-jar <JAR>]
    [--source embedded|file|env|vault|aws-kms] [--location <외부 위치>] [--active]
    [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--key-id <ID>` | 예 | 새 키 ID(영문·숫자·`_`·`-`, 1~64자). 이미 등록된 ID와 공개 기본 키 ID(`pass-default`·`default`)는 쓸 수 없음. 이 JAR 이력에서 쓰인 ID는 다른 키에 다시 쓰지 않으며 **같은 키를 되살릴 때만**(이력의 유형·64자 전체 지문, pass는 KDF·반복 횟수·Salt까지 같을 때) 허용 |
| `--type pass\|key` | 아니요 | 유형. 생략하면 `pass` |
| `--generate` | 재료 중 하나 | 새로 생성: pass는 32자 무작위 Passphrase(영문·숫자), key는 32바이트 보안 난수 키(`aws-kms`면 KMS가 만든 데이터 키). `embedded`·`aws-kms`에만. 대화형 터미널이면 성공 직후 생성값 전체를 **한 번** 보여 줌(pass는 복원 정보·64자 지문 포함). 스크립트·CI에서는 `--export`가 있어야 생성 |
| `--export <파일>` | 비대화형 `--generate`면 예 | `--generate`로 만든 값을 이 **새 파일**에 저장(덮어쓰지 않음, POSIX 600, 경로는 생성 전에 확인). pass는 **복원 백업**(키 ID·KDF·반복 횟수·Salt·지문·Passphrase), key는 `keygen`과 같은 표준 Base64 한 줄. 대화형이면 화면 표시와 함께 저장. `--generate`와만 |
| `--from-file <파일>` | 재료 중 하나 | pass: `--export` 복원 백업(같은 키 ID·KDF·반복 횟수·Salt로 **같은 키 복원**, 지문 확인) 또는 Passphrase 한 줄 파일(UTF-8, 1KiB 이하, 앞의 BOM 하나와 끝 줄바꿈 하나는 제외, **새 Salt = 새 키**). key: `keygen` 형식 AES 키 파일(표준 Base64 한 줄, 앞의 BOM과 앞뒤 공백·줄바꿈은 제외) |
| `--from-jar <JAR>` | 재료 중 하나 | 그 JAR에 등록된 **같은 키 ID**의 정의를 그대로 복사(두 JAR가 같은 키를 씀). Passphrase 원문은 어느 JAR에도 없으므로 꺼낼 수 없음. `--source`·`--location`과 함께 쓸 수 없음 |
| (재료 없음) | — | pass + `embedded`·`aws-kms`: Passphrase를 화면에 보이지 않게 **두 번** 입력. 외부 공급원(`file`·`env`·`vault`, key의 기존 KMS 데이터 키 파일): 그 위치에서 지금 한 번 읽음 |
| `--source <공급원>` | 아니요 | 실행할 때 키를 읽는 곳: `embedded`(기본, JAR에 저장), `file`, `env`, `vault`, `aws-kms` |
| `--location <위치>` | 외부 공급원이면 예 | `file`: 파일 경로, `env`: 환경변수 이름, `vault`: Secret 경로(`경로#필드`로 필드 지정, 없으면 `crypto.vault.field`), `aws-kms`: 데이터 키 파일(재료가 있으면 새로 만듦, 기존 파일은 덮어쓰지 않음) |
| `--active` | 아니요 | 추가한 키를 그 유형의 기본 키로 정함(`crypto.key.active.pass`·`crypto.key.active.key`) |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 이력에 남길 변경 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 바꾸기 전에 오류. `--yes`로 생략되지 않음 |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로(생략하면 `-configured.jar` 등, 기존 파일은 덮어쓰지 않음) |
| `--replace` | 아니요 | 백업 후 원본 교체 |
| `--yes` | 아니요 | `CHANGE` 확인 생략(대화형 터미널이 없으면 필요) |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

`--location`은 embedded에서 금지되고 외부 공급원에서는 필수입니다. `--type key --source embedded`로 새 키를 등록하려면 `--generate` 또는 `--from-file`이 필요합니다. pass에서 재료 옵션을 생략하면 `embedded`·`aws-kms`는 터미널에서 Passphrase를 두 번 묻고, `file`·`env`·`vault`는 지정 위치에서 읽습니다.

**pass 키를 만드는 방법:** 키마다 새 난수 Salt(16바이트)와 PBKDF2-HMAC-SHA256 반복 600,000회로 32바이트 AES 키를 파생합니다(Passphrase는 NFC 정규화 후 UTF-8). `embedded`·`aws-kms`는 **파생한 키만** 저장하고(KMS는 파생 키를 기존 데이터 키 형식·암호화 컨텍스트 `java-crypto-kit:key-id=<키 ID>`로 감쌈), `file`·`env`·`vault`는 Passphrase를 그 위치에 두고 Salt·반복 횟수만 설정에 남겨 실행할 때 파생합니다(JVM 안에서 한 번만 계산). 빈 값·공백만·두 입력 불일치·제어 문자·짝이 맞지 않는 서로게이트 같은 입력 오류를 거부합니다. 대화형 입력에는 강도 평가용 최소 길이 규칙이 없으며, 한 줄 Passphrase 파일은 UTF-8 파일 전체가 1KiB 이하여야 합니다(강도 판단은 [12.6절](../reference/security.md#126-passphrase-운영)). 공개 예제 Passphrase와 공개 기본 키, 이미 등록된 키와 같은 재료는 등록할 수 없습니다.

**외부 공급원과 지문 고정:** 외부 공급원 키는 등록할 때 재료를 한 번 읽어 키 지문을 `crypto.keys.<ID>.fingerprint`에 고정합니다.

실행할 때 그 위치의 값이 바뀌면 다른 키로 조용히 동작하지 않고 `KEY_SOURCE`(지문 불일치)로 실패합니다. 외부 값을 바꾸려면 **새 키 ID로 추가 → `use` → `rekey` → `remove`** 순서로 회전합니다.

`--from-file`과 외부 공급원을 함께 쓰면 지금 가진 사본으로 지문을 계산하고, 실행 시에는 `--location`에서 같은 값을 읽어야 합니다(예: 서버의 경로가 이 PC에 없을 때). Vault·AWS KMS에 연결할 때는 실행 설정(JVM `-D`, `CRYPTO_CONFIG_FILE`, 실행 중인 JAR 값)의 주소·토큰·리전을 씁니다.

재료를 별도로 주지 않고 외부에서 등록할 때는 그 위치를 지금 읽을 수 있어야 합니다. `--from-file`로 재료 사본을 등록했다면 실행 환경의 공급원이 같은 값을 제공하는지 배포 전에 `fingerprint`로 확인합니다.

**예제**

```powershell
# pass 키(Passphrase 숨김 입력 2회)를 추가하고 pass 기본 키로 정함
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass --active --operator example-admin --reason "운영 pass 키 등록"
# pass 키를 생성해(화면에 한 번 표시) 추가하고 복원 백업도 파일로 받음
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --generate --export "$HOME\jck-secure\member-pass.backup" --operator example-admin --reason "회원 pass 키 생성"
# 새 AES 키를 생성해 추가하고 keygen과 같은 키 파일로도 저장
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key add --key-id biz-aes --type key --generate --export "$HOME\jck-secure\biz-aes.key" --operator example-admin --reason "업무 AES 키 생성"
# Passphrase 파일 사본으로 등록하고 실행할 때는 환경변수에서 읽기(서버에 APP_PASS 필요)
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key add --key-id env-pass --from-file "$HOME\jck-secure\env.pass" --source env --location APP_PASS --operator example-admin --reason "환경변수 pass 키 등록"
```

```bash
# 서버의 Passphrase 파일을 지금 한 번 읽어 지문을 고정(실행할 때도 같은 파일)
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id file-pass --source file --location /etc/java-crypto-kit/app.pass --operator example-admin --reason "파일 pass 키 등록" --yes
# 다른 JAR의 같은 키 ID를 복사(두 JAR가 같은 키)
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id shared01 --from-jar ./team-a.jar --operator example-admin --reason "팀 A와 같은 키" --yes
# Vault Secret의 Passphrase(경로#필드)
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id vault-pass --source vault --location java-crypto-kit/app#pass --operator example-admin --reason "Vault pass 키 등록" --yes
# 스크립트·CI: 생성값을 화면에 보여 줄 수 없으므로 --export가 필요(없으면 생성 전에 중단)
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id ci-pass --generate --export /secure/ci-pass.backup --operator ci-bot --reason "배포 파이프라인 키" --yes
```

**확인과 결과:** 관리자 비밀번호를 확인하고(`--from-jar` JAR도 그 JAR의 비밀번호, 같으면 한 번만), 사유를 받고(옵션이 없으면 질문) 재료(숨김 입력 등)를 받은 뒤, 기존 암호문 영향(제목)·결과 JAR·사유·바뀌는 항목을 보여 주고 `CHANGE`를 입력받습니다(또는 `--yes`). 결과는 생성 JAR, 변경 항목(설정마다 한 줄), 추가 키 요약 줄이며 `--export`·KMS 데이터 키 파일을 만들었으면 그 경로를 덧붙입니다.

같은 키를 되살렸으면 `복원` 줄(`백업과 같은 키` 또는 `이력에 기록된 이 키 ID의 키와 같음`), Passphrase 한 줄 파일로 등록했으면 `Salt      : 새로 만듦(같은 Passphrase라도 이전에 등록한 키와 다른 키)` 줄이 붙습니다.

취소·실패하면 JAR와 내보낼 파일 모두 만들지 않습니다.

```text
관리자 비밀번호(입력 숨김):
Passphrase(입력 숨김):
Passphrase 확인(입력 숨김):
키를 추가합니다(기존 암호문은 그대로):
  결과: 새 JAR java-crypto-kit-0.1.0-configured-2.jar (원본은 그대로)
  사유: 운영 pass 키 등록
  crypto.keys.app-pass.type ((없음) -> pass)
  crypto.keys.app-pass.source ((없음) -> embedded)
  crypto.keys.app-pass.embedded (비공개)
  crypto.keys.app-pass.kdf ((없음) -> pbkdf2-sha256)
  crypto.keys.app-pass.kdf.iterations ((없음) -> 600000)
  crypto.keys.app-pass.salt ((없음) -> 8JEPh8RGg4EiKbQt6lZk4w==)
  crypto.key.active.pass (pass-default -> app-pass)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
생성 JAR  : C:\work\java-crypto-kit-0.1.0-configured-2.jar
변경 항목 : crypto.keys.app-pass.type ((없음) -> pass)
            ...
            crypto.key.active.pass (pass-default -> app-pass)
추가 키   : app-pass (pass, embedded, 지문 5d0c8a1e2b3f...44aa9c01)
```

**생성 화면(`--generate`):** 대화형 터미널에서는 결과 줄 다음에 빈 줄 하나를 두고 생성값을 한 번 보여 줍니다.

`생성값` 다음 줄에는 값만 있으므로 그 줄 전체를 옮깁니다. pass는 같은 키를 다시 만들 때 필요한 **복원 정보**(KDF·반복 횟수·Salt)와 64자 키 지문도 함께 나옵니다.

이 화면이 지나가면 원문은 조회·이력 어디에서도 다시 볼 수 없습니다(보관·재등록: [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)).

```text
추가 키   : member-pass (pass, embedded, 지문 2296463d5f2e...d1008f75)
내보내기  : C:\Users\me\jck-secure\member-pass.backup

유형      : pass
키 ID     : member-pass
생성값    : Passphrase(32자) - 다음 줄 전체가 값
<생성 결과: Passphrase 32자>
복원 정보 : pbkdf2-sha256, 600000회, Salt Qagckq0OzWd/jJzZhgd6PQ==
키 지문   : 2296463d5f2efd392d570d81aa8ce206cc27fd5d9eb4656be36b14d8d1008f75
안내      : 내보낸 백업 파일(복원 정보 포함)에 저장했습니다. 안전하게 보관하세요.
```

key 유형은 `생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값` 다음 줄에 `keygen` 키 파일과 같은 44자 한 줄이 나옵니다.

`--export`가 없으면 마지막 안내가 `값과 복원 정보를 지금 따로 안전하게 보관하세요.`(pass, 두 줄)·`지금 따로 안전하게 보관하세요. 조회·이력에서 다시 볼 수 없습니다.`(key)로 바뀝니다.

스크립트·CI에서 `--export` 없이 `--generate`를 쓰면 생성 전에 `[사유: USAGE] 비대화형 실행에서는 생성값을 화면에 보여 줄 수 없어 --generate에 --export <파일>이 필요합니다.

생성 전에 중단했습니다.`로 끝나고, `--export`가 있으면 값은 화면·로그에 나오지 않고 파일에만 저장됩니다.

**오류·주의:** 재료는 하나만 고릅니다. `--export`는 `--generate`와만, `--location`은 외부 공급원과만 씁니다.

`file`·`env`·`vault`는 `--generate`를 쓸 수 없습니다(재료를 그 위치에 직접 둠). key 유형을 `embedded`로 등록하려면 `--generate`나 `--from-file`이 필요합니다. 이전 버전 JAR(키 목록 미지원)는 거부합니다.

복원 백업의 키 ID가 `--key-id`와 다르거나, 백업으로 만든 키의 지문이 백업의 지문과 다르면(손상·수정) 등록하지 않습니다.

원본(Passphrase 파일·내보낸 키·복원 백업)과 결과 JAR는 비밀 파일입니다([12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관)·[5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)).

<a name="topic-key-registration--a5-키-생성-화면에-한-번-보이는-생성값과---export"></a>
### 키 생성: 화면에 한 번 보이는 생성값과 `--export` (A.5)

대화형 터미널에서 `--generate`로 만든 값은 성공 직후 화면에 **한 번** 나옵니다(`--show` 같은 옵션 없음). `--export`를 함께 주면 파일에도 저장합니다(pass는 복원 백업, key는 keygen과 같은 키 파일). 보관·재등록 방법은 [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)에 있습니다.

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id gen-pass --generate --operator example-admin --reason "pass 키 생성" --yes --out gen.jar
java -jar .\gen.jar config key add --key-id gen-aes --type key --generate --export "$SECURE\gen-aes.key" --operator example-admin --reason "key 키 생성" --yes --out gen2.jar
java -jar .\gen2.jar fingerprint --key-id gen-aes
java -jar .\gen2.jar fingerprint --key-file "$SECURE\gen-aes.key"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id gen-pass --generate --operator example-admin --reason "pass 키 생성" --yes --out gen.jar
java -jar ./gen.jar config key add --key-id gen-aes --type key --generate --export "$SECURE/gen-aes.key" --operator example-admin --reason "key 키 생성" --yes --out gen2.jar
java -jar ./gen2.jar fingerprint --key-id gen-aes
java -jar ./gen2.jar fingerprint --key-file "$SECURE/gen-aes.key"
```

```text
관리자 비밀번호(입력 숨김):
...
추가 키   : gen-pass (pass, embedded, 지문 3b271408bc6c...d7a238b4)

유형      : pass
키 ID     : gen-pass
생성값    : Passphrase(32자) - 다음 줄 전체가 값
<생성 결과: Passphrase 32자>
복원 정보 : pbkdf2-sha256, 600000회, Salt zeCLW3OFXUx1ncPi4GQhnA==
키 지문   : 3b271408bc6cd3820135789002325a6d054676ea06c214626349cea4d7a238b4
안내      : 값과 복원 정보를 지금 따로 안전하게 보관하세요.
            조회·이력에서 다시 볼 수 없습니다.

추가 키   : gen-aes (key, embedded, 지문 1d2e4488eacf...7364224d)
내보내기  : C:\Users\me\jck-secure\gen-aes.key

유형      : key
키 ID     : gen-aes
생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값
<생성 결과: 표준 Base64 44자 = gen-aes.key 파일 내용>
안내      : 내보낸 파일에도 저장했습니다. 그 파일을 안전하게 보관하세요.

키 지문   : 1d2e4488eacfefda5e8538f335f18883a14a778c9419e302c79fb33d7364224d   ← 두 fingerprint가 같음
```

pass 생성값만 적어 두면 같은 키를 되살릴 수 없으므로 `복원 정보`와 `키 지문`도 함께 보관합니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구) (d)). 스크립트·CI(대화형 터미널 아님)에서는 화면 표시가 없으므로 `--export`가 필요하고, 관리자 인증은 `--admin-pass-file`(A.1에서 만든 파일)로 합니다.

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id ci-pass --generate --export "$SECURE\ci-pass.backup" --operator example-admin --reason "CI 키" --yes --out ci.jar --admin-pass-file "$SECURE\admin.pw"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id ci-pass --generate --export "$SECURE/ci-pass.backup" --operator example-admin --reason "CI 키" --yes --out ci.jar --admin-pass-file "$SECURE/admin.pw"
```

```text
추가 키   : ci-pass (pass, embedded, 지문 e5f647e51275...bfc62c4f)
내보내기  : C:\Users\me\jck-secure\ci-pass.backup          ← 생성값은 화면·로그에 나오지 않고 이 파일에만 있음
```

`--export` 없이 실행하면 생성 전에 `[사유: USAGE] 비대화형 실행에서는 생성값을 화면에 보여 줄 수 없어 --generate에 --export <파일>이 필요합니다. 생성 전에 중단했습니다.`로 끝납니다.

내보낸 파일은 이미 있으면 덮어쓰지 않으며, 그 키의 원본이므로 키 파일과 같이 보관합니다.

<a name="topic-key-registration--a6-서버의-passphrase-파일환경변수를-등록지문-고정"></a>
### 서버의 Passphrase 파일·환경변수를 등록(지문 고정) (A.6)

Passphrase 파일은 UTF-8로 만듭니다(앞의 BOM 하나와 끝 줄바꿈 하나는 떼고 읽으므로 `Set-Content -Encoding UTF8`로 만든 파일도 됨). 아래는 BOM·줄바꿈 없이 만드는 예입니다.

실제 값은 명령 줄에 적지 말고 [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구) (b)처럼 붙여 넣어 저장합니다(셸 기록에 남지 않게).

```powershell
[IO.File]::WriteAllText("$SECURE\app.pass", 'example-file-passphrase', [Text.UTF8Encoding]::new($false))
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id file-pass --source file --location "$SECURE\app.pass" --operator example-admin --reason "파일 pass 키 등록" --yes --out file-pass.jar
java -jar .\file-pass.jar encrypt --key-id file-pass
$env:APP_PASS = 'example-env-passphrase'
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id env-pass --source env --location APP_PASS --operator example-admin --reason "환경변수 pass 키 등록" --yes --out env-pass.jar
java -jar .\env-pass.jar encrypt --key-id env-pass
```

```bash
printf '%s' 'example-file-passphrase' > "$SECURE/app.pass"; chmod 600 "$SECURE/app.pass"
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id file-pass --source file --location "$SECURE/app.pass" --operator example-admin --reason "파일 pass 키 등록" --yes --out file-pass.jar
java -jar ./file-pass.jar encrypt --key-id file-pass
export APP_PASS='example-env-passphrase'
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id env-pass --source env --location APP_PASS --operator example-admin --reason "환경변수 pass 키 등록" --yes --out env-pass.jar
java -jar ./env-pass.jar encrypt --key-id env-pass
```

```text
관리자 비밀번호(입력 숨김):
생성 JAR  : C:\work\file-pass.jar
변경 항목 : crypto.keys.file-pass.type ((없음) -> pass)
            ...
            crypto.keys.file-pass.fingerprint ((없음)
              -> deeed16a03e39f7d9ec5208d9dd14a5afc12506fcae86bf8efb1d52623e53dd0)
추가 키   : file-pass (pass, file, 지문 deeed16a03e3...23e53dd0)
ENC[v1:file-pass:...]
```

등록할 때 한 번 읽은 값의 지문을 고정하므로, 나중에 파일·환경변수의 값이 바뀌면 다른 키로 동작하지 않고 실패합니다(값을 바꿀 때는 [A.8](#topic-key-rotation--a8-키-회전-새-키-추가--rekey--이전-키-제거)처럼 새 키 ID로 회전).

```text
[java-crypto-kit] [사유: KEY_SOURCE] 암호화 키를 읽지 못했거나 키 형식·지문이 올바르지 않습니다. 키 file-pass의 공급원에서 받은 키가 등록할 때와 다릅니다(지문 불일치). ... 조치: ...
```

환경변수 키는 Tomcat을 실행하는 계정·서비스에 같은 변수가 있어야 합니다(Linux systemd `Environment=`, Windows 서비스 환경).

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-defaults"></a>

## 기본 키 선택 및 제거

<a name="topic-key-defaults--기본-키-변경과-키-제거"></a>
<a name="topic-key-defaults--219-config-key-use--기본-키-변경"></a>
### `config key use` — 기본 키 변경 (2.19)

**사용 상황:** 유형을 정하지 않은 새 암호화(또는 `--type`을 준 암호화)가 쓰는 **유형별 기본 키**를 바꿀 때. 다른 유형의 기본 키와 기존 암호문의 복호화는 그대로입니다.

```text
java -jar <입력 JAR> config key use --key-id <키 ID> --operator <수정자> [--reason <사유>]
    [--type pass|key] [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--key-id <ID>` | 예 | 기본 키로 정할 등록된 키 ID(유형 자동) |
| `--type pass\|key` | 아니요 | 기대하는 유형. 키의 유형과 다르면 실패(`CONFIGURATION`) |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 이력에 남길 변경 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 바꾸기 전에 오류. `--yes`로 생략되지 않음 |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로 |
| `--replace` | 아니요 | 백업 후 원본 교체 |
| `--yes` | 아니요 | `CHANGE` 확인 생략 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

pass 키는 `crypto.key.active.pass`, key 키는 `crypto.key.active.key`를 바꿉니다. key 유형에서 `crypto.key.*` AES 키를 고르면 `crypto.key.active.key`를 **비워** 둡니다(빈 값 = `crypto.key.*`를 따름, 이후 `config embed-key`로 AES 키를 바꾸면 기본도 따라감). 이미 기본 키인 키를 다시 고르면 바꿀 내용이 없어 실패합니다.

유형을 정하지 않은 새 암호화의 기본 **유형**은 `config set crypto.key.type=pass|key`로 바꿉니다.

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key use --key-id app-pass2 --operator example-admin --reason "새 pass 키로 전환"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config key use --key-id key01 --type key --operator example-admin --reason "key 기본 키 전환" --yes
```

**결과**

```text
관리자 비밀번호(입력 숨김):
기본 키를 바꿉니다(새 암호화에 쓸 키, 기존 암호문은 그대로):
  결과: 새 JAR java-crypto-kit-0.1.0-configured-3.jar (원본은 그대로)
  사유: 새 pass 키로 전환
  crypto.key.active.pass (app-pass -> app-pass2)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
생성 JAR  : C:\work\java-crypto-kit-0.1.0-configured-3.jar
변경 항목 : crypto.key.active.pass (app-pass -> app-pass2)
기본 키   : pass=app-pass2
```

<a name="topic-key-defaults--220-config-key-remove--키-제거"></a>
### `config key remove` — 키 제거 (2.20)

**사용 상황:** 더 쓰지 않는 키(회전이 끝난 이전 키, 쓰지 않을 공개 기본 키 등)를 키 목록에서 뺄 때. **제거한 키로 만든 암호문은 결과 JAR로 복호화할 수 없으므로** 먼저 `rekey`로 모두 옮깁니다.

```text
java -jar <입력 JAR> config key remove --key-id <키 ID> --operator <수정자> [--reason <사유>]
    [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--key-id <ID>` | 예 | 제거할 키 ID |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 이력에 남길 변경 사유(한 줄, 200자 이하, 비밀값 금지). 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 바꾸기 전에 오류. `--yes`로 생략되지 않음 |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로 |
| `--replace` | 아니요 | 백업 후 원본 교체 |
| `--yes` | 아니요 | `CHANGE` 확인 생략 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

그 유형의 **기본 키**와 `crypto.key.*` AES 키는 제거할 수 없습니다(기본 키는 먼저 `config key use`로 바꾸고, `crypto.key.*` 키는 `config embed-key`로 교체). 공개 기본 키도 자동으로 지우지 않으며, 이 명령으로 직접 제거할 때만 빠집니다.

제거한 키 ID는 다른 키에 다시 쓸 수 없고, 같은 키를 되살릴 때만(키 파일·복원 백업·`--from-jar`로, 이력의 64자 전체 지문과 같을 때) 다시 등록할 수 있습니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)). 이력에는 제거한 항목과 키 요약 줄이 남습니다.

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-3.jar config key remove --key-id app-pass --reason "회전 완료" --operator example-admin
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config key remove --key-id default --operator example-admin --reason "공개 AES 키 정리" --yes
```

**결과**

```text
관리자 비밀번호(입력 숨김):
키를 제거합니다(결과 JAR는 이 키의 암호문을 복호화하지 못함):
  결과: 새 JAR java-crypto-kit-0.1.0-configured-4.jar (원본은 그대로)
  사유: 회전 완료
  crypto.keys.app-pass.type (pass -> (없음))
  ...
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
생성 JAR  : C:\work\java-crypto-kit-0.1.0-configured-4.jar
변경 항목 : crypto.keys.app-pass.type (pass -> (없음))
            ...
제거 키   : app-pass
```

<a name="topic-key-defaults--a7-기본-키기본-유형-바꾸기"></a>
### 기본 키·기본 유형 바꾸기 (A.7)

`--reason`을 빼면 실행 전에 사유를 묻습니다(대화형 터미널).

```powershell
java -jar .\gen2.jar config key use --key-id gen-aes --operator example-admin --out use.jar
java -jar .\use.jar info
```

```bash
java -jar ./gen2.jar config key use --key-id gen-aes --operator example-admin --out use.jar
java -jar ./use.jar info
```

```text
관리자 비밀번호(입력 숨김):                    ← 관리자 비밀번호(사유보다 먼저)
사유(비밀값 제외): key 기본 키 전환             ← 사유 입력(화면에 보임, 비밀값을 적지 않음)
기본 키를 바꿉니다(새 암호화에 쓸 키, 기존 암호문은 그대로):
  결과: 새 JAR use.jar (원본은 그대로)
  사유: key 기본 키 전환
  crypto.key.active.key ((비어 있음) -> gen-aes)
계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): CHANGE
생성 JAR  : C:\work\use.jar
변경 항목 : crypto.key.active.key ((비어 있음) -> gen-aes)
기본 키   : key=gen-aes

key 기본  : gen-aes [JAR 기본값]             ← info
```

다른 유형의 기본 키와 기존 암호문의 복호화는 그대로입니다.

기본 유형은 `config set crypto.key.type=pass|key`로 바꿉니다([A.4](#topic-key-selection--a4-운영-aes-키key를-jar에-넣기)). 사유 질문에서 아무것도 입력하지 않고 Enter를 누르면 `사유를 입력하지 않아 중단했습니다.

아무것도 바뀌지 않았습니다.`로 끝납니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-export"></a>

## 키 관리정보 조회 및 백업

<a name="topic-key-export--키-조회-및-내보내기"></a>
<a name="topic-key-export--224-config-key-show--키-관리정보원문-확인"></a>
### `config key show` — 키 관리정보·원문 확인 (2.24)

**사용 상황:** 등록된 키의 정보 조회, 원문 확인, 백업 및 복구.

| 조회 방식 | 인증·확인 절차 |
|---|---|
| 관리정보 조회 | 관리자 인증 후 키 ID·유형·공급원·지문·KDF·Salt 확인 |
| `--show` | 관리자 인증 → 노출 경고 → `SHOW` 입력 → 보존된 원문 표시 |
| `--export` | 관리자 인증 → 파일 내보내기. `SHOW` 불필요, 비대화형 실행 가능 |

인증 전에 키 등록 여부를 알리지 않습니다. JAR를 변경하지 않으므로 사유 입력과 History 기록은 없습니다.


```text
java -jar <JAR> config key show --key-id <키 ID> [--show] [--export <파일>] [--jar <조회할 JAR>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--key-id <ID>` | 예 | 조회할 등록된 키 ID |
| `--show` | 아니요 | 원문을 화면에 표시. **대화형 전용**: 노출 경고 뒤 `SHOW`를 정확히 입력해야 하고(소문자·다른 입력·빈 입력은 취소), 원문은 대화형 터미널에만 쓰며 표준 출력·표준 오류·로그로 내보내지 않음 |
| `--export <파일>` | 아니요 | 원문을 **새 파일**에 저장(`SHOW` 확인 없음, 덮어쓰지 않음, POSIX 600, 경로는 인증 전에 확인). key는 `keygen`과 같은 표준 Base64 한 줄, pass는 복원 백업(키 ID·KDF·반복 횟수·Salt·지문·Passphrase). 비대화형에서도 `--admin-pass-file`로 인증해 쓸 수 있음 |
| `--jar <경로>` | 아니요 | 다른 JAR의 키를 볼 때(그 JAR의 관리자 비밀번호도 확인). 생략하면 실행 중인 JAR |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**원문이 있는 경우:** key 유형은 JAR 내장 키와 외부 공급원(file·env·vault·aws-kms)의 AES 키를 그대로 읽어 표준 Base64로 보여 줍니다. pass 유형은 **Passphrase 원문이 공급원(file·env·vault)에 실제로 보관된 경우에만** 보여 줍니다.

JAR 내장·aws-kms pass 키는 PBKDF2 파생 키만 보관하므로 원문을 되돌릴 수 없으며(파생 키에서 원문을 복원하는 방법은 없음), 이때는 `원문 : 없음 - PBKDF2 파생 키만 있어 원문 복원 불가`로 표시하고 `--show`·`--export`는 아무것도 보이거나 만들지 않고 실패합니다.

그런 키는 생성할 때 만든 복원 백업(`--from-file`)이나 원본 JAR(`--from-jar`)로 옮깁니다([5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)). 삭제된 키는 등록되어 있지 않으므로 조회할 수 없습니다.

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key show --key-id key01
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key show --key-id key01 --show
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key show --key-id key01 --export "$HOME\jck-secure\key01.export"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config key show --key-id key01
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config key show --key-id key01 --export ~/jck-secure/key01.export --admin-pass-file "$ADMIN_PW_FILE"
```

**결과(관리정보):**

```text
관리자 비밀번호(입력 숨김):
키 ID     : key01
유형      : key
공급원    : embedded
상태      : 사용자 지정, 기본 key 키, crypto.key.*
키 지문   : ab12cd34...(64자 전체)
원문      : JAR 내장 AES 키(--show 화면 표시, --export 파일)
```

pass 키는 `KDF       : pbkdf2-sha256, 600,000회`, `Salt      : <Base64>`, `Salt 해시 : <64자>`와 원문 상태(`공급원에 보관된 Passphrase 원문` 또는 `없음 - PBKDF2 파생 키만 있어 원문 복원 불가`)가 붙습니다.

**결과(`--show`):** 관리정보 뒤에 경고와 확인을 받고, `SHOW`면 원문을 보여 줍니다. 그 밖의 입력이면 `취소했습니다. 원문을 표시하거나 내보내지 않았습니다.`로 끝납니다(종료 코드 0).

```text
[비밀값 표시 경고]
키 원문을 화면에 표시합니다. 화면 공유·녹화·터미널 기록·주변 사람에게
노출될 수 있습니다. 원문은 이력·로그에 남지 않으니 확인 후 화면을 지우세요.
계속하려면 SHOW를 입력하세요(그 외 입력은 취소): SHOW

유형      : key
키 ID     : key01
원문      : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값
<표준 Base64 44자 = keygen 키 파일 한 줄>
키 지문   : ab12cd34...(64자 전체)
안내      : 필요한 곳에 보관한 뒤 화면을 지우세요. 이력·로그에는 남지 않습니다.
이력      : 저장 안 함(JAR를 바꾸지 않는 조회)
```

**결과(`--export`):** `내보내기  : <파일 경로>`, `형식      : key 파일(표준 Base64 한 줄, --from-file로 재등록)` 또는 `pass 복원 백업(...)`, `이력      : 저장 안 함(JAR를 바꾸지 않는 조회)`을 출력하며 원문은 화면에 쓰지 않습니다.

내보낸 파일로 다른 JAR(원본 JAR가 없어도)에 같은 키 ID로 다시 등록하면 같은 키·같은 지문이 되어 예전 암호문이 복호화됩니다(`config key add --key-id <같은 ID> --from-file <파일>`, key는 `--type key`).

**오류·주의:** 관리자 인증 실패·취소, `SHOW` 불일치에서는 원문을 표시하거나 파일을 만들지 않습니다.

관리자 검증값·변경 이력이 손상된 JAR(실행 중인 JAR나 `--jar` 대상)는 인증 전에 `[사유: INTEGRITY]`로 거부하며 관리정보·원문을 다루지 않습니다([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)). 비대화형에서 `--show`는 거부합니다(`--export`를 씀). 외부 공급원의 값이 등록할 때와 다르면(고정 지문 불일치) 원문을 보여 주지 않습니다.

내보낸 파일·화면의 원문은 키 그 자체이므로 [12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관)대로 보관하고, 원문을 이력·로그·티켓에 적지 않습니다.

이 명령은 CLI 사용 통제일 뿐 JAR 소지자의 키 추출을 막는 기능이 아닙니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)).

<a name="topic-key-export--a17-키-원문-확인내보내기와-복구"></a>
### 키 원문 확인·내보내기와 복구 (A.17)

관리자 인증 뒤 키 하나의 관리정보를 보고, 운영에 필요하면 원문을 확인·내보냅니다. 화면 표시는 노출 경고 뒤 `SHOW`를 정확히 입력해야 합니다(대화형 전용). 내보낸 key 파일로 원본 JAR 없이 새 JAR에 같은 키 ID로 등록하면 예전 암호문이 복호화됩니다.

```powershell
java -jar .\app-aes.jar config key show --key-id key01
java -jar .\app-aes.jar config key show --key-id key01 --show
java -jar .\app-aes.jar config key show --key-id key01 --export "$SECURE\key01.export"
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id key01 --type key --from-file "$SECURE\key01.export" --operator example-admin --reason "내보낸 키로 복구" --yes --out restored.jar
java -jar .\restored.jar verify --value 'ENC[v1:key01:...]'
java -jar .\file-pass.jar config key show --key-id file-pass --show
java -jar .\app-pass.jar config key show --key-id app-pass --show
```

```bash
java -jar ./app-aes.jar config key show --key-id key01
java -jar ./app-aes.jar config key show --key-id key01 --show
java -jar ./app-aes.jar config key show --key-id key01 --export "$SECURE/key01.export"
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id key01 --type key --from-file "$SECURE/key01.export" --operator example-admin --reason "내보낸 키로 복구" --yes --out restored.jar
java -jar ./restored.jar verify --value 'ENC[v1:key01:...]'
java -jar ./file-pass.jar config key show --key-id file-pass --show
java -jar ./app-pass.jar config key show --key-id app-pass --show
```

```text
관리자 비밀번호(입력 숨김):
키 ID     : key01
유형      : key
공급원    : embedded
상태      : 사용자 지정, 기본 key 키, crypto.key.*
키 지문   : 5186b17515455bfcbac7e0f19799dc0ea985e30845d29ab860ec35dbfe8a3a18
원문      : JAR 내장 AES 키(--show 화면 표시, --export 파일)

[비밀값 표시 경고]                              ← --show: 관리정보 뒤 경고와 확인
키 원문을 화면에 표시합니다. 화면 공유·녹화·터미널 기록·주변 사람에게
노출될 수 있습니다. 원문은 이력·로그에 남지 않으니 확인 후 화면을 지우세요.
계속하려면 SHOW를 입력하세요(그 외 입력은 취소): SHOW
...
원문      : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값
<example.key 파일과 같은 표준 Base64 44자>
키 지문   : 5186b17515455bfcbac7e0f19799dc0ea985e30845d29ab860ec35dbfe8a3a18

내보내기  : C:\Users\me\jck-secure\key01.export    ← --export(원문은 화면에 없음)
형식      : key 파일(표준 Base64 한 줄, --from-file로 재등록)
이력      : 저장 안 함(JAR를 바꾸지 않는 조회)

OK                                              ← restored.jar로 예전 암호문 복호화

원문      : Passphrase(23자) - 다음 줄 전체가 값  ← file-pass: 파일에 보관된 원문
example-file-passphrase

[java-crypto-kit] [사유: KEY_SOURCE] 키 app-pass은(는) 공급원 embedded에 PBKDF2 파생 키만 있어 Passphrase 원문을 복원할 수 없습니다(파생 키에서 원문을 되돌릴 수 없음). 조치: ...
```

`'ENC[v1:key01:...]'`는 [A.4](#topic-key-selection--a4-운영-aes-키key를-jar에-넣기)에서 key01로 만든 암호문으로 바꿉니다. `SHOW` 외의 입력은 `취소했습니다. 원문을 표시하거나 내보내지 않았습니다.`로 끝납니다.

JAR 내장 pass 키(`app-pass`)는 파생 키만 있으므로 생성할 때 만든 복원 백업이나 원본 JAR(`--from-jar`)로 옮깁니다([A.10](#topic-key-recovery--a10-생성값으로-재등록예전-암호문-복구)). 내보낸 파일은 키 그 자체이므로 키 파일처럼 보관하고 필요가 끝나면 지웁니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-recovery"></a>

## 키 복구 및 다른 JAR로 이전

<a name="topic-key-recovery--키-백업-및-복구"></a>
<a name="topic-key-recovery--56-자동-생성한-passkey-보관재등록복구"></a>
### 자동 생성한 pass/key 보관·재등록·복구 (5.6)

`keygen`과 `config key add --generate`가 만든 값은 대화형 터미널에 **한 번만** 나오고, 그 뒤에는 일반 조회·이력 어디에서도 다시 볼 수 없습니다(키 JAR가 남아 있으면 관리자 인증 뒤 [`config key show`](#topic-key-export--224-config-key-show--키-관리정보원문-확인)의 `--show`(`SHOW` 확인)·`--export`로 key 원문과 file·env·vault에 보관된 Passphrase를 다시 확인·내보낼 수 있으나, JAR 내장 pass 키의 Passphrase는 파생 키만 있어 되돌릴 수 없음). 이 절은 그 값을 보관하는 방법과, 나중에 같은 값을 **새 키로 다시 등록하는 것**과 **예전 암호문까지 다시 복호화하는 것**의 차이를 설명합니다.

<a name="topic-key-recovery--먼저-구분할-두-가지"></a>
#### 먼저 구분할 두 가지


| 목적 | key(AES 키) | pass(Passphrase) |
|---|---|---|
| 같은 값을 **새 키로** 다시 등록 | 표준 Base64 한 줄을 파일로 저장해 `--from-file` | Passphrase 한 줄 파일로 `--from-file`: **새 Salt가 만들어져 다른 키**(지문이 다름) |
| **예전 암호문**(`ENC[v1:<키 ID>:...]`·JCKF 파일)까지 복호화 | **원래 키 ID** + 같은 32바이트 키(같은 Base64) | **원래 키 ID** + 같은 Passphrase + 같은 Salt·KDF·반복 횟수(복원 백업, 또는 원본 JAR에서 `--from-jar`) |
| 확인 | 64자 지문이 같고 예전 암호문이 실제로 복호화됨 | 64자 지문이 같고 예전 암호문이 실제로 복호화됨 |

동일 키 ID를 재사용할 때는 기존 이력과 실제 키의 동일성 조건을 만족해야 합니다. 다른 키로 같은 ID를 덮어쓰는 방식으로 복구하지 않습니다. `config key show`는 조회할 `--key-id`가 필수이며, 사유가 필요한 명령에서 `--reason`을 생략하면 대화형으로 질문합니다. 비대화형에서는 사유를 명시합니다.

키 ID가 다르면 예전 암호문은 그 키를 찾지 못해 `KEY_ID_MISMATCH`, 키 ID는 같지만 키가 다르면(예: 같은 Passphrase를 새 Salt로 등록) `INTEGRITY`로 실패합니다. 다른 키로 바꿔 시도하거나 공개 키로 대신하지 않습니다.

<a name="topic-key-recovery--값과-파일의-형식"></a>
#### 값과 파일의 형식


| 무엇 | 형식 | 다시 등록하는 방법 |
|---|---|---|
| key 생성값(화면·`keygen` 키 파일·key `--export`) | 32바이트 키의 **표준 Base64 한 줄**(44자, `=`로 끝남). 화면의 값과 키 파일 내용이 같음 | `config key add --type key --from-file`, `config embed-key --from-file` |
| pass 생성값(화면) | 32자 Passphrase(영문·숫자). **이것만으로는 같은 키를 만들 수 없음**(Salt 등 필요) | 한 줄 파일이면 새 키, 복원 정보와 함께 백업 형식으로 두면 같은 키 |
| pass 복원 백업(`--export`) | 아래 형식(머리줄, 키 ID·KDF·반복 횟수·Salt·지문·Passphrase), UTF-8 | `config key add --key-id <백업의 키 ID> --from-file <백업>` |
| 키가 아닌 값 | 64자 키 지문, 짧은 지문, JAR 안의 `obf1:` 값([12.7절](../reference/security.md#127-jar-내장값의-경량-난독화obf1)), `ENC[...]` 암호문, KMS 데이터 키 파일(KMS가 암호화한 키) | 이 값으로는 키를 등록할 수 없음 |

pass 복원 백업의 모양(값은 예시):

```text
# java-crypto-kit pass-key-backup v1
# SECRET file (contains the passphrase). 비밀 파일(Passphrase 포함)
# Restore / 복원: config key add --key-id member-pass --from-file <this file>
key-id=member-pass
kdf=pbkdf2-sha256
kdf.iterations=600000
salt=Qagckq0OzWd/jJzZhgd6PQ==
fingerprint=2296463d5f2efd392d570d81aa8ce206cc27fd5d9eb4656be36b14d8d1008f75
passphrase=<생성 결과: Passphrase>
```

첫 줄(머리줄)이 정확히 같아야 백업으로 읽습니다. 그 밖의 `#` 줄과 빈 줄은 건너뛰고, 여섯 항목은 각각 한 번씩 있어야 하며 값은 `=` 뒤 그대로 씁니다(Passphrase의 앞뒤 공백도 값). 파일 앞의 UTF-8 BOM 하나와 줄 끝 CR은 허용합니다.

등록할 때 이 Passphrase·Salt·반복 횟수로 키를 다시 만들어 `fingerprint`와 같은지 확인하므로, 값이 하나라도 틀리면 등록하지 않습니다.

**따라 하기:** 아래 예는 한 흐름으로 이어지며 Windows PowerShell 5.1(JDK 8)과 Linux bash(JDK 21)에서 실제로 실행해 확인했습니다.

관리자 비밀번호를 설정한 JAR(`java-crypto-kit-0.1.0-configured.jar`, 키는 공개 JAR와 같음)와 시험용 `report.csv`가 현재 폴더에, 키를 둘 `$SECURE` 폴더([A.1](cli.md#topic-admin--a1-준비-관리자-비밀번호와-보호된-폴더))가 있다고 가정합니다.

생성값·지문·Salt·암호문은 실행할 때마다 다릅니다. 키를 등록하는 `config key add`와 `file decrypt`는 실행할 때마다 `관리자 비밀번호(입력 숨김):`를 먼저 묻습니다(아래 결과 화면에서는 그 줄을 생략).

준비 — keygen 키 파일로 등록한 key 키, 백업과 함께 생성한 pass 키, 화면에만 나온 key 키와 각각의 암호문을 만듭니다(`CHANGE` 입력).

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar keygen --out "$SECURE\account.key" --reason "account 키 준비"
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id account-key --type key --from-file "$SECURE\account.key" --operator example-admin --reason "account 키 등록" --yes --out member.jar
java -jar .\member.jar config key add --key-id member-pass --generate --export "$SECURE\member-pass.backup" --operator example-admin --reason "member pass 생성" --out member2.jar
java -jar .\member2.jar config key add --key-id member-key --type key --generate --operator example-admin --reason "member key 생성" --out member3.jar
java -jar .\member3.jar encrypt --key-id member-pass
java -jar .\member3.jar file encrypt --in .\report.csv --key-id member-pass --out .\report.jck
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar keygen --out "$SECURE/account.key" --reason "account 키 준비"
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id account-key --type key --from-file "$SECURE/account.key" --operator example-admin --reason "account 키 등록" --yes --out member.jar
java -jar ./member.jar config key add --key-id member-pass --generate --export "$SECURE/member-pass.backup" --operator example-admin --reason "member pass 생성" --out member2.jar
java -jar ./member2.jar config key add --key-id member-key --type key --generate --operator example-admin --reason "member key 생성" --out member3.jar
java -jar ./member3.jar encrypt --key-id member-pass
java -jar ./member3.jar file encrypt --in ./report.csv --key-id member-pass --out ./report.jck
```

같은 방법으로 `encrypt --key-id account-key`·`encrypt --key-id member-key`의 암호문도 만들어 둡니다. 아래 `ENC[v1:...:...]`는 이때 만든 암호문 한 줄 전체로 바꿉니다.

<a name="topic-key-recovery--a-keygen-키-파일로-다시-등록"></a>
#### (a) keygen 키 파일로 다시 등록

키 파일이 곧 원문입니다. 새 JAR에 **원래 키 ID**로 등록하면 예전 암호문이 복호화됩니다.


```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id account-key --type key --from-file "$SECURE\account.key" --operator example-admin --reason "account 키 재등록" --yes --out new-a.jar
java -jar .\new-a.jar verify --value 'ENC[v1:account-key:...]'
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id account-key --type key --from-file "$SECURE/account.key" --operator example-admin --reason "account 키 재등록" --yes --out new-a.jar
java -jar ./new-a.jar verify --value 'ENC[v1:account-key:...]'
```

```text
추가 키   : account-key (key, embedded, 지문 0b09f0535df2...e352029c)
OK
```

`crypto.key.*` 자리의 AES 키(예: `key01`)였다면 `config embed-key --from-file <키 파일> --key-id <원래 키 ID> --reason <사유>`로 같은 자리에 다시 넣을 수도 있습니다.

<a name="topic-key-recovery--b-화면의-base64를-파일로-저장해-다시-등록"></a>
#### (b) 화면의 Base64를 파일로 저장해 다시 등록

`--export` 없이 생성한 key 값은 화면이 유일한 사본입니다. 첫 명령을 실행한 뒤 화면의 `생성값` 다음 줄 전체를 붙여 넣고 Enter를 누르면 `keygen` 키 파일과 같은 파일이 됩니다.

값을 명령 줄에 적지 않으므로 셸 기록(PowerShell PSReadLine 기록, bash `history`)에 남지 않습니다.


```powershell
Read-Host "생성값(붙여 넣기)" | Set-Content -Path "$SECURE\member-key.key" -Encoding UTF8
java -jar .\member3.jar fingerprint --key-id member-key
java -jar .\member3.jar fingerprint --key-file "$SECURE\member-key.key"
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-key --type key --from-file "$SECURE\member-key.key" --operator example-admin --reason "member key 재등록" --yes --out new-b.jar
java -jar .\new-b.jar verify --value 'ENC[v1:member-key:...]'
```

```bash
IFS= read -r -p '생성값(붙여 넣기): ' v && (umask 077 && printf '%s\n' "$v" > "$SECURE/member-key.key"); unset v
java -jar ./member3.jar fingerprint --key-id member-key
java -jar ./member3.jar fingerprint --key-file "$SECURE/member-key.key"
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-key --type key --from-file "$SECURE/member-key.key" --operator example-admin --reason "member key 재등록" --yes --out new-b.jar
java -jar ./new-b.jar verify --value 'ENC[v1:member-key:...]'
```

```text
생성값(붙여 넣기): <생성 결과를 붙여 넣음>
키 지문   : afbf5bc43e6d1ede0a00c45cf36b5b8feeb09c006ee1f9c411395644ea484f0c   ← --key-id(JAR의 키)
키 지문   : afbf5bc43e6d1ede0a00c45cf36b5b8feeb09c006ee1f9c411395644ea484f0c   ← --key-file(저장한 파일, 같아야 함)
추가 키   : member-key (key, embedded, 지문 afbf5bc43e6d...ea484f0c)
OK
```

Windows PowerShell 5.1의 `Set-Content -Encoding UTF8`은 파일 앞에 BOM을 붙이고 줄 끝을 CRLF로 쓰지만 그대로 같은 키로 읽습니다(PowerShell 7은 BOM 없음). Windows PowerShell 5.1의 `Out-File`과 `>`는 UTF-16으로 저장하므로 키 파일로 읽지 못하고 `KEY_SOURCE`(표준 Base64 형식 아님)로 거부됩니다.

이때는 값을 고치지 말고 위 방법으로 다시 저장합니다.

<a name="topic-key-recovery--c-passphrase를-한-줄-파일로-저장해-다시-등록새-키"></a>
#### (c) Passphrase를 한 줄 파일로 저장해 다시 등록(새 키)

pass 생성값만 저장해서는 같은 키를 되살릴 수 없습니다. 한 줄 파일로 등록하면 **새 Salt**가 만들어져 다른 키가 되므로 새 키 ID로 새 암호화에 씁니다.


```powershell
Read-Host "생성값(붙여 넣기)" | Set-Content -Path "$SECURE\member-pass.txt" -Encoding UTF8
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass2 --from-file "$SECURE\member-pass.txt" --operator example-admin --reason "같은 문구로 새 키" --yes --out new-c.jar
```

```bash
IFS= read -r -p '생성값(붙여 넣기): ' v && (umask 077 && printf '%s\n' "$v" > "$SECURE/member-pass.txt"); unset v
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass2 --from-file "$SECURE/member-pass.txt" --operator example-admin --reason "같은 문구로 새 키" --yes --out new-c.jar
```

```text
추가 키   : member-pass2 (pass, embedded, 지문 48421c17a3da...e473047d)
Salt      : 새로 만듦(같은 Passphrase라도 이전에 등록한 키와 다른 키)
```

반례: 같은 한 줄 파일을 원래 키 ID(`member-pass`)로 **이력이 없는 새 JAR**에 등록하면 등록은 되지만 Salt가 달라 다른 키이므로 예전 암호문이 `INTEGRITY`로 실패합니다(이력에 그 키 ID가 있는 JAR에서는 이력의 키와 달라 등록 자체를 거부).

```text
추가 키   : member-pass (pass, embedded, 지문 78960ae12c59...d9ab1e09)     ← 원래 지문 2296463d5f2e...d1008f75와 다름
Salt      : 새로 만듦(같은 Passphrase라도 이전에 등록한 키와 다른 키)
[java-crypto-kit] [사유: INTEGRITY] 암호문 무결성 검증에 실패했습니다(다른 키이거나 암호문이 변조·손상됨). 조치: ...
```

pass 한 줄 파일은 줄 끝을 뺀 모든 글자를 Passphrase로 읽습니다. 라벨(`생성값    :`)·따옴표·공백이 섞이면 다른 Passphrase가 되므로 화면의 값 줄만 붙여 넣습니다(key 파일은 이런 값을 형식 오류로 거부).

<a name="topic-key-recovery--d-예전-암호문-복구에-필요한-pass-복원-정보"></a>
#### (d) 예전 암호문 복구에 필요한 pass 복원 정보

같은 pass 키를 다시 만들려면 **Passphrase + 원래 키 ID + Salt + KDF(`pbkdf2-sha256`)·반복 횟수**가 모두 필요하고(정규화 규칙은 NFC로 고정), 다시 만든 키의 64자 지문이 원래와 같아야 합니다. 이 값은 다음에서 얻습니다.


| 값 | 생성 화면 | `--export` 백업 | 원본 JAR(남아 있을 때) |
|---|---|---|---|
| Passphrase | `생성값` 다음 줄 | `passphrase=` | **없음**(JAR에는 파생 키만 있음) |
| 키 ID | `키 ID` | `key-id=` | `config show`의 키 목록 |
| KDF·반복 횟수·Salt | `복원 정보` | `kdf=`·`kdf.iterations=`·`salt=` | `config show`의 `crypto.keys.<ID>.kdf`·`.kdf.iterations`·`.salt` |
| 64자 지문 | `키 지문` | `fingerprint=` | `fingerprint --key-id <ID>` |

`--export` 없이 생성했다면 화면의 값으로 같은 형식의 백업 파일을 만들어 둡니다. `<...>` 두 곳을 화면의 값으로 바꿔 실행한 뒤 Passphrase를 붙여 넣습니다.

```powershell
$p = Read-Host "Passphrase(붙여 넣기)"; Set-Content -Path "$SECURE\member-pass-manual.backup" -Encoding UTF8 -Value "# java-crypto-kit pass-key-backup v1", "key-id=member-pass", "kdf=pbkdf2-sha256", "kdf.iterations=600000", "salt=<복원 정보의 Salt>", "fingerprint=<키 지문 64자>", "passphrase=$p"; Remove-Variable p
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE\member-pass-manual.backup" --operator example-admin --reason "화면 정보로 복구" --yes --out new-d.jar
```

```bash
IFS= read -r -p 'Passphrase(붙여 넣기): ' p && (umask 077 && printf '%s\n' '# java-crypto-kit pass-key-backup v1' 'key-id=member-pass' 'kdf=pbkdf2-sha256' 'kdf.iterations=600000' 'salt=<복원 정보의 Salt>' 'fingerprint=<키 지문 64자>' "passphrase=$p" > "$SECURE/member-pass-manual.backup"); unset p
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE/member-pass-manual.backup" --operator example-admin --reason "화면 정보로 복구" --yes --out new-d.jar
```

```text
추가 키   : member-pass (pass, embedded, 지문 2296463d5f2e...d1008f75)
복원      : 백업과 같은 키(키 ID·KDF·반복 횟수·Salt·지문 일치)
```

Salt 등을 잘못 옮기면 `[사유: KEY_SOURCE] ... 백업의 Passphrase·Salt·반복 횟수로 만든 키가 백업의 키 지문과 다릅니다(백업 손상 또는 수정). JAR는 바뀌지 않았습니다.`로 등록하지 않습니다.

<a name="topic-key-recovery--e---export-백업으로-새-jar에-복원"></a>
#### (e) `--export` 백업으로 새 JAR에 복원

원본 JAR가 없어도 됩니다. `--key-id`는 백업의 키 ID와 같아야 합니다(다르면 예전 암호문을 찾지 못하므로 거부).


```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE\member-pass.backup" --operator example-admin --reason "백업에서 복구" --yes --out new-e.jar
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE/member-pass.backup" --operator example-admin --reason "백업에서 복구" --yes --out new-e.jar
```

```text
변경 항목 : crypto.keys.member-pass.type ((없음) -> pass)
            ...
            crypto.keys.member-pass.salt ((없음) -> Qagckq0OzWd/jJzZhgd6PQ==)
추가 키   : member-pass (pass, embedded, 지문 2296463d5f2e...d1008f75)
복원      : 백업과 같은 키(키 ID·KDF·반복 횟수·Salt·지문 일치)
```

<a name="topic-key-recovery--f-원본-jar에서-그대로-옮기기--from-jar"></a>
#### (f) 원본 JAR에서 그대로 옮기기(`--from-jar`)

원본 JAR가 남아 있으면 Passphrase 없이 키 정의(파생 키·Salt·KDF·키 ID)를 복사합니다. Passphrase 원문을 되살리는 기능은 아닙니다.


```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-jar .\member3.jar --operator example-admin --reason "원본 JAR에서 이관" --yes --out new-f.jar
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-jar ./member3.jar --operator example-admin --reason "원본 JAR에서 이관" --yes --out new-f.jar
```

```text
추가 키   : member-pass (pass, embedded, 지문 2296463d5f2e...d1008f75)
```

<a name="topic-key-recovery--g-같은-키인지-지문으로-확인"></a>
#### (g) 같은 키인지 지문으로 확인

64자 전체가 같으면 같은 키입니다(짧은 지문만으로 판단하지 않음). key 파일은 `fingerprint --key-file <파일>`로 비교합니다((b)).


```powershell
java -jar .\member3.jar fingerprint --key-id member-pass
java -jar .\new-e.jar fingerprint --key-id member-pass
```

```bash
java -jar ./member3.jar fingerprint --key-id member-pass
java -jar ./new-e.jar fingerprint --key-id member-pass
```

```text
키 ID     : member-pass
키 유형   : pass
키 상태   : 사용자 지정
키 지문   : 2296463d5f2efd392d570d81aa8ce206cc27fd5d9eb4656be36b14d8d1008f75   ← 두 JAR가 같아야 함
```

<a name="topic-key-recovery--h-예전-암호문파일을-실제로-복호화"></a>
#### (h) 예전 암호문·파일을 실제로 복호화

지문이 같아도 마지막으로 실제 암호문으로 확인합니다(평문을 보여 주지 않는 `verify` 권장).


```powershell
java -jar .\new-e.jar verify --value 'ENC[v1:member-pass:...]'
java -jar .\new-e.jar file decrypt --in .\report.jck --out .\report-check.csv
```

```bash
java -jar ./new-e.jar verify --value 'ENC[v1:member-pass:...]'
java -jar ./new-e.jar file decrypt --in ./report.jck --out ./report-check.csv
```

```text
OK
복호화 완료: report.jck -> report-check.csv (18바이트)
```

<a name="topic-key-recovery--이력이-있는-jar에-되살릴-때"></a>
#### 이력이 있는 JAR에 되살릴 때

그 JAR 이력에 같은 키 ID가 있으면 위 방법(키 파일·백업·`--from-jar`)으로 **이력에 기록된 키와 같은 키**일 때만 등록되고 결과에 `복원      : 이력에 기록된 이 키 ID의 키와 같음(유형·전체 지문 일치)`(백업이면 `백업과 같은 키`)이 나옵니다.

다른 키면 `키 ID <ID>은(는) 이 JAR의 변경 이력(config history)에서 다른 키에 쓰였습니다(다른 항목: ...)`로 거부합니다. 이력이 없는 새 JAR에는 비교할 기록이 없으므로 (g)·(h)로 직접 확인합니다.


<a name="topic-key-recovery--보관-지침"></a>
#### 보관 지침


- **어디에:** 생성값·키 파일·복원 백업은 실제 비밀 자료입니다. Git 저장소 밖의 보호된 폴더(Linux 파일 `600`·폴더 `700`, Windows는 상속을 끊고 필요한 계정만 허용, [12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관))나 조직의 비밀 보관소에 두고, 서로 다른 안전한 곳에 사본을 둡니다. 그 키로 만든 **모든 암호문을 옮기거나 폐기할 때까지** 보관합니다.
- **함께 둘 것:** key는 키 파일(또는 화면의 값)과 원래 키 ID. pass는 복원 백업 전체(또는 화면의 Passphrase·키 ID·복원 정보·키 지문). Passphrase만 남기면 예전 암호문은 복구할 수 없습니다.
- **노출 경로:** 생성 화면은 화면 공유·녹화·터미널 스크롤 기록에 남을 수 있으므로 혼자 쓰는 터미널에서 생성하고, 보관한 뒤 화면을 지웁니다(`Clear-Host`·`clear`, 스크롤 기록이 남는 터미널은 창을 닫음). 값을 명령 줄 인자로 적지 않습니다(셸 기록·프로세스 목록). 클립보드로 옮겼다면 붙여 넣은 뒤 비우고, Windows 클립보드 기록(Win+V)·클라우드 동기화를 쓰면 그 기록도 지웁니다. 티켓·채팅·메일에 붙이지 않습니다.
- **CI·자동화:** 화면 표시가 없으므로 `--export <보호된 경로>`를 쓰고, 파일 내용을 `cat`·`Get-Content`로 로그에 출력하지 않습니다. 작업 산출물(artifact)·캐시에 올라가지 않게 작업 폴더 밖 경로에 둡니다.
- **인코딩:** 파일은 UTF-8로 둡니다. 앞의 BOM 하나와 줄 끝(CRLF·LF)은 허용하지만, 그 밖의 글자를 섞으면 key는 `KEY_SOURCE`로 거부되고 pass 한 줄 파일은 다른 Passphrase가 됩니다. Windows PowerShell 5.1에서는 `Out-File`·`>`(UTF-16) 대신 `Set-Content -Encoding UTF8`을 씁니다.
- **원본 JAR:** pass 키를 내장한 JAR에는 Passphrase 원문은 없지만 파생된 AES 키가 들어 있어, JAR를 가진 사람은 그 키를 꺼낼 수 있습니다([12.7절](../reference/security.md#127-jar-내장값의-경량-난독화obf1)의 난독화는 이를 막지 않음). JAR도 키 파일과 같은 비밀 파일로 다룹니다. 반대로 원본 JAR가 남아 있으면 백업이 없어도 (f)로 같은 키를 옮길 수 있습니다.
- **모두 잃었을 때:** key는 키 파일·화면 값과 그 키가 든 JAR를 모두 잃은 경우, pass는 복원 정보(Salt 등)와 원본 JAR를 모두 잃은 경우 그 키의 예전 암호문은 복구할 수 없습니다. 새 키를 만들고 원래 값(DB 비밀번호 등)으로 다시 암호화합니다.

<a name="topic-key-recovery--a9-다른-jar에-같은-키-복사"></a>
### 다른 JAR에 같은 키 복사 (A.9)

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass2 --from-jar .\app-pass-v2.jar --operator example-admin --reason "업무 JAR에 같은 키" --yes --out other.jar
java -jar .\other.jar verify --value 'ENC[v1:app-pass2:...]'
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id app-pass2 --from-jar ./app-pass-v2.jar --operator example-admin --reason "업무 JAR에 같은 키" --yes --out other.jar
java -jar ./other.jar verify --value 'ENC[v1:app-pass2:...]'
```

```text
관리자 비밀번호(입력 숨김):                         ← 원본 JAR도 같은 비밀번호면 한 번만
추가 키   : app-pass2 (pass, embedded, 지문 ...)
OK                                                  ← 다른 JAR가 만든 암호문을 복호화
```

`'ENC[v1:app-pass2:...]'`는 [A.8](#topic-key-rotation--a8-키-회전-새-키-추가--rekey--이전-키-제거)의 `rekey`가 출력한 새 암호문으로 바꿉니다. 키 정의(파생 키 포함)만 복사하며 Passphrase 원문은 어느 JAR에도 없습니다.

`--from-jar` 원본의 관리자 비밀번호가 실행 중인 JAR와 다르면 원본 JAR의 비밀번호를 따로 묻습니다(비대화형 `--admin-pass-file`은 비밀번호 하나로 두 JAR를 모두 확인하므로 다르면 실패). 두 JAR를 Tomcat `lib`와 웹앱 `WEB-INF/lib`에 나눠 둘 때의 주의는 [3.7절](tomcat-jdbc.md#topic-tomcat--37-jar를-lib과-웹앱에-함께-둘-때)에 있습니다.

<a name="topic-key-recovery--a10-생성값으로-재등록예전-암호문-복구"></a>
### 생성값으로 재등록·예전 암호문 복구 (A.10)

상황별 핵심 명령입니다.

새 키로 다시 등록하는 것과 예전 암호문까지 복구하는 것의 차이, 백업 형식, 예상 출력 전체는 [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)에 있습니다(아래 이름은 5.6절 예와 같음). `'ENC[v1:member-key:...]'`·`'ENC[v1:member-pass:...]'`는 자리표시자이므로 5.6절에서 그 키로 만든 암호문으로 바꿉니다.

키 JAR가 남아 있으면 관리자 인증 뒤 `config key show --export`로 원문을 내보내 같은 방법으로 등록할 수도 있습니다([A.17](#topic-key-export--a17-키-원문-확인내보내기와-복구)).

```powershell
# key: 화면의 Base64를 붙여 넣어 키 파일로 저장 → 원래 키 ID로 새 JAR에 등록 → 예전 암호문 확인
Read-Host "생성값(붙여 넣기)" | Set-Content -Path "$SECURE\member-key.key" -Encoding UTF8
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-key --type key --from-file "$SECURE\member-key.key" --operator example-admin --reason "member key 재등록" --yes --out new-b.jar
java -jar .\new-b.jar verify --value 'ENC[v1:member-key:...]'
# pass: --export 복원 백업으로 원본 JAR 없이 같은 키 복원
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE\member-pass.backup" --operator example-admin --reason "백업에서 복구" --yes --out new-e.jar
# pass: 원본 JAR가 있으면 그대로 옮기기
java -jar .\java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-jar .\member3.jar --operator example-admin --reason "원본 JAR에서 이관" --yes --out new-f.jar
# 같은 키인지(64자 전체 지문)와 예전 암호문·파일 복호화 확인
java -jar .\new-e.jar fingerprint --key-id member-pass
java -jar .\new-e.jar verify --value 'ENC[v1:member-pass:...]'
java -jar .\new-e.jar file decrypt --in .\report.jck --out .\report-check.csv
```

```bash
IFS= read -r -p '생성값(붙여 넣기): ' v && (umask 077 && printf '%s\n' "$v" > "$SECURE/member-key.key"); unset v
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-key --type key --from-file "$SECURE/member-key.key" --operator example-admin --reason "member key 재등록" --yes --out new-b.jar
java -jar ./new-b.jar verify --value 'ENC[v1:member-key:...]'
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-file "$SECURE/member-pass.backup" --operator example-admin --reason "백업에서 복구" --yes --out new-e.jar
java -jar ./java-crypto-kit-0.1.0-configured.jar config key add --key-id member-pass --from-jar ./member3.jar --operator example-admin --reason "원본 JAR에서 이관" --yes --out new-f.jar
java -jar ./new-e.jar fingerprint --key-id member-pass
java -jar ./new-e.jar verify --value 'ENC[v1:member-pass:...]'
java -jar ./new-e.jar file decrypt --in ./report.jck --out ./report-check.csv
```

```text
관리자 비밀번호(입력 숨김):                       ← key add마다
추가 키   : member-key (key, embedded, 지문 afbf5bc43e6d...ea484f0c)
OK
복원      : 백업과 같은 키(키 ID·KDF·반복 횟수·Salt·지문 일치)
추가 키   : member-pass (pass, embedded, 지문 2296463d5f2e...d1008f75)    ← --from-jar
키 지문   : 2296463d5f2efd392d570d81aa8ce206cc27fd5d9eb4656be36b14d8d1008f75   ← 원래 JAR와 같아야 함
OK
관리자 비밀번호(입력 숨김):                       ← file decrypt
복호화 완료: report.jck -> report-check.csv (18바이트)
```

Passphrase만 한 줄 파일로 등록하면 새 Salt로 **다른 키**가 되어 예전 암호문은 복구되지 않습니다(`Salt      : 새로 만듦(...)`, [5.6절](#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구) (c)).

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-rotation"></a>

## 키 교체 및 암호문 이전

<a name="topic-key-rotation--키-교체와-암호문-전환"></a>
<a name="topic-key-rotation--29-rekey--기존-암호문을-새-키로-바꾸기"></a>
### `rekey` — 기존 암호문을 새 키로 바꾸기 (2.9)

**사용 상황:** 운영 중인 암호문이 있는 상태에서 키를 교체할 때(다른 JAR·설정의 키로, 또는 같은 JAR 안의 다른 키로). 기존 암호문을 자동으로 고치지 않으므로 **이전 키와 이전 키 내장 JAR를 보존한 채** 진행합니다([9.2 키 교체](#topic-key-rotation--92-키-교체)).

```text
java -jar <실행 JAR> rekey [--type pass|key] [--key-id <대상 키 ID>]
    [--from-config <이전 설정> | --from-jar <이전 JAR>]
    [--to-config <새 설정> | --to-jar <새 JAR>] [--value <기존 암호문>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--type pass\|key` | 선택 | 대상 키 유형. 생략하면 **기존 암호문과 같은 유형**의 기본 키(재암호화는 새 암호화가 아니므로 유형을 바꾸지 않음) |
| `--key-id <ID>` | 선택 | 대상 키 ID(유형 자동). `--type`과 함께 쓰면 유형 확인 |
| `--from-config <경로>` | 선택 | 이전 키 쪽: 실행 JAR 내장값 + 지정 Properties(JVM `-D`·환경변수 우선순위는 섞지 않음) |
| `--from-jar <JAR>` | 선택 | 이전 키 쪽: 그 JAR의 내장 설정만 사용 |
| `--to-config <경로>` | 선택 | 새 키 쪽: 실행 JAR 내장값 + 지정 Properties |
| `--to-jar <JAR>` | 선택 | 새 키 쪽: 그 JAR의 내장 설정만 사용 |
| `--value <암호문>` | 아니요 | 기존 암호문을 인자로 전달. 생략하면 화면에 보이지 않게 입력 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**조합 규칙:** `--from-*`·`--to-*`·`--type`·`--key-id` 중 **적어도 하나**를 지정합니다. 같은 쪽에 `--from-config`와 `--from-jar`(또는 `--to-config`와 `--to-jar`)를 함께 줄 수 없습니다.

지정하지 않은 쪽은 실행 JAR의 최종 설정을 씁니다.

`--type`·`--key-id`만 주면 **같은 설정 안의 다른 키**로 바꿉니다(회전, pass↔key 유형 간 재암호화도 가능). 이전 키는 기존 암호문의 키 ID로 고르며, 이전 키와 대상 키는 **서로 다른 키와 키ID**여야 합니다.

**예제**

```powershell
# 새 키 내장 JAR로 실행하고, 이전 키 내장 JAR를 이전 키로 지정
java -jar .\java-crypto-kit-0.1.0-configured-3.jar rekey --from-jar .\java-crypto-kit-0.1.0-configured-2.jar
```

```bash
# 이전 키·새 키를 각각 설정 파일로 지정
java -jar ./java-crypto-kit-0.1.0-configured-2.jar rekey --from-config /secure/old.properties --to-config /secure/new.properties
# 같은 JAR 안에서 다른 키로(키 목록에 추가한 app-pass2로 회전, 공개 AES 키 암호문을 pass 키로 옮기기 등)
java -jar ./java-crypto-kit-0.1.0-configured-2.jar rekey --key-id app-pass2
```

**관리자 인증:** 실행 중인 JAR의 관리자 비밀번호를 확인하고, `--from-jar`(이전 키를 꺼내 복호화하는 JAR)가 관리자 비밀번호를 쓰는 JAR이면 그 JAR의 비밀번호도 확인합니다(같으면 한 번만). `--to-jar`는 그 JAR의 키로 새 암호문을 만들기만 하고 JAR를 바꾸지 않으므로 묻지 않습니다.

인증은 기존 암호문을 받기 전에 합니다.

**결과:** 기존 암호문을 입력하면 그 키 ID의 이전 키로 인증·복호화 → 대상 키와 새 IV로 재암호화 → 새 암호문이 대상 키로 복호화되고 키 ID가 대상 키인지 검증한 뒤 **새 암호문 한 줄만** 표준 출력에 씁니다. 평문은 출력하지 않으며 Resource XML도 자동으로 바꾸지 않습니다.

- **표준 오류:** 새 키가 사용자 지정 키이면 비어 있습니다. 새 키가 공개 기본 키이면 재암호화와 검증이 **모두 성공한 뒤에만** 공통 경고 `[WARN] 공개 기본 키 사용 중 (별도 키 설정 권장)` 한 줄이 나옵니다(`crypto.warning.enabled=false`면 없음). 이전 키가 공개 기본 키인 것은 경고하지 않습니다.
- **실패하면** 새 암호문도 경고도 없이 오류 한 줄(`[사유: 코드]`)만 씁니다.

**배포 순서:** Resource에 쓰는 **모든** 기존 암호문을 재암호화 → 새 키 내장 JAR와 새 암호문을 함께 배포 → WAS 재기동 후 실제 SQL 확인 → 이전 JAR·암호문은 원복용으로 보관. 이전 키를 잃었다면 `rekey`로 복구할 수 없으므로 DB 비밀번호 평문을 승인 절차에 따라 다시 `encrypt`해야 합니다.

**오류·주의:** 같은 키·같은 키ID면 새 키·새 ID를 준비합니다. `KEY_ID_MISMATCH`는 이전 키 쪽 설정을, `INTEGRITY`는 이전 키가 맞는지와 암호문 손상을 확인합니다. `--value`는 셸 기록에 남으므로 대화형 입력을 권장합니다.

<a name="topic-key-rotation--92-키-교체"></a>
### 키 교체 (9.2)

키 목록 덕분에 **한 JAR 안에서 이전 키와 새 키를 함께 두고** 옮길 수 있습니다(같은 JAR가 이전 암호문과 새 암호문을 모두 복호화).

| 순서 | 작업 | 확인 |
|---|---|---|
| 1. 보존 | **현재 키 내장 JAR·키·기존 모든 Resource 암호문**을 안전하게 백업 | JAR와 암호문을 같은 시점으로 되돌릴 수 있음 |
| 2. 새 키 추가 | pass: `config key add --key-id <새 ID> --active`. key: `config embed-key --key-id <새 ID>`(이전 AES 키는 키 목록에 남음) 또는 `config key add --type key ... --active` | 새 JAR의 `config show`에서 두 키와 기본 키 확인 |
| 3. 재암호화 | 새 JAR로 Resource의 기존 암호문 **각각** `rekey --key-id <새 ID>`(같은 JAR 안 회전) | 새 `ENC[...]`의 키ID 확인 |
| 4. 전환 | 새 JAR와 **모든 Resource의 새 암호문을 함께** 적용 | `lib`에 JAR 하나, 각 Resource SQL 성공 |
| 5. 정리 | 모든 암호문을 옮긴 뒤 `config key remove --key-id <이전 ID>`로 이전 키 제거(선택) | 남은 암호문이 없는지 확인한 뒤 |
| 6. 원복 | 장애 시 이전 JAR·이전 암호문·이전 키 설정을 **한 세트로** 복원 | 이전 상태의 SQL 성공 |

```powershell
# 새 pass 키를 추가해 기본으로 정하고, 같은 JAR 안에서 기존 암호문을 새 키로 옮깁니다.
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config key add --key-id app-pass2 --active --operator example-admin --reason "정기 키 회전"
java -jar .\java-crypto-kit-0.1.0-configured-3.jar rekey --key-id app-pass2
# 다른 JAR(이전 키 내장 JAR)의 암호문을 새 JAR로 옮길 때
java -jar .\java-crypto-kit-0.1.0-configured-3.jar rekey --from-jar .\java-crypto-kit-0.1.0-configured-2.jar
```

**외부 Passphrase·키 값의 변경:** 파일·환경변수·Vault의 값을 같은 키 ID 그대로 바꾸면 지문 고정 때문에 실패합니다(의도치 않은 변경을 막기 위함). 값을 바꿀 때는 새 값으로 **새 키 ID를 추가**하고 위 3~5단계로 옮깁니다.

`rekey`는 XML을 자동으로 바꾸지 않습니다. **이전 키를 이미 잃었다면 기존 암호문은 복구할 수 없습니다.** Vault 최신 버전이나 KMS 새 데이터 키를 무심코 쓰면 기존 암호문이 깨질 수 있으므로 Vault는 `crypto.vault.ver`로 버전을 고정합니다.

<a name="topic-key-rotation--a8-키-회전-새-키-추가--rekey--이전-키-제거"></a>
### 키 회전: 새 키 추가 → rekey → 이전 키 제거 (A.8)

```powershell
java -jar .\app-pass.jar config key add --key-id app-pass2 --active --operator example-admin --reason "정기 키 회전" --out app-pass-v2.jar
java -jar .\app-pass-v2.jar rekey --key-id app-pass2
java -jar .\app-pass-v2.jar config key remove --key-id app-pass --operator example-admin --reason "회전 완료" --out app-pass-v3.jar
java -jar .\app-pass-v3.jar config history
```

```bash
java -jar ./app-pass.jar config key add --key-id app-pass2 --active --operator example-admin --reason "정기 키 회전" --out app-pass-v2.jar
java -jar ./app-pass-v2.jar rekey --key-id app-pass2
java -jar ./app-pass-v2.jar config key remove --key-id app-pass --operator example-admin --reason "회전 완료" --out app-pass-v3.jar
java -jar ./app-pass-v3.jar config history
```

```text
crypto.key.active.pass (app-pass -> app-pass2)     ← add(관리자 비밀번호 + Passphrase 2회 + CHANGE)
관리자 비밀번호(입력 숨김):                        ← rekey(관리자 비밀번호 먼저)
기존 암호문(입력 숨김):                            ← rekey: 기존 ENC[v1:app-pass:...] 입력
ENC[v1:app-pass2:-LMuh90_Zpsnp-lx:FckiFyX0GJoCJHYOfHWaWOnzo7j-BPE8F20hii9SMuq4Wuc]
키를 제거합니다(결과 JAR는 이 키의 암호문을 복호화하지 못함):   ← remove(관리자 비밀번호 + CHANGE)
  결과: 새 JAR app-pass-v3.jar (원본은 그대로)
  사유: 회전 완료
  ...
제거 키   : app-pass
표시 범위 : pass 관련 3건(전체 4건)                ← config history(#1은 관리자 설정 기록)
...
#4  2026-11-23T05:07:39Z  수정자 example-admin  config key remove  [pass]
    사유: 회전 완료
    ...
    키 app-pass: pass, embedded, 입력 -> (없음)
      키 지문: e87f0d656730...(64자 전체)
      KDF: pbkdf2-sha256, 600,000회
      Salt SHA-256:
        <64자>
```

Resource의 **모든** 암호문을 `rekey`로 옮긴 뒤에 이전 키를 제거합니다.

제거한 키의 암호문은 결과 JAR에서 `KEY_ID_MISMATCH`로 실패하고, 제거한 키 ID는 다른 키에 다시 쓸 수 없습니다(같은 키를 되살릴 때만 허용, [A.10](#topic-key-recovery--a10-생성값으로-재등록예전-암호문-복구)).

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-history"></a>

## 설정 변경 이력

<a name="topic-history--설정-변경-이력"></a>
<a name="topic-history--211-config-history--설정-변경-이력"></a>
### `config history` — 설정 변경 이력 (2.11)

**사용 상황:** JAR 내장 설정을 언제·누가·왜·무엇을 바꿨는지 확인할 때. 관리자 비밀번호를 확인한 뒤 보여 줍니다(`--jar`로 다른 JAR를 보면 그 JAR의 비밀번호도 확인). 기본은 **pass 키와 관련된 이력**이고, key(AES) 키 이력은 `--type key`, 일반 설정·관리자 비밀번호 기록까지 모두 보려면 `--all`을 씁니다.

```text
java -jar <실행 JAR> config history [--type pass|key | --all] [--jar <조회할 JAR>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--type pass\|key` | 아니요 | 그 유형의 키와 관련된 변경만. 생략하면 `pass` |
| `--all` | 아니요 | 두 유형과 일반 설정(언어·Pool·경고 등)의 변경, 관리자 비밀번호 설정·변경 기록까지 전체. `--type`과 함께 쓸 수 없음 |
| `--jar <경로>` | 아니요 | 다른 JAR의 변경 이력을 볼 때. 생략하면 실행 중인 JAR |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config history
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config history --type key
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured-2.jar config history --all
java -jar ./tools/java-crypto-kit-0.1.0-configured.jar config history --jar /opt/tomcat/lib/java-crypto-kit-0.1.0-configured-2.jar --type key
```

**결과:** 이력 검증 결과(전체 건수)와 `표시 범위`(예: `key 관련 2건(전체 3건)`) 뒤에 변경마다 순번, UTC 시각(ISO 8601, 끝의 `Z`), 수정자(`--operator`), 명령(`config set`·`config embed-key`·`config key add`·`config key use`·`config key remove`·`admin setup`·`admin password change`), 유형 꼬리표(`[pass]`·`[key]`·`[key, pass]`·`[일반]`·`[관리자]`), 사유(`--reason`), 설정별 이전 값 → 변경 값을 보여 줍니다.

걸러 보아도 순번은 원래 번호 그대로입니다.

기록된 관리정보는 마스킹하지 않습니다: Salt·KDF·반복 횟수 같은 설정 줄은 값 그대로, 키를 추가·제거·교체한 기록은 `키 <ID>: (없음) -> pass, embedded, 생성` 같은 **키 요약 줄**(유형·공급원·`crypto.key.*` 여부·공개 기본 키 여부·출처) 아래에 기록된 **64자 전체 지문**, pass는 KDF·반복 횟수·Salt SHA-256을 보여 줍니다.

키 원문(내장 키 값)은 이력에 없으므로 `(비공개) -> (교체됨)`(교체)·`(없음) -> (비공개)`(추가)·`(비공개) -> (없음)`(제거)로만 나오고, 이전 형식의 이력처럼 값을 기록하지 않은 Salt 줄은 지어내지 않고 `(기록 없음)`으로 구분합니다.

관리자 비밀번호 설정·변경은 `관리자 비밀번호: (없음) -> (설정됨)`·`(설정됨) -> (변경됨)`만 남습니다(비밀번호·검증값·인증용 Salt 없음). 출처는 `생성`(`--generate`), `입력`(숨김 입력), `파일`(`--from-file`의 키 파일·Passphrase 한 줄 파일), `복원`(복원 백업이나 이력의 키와 같은 키로 되살림), `복사`(`--from-jar`), `외부`(외부 공급원에서 읽음), `옮김`(`crypto.key.*`에서 키 목록으로)입니다.

값이 길어 80열을 넘으면 `->` 앞에서 줄을 바꿉니다(값은 자르지 않음). 성공한 변경만 기록하며, 새 결과 JAR와 `--replace` 후에도 이력은 그대로 이어집니다. 한 번도 바꾸지 않은 JAR는 `변경 이력 없음`이 정상입니다.

```text
관리자 비밀번호(입력 숨김):
JAR 설정 변경 이력: java-crypto-kit-0.1.0-configured-3.jar (버전 0.1.0)
빌드 일시 : 2026-11-23T05:05:18Z
이력 검증 : 정상(4건, 해시 체인·현재 설정 일치)
표시 범위 : key 관련 2건(전체 4건)

#3  2026-11-23T05:06:08Z  수정자 example-admin  config key add  [key]
    사유: key 키 생성
    crypto.keys.gen-aes.type: (없음) -> key
    crypto.keys.gen-aes.source: (없음) -> embedded
    crypto.keys.gen-aes.embedded: (없음) -> (비공개)
    키 gen-aes: (없음) -> key, embedded, 생성
      키 지문: 1d2e4488eacf...(64자 전체)

#4  2026-11-23T05:07:29Z  수정자 example-admin  config key use  [key]
    사유: key 기본 키 전환
    crypto.key.active.key: (비어 있음) -> gen-aes
```

`--all`로 보면 관리자 비밀번호 기록과 pass 키 기록(Salt 값과 KDF 관리정보)도 나옵니다.

```text
#1  2026-11-23T05:05:40Z  수정자 example-admin  admin setup  [관리자]
    사유: 최초 설정
    관리자 비밀번호: (없음) -> (설정됨)

#2  2026-11-23T05:05:52Z  수정자 example-admin  config key add  [pass]
    사유: 운영 pass 키 등록
    crypto.keys.app-pass.type: (없음) -> pass
    ...
    crypto.keys.app-pass.salt: (없음) -> <Salt(Base64)>
    키 app-pass: (없음) -> pass, embedded, 입력
      키 지문: 5d0c8a1e...(64자 전체)
      KDF: pbkdf2-sha256, 600,000회
      Salt SHA-256:
        <64자>
```

**유형 분류:** pass 키의 항목(`crypto.keys.<pass 키 ID>.*`)과 `crypto.key.active.pass`는 pass, key 키의 항목·`crypto.key.*`(이전 형식의 AES 키 자리)·`crypto.key.active.key`는 key, 기본 유형 `crypto.key.type`은 두 유형 모두에 속합니다.

키와 무관한 설정만 바꾼 변경은 `[일반]`, 관리자 비밀번호 설정·변경은 `[관리자]`이며 둘 다 `--all`에서만 보입니다(pass·key 키 변경으로 분류하지 않음). 이전 형식 JAR에서 이어진 `crypto.key.*` 변경(`embed-key` 등)은 key로 분류되므로 **기본 조회(pass)에는 나오지 않고** `--type key`나 `--all`로 봅니다(pass로 분류하지 않음). 유형을 알 수 없는 키 항목도 버리지 않고 key로 보여 줍니다.

걸러 보기 전에 **전체 이력의 해시 체인과 현재 설정 일치를 먼저 검증**하므로, 화면에 나오지 않는 항목이 손상돼도 `[사유: INTEGRITY]`로 끝납니다.

**주의:** 해시 체인은 단순 수정·손상을 찾는 용도이며 **수정자가 위변조할 수 없는 감사 로그가 아닙니다**([12.4절](../reference/security.md#124-jar-설정-이력의-성격)). 이력이 손상됐거나 현재 설정과 맞지 않으면 `[사유: INTEGRITY]`로 끝납니다.

이력을 믿을 수 없으면 `--replace`나 ZIP 수정으로 복구하려 하지 말고 검증된 이전 JAR로 돌아갑니다. 사유는 수정자가 입력한 설명입니다.

JAR를 바꾸지 않는 `keygen`·`kms datakey`는 사유를 받아도 이 이력에 남지 않습니다([12.4절](../reference/security.md#124-jar-설정-이력의-성격)). JAR 안의 이력 본문은 경량 난독화(`obf1`)로 저장되어 압축을 풀어도 바로 읽히지 않으며, 이 명령은 이전 형식의 평문 이력도 그대로 읽습니다([12.7절](../reference/security.md#127-jar-내장값의-경량-난독화obf1)).

<a name="topic-history--a11-변경-이력-보기유형별"></a>
### 변경 이력 보기(유형별) (A.11)

```powershell
java -jar .\use.jar config history
java -jar .\use.jar config history --type key
java -jar .\use.jar config history --all
```

```bash
java -jar ./use.jar config history
java -jar ./use.jar config history --type key
java -jar ./use.jar config history --all
```

```text
관리자 비밀번호(입력 숨김):
JAR 설정 변경 이력: use.jar (버전 0.1.0)
빌드 일시 : 2026-11-23T05:05:18Z
이력 검증 : 정상(4건, 해시 체인·현재 설정 일치)
표시 범위 : pass 관련 1건(전체 4건)              ← 기본(pass)

#2  2026-11-23T05:06:07Z  수정자 example-admin  config key add  [pass]
    사유: pass 키 생성
    crypto.keys.gen-pass.type: (없음) -> pass
    ...
    crypto.keys.gen-pass.salt: (없음) -> zeCLW3OFXUx1ncPi4GQhnA==
    키 gen-pass: (없음) -> pass, embedded, 생성
      키 지문: 3b271408bc6cd3820135789002325a6d054676ea06c214626349cea4d7a238b4
      KDF: pbkdf2-sha256, 600,000회
      Salt SHA-256:
        <64자>

표시 범위 : key 관련 2건(전체 4건)               ← --type key: #3 gen-aes 생성, #4 key 기본 키 전환
표시 범위 : 전체 4건                             ← --all: #1 관리자 비밀번호 설정([관리자])까지 전체
```

관리정보(Salt·KDF·전체 지문)는 마스킹하지 않고, 키 원문·관리자 비밀번호는 이력에 없습니다. 이전 형식에서 이어진 `crypto.key.*`(AES 키) 변경은 key로 분류되어 기본 조회에 나오지 않으므로 `--type key`나 `--all`로 봅니다.

화면에 일부만 보여도 전체 이력을 먼저 검증합니다([2.11절](#topic-history--211-config-history--설정-변경-이력)).

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
