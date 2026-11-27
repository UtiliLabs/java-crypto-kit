# CLI 사용 가이드

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

관리형 CLI는 DB 접속정보·설정값·파일을 암복호화하고 JAR의 키와 설정을 관리합니다. 독립 `api` CLI는 직접 준비한 키로 암복호화·서명·토큰 검증을 실행합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[언제 CLI를 사용하나요?](#guide-section-1) · [처음 실행하는 순서](#topic-cli-encryption--첫-실행-예제) · [암호화할 때 어떤 옵션을 선택할까요?](#guide-section-3) · [최초 준비와 관리자 인증](#topic-admin) · [명령 찾기 및 공통 사용 규칙](#topic-cli) · [문자열 암호화·복호화·검증](#topic-cli-encryption) · [설정 변경 및 진단](#topic-cli-settings) · [독립 명령·단축어](#api-cli)

---

<a name="guide-section-1"></a>
## 언제 CLI를 사용하나요?

| 하려는 작업 | 사용하는 명령 | 실제 작업 절차 |
|---|---|---|
| 처음 JAR를 내려받음 | `admin setup` | [최초 설정](#topic-admin--222-admin-setup--관리자-비밀번호-최초-설정) |
| Tomcat DB 비밀번호·계정 암호화 | `encrypt`, `verify` | [Tomcat 연동](tomcat-jdbc.md) |
| 기존 암호문의 원문 또는 복호화 가능 여부 확인 | `decrypt`, `verify` | [문자열 암복호화](#topic-cli-encryption) |
| 정산 파일·문서 암복호화 | `file encrypt`, `file decrypt` | [파일 암복호화](file-encryption.md) |
| 사용자 지정 키 생성·등록·선택 | `keygen`, `config key add`, `config embed-key`, `config key use` | [키 관리](key-management.md) |
| 기존 암호문의 키를 바꾸거나 복구 | `rekey`, `config key show`, `fingerprint` | [키 관리](key-management.md#topic-key-recovery) |
| JAR 내장 설정·실제 적용값·오류 확인 | `config show`, `info`, `doctor`, `config set` | [설정 및 진단](#topic-cli-settings) |
| AWS KMS 데이터 키 준비 | `kms datakey` | [AWS KMS](external-key-providers.md#topic-aws-kms) |
| 직접 키 암복호화, 데이터·토큰 검증 | `api aes`, `api sig`, `api jwt`, `api oauth` 등 | [독립 명령과 옵션](#api-cli) |

JAR를 `java -jar`로 실행합니다. Help와 Examples는 관리자 설정 전에도 조회할 수 있으며, 업무 명령은 먼저 관리자 설정을 마쳐야 합니다. Windows와 Linux 모두 같은 java -jar 명령으로 내부 설정을 갱신합니다.

독립 CLI는 AES-128/256·AAD, RSA·Hybrid, HMAC·해시·전자서명, 비밀번호·난수, OTP·JWT·OAuth, X.509 정보·키 변환을 제공합니다. PKCS12/JKS 읽기, PKIX 체인 검증, 안전 비교는 Java API에서 사용합니다. [업무별 선택](../user-guide.md#업무별-java-api와-독립-cli)

<a name="topic-cli-encryption--첫-실행-예제"></a>
## 처음 실행하는 순서

최초 등록과 이후 내부 변경은 같은 JAR 안에 저장합니다. 예약 영역이 없는 JAR는 조회·키 이관용 원본으로 사용합니다.

최초 1회 관리자 비밀번호를 설정합니다(10~128자, 영문·숫자·특수문자 필수). 관리자 검증값과 키는 같은 파일에 저장합니다. 변경 전 복제본이 필요하면 JAR를 직접 복사하세요.

```bash
# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar java-crypto-kit-0.2.1.jar admin setup
```

같은 JAR로 암호화·복호화합니다. `enc`(`encrypt`)는 평문을, `dec`(`decrypt`)는 관리자 비밀번호와 암호문을 입력받습니다. 민감 입력은 숨김 처리합니다. `verify`는 암호문을 확인하며 평문을 출력하지 않습니다.

```bash
# 입력한 값을 활성 키로 암호화
java -jar java-crypto-kit-0.2.1.jar enc

# 관리자 인증 후 암호문을 복호화
java -jar java-crypto-kit-0.2.1.jar dec

# 평문 표시 없이 암호문의 무결성 확인
java -jar java-crypto-kit-0.2.1.jar verify
```

- 암호화 기본값: `pass`. AES 키 유형은 `encrypt --type key`.
- 복호화: 관리자 비밀번호와 암호문 전체를 입력합니다. Key ID는 자동 선택됩니다.
- 검증: 평문을 표시하지 않고 `OK` 또는 오류를 반환합니다.

> [!IMPORTANT]
> 최초 설정 키는 JAR별로 다릅니다. 같은 암호문을 사용할 서버에는 동일 키와 ID가 필요합니다.

[관리자 인증](#topic-admin--14-cli-관리자-비밀번호) · [CLI 명령·옵션](#topic-cli)

<a name="guide-section-3"></a>
## 암호화할 때 어떤 옵션을 선택할까요?

| 원하는 결과 | 실행할 명령(앞에 `java -jar <JAR>` 추가) | 특징 |
|---|---|---|
| 설정에 지정된 기본 암호화 키 | `encrypt` | 배포 기본 유형은 pass. 운영에서는 실제 기본 키 확인 |
| pass 유형의 기본 키 | `encrypt --type pass` | 등록한 Passphrase 파생 키 사용 |
| key 유형의 기본 키 | `encrypt --type key` | 등록한 32바이트 AES 키 사용 |
| 특정 업무 키 | `encrypt --key-id app-aes` | 키 ID를 고정. ID가 등록되어 있어야 함 |
| 암호문 복원 | `decrypt` | 관리자 인증 후 전체 암호문 입력. 키 ID 자동 선택 |
| 평문 노출 없이 확인 | `verify` | 암호문 무결성·복호화 가능 여부 확인. DB 로그인 검사는 아님 |

`pass`는 PBKDF2로 AES 키를 파생하는 방식이며 `key`는 AES 키를 그대로 쓰는 방식입니다. 둘 다 AES-256-GCM입니다. 최초 설정은 두 유형에 각각 새 키를 생성합니다. `--type`은 유형별 기본 키, `--key-id`는 특정 등록 키를 선택합니다. `--type`과 `--key-id`를 함께 쓰면 일치해야 합니다. 키 등록 시 `--active`는 해당 유형의 기본 키만 바꾸므로 `crypto.key.type`과 구분합니다.

최초 관리자 설정과 명령마다의 인증도 구분합니다. `encrypt`, `verify`, `file encrypt`, `info`, `doctor`, `fingerprint`는 최초 설정 이후 관리자 비밀번호를 매번 묻지 않습니다. `decrypt`, `file decrypt`, 키·설정 변경 및 민감 조회는 매번 인증합니다. 전체 구분은 [명령 목록](#topic-cli--22-명령-목록)을 참고하세요. 비대화형 실행은 해당 명령의 입력 및 인증 옵션을 모두 갖춰야 합니다.

### 옵션의 대상과 함께 쓸 수 있는 조합

`file encrypt`와 `file decrypt`는 `--in`과 `--out`을 모두 요구합니다. [파일 명령과 출력 예제](file-encryption.md)

| 하려는 일 | 옵션을 고르는 기준 |
|---|---|
| 실행 환경 또는 JAR 조사 | `--config`는 이번 암복호화·진단이 읽을 외부 Properties입니다. `config show --jar`는 지정한 JAR 안의 값을 봅니다. 실제 적용값은 `info`에서 확인하세요. |
| 새 키 등록 | 재료를 지정할 때 `--generate`, `--from-file`, `--from-jar`는 서로 배타적입니다. 기본 내장 pass 키를 직접 입력하거나 외부 위치에서 읽을 때는 세 옵션을 생략합니다. 기존 JAR에서 가져오면 그 키의 정의도 복사하므로 `--source`와 `--location`을 함께 지정할 수 없습니다. |
| 키 값을 파일로 보관 | `config key add --generate`의 `--export`는 생성값 백업입니다. 이미 등록한 키는 `config key show --key-id <ID> --export <새 파일>`을 씁니다. 내장·KMS pass 키는 파생된 키만 있으므로 Passphrase 원문을 다시 내보낼 수 없습니다. |
| 기존 AES 키 파일의 지문 비교 | `fingerprint --key-file <파일>`은 파일만 읽습니다. 설정에 등록한 키를 조사하는 `--config`, `--type`, `--key-id`와 함께 쓸 수 없습니다. |
| 기존 문자열 암호문의 키 교체 | `rekey`의 읽는 쪽은 `--from-config` 또는 `--from-jar`, 쓰는 쪽은 `--to-config` 또는 `--to-jar`입니다. 한쪽을 생략하면 실행 설정을 씁니다. 같은 설정에서도 `--key-id`로 대상 키를 고를 수 있습니다. 유형을 따로 고르지 않고 대상 ID도 생략하면 원래 유형의 기본 키로 옮깁니다. |
| JAR 저장 | 현재 파일의 이름과 경로를 유지합니다. --replace는 기존 스크립트 호환용이며 키 변경 확인은 --yes로 생략할 수 있습니다. |
| 이력 범위 선택 | `config history`는 pass 이력, `--type key`는 key 이력, `--all`은 일반 설정·관리자 기록을 포함한 전체 이력입니다. `--all`과 `--type`은 함께 쓸 수 없습니다. |

[명령별 전체 옵션·필수값·실행 예제](#topic-cli--22-명령-목록)

<a name="topic-admin"></a>

## 최초 준비와 관리자 인증

<a name="topic-admin--cli-관리자-비밀번호"></a>
<a name="topic-admin--14-cli-관리자-비밀번호"></a>
### CLI 관리자 비밀번호 (1.4)

CLI는 키를 만들고 바꾸며 복호화한 평문과 키 원문을 보여 줄 수 있으므로, CLI를 쓰기 전에 **관리자 비밀번호**를 정하고 민감 명령마다 확인합니다. 관리자 비밀번호는 데이터 암호화 키(pass·key)와 별개의 인증 정보입니다.

바꿔도 키·키 ID·Salt·KDF·기존 암호문·이력은 그대로이고, 반대로 키를 바꿔도 관리자 비밀번호는 그대로 이어집니다.

**CLI에만 적용**되며 Java API(`CredentialCrypto`)와 Tomcat `EncryptedDataSourceFactory`는 비밀번호를 묻지 않고 이전과 똑같이 동작합니다(서버 기동 중 입력 없음).

<a name="topic-admin--최초-설정"></a>
#### 최초 설정

배포 JAR(그리고 소스에서 빌드한 JAR)은 관리자 비밀번호가 없는 상태입니다. 설정 전에도 전체·기능별 Help, Examples 및 버전 정보를 조회할 수 있습니다. 실제 업무 명령은 최초 설정을 요구합니다.


| 단계 | 내용 |
|---|---|
| 1 | 배포 JAR로 [`admin setup`](#topic-admin--222-admin-setup--관리자-비밀번호-최초-설정)을 실행합니다. 다른 명령을 처음 실행해도 같은 설정 절차로 들어갑니다(그 명령은 실행하지 않음). |
| 2 | 새 비밀번호 → 비밀번호 확인 순서로 입력합니다(비밀번호는 화면에 보이지 않고 2회 입력). |
| 3 | 독립 랜덤 pass·AES 키를 자동 생성하고 비밀번호 검증값과 함께 같은 JAR에 저장합니다. 작업자를 지정하지 않으면 `SYSTEM`으로 기록합니다. |
| 4 | 같은 파일명과 경로로 계속 실행합니다. 내부 내용이 바뀌므로 갱신 이후 SHA-256이 공식 배포본과 다른 것이 정상입니다. |

```powershell
# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar java-crypto-kit-0.2.1.jar admin setup
```

```bash
# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar ./java-crypto-kit-0.2.1.jar admin setup
```

```text
[CLI 관리자 비밀번호 설정]
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)

새 관리자 비밀번호(입력 숨김):
비밀번호 확인(입력 숨김):

관리자    : 비밀번호 설정 완료
활성 키   : pass=pass-0123456789abcdef0123456789abcdef
            key=key-<자동 생성 ID>
갱신 JAR  : C:\work\java-crypto-kit-0.2.1.jar
작업자    : SYSTEM
설정 JAR를 안전하게 백업하고 CLI·내장 키 Java/Tomcat에 사용하세요. 내장 pass 원문은 다시 조회할 수 없습니다.
```

위 경로와 키 ID는 예시입니다. 결과의 `갱신 JAR`는 설정을 실행한 파일입니다. POSIX에서는 갱신 경로 다음에 `권한      : 소유자만(600). 배포할 때 서비스 계정이 읽게 정하세요(가이드 12.2).`가 표시됩니다.

영문 설정 완료 출력도 같은 정보를 표시합니다.

```text
Admin       : password set
Active keys : pass=pass-0123456789abcdef0123456789abcdef
              key=key-<자동 생성 ID>
Updated JAR: C:\work\java-crypto-kit-0.2.1.jar
Operator    : SYSTEM
Back up this JAR securely for Java, Tomcat and CLI use. The embedded passphrase cannot be retrieved.
```

대화형 CLI는 미설정 상태에서 다른 명령을 실행하면 최초 설정을 시작합니다. 설정을 마친 뒤 같은 JAR로 요청한 명령을 다시 실행합니다. Windows에서도 같은 명령으로 최초 설정합니다. 비대화형 미설정 JAR에서 업무 명령은 ADMIN_SETUP으로 끝납니다.

```text
[CLI 초기 설정 필요]
이 JAR은 관리자 비밀번호가 설정되지 않아 CLI 기능을 쓸 수 없습니다.
현재 JAR java-crypto-kit-0.2.1.jar에 설정을 저장합니다.
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)

새 관리자 비밀번호(입력 숨김):
비밀번호 확인(입력 숨김):

관리자    : 비밀번호 설정 완료
활성 키   : pass=pass-0123456789abcdef0123456789abcdef
            key=key-<자동 생성 ID>
갱신 JAR  : C:\work\java-crypto-kit-0.2.1.jar
작업자    : SYSTEM
설정 JAR를 안전하게 백업하고 CLI·내장 키 Java/Tomcat에 사용하세요. 내장 pass 원문은 다시 조회할 수 없습니다.
[java-crypto-kit] [사유: ADMIN_SETUP] 설정을 마쳤습니다. java-crypto-kit-0.2.1.jar에서 encrypt 명령을 다시 실행하세요.
```

<a name="topic-admin--비밀번호-규칙"></a>
#### 비밀번호 규칙

(최초 설정·변경·비밀번호 파일 모두 같음)


| 항목 | 규칙 |
|---|---|
| 길이 | 10~128자(운영 권장 12~16자 이상, 강제 아님) |
| 영문자 | A–Z 또는 a–z 1자 이상(대문자·소문자를 각각 요구하지 않음) |
| 숫자 | 0–9 1자 이상 |
| 특수문자 | ASCII 문장부호·기호 32개(`!"#$%&'()*+,-./:;<=>?@[\]^_`, 백틱, `{`, 세로 막대, `}~`) 중 1자 이상 |
| 쓸 수 없는 문자 | 공백(특수문자로 세지 않음), 한글·이모지 등 비ASCII, 제어문자 |

| 입력 예 | 결과 |
|---|---|
| `admin@12345` | 통과 |
| `ADMIN@12345` | 통과(대문자만으로도 영문자 조건 충족) |
| `Admin12345` | 거부 — 특수문자 없음 |
| `admin@@@@@` | 거부 — 숫자 없음 |
| `12345@6789` | 거부 — 영문자 없음 |
| `admin@123` | 거부 — 10자 미만 |

통과 예는 규칙 설명용입니다. 운영 비밀번호로 쓰지 않습니다. 규칙에 맞지 않거나 두 입력이 다르면 이유를 보여 주고 다시 받으며(한 실행에 3번), 3번 실패하면 아무것도 만들지 않습니다(`[사유: ADMIN_PASSWORD]`).

<a name="topic-admin--관리자-비밀번호를-묻는-명령"></a>
#### 관리자 비밀번호를 묻는 명령


| 명령 | 관리자 비밀번호 | 이유 |
|---|---|---|
| `decrypt`, `file decrypt` | 실행할 때마다 | 평문 출력 |
| `rekey` | 실행할 때마다(`--from-jar` JAR도 그 JAR의 비밀번호) | 기존 키로 복호화 |
| `keygen`, `kms datakey` | 실행할 때마다 | 새 비밀키 생성 |
| `config embed-key`, `config key add`·`use`·`remove`, `config set` | 실행할 때마다(`--jar`·`--from-jar` JAR도 그 JAR의 비밀번호) | JAR·키 변경 |
| `config show`, `config history`, `config key show` | 실행할 때마다(`--jar` JAR도 그 JAR의 비밀번호) | 관리정보를 마스킹 없이 조회, 키 원문 확인 |
| `admin password change` | 현재 비밀번호 | 검증값 변경 |
| `encrypt`, `file encrypt`, `verify`, `fingerprint`, `info`, `doctor`, `help` | 묻지 않음(최초 설정만 필요) | 평문·키 원문을 보여 주지 않음 |
| `admin setup` | 없음(미설정 JAR에서만) | 최초 설정 |

- **순서:** 인자·경로 검사(형식, 함께 쓸 수 없는 옵션, 결과 파일이 이미 있는지, 대화형 여부) → 관리자 인증(실행 중인 JAR, 그리고 `--jar`·`--from-jar` JAR) → 대상 JAR의 키·설정 확인(키 등록 여부·Key ID 충돌 등) → 사유(`--reason`) → 재료 입력·생성 → `CHANGE` 확인 → JAR 쓰기. 입력만으로 알 수 있는 오류는 비밀번호를 묻기 전에 알리고, 대상 JAR의 내용(어떤 키가 등록되어 있는지 등)은 인증한 뒤에만 판단합니다.

  인증에 실패하면 키 파일 읽기·키 생성·KMS 호출·파일·JAR 쓰기·복호화를 하나도 하지 않습니다. `decrypt`는 인증한 뒤에 설정을 읽고 암호문을 받습니다.
- **관리자 인증·사유·`CHANGE`는 서로 대신하지 않습니다.** `--yes`는 `CHANGE` 확인만 생략하고 관리자 인증·사유는 생략하지 않습니다.
- **다른 JAR:** `--jar`(바꾸거나 조회할 JAR)·`--from-jar`(키를 꺼내 쓰는 JAR)가 관리자 비밀번호를 쓰는 JAR이면 그 JAR의 비밀번호도 따로 확인합니다(실행 중인 JAR의 인증으로 대신하지 않음, 같은 비밀번호면 한 번만 입력). 미설정 JAR은 그 JAR로 먼저 `admin setup`을 해야 대상이 됩니다.

  `rekey --to-jar`는 그 JAR의 키로 암호화만 하고 JAR를 바꾸지 않으므로 비밀번호를 묻지 않지만, 그 JAR가 손상되었으면(아래 저장 방식) 쓰지 않습니다.

  예약 설정 영역이 없는 JAR는 읽기와 키 이관의 원본으로 지원합니다. 변경은 예약 영역이 있는 대상 JAR에 적용합니다.
- **비대화형(CI·Docker·배포 자동화):** `--admin-pass-file <파일>`로 비밀번호 한 줄(UTF-8, 1KiB 이하, 앞의 BOM 하나와 끝의 줄바꿈 하나는 무시)을 줍니다.

  최초 설정(`admin setup --admin-pass-file <파일>`, 같은 규칙 검사, 2회 입력 대신 파일 1회)과 민감 명령의 인증에 쓰며, 파일 내용은 저장된 검증값과 실제로 대조합니다. 이 옵션 없이 비대화형으로 실행하면 아무것도 하지 않고 실패합니다.

  비밀번호를 명령행 인자·환경변수·`-D`로 받는 기능은 없습니다. 비밀번호 파일 하나로 모든 대상 JAR를 확인하므로 비밀번호가 다른 JAR을 함께 다루려면 대화형으로 실행합니다. `admin password change`는 대화형 전용입니다.
- **비밀번호 파일 권한:** Linux·macOS에서는 다른 사용자(other)가 읽거나 쓸 수 있는 파일을 거부합니다(`[사유: ADMIN_AUTH]`, 설정은 `ADMIN_PASSWORD`, 파일 내용을 읽기 전에 확인). `umask 077`이나 `chmod 600`으로 만들고, 통제된 그룹만 읽게 하는 640·440도 허용합니다.

  심볼릭 링크는 최종 대상 파일의 권한을 봅니다(Kubernetes Secret 볼륨은 `defaultMode: 0400` 또는 `0440`). Windows(NTFS)에는 이 권한이 없어 검사하지 않으므로, 사용자 프로필 아래처럼 다른 사용자가 읽을 수 없는 폴더에 두고 작업이 끝나면 지웁니다([12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관)).
- **실패·재시도:** 대화형은 한 실행에 3번까지 다시 입력하고, 3번 틀리거나 빈 입력(취소)이면 아무것도 하지 않고 끝납니다(`[사유: ADMIN_AUTH]`). 새로 실행하면 다시 3번이며 영구 잠금은 없습니다(운영 중단을 막기 위함). 대신 검증값마다 PBKDF2 600,000회를 거쳐 대입 속도를 늦춥니다.
- **저장 방식:** JAR 예약 영역의 관리자 필드에 PBKDF2-HMAC-SHA256(16바이트 보안 난수 Salt, 600,000회, 32바이트) 결과만 둡니다. 원문·가역 표현은 없고, 저장된 값을 비밀번호로 넣어도 통과하지 않습니다. 이 항목은 설정이 아니어서 `-D`·외부 Properties로 바꿀 수 없고, 어떤 조회에도 원문·검증값·인증용 Salt를 보여 주지 않습니다(이력에는 설정·변경 사실과 작업자·사유만).
- **손상(Fail Closed):** 다음 JAR는 손상으로 보고 CLI가 그 JAR로는 아무것도 하지 않습니다(`[사유: INTEGRITY]`와 원인 한 줄, 관리정보 조회·키 원문 표시·내보내기·복호화·내부 갱신 모두 거부, 원본 그대로). 실행 중인 JAR뿐 아니라 `--jar`·`--from-jar`·`--to-jar`로 지정한 JAR도 같은 기준입니다. Java API·Tomcat은 관리자 상태를 검사하지 않으며, 설정을 읽을 때 예약 영역의 무결성을 검증합니다.
  - 검증값 형식 손상·알 수 없는 버전·반복 횟수 범위 밖
  - 검증값은 있는데 변경 이력이 없음(이력 삭제), 또는 이력의 관리자 기록이 맞지 않음(최초 설정 기록 누락·중복·순서 오류)
  - 이력에 관리자 설정 기록이 있는데 검증값 항목이 없음(검증값 삭제)
  - 변경 이력 자체의 손상(해시 체인·형식 오류), 이력 없이 JAR 안 설정을 바꿈(설정 지문 불일치)

  복구는 손상 전에 보관한 JAR이나 키 백업으로 다시 준비하는 것입니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)). 이력의 해시 체인은 키가 없는 SHA-256이므로 이 탐지는 실수·단순 수정·결손을 막는 것이고, 이력 파일을 처음부터 다시 계산하는 위조까지 막지는 못합니다.
- **한계:** CLI 사용 통제일 뿐입니다. JAR 파일을 읽거나 고칠 수 있는 사람은 내장 키를 직접 꺼내거나 검증값 항목을 바꿀 수 있고, 같은 JVM의 코드는 Java API로 복호화할 수 있습니다. 설정된 JAR을 복사하면 검증값도 함께 복사됩니다(사용자·서버별 독립 인증 아님). 분실·이전 JAR 처리: [12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계).

<a name="topic-admin--222-admin-setup--관리자-비밀번호-최초-설정"></a>
### `admin setup` — 관리자 비밀번호 최초 설정 (2.22)

**사용 상황:** 배포 JAR(또는 빌드한 JAR)로 CLI를 처음 쓸 때 한 번. 관리자 비밀번호가 없는 JAR에서만 실행되며(이미 설정된 JAR은 덮어쓰지 않고 거부), 독립 랜덤 pass·AES 키를 자동 생성해 현재 JAR에 검증값과 함께 저장합니다.

개념·규칙·인증 대상은 [1.4절](#topic-admin--14-cli-관리자-비밀번호)에 있습니다.

```text
java -jar <미설정 JAR> admin setup [--operator <작업자>] [--admin-pass-file <파일>] [--pass-export <파일>] [--replace] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--replace` | 아니요 | 같은 파일을 갱신하는 기존 스크립트 호환 옵션. |
| `--pass-export <파일>` | 아니요 | 최초 pass 키의 보호된 복원 파일을 새 경로에 저장합니다. |
| `--operator <ID>` | 아니요 | 이력에 남길 작업자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자). 대화형·비대화형 모두 생략 시 `SYSTEM` |
| `--admin-pass-file <파일>` | 비대화형이면 예 | 새 비밀번호 한 줄이 든 파일(UTF-8, 1KiB 이하, 앞의 BOM 하나·끝의 줄바꿈 하나 무시). 대화형 2회 입력 대신 파일을 1회 읽어 같은 규칙으로 검사. CI에서는 Secret을 권한을 좁힌 임시 파일로 만들고 실행 뒤 지움 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar java-crypto-kit-0.2.1.jar admin setup
```

```bash
# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar ./java-crypto-kit-0.2.1.jar admin setup

# 비대화형(CI): Secret을 권한 600 임시 파일로 만들어 쓰고 바로 지웁니다(값을 명령 줄·로그에 적지 않음).
umask 077; printf '%s\n' "$JCK_ADMIN_PASSWORD" > "$RUNNER_TEMP/admin.pw"

# 독립 구성으로 사용할 JAR 복사본 준비
cp ./java-crypto-kit-0.2.1.jar ./jck-ci.jar

# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar ./jck-ci.jar admin setup --admin-pass-file "$RUNNER_TEMP/admin.pw"
```

선택 옵션 `--pass-export <새 보호 파일>`은 생성된 pass 원문과 원래 ID·Salt·KDF를 복원 백업에 저장합니다. 작업자는 기본 SYSTEM이며 기존 자동화는 `--operator <ID>`를 지정할 수 있습니다.

**결과:** 대화형은 제목·규칙 한 줄 뒤에 새 비밀번호 → 비밀번호 확인을 받습니다.

규칙 위반·두 입력 불일치면 이유(`규칙에 맞지 않습니다: 특수문자 없음.`, `두 입력이 다릅니다.`)와 남은 기회를 보여 주고 다시 받으며, 3번 실패·빈 입력이면 아무것도 만들지 않습니다(`[사유: ADMIN_PASSWORD]`). 성공하면 생성된 키 ID, 갱신된 현재 JAR 경로 및 작업자를 표시합니다.

생성된 키와 키 ID를 검증값과 함께 저장하며 이력에 `admin setup [관리자]` 기록 1건(사유 `최초 설정`, 비밀번호·검증값 없음)이 더해집니다.

```text
[CLI 관리자 비밀번호 설정]
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)

새 관리자 비밀번호(입력 숨김):
규칙에 맞지 않습니다: 특수문자 없음. 다시 입력하세요(남은 기회 2번).
새 관리자 비밀번호(입력 숨김):
비밀번호 확인(입력 숨김):

관리자    : 비밀번호 설정 완료
활성 키   : pass=pass-0123456789abcdef0123456789abcdef
            key=key-<자동 생성 ID>
갱신 JAR  : C:\work\java-crypto-kit-0.2.1.jar
작업자    : SYSTEM
설정 JAR를 안전하게 백업하고 CLI·내장 키 Java/Tomcat에 사용하세요. 내장 pass 원문은 다시 조회할 수 없습니다.
```

**오류·주의:** 이미 설정된 JAR은 `[사유: ADMIN_SETUP] 이 JAR은 관리자 비밀번호가 이미 설정되어 있습니다(덮어쓰기 불가)`로 거부합니다(바꾸려면 [2.23절](#topic-admin--223-admin-password-change--관리자-비밀번호-변경)). 검증값이 손상됐거나 이력에 설정 기록이 있는데 검증값이 없는 JAR은 다시 설정할 수 없습니다(`INTEGRITY`, 신뢰하는 원본·백업으로 다시 준비). 관리자 기능이 없는 JAR에는 설정하지 않습니다(이 버전 JAR를 먼저 설정한 뒤 키 이관, [9.4절](../reference/troubleshooting.md#94-이전-형식-설정jar에서-올리기)). 최초 설정 후에는 같은 경로의 JAR로 계속 실행합니다.

<a name="topic-admin--223-admin-password-change--관리자-비밀번호-변경"></a>
### `admin password change` — 관리자 비밀번호 변경 (2.23)

**사용 상황:** 관리자 비밀번호를 바꿀 때(정기 변경, 담당자 교체 등). 현재 비밀번호를 알아야 하며 대화형 터미널에서만 실행합니다(새 비밀번호를 두 번 입력해 확인). 변경은 같은 JAR에 저장합니다.

```text
java -jar <설정된 JAR> admin password change [--operator <작업자>] [--reason <사유>] [--replace] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--replace` | 아니요 | 같은 파일을 갱신하는 기존 스크립트 호환 옵션. |
| `--operator <ID>` | 아니요 | 이력에 남길 작업자 식별자. 생략하면 `작업자 ID:`를 물음 |
| `--reason <사유>` | 사유 필수, 대화형은 질문 | 변경 사유(한 줄, 200자 이하, 비밀값 금지). 생략하면 `사유(비밀값 제외):`를 물음 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 현재 비밀번호로 인증한 뒤 새 관리자 비밀번호 설정
java -jar java-crypto-kit-0.2.1.jar admin password change --operator example-admin --reason "정기 변경"
```

```bash
# 현재 비밀번호로 인증한 뒤 새 관리자 비밀번호 설정
java -jar ./java-crypto-kit-0.2.1.jar admin password change --operator example-admin --reason "정기 변경"
```

**결과:** 현재 비밀번호 → (작업자 ID·사유) → 새 비밀번호 → 비밀번호 확인 순서로 받습니다.

현재 비밀번호가 3번 틀리면 바꾸지 않습니다(`ADMIN_AUTH`). 새 비밀번호가 규칙에 맞지 않거나, 두 입력이 다르거나, **현재 비밀번호와 같으면** 이유를 알리고 다시 받으며 3번 실패하면 바꾸지 않습니다(`ADMIN_PASSWORD`). 성공하면 갱신된 JAR에서는 새 비밀번호만 통하고, 키·키 ID·Salt·KDF·기존 암호문·이력은 그대로이며 이력에 `admin password change [관리자]` 기록(작업자·사유)이 더해집니다.

```text
[CLI 관리자 비밀번호 변경]
현재 관리자 비밀번호(입력 숨김):
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)
새 관리자 비밀번호(입력 숨김):
비밀번호 확인(입력 숨김):

관리자    : 비밀번호 변경 완료
갱신 JAR  : C:\work\java-crypto-kit-0.2.1.jar
작업자    : example-admin
사유      : 정기 변경
안내      : 같은 JAR에서 새 관리자 비밀번호를 사용하세요.
```

**주의:** 변경 전에 직접 복사한 JAR는 **이전 비밀번호로 계속 열립니다.** 서버·작업 PC에 보관한 복사본의 보관·폐기를 직접 정합니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)). 현재 비밀번호를 모르면 이 명령을 쓸 수 없고, 인증 없이 초기화하는 기능도 없습니다.

<a name="topic-admin--a1-준비-관리자-비밀번호와-보호된-폴더"></a>
### 준비: 관리자 비밀번호와 보호된 폴더 (A.1)

키를 둘 보호된 폴더를 만들고, 배포 JAR로 `admin setup`을 실행합니다. 이 명령은 관리자 비밀번호를 설정하고 독립된 랜덤 PASS·KEY를 함께 생성합니다(설정 전에는 Help·Examples 조회와 `admin setup`만 실행됩니다). 마지막 두 줄은 스크립트·CI 예제([A.5](key-management.md#topic-key-registration--a5-키-생성-화면에-한-번-보이는-생성값과---export)·[A.15](../reference/troubleshooting.md#a15-자주-보는-오류)·[A.16](#topic-admin--a16-관리자-비밀번호-변경인증-실패자동화))에서 쓸 관리자 비밀번호 파일을 화면에 보이지 않게 입력받아 만듭니다(비밀번호를 명령 줄·셸 기록에 남기지 않음).

```powershell
# 비밀 파일을 보관할 디렉터리 지정
$SECURE = "$HOME\jck-secure"

# 비밀 파일용 디렉터리 생성
New-Item -ItemType Directory -Force -Path $SECURE | Out-Null

# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar java-crypto-kit-0.2.1.jar admin setup

# 관리자 비밀번호 숨김 입력
$pw = Read-Host '관리자 비밀번호(파일용)' -AsSecureString

# 비밀값을 UTF-8 파일에 저장
[IO.File]::WriteAllText("$SECURE\admin.pw", [pscredential]::new('x', $pw).GetNetworkCredential().Password, [Text.UTF8Encoding]::new($false)); Remove-Variable pw
```

```bash
# 비밀 파일을 보관할 디렉터리 지정
SECURE=~/jck-secure

# 소유자 전용 디렉터리 생성
mkdir -p -m 700 "$SECURE"

# 관리자 비밀번호를 등록하고 같은 JAR에 랜덤 PASS (Passphrase)·KEY (AES Key) 저장
java -jar ./java-crypto-kit-0.2.1.jar admin setup

# 입력값을 소유자 전용 파일에 저장
IFS= read -r -s -p '관리자 비밀번호(파일용): ' pw; echo; (umask 077 && printf '%s\n' "$pw" > "$SECURE/admin.pw"); unset pw
```

```text
[CLI 관리자 비밀번호 설정]
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)

새 관리자 비밀번호(입력 숨김):                ← 규칙에 맞는 비밀번호(예제 값은 쓰지 않음)
비밀번호 확인(입력 숨김):                     ← 같은 값 다시 입력

관리자    : 비밀번호 설정 완료
활성 키   : pass=pass-0123456789abcdef0123456789abcdef
            key=key-<자동 생성 ID>
갱신 JAR  : C:\work\java-crypto-kit-0.2.1.jar
작업자    : SYSTEM
설정 JAR를 안전하게 백업하고 CLI·내장 키 Java/Tomcat에 사용하세요. 내장 pass 원문은 다시 조회할 수 없습니다.
```

이 부록의 `$SECURE`는 이 폴더입니다(키 파일·Passphrase 파일·내보낸 키와 복원 백업·관리자 비밀번호 파일). Windows에서 `C:\` 바로 아래 폴더를 쓰면 권한을 따로 제한합니다([12.2절](../reference/security.md#122-키-파일과-키-내장-jar-보관)). 운영 서버·CI에서는 비밀번호 파일을 Secret 저장소 값으로 작업할 때만 만들고 끝나면 지웁니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)).

<a name="topic-admin--a16-관리자-비밀번호-변경인증-실패자동화"></a>
### 관리자 비밀번호 변경·인증 실패·자동화 (A.16)

비밀번호 변경은 대화형 전용입니다(현재 비밀번호 → 새 비밀번호 2회). 변경 전에 복사한 JAR은 이전 비밀번호로 계속 열립니다.

```powershell
# 독립 구성으로 사용할 JAR 복사본 준비
Copy-Item -LiteralPath .\java-crypto-kit-0.2.1.jar -Destination admin2.jar

# 현재 비밀번호로 인증한 뒤 새 관리자 비밀번호 설정
java -jar admin2.jar admin password change --operator example-admin --reason "정기 변경"

# 설정 변경 이력과 작업 사유 확인
java -jar .\admin2.jar config history --all

# 관리자 인증 후 암호문을 복호화
java -jar .\admin2.jar dec
```

```bash
# 독립 구성으로 사용할 JAR 복사본 준비
cp ./java-crypto-kit-0.2.1.jar admin2.jar

# 현재 비밀번호로 인증한 뒤 새 관리자 비밀번호 설정
java -jar admin2.jar admin password change --operator example-admin --reason "정기 변경"

# 설정 변경 이력과 작업 사유 확인
java -jar ./admin2.jar config history --all

# 관리자 인증 후 암호문을 복호화
java -jar ./admin2.jar dec
```

```text
[CLI 관리자 비밀번호 변경]
현재 관리자 비밀번호(입력 숨김):              ← 지금 비밀번호
비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)
새 관리자 비밀번호(입력 숨김):                ← 새 비밀번호(현재와 달라야 함)
비밀번호 확인(입력 숨김):

관리자    : 비밀번호 변경 완료
갱신 JAR  : C:\work\admin2.jar
작업자    : example-admin
사유      : 정기 변경
안내      : 같은 JAR에서 새 관리자 비밀번호를 사용하세요.

#2  2026-11-23T06:10:02Z  수정자 example-admin  admin password change  [관리자]   ← config history --all
    사유: 정기 변경
    관리자 비밀번호: (설정됨) -> (변경됨)

관리자 비밀번호(입력 숨김):                   ← decrypt에 이전 비밀번호를 넣으면(실패 시연)
관리자 비밀번호가 맞지 않습니다. 다시 입력하세요(남은 기회 2번).
...
[java-crypto-kit] [사유: ADMIN_AUTH] 관리자 비밀번호가 맞지 않습니다(3번 실패). 아무것도 하지 않았습니다. 분실했다면 사용자 가이드 12.8을 보세요.
```

갱신된 JAR에서는 새 비밀번호만 통합니다. 실패해도 다음 실행은 다시 3번 시도할 수 있습니다(영구 잠금 없음). 스크립트·CI에서는 관리자 비밀번호를 파일로 줍니다.

비밀번호 파일은 한 줄(UTF-8)이며 권한을 좁히고(Linux·macOS는 `chmod 600` 등 다른 사용자가 읽을 수 없어야 받음) 작업 뒤 지웁니다.

```powershell
# 설정 변경 이력과 작업 사유 확인
java -jar .\java-crypto-kit-0.2.1.jar config history --type key --admin-pass-file "$SECURE\admin.pw"
```

```bash
# 설정 변경 이력과 작업 사유 확인
java -jar ./java-crypto-kit-0.2.1.jar config history --type key --admin-pass-file "$SECURE/admin.pw"
```

```text
JAR 설정 변경 이력: java-crypto-kit-0.2.1.jar (버전 0.2.1)
빌드 일시 : 2026-11-23T05:05:18Z
이력 검증 : 정상(1건, 해시 체인·현재 설정 일치)
표시 범위 : key 관련 0건(전체 1건)
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-cli"></a>

## 명령 찾기 및 공통 사용 규칙

<a name="topic-cli--cli-명령과-공통-옵션"></a>
<a name="topic-cli--2-cli-명령"></a>
<a name="topic-cli--21-공통-규칙"></a>
### 공통 규칙 (2.1)

<a name="topic-cli--실행-환경과-기본-옵션"></a>
#### 실행 환경과 기본 옵션

- **형식:** `java [-D<설정>=<값> ...] -jar <JAR> <명령> [옵션]`. 체험은 `admin setup`이 만든 PASS·KEY로, 운영은 업무 키를 등록한 JAR(또는 외부 키 설정)로 실행합니다. 배포 JAR은 먼저 [1.4절](#topic-admin--14-cli-관리자-비밀번호)대로 `admin setup`을 실행합니다(관리자 비밀번호 설정과 PASS·KEY 생성). 설정 전에도 Help·Examples는 조회할 수 있고, 그 밖의 명령은 최초 설정을 요구합니다.

- **관리자 비밀번호:** 민감 명령(복호화·키 생성/등록/변경/삭제·키와 설정 조회, [2.2절](#topic-cli--22-명령-목록)의 `*`)은 실행할 때마다 `관리자 비밀번호(입력 숨김):`를 먼저 묻습니다(3번까지, 취소하면 아무것도 하지 않음). 비대화형은 `--admin-pass-file <파일>`로 줍니다.

  순서는 인자·경로 검사 → 관리자 인증 → 대상 JAR의 키 확인 → 사유 → 재료 입력·생성 → `CHANGE` 확인이며(인증 전에는 키 등록 여부 같은 JAR 내용을 알리지 않음), `--yes`는 관리자 인증을 생략하지 않습니다.

- **`-Dcrypto.*`** 는 `java`와 `-jar` **사이**에 둡니다. PowerShell은 따옴표로 감쌉니다(예: `java "-Dcrypto.lang=en" -jar .\java-crypto-kit-0.2.1.jar info`).

- **`--lang ko|en`** 은 그 실행 한 번의 언어만 바꿉니다. 기본 언어는 설정 `crypto.lang`(기본 `ko`)입니다.

- **한글이 나오지 않을 때(영어 자동 전환):** 언어가 `ko`여도 콘솔 문자 인코딩이 한글을 표현할 수 없으면(예: Linux `LANG=C`·`POSIX`, 한글이 없는 Windows 코드 페이지 437 등) 표준 오류에 `[java-crypto-kit] Console encoding ... cannot show Korean, so English is used` 한 줄을 보여 주고 영어로 출력합니다(글자 깨짐 방지, 오류가 아님). 한글로 보려면 Linux는 `export LANG=C.UTF-8`(또는 `ko_KR.UTF-8`), Windows PowerShell 5.1은 한국어 Windows 기본 코드 페이지 949(`chcp 949`)에서 실행합니다(PowerShell 7·Windows Terminal도 같은 콘솔 코드 페이지를 따름). `--lang ko`를 직접 주면 자동 전환하지 않으므로 한글을 표현하지 못하는 콘솔에서는 글자가 깨질 수 있습니다.

  항상 영어로 쓰려면 `--lang en` 또는 `crypto.lang=en`입니다.

- **`--help`** 또는 **`-h`** 는 명령 사용법을 보여 줍니다. 도움말은 키 파일·DB가 없어도 실행됩니다.

- **옵션 값:** 값을 받는 옵션은 `--옵션 값`과 `--옵션=값` 모두 됩니다. 값을 받는 옵션과 `config set`의 `<설정>=<값>`은 같은 것을 두 번 쓰면 오류로 멈춥니다. 플래그(`--yes`·`--replace`·`--offline`)는 값 없이 쓰며(`--yes=true`처럼 쓰면 오류) 두 번 써도 한 번으로 처리합니다. `--lang`을 여러 번 쓰면 마지막 값이 적용됩니다. 각 명령 표에 있는 옵션만 쓸 수 있습니다.

- **대화형 입력:** 관리자 비밀번호(`--admin-pass-file`이 없을 때), `encrypt`·`decrypt`, 재료 옵션 없이 pass 키를 추가하는 `config key add`, `--value` 없이 실행한 `verify`·`rekey`, `--reason` 없이 실행한 키 생성·변경 명령의 사유, `--yes` 없는 키 변경 확인은 입력을 터미널에서 받으므로 실제 PowerShell·명령 프롬프트·Linux 터미널(ssh)에서 실행합니다.

  IDE 콘솔·파이프·리다이렉트·스크립트에서는 입력을 숨기거나 물어볼 수 없어 실행하지 않습니다(필요한 값을 옵션으로 미리 줌).

<a name="topic-cli--키-선택과-변경"></a>
#### 키 선택과 변경

- **키 선택:** 새 암호화(`encrypt`·`file encrypt`)는 옵션이 없으면 기본 유형(`crypto.key.type`, 기본 `pass`)의 기본 키, `--type pass|key`면 그 유형의 기본 키, `--key-id <ID>`면 그 키(유형은 키에서 자동), 둘 다 주면 유형을 확인한 뒤 그 키를 씁니다.

  고르지 못하면 다른 키로 바꾸지 않고 `CONFIGURATION`으로 실패합니다. 복호화(`decrypt`·`verify`·`file decrypt`·Tomcat)는 유형을 고르지 않고 암호문(파일은 헤더)의 키 ID로 등록된 키를 찾습니다([5.5절](key-management.md#topic-key-management--55-키-목록과-유형-선택)).

- **변경 사유:** 키를 만들거나 바꾸는 명령(`keygen`, `kms datakey`, `config embed-key`, `config key add|use|remove`, 키에 영향을 주는 `config set`)에는 `--reason <사유>`(한 줄, 200자 이하, 비밀값을 적지 않음)가 필요합니다.

  빠지면 대화형 터미널에서는 실행 전에 `사유(비밀값 제외):`를 묻고(빈 입력은 중단), 스크립트·CI에서는 키 생성·KMS 호출·JAR 변경 전에 `USAGE`로 끝납니다. `--yes`는 확인만 생략하며 사유를 대신하지 않습니다.

  JAR를 바꾸는 명령의 사유는 JAR 변경 이력([`config history`](key-management.md#topic-history--211-config-history--설정-변경-이력))에 남고, JAR를 바꾸지 않는 `keygen`·`kms datakey`의 사유는 결과 화면에만 나오며 **어디에도 저장되지 않습니다**(결과의 `이력 : 저장 안 함`).

- **키 변경 확인:** 실제 키나 기본 키·기본 유형이 바뀌는 JAR 변경(`config embed-key`, `config key add|use|remove`, 키에 영향을 주는 `config set`)은 확인 화면에 기존 암호문에 주는 영향(제목), 대상 JAR, 사유, 바뀌는 항목(이전 -> 이후)을 보여 주고 `CHANGE` 입력을 받습니다. 무인 자동화는 `--yes`로 생략합니다. 확인 전에 취소하거나 갱신을 시작하기 전에 실패하면 JAR의 설정·키·이력은 그대로입니다. 갱신은 비활성 영역에 새 상태를 쓰고 다시 읽어 확인한 뒤 선택자를 바꾸므로, 선택자를 바꾸기 전에 중단되면 이전 상태가, 바꾼 뒤에 중단되면 새 상태가 사용됩니다([4.4절](../reference/technical-specification.md#44-jar-내부-예약-영역-갱신)). 선택자를 바꾼 뒤의 동기화·이전 영역 정리 단계에서 오류가 보고되면 새 상태가 이미 적용됐을 수 있으므로, 다시 실행하기 전에 `config show`와 `config history --all`로 적용 상태를 먼저 확인합니다.

- **비밀값은 인자로 넘기지 않습니다.** 평문 비밀번호·AES 키·Passphrase·Vault 토큰·관리자 비밀번호를 받는 명령 옵션이나 `-D`는 없습니다(키 재료와 관리자 비밀번호는 파일·숨김 입력·생성으로만 받음).

<a name="topic-cli--결과-출력과-비밀정보-표시"></a>
#### 결과 출력과 비밀정보 표시

- **출력:** 한 명령은 "입력(필요할 때) → 결과"입니다. 결과(암호문·평문·조회 내용)는 표준 출력에, 오류와 경고는 표준 오류에 씁니다.

  정상 실행에는 다음 단계 안내나 권고 문구를 붙이지 않습니다(예외: 자동 생성 직후의 짧은 보관 안내, 관리자 비밀번호 설정·변경 결과의 사용할 JAR 안내, 원문 표시 뒤 주의 안내. 운영·보안 참고는 [12장](../reference/security.md#12-운영보안-참고)). 입력 프롬프트는 `암호화할 값(입력 숨김):`처럼 짧고, 입력한 글자는 화면에 보이지 않습니다.

  여러 항목(바꾼 설정, 적용·무시한 `-D` 등)은 한 줄에 하나씩 값 열에 맞춰 보여 주고, 한 항목이 80열을 넘으면 설정 이름 다음과 `->` 앞에서만 줄을 바꿉니다(경로·URL·지문·암호문 같은 값은 자르지 않음).

- **키 미설정:** 두 유형을 지원합니다. PASS (Passphrase)는 `--type pass`, KEY (AES Key)는 `--type key`로 선택합니다. 특정 유형의 활성 키가 없으면 그 유형의 등록 및 활성 키 ID를 확인합니다.
- **공개 키 차단:** 어느 공급원에서든 공개된 기본 키는 사용할 수 없습니다. 파일·환경변수·Vault의 공개된 기본 Passphrase도 Salt와 반복 횟수와 관계없이 차단합니다.

- **키 지문·관리정보 표시:** 관리자 인증 뒤 보는 `config show`·`config history`·`config key show`는 관리정보(64자 전체 지문, pass는 KDF·반복 횟수·Salt·Salt SHA-256, 작업자·사유)를 마스킹 없이 보여 줍니다.

  인증 없이 쓰는 `info`·`doctor`와 변경 결과 화면(`config embed-key`·`config key add`)은 키 지문을 `ab12cd34ef56...7890abcd`처럼 앞 12자와 뒤 8자만 보여 주고, 정확히 비교하는 `fingerprint`·`keygen`·`kms datakey`와 pass 키 생성 화면은 64자 전체를 보여 줍니다.

  등록된 키의 원문은 관리자 인증 뒤 [`config key show`](key-management.md#topic-key-export--224-config-key-show--키-관리정보원문-확인)에서만 다루며(화면 표시 `--show`는 노출 경고 뒤 `SHOW`를 정확히 입력해야 하고 대화형 전용, 새 파일로 내보내는 `--export`는 `SHOW` 없이 비대화형에서도 됨), 관리자 비밀번호 원문·검증값은 어떤 조회에도 나오지 않습니다.

- **자동 생성값 표시:** `keygen`과 `config key add --generate`는 대화형 터미널에서 성공 직후 생성한 원문 전체(pass: Passphrase, key: 키 파일과 같은 표준 Base64 한 줄)를 **한 번만** 값만 있는 한 줄로 보여 줍니다(`--show` 같은 옵션 없음). 표준 출력·표준 오류·로그로는 내보내지 않으므로 스크립트·CI에서는 보이지 않고, 그래서 대화형이 아닌 `config key add --generate`는 `--export <파일>`이 있어야 생성합니다(없으면 생성 전에 중단). 보관·재등록·복구: [5.6절](key-management.md#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구).

- **종료 코드:** 0 = 성공, 1 = 실패. `doctor`는 FAIL이 하나라도 있으면 1입니다.

- **오류 형식:** 표준 오류에 한 줄로 `[java-crypto-kit] [사유: 코드] 원인 조치: 확인할 내용`(영어 `[reason: CODE] ... Action: ...`)을 출력합니다. 코드별 조치는 [9.3절](../reference/troubleshooting.md#93-오류-코드별-조치)에 있습니다.

<a name="topic-cli--22-명령-목록"></a>
### 명령 목록 (2.2)

`config`, `file`, `kms`, `admin`은 명령 그룹이며 아래 하위 명령으로 실행합니다(`config key`는 그 아래 `add`·`use`·`remove`·`show`, `admin password`는 `change`). `*` 표시 명령은 실행할 때마다 관리자 비밀번호를 확인합니다([1.4절](#topic-admin--14-cli-관리자-비밀번호)).

| 구분 | 명령 | 용도 |
|---|---|---|
| 관리자 | [`admin setup`](#topic-admin--222-admin-setup--관리자-비밀번호-최초-설정) · [`admin password change`](#topic-admin--223-admin-password-change--관리자-비밀번호-변경) `*` | 관리자 비밀번호 최초 설정 / 변경(같은 JAR 갱신) |
| 문자열 | [`encrypt`](#topic-cli-encryption--23-encrypt--문자열-암호화) · [`decrypt`](#topic-cli-encryption--24-decrypt--문자열-복호화) `*` · [`verify`](#topic-cli-encryption--25-verify--복호화-가능-여부-확인) | DB 비밀번호 등 암호화 / 평문 표시 / 평문 없이 검증 |
| 키 | [`keygen`](key-management.md#topic-key-generation--26-keygen--새-키-파일-만들기) `*` · [`config embed-key`](key-management.md#topic-key-generation--27-config-embed-key--사용자-지정-키-내장) `*` · [`fingerprint`](key-management.md#topic-key-generation--28-fingerprint--키가-같은지-비교) · [`rekey`](key-management.md#topic-key-rotation--29-rekey--기존-암호문을-새-키로-바꾸기) `*` | 새 AES 키 파일 / 현재 JAR에 AES 키 내장 / 키 비교 / 다른 키로 재암호화 |
| 키 목록 | [`config key add`](key-management.md#topic-key-registration--218-config-key-add--키-추가) `*` · [`config key use`](key-management.md#topic-key-defaults--219-config-key-use--기본-키-변경) `*` · [`config key remove`](key-management.md#topic-key-defaults--220-config-key-remove--키-제거) `*` · [`config key show`](key-management.md#topic-key-export--224-config-key-show--키-관리정보원문-확인) `*` | pass·key 키 추가 / 유형별 기본 키 변경 / 키 제거(같은 JAR 갱신) / 키 관리정보·원문 확인 |
| JAR 설정 | [`config show`](#topic-cli-settings--210-config-show--jar-내장값-조회) `*` · [`config history`](key-management.md#topic-history--211-config-history--설정-변경-이력) `*` · [`config set`](#topic-cli-settings--212-config-set--jar-기본-설정-변경) `*` | 내장값 조회 / 변경 이력 / 기본 설정 변경 |
| 점검 | [`info`](#topic-cli-settings--213-info--실행-시-적용-설정과-출처) · [`doctor`](#topic-cli-settings--214-doctor--설정과-키-진단) | 최종 적용 설정과 출처 / 설정·키·암복호화 진단 |
| 파일 | [`file encrypt`](file-encryption.md#topic-file-encryption--215-file-encrypt--파일-암호화) · [`file decrypt`](file-encryption.md#topic-file-encryption--216-file-decrypt--파일-복호화) `*` | CSV·PDF·이미지 등 파일 암복호화 |
| AWS KMS | [`kms datakey`](external-key-providers.md#topic-aws-kms--217-kms-datakey--aws-kms-데이터-키-파일-만들기) `*` | KMS가 보호하는 데이터 키 파일 만들기 |
| 도움말 | [`help`, `config help` 등](#topic-cli--221-도움말-명령) | 전체 명령, 버전, 설정 목록, 기능별 예제 |

<a name="topic-cli--221-도움말-명령"></a>
### 도움말 명령 (2.21)

| 알고 싶은 것 | 명령 | 내용 |
|---|---|---|
| 어떤 기능이 있나 | `help` | 버전, 전체 명령 목록, 외부 설정 지정 방법, 오류 형식 |
| 설정 값 | `config help` | `config` 하위 명령, 설정 우선순위, `crypto.*` 설정의 이름·허용값·기본값 표(80열)와 키 목록 항목 이름. 목적·예제·주의는 이 가이드 [10장](../reference/configuration.md#10-설정-사전) |
| 키 목록 | `help config key`, `config key add --help` 등 | 키 추가·기본 키 변경·제거 명령, 유형 및 공개된 기본 키 차단 |
| Tomcat 설정 | `help tomcat` | 적용 5단계와 Resource 핵심 속성, 지원 버전. 전체 Resource 예제는 [3장](tomcat-jdbc.md#topic-tomcat--3-tomcat-jndi-연동) |
| Vault·KMS | `help vault`, `help aws-kms` | 필수 설정·준비 항목·확인 명령 |
| 명령 하나의 옵션 | `<명령> --help` | 그 명령의 용도, 실제 옵션 전체, 결과 모양, 예제 |
| 복사용 예제 | `file --examples`, `config key add --examples`, `api jwt --examples` | 명령이나 기능군의 실행 예제 |
| 관리자 비밀번호 | `admin setup --help`, `admin password change --help` | 최초 설정·변경 방법과 비밀번호 규칙 |

전체·기능별 Help와 Examples는 관리자 비밀번호 없이 배포 JAR와 설정 완료 JAR에서 조회할 수 있습니다. 기존 명령과 `api`의 Examples는 같은 초기 설정 안내를 표시합니다. 배포 JAR에서 조회했다면 `admin setup`을 그 JAR로 실행하고, 최초 설정이 완료되면 암복호화 등 실무 명령도 같은 파일명과 경로의 JAR로 실행하세요. `admin setup --examples`는 최초 설정용 배포 JAR를 안내합니다. 조회는 사용자 설정·키 파일을 읽거나, 인증 상태를 검사하거나, 외부에 접속하지 않습니다. 인자 없이 미설정 JAR를 실행하면 초기 설정 절차와 조회 방법을 함께 표시합니다. 실제 업무 명령에는 명령별 관리자 정책이 적용됩니다. Help는 기본 배포 JAR 이름 기준 80열로 표시합니다.

예외는 필수 옵션을 모두 쓴 복사용 예제 세 줄(`config embed-key`, `config key remove`, 비대화형 `admin setup`)입니다(사유를 생략하는 대화형 명령은 실행할 때 물어봄). 그 밖의 긴 예제(`config set --replace`·키 파일 전환·Pool 선택, `config key add`의 공급원별 예제, KMS `--from-file`·`--config`, 셸별 `CP` 만들기)는 이 가이드의 명령별 절과 [부록 A](#topic-cli--부록-a-실무-명령어집)에 있습니다.

`tomcat`·`vault`·`aws-kms`는 도움말 주제이며 실행 명령이 아닙니다.

```powershell
# 명령의 옵션과 사용법 조회
java -jar .\java-crypto-kit-0.2.1.jar --help

# 설정 이름과 허용값 조회
java -jar .\java-crypto-kit-0.2.1.jar config help

# CLI 사용법 조회
java -jar .\java-crypto-kit-0.2.1.jar help tomcat

# 명령의 옵션과 사용법 조회
java -jar .\java-crypto-kit-0.2.1.jar config set --help --lang en

# 실행 전 명령별 실무 예제 확인
java -jar .\java-crypto-kit-0.2.1.jar config key add --examples

# 실행 전 명령별 실무 예제 확인
java -jar .\java-crypto-kit-0.2.1.jar api jwt --examples
```


<a name="topic-cli--부록-a-실무-명령어집"></a>
### 부록 A. 실무 명령어집

자주 하는 작업을 순서대로 모은 명령입니다. 각 상황에 Windows PowerShell과 Linux bash 명령을 나눠 적고, 입력 프롬프트와 기대 결과를 붙였습니다.

 옵션의 전체 의미는 [2장](#topic-cli--2-cli-명령)에 있습니다.

- 명령은 [A.1](#topic-admin--a1-준비-관리자-비밀번호와-보호된-폴더)에서 관리자 비밀번호를 설정한 JAR(`java-crypto-kit-0.2.1.jar`)이 있는 폴더에서 실행합니다. 일부 예제는 독립된 구성을 위해 먼저 JAR를 직접 복사합니다. 복사한 JAR에도 같은 관리자 비밀번호가 이어집니다.
- 복호화·키 관리·`config show`·`config history`·`config key show` 같은 민감 명령은 `관리자 비밀번호(입력 숨김):`를 먼저 묻습니다(아래 화면의 그 줄). 스크립트·CI에서는 `--admin-pass-file <파일>`을 붙입니다.
- 키를 만들거나 바꾸는 명령에는 사유(`--reason`)를 붙였습니다. 빼면 대화형 터미널에서 `사유(비밀값 제외):`를 묻고([A.7](key-management.md#topic-key-defaults--a7-기본-키기본-유형-바꾸기)), 스크립트·CI에서는 아무것도 바꾸기 전에 오류로 끝납니다.
- 지문·Salt·암호문은 실행할 때마다 달라집니다. 아래 결과의 값은 예시이며 모양만 같으면 정상입니다. 자동 생성값(비밀 원문)은 `<생성 결과>`로 적었습니다.
- 명령의 `'ENC[v1:<키 ID>:...]'`는 **자리표시자**입니다. 그 키로 앞 단계에서 실제로 만든 암호문 한 줄 전체(대괄호 포함)로 바꿔 실행합니다. **실패 시연**이라고 적은 명령은 오류 화면을 보여 주려고 일부러 틀리게 적은 것입니다.
- 숨김 입력(`(입력 숨김):`)·사유 질문·`CHANGE` 확인은 실제 터미널에서 입력합니다. 무인 실행에는 `--yes`를 붙입니다(키 변경 확인만 생략, 사유는 필요). 숨김 입력이 필요한 명령은 스크립트·파이프에서 실행하지 않습니다.
- 공개된 기본 키로 만든 데이터는 격리된 환경에서 이전 버전 JAR로 복호화한 뒤 새 키로 다시 암호화하세요.
- 최초 설정은 Linux에서 소유자 전용 권한(600)으로 저장합니다. 배포 시 서비스 계정의 접근 권한을 확인합니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-cli-encryption"></a>

## 문자열 암호화·복호화·검증

<a name="topic-cli-encryption--cli-문자열-암복호화"></a>
<a name="topic-cli-encryption--1-cli-암복호화"></a>
<a name="topic-cli-encryption--23-encrypt--문자열-암호화"></a>
### `encrypt` — 문자열 암호화 (2.3)

**사용 상황:** DB 비밀번호(필요하면 DB 계정도)를 `ENC[...]`로 바꿔 Tomcat Resource 등에 넣을 때. 운영에서는 **WAS가 쓰는 것과 같은 키·키ID를 가진 JAR(또는 같은 외부 설정)** 로 실행합니다.

```text
java -jar <JAR> enc [--type pass|key] [--key-id <키 ID>] [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--type pass\|key` | 아니요 | 키 유형. 생략하면 `crypto.key.type`(기본 `pass`). 그 유형의 기본 키(`crypto.key.active.pass`·`crypto.key.active.key`)를 씀 |
| `--key-id <ID>` | 아니요 | 등록된 키 ID로 직접 선택(유형은 키에서 자동). `--type`과 함께 쓰면 유형이 같은지 확인한 뒤 사용 |
| `--config <경로>` | 아니요 | WAS와 같은 외부 설정 파일로 암호화할 때. 생략하면 JAR 내장 설정(또는 `-Dcrypto.config.file`·`CRYPTO_CONFIG_FILE`) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 설정 JAR의 활성 pass 키
java -jar .\java-crypto-kit-0.2.1.jar enc

# 최초 설정에서 생성한 활성 AES 키로 암호화
java -jar .\java-crypto-kit-0.2.1.jar enc --type key

# 운영: 그 JAR의 기본 키
java -jar .\java-crypto-kit-0.2.1.jar enc

# 입력한 값을 활성 키로 암호화
java -jar .\java-crypto-kit-0.2.1.jar enc --key-id key01
```

```bash
# 입력한 값을 활성 키로 암호화
java -jar ./java-crypto-kit-0.2.1.jar enc

# 입력한 값을 활성 키로 암호화
java -jar ./java-crypto-kit-0.2.1.jar enc --type key --config /etc/java-crypto-kit/app.properties
```

정식 명령으로 실행하려면 `java -jar ./java-crypto-kit-0.2.1.jar encrypt --lang ko`를 사용합니다.

**결과:** 키를 먼저 고른 뒤 평문을 화면에 보이지 않게 입력받고, 표준 출력에 암호문 한 줄만 씁니다(설정이 `base64`면 `B64[...]`). 이 한 줄 전체(대괄호 포함)를 Tomcat Resource의 `password`에 넣습니다.

암호문에 키 ID가 들어 있으므로 복호화할 때 유형을 고르지 않습니다. 같은 평문도 매번 다른 암호문이 나오는 것이 정상입니다. 공개된 기본 키를 선택하면 실행이 실패합니다.

```text
암호화할 값(입력 숨김):
ENC[v1:app-pass:...]
```

**오류·주의:** 등록되지 않은 키 ID·유형 불일치·잘못된 `--type`은 평문을 묻기 전에 실패합니다(`CONFIGURATION`/`USAGE`). IDE 콘솔·파이프에서 실행하면 대화형 터미널 오류로 거부합니다.

키 파일 누락 등 `KEY_SOURCE` 오류는 `doctor`로 원인을 확인합니다. 평문을 명령 인자로 받는 옵션은 없습니다(셸 기록·프로세스 목록 노출 방지).

<a name="topic-cli-encryption--24-decrypt--문자열-복호화"></a>
### `decrypt` — 문자열 복호화 (2.4)

**사용 상황:** 암호문의 실제 값을 확인할 때. 복호화 가능 여부만 보려면 [`verify`](#topic-cli-encryption--25-verify--복호화-가능-여부-확인)를 씁니다.

```text
java -jar <JAR> dec [--config <외부 Properties>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 키 내장 JAR와 다른 외부 키 공급 설정으로 복호화할 때 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 관리자 인증 후 암호문을 복호화
java -jar .\java-crypto-kit-0.2.1.jar dec
```

```bash
# 관리자 인증 후 암호문을 복호화
java -jar ./java-crypto-kit-0.2.1.jar dec
```

정식 명령으로 실행하려면 `java -jar ./java-crypto-kit-0.2.1.jar decrypt --lang ko`를 사용합니다.

**결과:** 먼저 관리자 비밀번호를 확인하고([1.4절](#topic-admin--14-cli-관리자-비밀번호), `--admin-pass-file`을 주면 묻지 않음), 그다음 `ENC[...]`/`B64[...]` 암호문을 화면에 보이지 않게 **한 번** 입력하면, 암호문의 키 ID로 등록된 키(pass·key 모두)를 찾아 AES-GCM 인증 태그 검증에 성공한 경우에만 표준 출력에 `복호화 결과: <평문>`을 바로 표시합니다.

별도의 확인 입력은 없습니다. 평문 안의 공백·줄바꿈은 그대로 출력합니다. 암호문을 명령 인자로 받지 않으며 대화형 터미널에서만 실행합니다.

```text
관리자 비밀번호(입력 숨김):
암호문(입력 숨김):
복호화 결과: example-value
```

**오류·주의:** 관리자 비밀번호가 3번 틀리거나 입력을 취소하면 암호문을 받지 않고 `ADMIN_AUTH`로 끝납니다.

검증에 실패하면 평문 없이 `INTEGRITY`·`KEY_ID_MISMATCH`(그 키 ID가 이 설정에 등록되지 않음) 등의 오류로 끝납니다(종료 코드 1). 다른 키로 다시 시도하지 않습니다.

키나 암호문이 다른 경우이므로 [`fingerprint`](key-management.md#topic-key-generation--28-fingerprint--키가-같은지-비교)로 키부터 비교합니다. 평문이 화면에 표시되므로 화면 공유·터미널 기록 관리는 [12.3절](../reference/security.md#123-평문을-다루는-명령)을 봅니다.

<a name="topic-cli-encryption--25-verify--복호화-가능-여부-확인"></a>
### `verify` — 복호화 가능 여부 확인 (2.5)

**사용 상황:** 암호문이 현재 키로 복호화되는지 평문을 보여 주지 않고 확인할 때(배포 전 점검, 자동화 점검).

```text
java -jar <JAR> verify [--config <외부 Properties>] [--value <암호문>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 확인할 WAS와 같은 외부 설정을 쓸 때 |
| `--value <ENC/B64 암호문>` | 아니요 | 암호문을 인자로 주는 자동화 점검. 생략하면 화면에 보이지 않게 입력. 평문을 받는 옵션이 아님 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 대화형(권장: 암호문이 셸 기록에 남지 않음)
java -jar .\java-crypto-kit-0.2.1.jar verify

# 자동화에서만: 셸 기록에 암호문이 남습니다
java -jar .\java-crypto-kit-0.2.1.jar verify --value 'ENC[v1:key01:실제IV:실제암호문]'
```

```bash
# 평문 표시 없이 암호문의 무결성 확인
java -jar ./java-crypto-kit-0.2.1.jar verify
```

**결과:** 암호문의 키 ID로 등록된 키를 찾아 키·AES-GCM 인증 태그가 맞으면 `OK` 한 줄(종료 0)이며 평문은 표시하지 않습니다. 맞지 않으면 사유 코드와 함께 종료 코드 1입니다. DB 계정·비밀번호가 실제 DB에 맞는지는 검사하지 않습니다.

**오류·주의:** `KEY_ID_MISMATCH`면 키 내장 JAR의 키 목록(`config show`·`info`)과 암호문의 키ID를 비교하고, `INTEGRITY`면 키 지문과 암호문 변조 여부를, `INVALID_TOKEN`이면 암호문 전체를 다시 복사했는지 확인합니다.

<a name="topic-cli-encryption--a2-체험-공개-키로-암호화복호화검증"></a>
### 설정 JAR로 암호화·복호화·검증 (A.2)

```sh
# 활성 pass 키로 입력값을 암호화
java -jar java-crypto-kit-0.2.1.jar enc

# 이전 단계에서 복사한 암호문 전체를 입력해 인증 태그 확인
java -jar java-crypto-kit-0.2.1.jar verify

# 관리자 비밀번호와 같은 암호문을 입력해 원문 확인
java -jar java-crypto-kit-0.2.1.jar dec
```

AES 유형의 활성 키를 쓰려면 첫 단계에서 `enc --type key`를 실행하세요. 복호화할 때는 암호문에 기록된 키 ID를 읽습니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-cli-settings"></a>

## 설정 변경 및 진단

<a name="topic-cli-settings--cli-설정-및-진단"></a>
<a name="topic-cli-settings--210-config-show--jar-내장값-조회"></a>
### `config show` — JAR 내장값 조회 (2.10)

**사용 상황:** JAR 안에 저장된 기본 설정·키 관리정보와 최근 변경 요약을 확인할 때. 관리자 비밀번호를 확인한 뒤 보여 줍니다(`--jar`로 다른 JAR를 보면 그 JAR의 비밀번호도 확인, 미설정 JAR은 볼 수 없음).

```text
java -jar <실행 JAR> config show [--jar <조회할 JAR>] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--jar <경로>` | 아니요 | 다른 JAR의 내장 설정을 볼 때. 생략하면 실행 중인 JAR |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# JAR에 저장된 키 목록과 설정 조회
java -jar .\java-crypto-kit-0.2.1.jar config show

# 보호된 backup 폴더의 다른 JAR 설정 조회
java -jar .\java-crypto-kit-0.2.1.jar config show --jar .\backup\java-crypto-kit-0.2.1.jar
```

```bash
# JAR에 저장된 키 목록과 설정 조회
java -jar ./java-crypto-kit-0.2.1.jar config show

# 보호된 backup 폴더의 다른 JAR 설정 조회
java -jar ./java-crypto-kit-0.2.1.jar config show --jar ./backup/java-crypto-kit-0.2.1.jar
```

다른 JAR를 조회하려면 `backup`에 해당 파일이 있어야 합니다. 대상 JAR의 관리자 인증 규칙도 적용하며 두 JAR를 모두 읽기 전용으로 엽니다.

**결과:** 첫 줄에 JAR 내부 값임을 밝히고, JAR 파일·버전, 이력 상태(변경 횟수·마지막 시각·수정자), 관리자 비밀번호 상태, 빌드 일시, **기본 유형·유형별 기본 키·키 목록**(키마다 유형·공급원·상태 한 줄과 그 아래 64자 전체 지문, pass는 KDF·반복 횟수·Salt·Salt SHA-256), 설정 파일 지문, 설정 검증 결과를 한 번 보여 준 뒤 내장 설정값 전체를 한 번만 나열합니다.

관리정보는 마스킹하지 않고, 키 원문만 `(비공개)`로 표시합니다(원문 확인: [`config key show --key-id <ID> --show`](key-management.md#topic-key-export--224-config-key-show--키-관리정보원문-확인)).

```text
관리자 비밀번호(입력 숨김):
JAR 내부 설정 (외부 설정·-D 미반영, 실행 시 적용값은 info)
JAR 파일  : java-crypto-kit-0.2.1.jar (버전 0.2.1)
상태      : 변경 2회 - 마지막 2026-11-22T05:30:12Z, 수정자 example-admin
관리자    : 비밀번호 설정됨(민감 명령은 관리자 인증 필요)
빌드 일시 : 2026-11-21T00:00:00Z
기본 유형 : pass
기본 키   : pass=app-pass, key=key01
키 목록   :
  key01: key, embedded, 사용자 지정, crypto.key.*
    키 지문: ab12cd34...(64자 전체)
  key-<생성 ID>: key, embedded, 사용자 지정
    키 지문: aac695cbd2498e97131ae49579a219c5e7f41e87e2738ba49199847c00e41a49
  app-pass: pass, embedded, 사용자 지정
    키 지문: 3dca588c78a17aad886e9403e8743990d79d479bbe610664adc3ff7e94453656
    KDF: pbkdf2-sha256, 600,000회
    Salt: Bt9HhTFtDOVUgGsvFtnzMw==
    Salt SHA-256:
      8200bda925bf9fac1d4b4006943e19c25d4f7026363ce23276892d2595e023dc
설정 지문 : sha256:0123456789abcdef
설정 검증 : 정상

crypto.lang = ko
crypto.key.source = embedded
crypto.key.id = key01
crypto.key.embedded = (비공개)
...
```

`설정 지문`은 JAR 안의 설정 파일 내용을 식별하는 값이며 **키 지문이 아닙니다**. 키 목록의 `crypto.key.*`는 `crypto.key.source`·`crypto.key.id` 등 고정 설정으로 정하는 AES 키 슬롯이라는 표시입니다.

외부 공급원 키는 읽지 않고 `외부 키`와 등록할 때 고정한 지문(`<64자> (고정 지문)`, 없으면 `모름(외부 키, 고정 지문 없음)`)만 보여 줍니다.

한 줄이 80열을 넘으면 키 ID·항목 이름 다음에서 줄을 바꿉니다(값은 자르지 않음). `관리자` 줄은 이 JAR의 관리자 비밀번호 상태(`비밀번호 설정됨`, 관리자 기능이 없는 JAR이면 `지원 안 함(이전 버전 JAR, CLI 인증 없음)`)이며 비밀번호·검증값은 보여 주지 않습니다.

**주의:** 외부 Properties와 JVM `-D`(외부 설정에 추가한 키 포함)는 반영하지 않습니다.

WAS가 실제로 쓰는 값과 키는 [`info`](#topic-cli-settings--213-info--실행-시-적용-설정과-출처)·[`fingerprint`](key-management.md#topic-key-generation--28-fingerprint--키가-같은지-비교)로 확인합니다([5.4절](key-management.md#topic-key-management--54-지금-쓰는-키-확인)). 이력이 손상된 JAR는 정상으로 표시하지 않고 오류로 끝납니다(종료 코드 1).

<a name="topic-cli-settings--212-config-set--jar-기본-설정-변경"></a>
### `config set` — JAR 기본 설정 변경 (2.12)

**사용 상황:** WAS마다 외부 Properties나 `-D`를 반복하지 않고 JAR의 기본 설정(언어, 경고, 키 공급원, Pool 종류 등)을 바꿀 때. 실행 중인 프로세스의 설정을 바꾸는 명령이 아니며, 갱신한 JAR를 다시 배포해야 적용됩니다.

```text
java -jar <입력 JAR> config set <설정>=<값> [<설정>=<값> ...] --operator <수정자>
    [--reason <사유>] [--jar <대상 JAR>] [--replace] [--yes] [--admin-pass-file <파일>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `<설정>=<값>` | 예 | 한 개 이상. 설정·기본값·허용값은 [10장](../reference/configuration.md#10-설정-사전). 키 원문 `crypto.key.embedded`는 이 명령으로 바꿀 수 없음(`config embed-key` 사용). 키 목록 항목(`crypto.keys.<ID>.*`)은 **위치 항목**(`file`·`env`·`vault.path`·`vault.field`·`vault.ver`·`aws.kms.data-key.file`)만 바꿀 수 있고, 유형·공급원·내장 값·KDF·Salt·고정 지문을 바꾸면 같은 키 ID가 다른 키가 되므로 거부함(새 키 ID로 `config key add`) |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자) |
| `--reason <사유>` | 키 관련 설정이면 예 | 이력에 남길 변경 사유(한 줄, 200자 이하, 비밀값 금지). 키 관련 설정(키 공급원·키ID·기본 유형·기본 키·키 위치 등)을 바꾸면 필수: 빠지면 대화형 터미널에서 묻고, 스크립트·CI에서는 바꾸기 전에 오류. 키와 무관한 설정만 바꿀 때는 선택 |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--replace` | 아니요 | 기존 스크립트 호환용. 생략해도 같은 경로를 갱신합니다. |
| `--yes` | 아니요 | 키 관련 설정(키 공급원·키ID·기본 유형·기본 키·키 위치 등)을 바꿀 때의 `CHANGE` 확인 생략(무인 자동화). 키 관련 설정은 확인하고, 키와 무관한 설정은 확인하지 않음 |
| `--admin-pass-file <파일>` | 아니요 | 관리자 비밀번호 파일(한 줄, 비대화형 인증). 생략하면 대화형 터미널에서 묻고, 비대화형이면 아무것도 하지 않고 실패([1.4절](#topic-admin--14-cli-관리자-비밀번호)) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 키·설정을 같은 JAR 경로에서 변경합니다.
java -jar java-crypto-kit-0.2.1.jar config set crypto.lang=en --operator example-admin --reason "English messages"

# JAR에 저장된 키 목록과 설정 조회
java -jar .\java-crypto-kit-0.2.1.jar config show

# XML에서 cryptoPool을 생략한 Resource의 기본 Pool 변경
java -jar java-crypto-kit-0.2.1.jar config set crypto.pool.factory=org.apache.tomcat.jdbc.pool.DataSourceFactory --operator example-admin
```

```bash
# 경고 옵션 변경(공개된 기본 키 차단은 항상 적용)
java -jar ./java-crypto-kit-0.2.1.jar config set crypto.warning.enabled=false --operator example-admin

# 기존 AES 슬롯과 같은 키를 담은 파일로 공급 위치 변경
java -jar ./java-crypto-kit-0.2.1.jar config set crypto.key.source=file crypto.key.file=/etc/java-crypto-kit/app.key --operator example-admin --reason "같은 키를 파일에서 공급"

# 유형을 정하지 않은 새 암호화의 기본 유형을 key로
java -jar ./java-crypto-kit-0.2.1.jar config set crypto.key.type=key --operator example-admin --reason "기본 유형 key" --yes

# 같은 JAR의 내부 설정 갱신(키 관련 설정은 CHANGE 확인 또는 --yes)
java -jar ./tools/java-crypto-kit-0.2.1.jar config set crypto.lang=ko --jar /opt/tomcat/lib/java-crypto-kit-0.2.1.jar --replace --operator example-admin
```

**결과:** 출력된 **갱신 JAR** 경로(같은 경로)가 다음 실행·배포 대상입니다. 어떤 설정이든 먼저 관리자 비밀번호를 확인합니다.

키와 무관한 설정은 확인 입력 없이 같은 JAR를 갱신하고, 키 관련 설정은 사유를 받은 뒤 확인 화면(`키 관련 설정을 바꿉니다(키 위치·키 ID가 바뀌면 그 키의 기존 암호문에 영향):`, 갱신 대상, 사유, 설정마다 한 줄)을 보여 주고 `CHANGE` 입력(또는 `--yes`)을 받습니다.

갱신이 끝나면 대상 JAR 경로와 변경 항목을 표시합니다.

```text
갱신 JAR  : /opt/app/java-crypto-kit-0.2.1.jar
변경 항목 : crypto.lang (ko -> en)
```

여러 설정을 바꾸면 두 번째 설정부터 값 열에 맞춰 아랫줄에 나옵니다. 값이 길어 80열을 넘으면 설정 이름 다음과 `->` 앞에서 줄을 바꾸며 값은 자르지 않습니다(위 Pool 예제의 결과).

```text
변경 항목 : crypto.pool.factory
              (org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory
              -> org.apache.tomcat.jdbc.pool.DataSourceFactory)
```

바꾼 뒤 전체 설정을 실행 시와 같은 규칙으로 다시 검증하고, 비활성 영역에 쓴 새 상태를 다시 읽어 확인한 뒤에만 선택자를 바꿉니다.

`config show`는 그 JAR의 내장값, `config history`는 누적 이력, `info`는 외부 Properties·허용된 `-D`까지 반영한 실제 값을 보여 줍니다.

이력에 확인된 키 지문이 없는 레거시 슬롯은 `crypto.key.source=file`을 먼저 설정하고 `crypto.key.file`은 실행 시 `-D`·외부 Properties로 지정할 수 있습니다. 이력에 지문이 있는 슬롯을 같은 ID로 옮길 때는 같은 키를 읽을 수 있도록 새 위치를 먼저 준비합니다. 활성 공급원이나 위치를 변경할 때 키가 이력과 다르거나 읽을 수 없으면 `KEY_SOURCE`로 거부합니다.

**오류·주의:** 대상 JAR가 사용 중이면 잠금을 해제한 뒤 실행합니다. 잘못된 설정 이름·값은 [10장](../reference/configuration.md#10-설정-사전)을 확인합니다.

실행 대상 JAR의 내부 설정을 동일 경로에 갱신합니다. 쓰기 권한이나 변경에 필요한 파일 잠금을 얻지 못하면 실패합니다. 서명된 JAR, 설정·이력이 손상된 JAR, 예약 영역이 없는 구형 JAR는 편집할 수 없습니다. 키 목록에 새 프로필을 추가하려면 `config key add`를 사용합니다. 다른 키 재료로 교체하거나 키 ID를 바꾸면 기존 암호문에 영향이 있습니다. 이전 키와 ID를 쓸 수 있을 때 `rekey`로 이전하고 복호화 결과를 확인하세요.

이전 상태가 필요하면 변경 전에 보호된 위치에 JAR를 직접 복사하세요.

<a name="topic-cli-settings--213-info--실행-시-적용-설정과-출처"></a>
### `info` — 실행 시 적용 설정과 출처 (2.13)

**사용 상황:** 이번 실행에서 실제로 적용된 설정 값과 그 출처(JAR·외부 파일·JVM)를 확인할 때.

```text
java -jar <JAR> info [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 특정 외부 Properties를 썼을 때의 최종 설정과 출처 확인 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 적용된 설정과 활성 키 조회
java -jar .\java-crypto-kit-0.2.1.jar info

# 적용된 설정과 활성 키 조회
java -jar .\java-crypto-kit-0.2.1.jar info --config C:/secure/app.properties
```

```bash
# 적용된 설정과 활성 키 조회
java -Dcrypto.config.file=/etc/java-crypto-kit/app.properties -jar ./java-crypto-kit-0.2.1.jar info
```

**결과:** 먼저 **기본 유형과 유형별 기본 키**를, 이어서 **등록된 키마다** 꼬리표(유형, 그 유형의 기본 키면 `기본`, `crypto.key.*` AES 키면 `crypto.key.*`)·공급원·위치·(pass는 KDF)·키 상태·짧은 키 지문·조회 결과를, 마지막으로 알고리즘·출력 형식·언어·경고·Pool·외부 설정·`-D` 정책과 적용·무시한 `-D`(한 줄에 하나씩)·JAR 이력을 보여 줍니다.

`[ ]`는 그 값의 출처(`JAR 기본값`·`외부 설정 파일`·`JVM 속성 -D`)입니다. 키·Passphrase·비밀값은 출력하지 않습니다.

```text
기본 유형 : pass [JAR 기본값]
pass 기본 : app-pass [JAR 기본값]
key 기본  : key01 [JAR 기본값]

키 key01 (key, 기본, crypto.key.*)
  공급원 : embedded [JAR 기본값]
  위치   : JAR 내장(crypto.key.embedded)
  상태   : 사용자 지정
  지문   : ab12cd34ef56...7890abcd
  조회   : OK

키 app-pass (pass, 기본)
  공급원 : embedded [JAR 기본값]
  위치   : JAR 내장(crypto.keys.app-pass.embedded)
  KDF    : pbkdf2-sha256, 반복 600,000회
  상태   : 사용자 지정
  지문   : 5d0c8a1e2b3f...44aa9c01
  조회   : OK

알고리즘  : AES/GCM/NoPadding [JAR 기본값]
출력 형식 : enc [JAR 기본값]
언어      : ko [JAR 기본값]
경고 출력 : true [JAR 기본값]
Pool      : org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory [JAR 기본값]
외부 설정 : 없음
JVM -D    : 허용 [JAR 기본값]
적용 -D   : 없음
JAR 이력  : 변경 1회 - 마지막 2026-11-22T05:30:12Z, 수정자 example-admin
```

`-D`를 적용하면 `적용 -D` 줄에 설정 이름을 한 줄에 하나씩 보여 주고(값은 출력하지 않음), `crypto.jvm.override.enabled=false`라서 적용하지 않은 `-D`가 있으면 `무시 -D` 줄을 덧붙입니다.

```text
JVM -D    : 허용 [JAR 기본값]
적용 -D   : crypto.key.id
            crypto.warning.enabled
```

외부 설정이나 `-D`를 쓰면서 `crypto.key.source`는 JAR 값을 그대로 쓰면 `crypto.key.*` 키의 공급원 출처에 `JAR 기본값 - 외부 설정·-D에 crypto.key.source 없음`이라고 표시합니다(의도치 않게 내장 키를 쓰는지 바로 보임).

**오류·주의:** 키를 하나라도 읽지 못하면 그 키에 `조회   : FAIL`을 표시하고(다른 키 확인은 계속) 표준 오류에 키마다 원인 한 줄을 쓴 뒤 실패(종료 1)합니다. 읽지 못한 키의 지문은 만들어 보이지 않습니다.

CLI를 실행한 계정의 환경변수와 Tomcat **서비스 계정**의 환경변수는 다를 수 있습니다.

<a name="topic-cli-settings--214-doctor--설정과-키-진단"></a>
### `doctor` — 설정과 키 진단 (2.14)

**사용 상황:** WAS 기동 전에 설정·키·암복호화가 정상인지 한 번에 점검할 때.

```text
java -jar <JAR> doctor [--config <외부 Properties>] [--offline] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 특정 서버의 외부 설정으로 미리 진단 |
| `--offline` | 아니요 | Vault·KMS에 **연결하지 않고** 설정·토큰·SDK·파일 준비 상태만 점검. 원격 확인은 SKIP |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 키 공급원과 암복호화 동작 진단
java -jar .\java-crypto-kit-0.2.1.jar doctor
```

```bash
# 키 공급원과 암복호화 동작 진단
java -jar ./java-crypto-kit-0.2.1.jar doctor --config /etc/java-crypto-kit/app.properties

# 키 공급원과 암복호화 동작 진단
java -jar ./java-crypto-kit-0.2.1.jar doctor --offline
```

**점검 항목:** JAR 내장 설정, JAR 설정 이력, 설정 로딩(외부 Properties·`-D` 포함, 오타·충돌·잘못된 키 목록 항목은 여기서 중단), 적용·무시된 `-D`, 알고리즘, 기본 유형·유형별 기본 키, **등록된 키마다** 공급원 준비(키 파일 존재·종류·읽기 권한, 키 환경변수, Vault 필수 설정·토큰·CA 파일, AWS SDK·KMS 키 ID·데이터 키 파일·리전)와 실제 키 로딩(외부 키는 고정 지문 일치 확인, 키 상태·짧은 지문), 암호화·복호화·변조 거부 자체 검사(읽은 키 하나로, 가능하면 새 암호화의 기본 키). 한 키가 실패해도 다른 키 점검은 계속합니다.

**결과**

```text
[PASS] JAR 내장 설정 정상
[INFO] JAR 설정 이력: 최초 빌드 상태(변경 이력 없음)
[PASS] 설정 로딩 정상
[PASS] 알고리즘 AES/GCM/NoPadding
[INFO] 기본 유형 pass, pass 기본 app-pass, key 기본 key01
[INFO] 키 key01 (key, 기본, crypto.key.*):
       embedded, JAR 내장(crypto.key.embedded)
[PASS] 키 로딩 정상: key01, 사용자 지정, 지문 ab12cd34ef56...7890abcd
[INFO] 키 app-pass (pass, 기본):
       embedded, JAR 내장(crypto.keys.app-pass.embedded)
[PASS] 키 로딩 정상: app-pass, 사용자 지정, 지문 5d0c8a1e2b3f...44aa9c01
[PASS] 암호화·복호화·변조 거부 검사 정상
결과: PASS
```

| 표시 | 뜻·조치 |
|---|---|
| `PASS` | 실제로 실행한 점검이 정상(키 로딩, 암복호화 자체 검사 등) |
| `FAIL` | 키 파일 누락·형식 오류·설정 오류·원격 조회 실패 등. 바로 아래 `조치:` 한 줄을 보고 고친 뒤 다시 실행(종료 1) |
| `SKIP` | `--offline` 등으로 실행하지 않은 확인. PASS로 보지 않음 |
| `INFO` | 판단에 필요한 사실: 변경 이력, 적용된 외부 설정·`-D`, 기본 유형·기본 키, 키마다 공급원·위치, Vault CA 신뢰 방식, KMS 리전·엔드포인트 |
| `WARN` | 지정한 `-D`가 `crypto.jvm.override.enabled=false` 때문에 적용되지 않은 경우처럼 **설정이 의도대로 적용되지 않은** 경우에만. 종료 코드에는 영향 없음 |

적용·무시한 `-D`가 하나면 `[INFO] 적용된 -D: crypto.key.id`처럼 한 줄, 여러 개면 제목 줄 아래에 이름을 한 줄에 하나씩(조치 줄과 같은 들여쓰기) 보여 줍니다.

```text
[INFO] 적용된 -D:
       crypto.key.id
       crypto.warning.enabled
```

마지막 줄은 `결과: PASS` 또는 `결과: FAIL n건`이며 WARN·SKIP이 있으면 `(WARN 1, SKIP 1)`처럼 개수를 덧붙입니다.

공개된 기본 키가 등록된 경우 실제 키 로딩은 실패합니다. 진단의 키 ID와 공급원을 확인하세요.

키 파일 권한 범위, Vault 버전 고정, KMS 엔드포인트·자격증명 방식 같은 운영 판단은 점검하지 않습니다([12장](../reference/security.md#12-운영보안-참고)).

**주의:** `doctor`는 Tomcat JNDI와 실제 DB 연결을 검증하지 않으므로 그것을 PASS로 표시하지 않습니다. 운영 준비는 **키 상태 `사용자 지정`·지문 확인 + `doctor` 결과 PASS + 애플리케이션의 실제 JNDI 조회·SQL 확인**으로 판단합니다.

<a name="api-cli"></a>
## 독립 보안 API CLI

`api <기능> <동작>`은 키와 정책을 직접 공급하는 기존 Java 보안 API를 호출합니다. 관리형 키 목록과 History는 그대로입니다. 실행에는 CLI 최초 설정이 필요하고, 보안 데이터·비밀키·개인키·토큰을 다루는 명령은 기존 관리자 인증을 매번 수행합니다.

```sh
# 명령의 옵션과 사용법 조회
java -jar java-crypto-kit-0.2.1.jar api --help

# 명령의 옵션과 사용법 조회
java -jar java-crypto-kit-0.2.1.jar api jwt --help

# 명령의 옵션과 사용법 조회
java -jar java-crypto-kit-0.2.1.jar api jwt create --help

# 실행 전 명령별 실무 예제 확인
java -jar java-crypto-kit-0.2.1.jar api jwt --examples
```

`api --help`는 암복호화·데이터 검증·보안 유틸리티·키와 인증서·인증과 인가를 업무별로 보여 줍니다. 개별 `--help`에서 필수 옵션·기본값·한도와 배타 조건을, `--examples`에서 연결 명령을 확인하세요. 조회에 함께 지정할 수 있는 옵션은 언어(`--lang ko|en`)입니다. 미설정 JAR에서 예제를 조회했다면 [공통 초기 설정 안내](#topic-cli--221-도움말-명령)에 따라 실행합니다. 독립 명령의 키는 옵션 또는 숨김 입력으로 제공합니다.

<a name="cli-aliases"></a>
### 정식 명령과 단축어

같은 실행에서 정식 명령과 짧은 옵션을 섞어 쓸 수 있습니다. 정식 옵션과 해당 단축어를 함께 지정하면 중복으로 거부합니다. Help와 Examples에도 명령 단축어를 사용할 수 있습니다.

| 정식 명령·기능군 | 단축어 |
|---|---|
| `encrypt` / `decrypt` | `enc` / `dec`. 최상위, `file`, `api aes/rsa/hybrid`에 적용 |
| `api signature`, `api certificate`, `api random` | `api sig`, `api cert`, `api rand` |
| `api keyconvert`, `api request-auth` | `api keyconv`, `api req-auth` |
| `api hash generate`, `api otp generate` | `api hash gen`, `api otp gen` |

| 용도 | 정식 옵션 → 단축어 |
|---|---|
| 알고리즘·표현 | `--algorithm` → `--alg`, `--format` → `--fmt`, `--encoding` → `--enc`, `--input-encoding` → `--in-enc`, `--key-encoding` → `--key-enc` |
| 키·검증 파일 | `--public-key` → `--pub-key`, `--private-key` → `--priv-key`, `--signature-file` → `--sig-file` |
| 크기·횟수 | `--length` → `--len`, `--iterations` → `--iter` |
| JWT·OAuth | `--issuer` → `--iss`, `--subject` → `--sub`, `--audience` → `--aud`, `--jwt-id` → `--jti`, `--issued-at` → `--iat`, `--not-before` → `--nbf`, `--expires-in` → `--ttl`(초 단위 유효기간) |

옵션 단축어는 해당 정식 옵션을 지원하는 독립 명령에서 사용합니다. TOTP 등록 URI의 발급자 표지에는 `--issuer`를 사용합니다. `--alg sha256`와 `--alg=sha256`를 모두 쓸 수 있습니다.

```sh
# 입력 파일의 해시 계산
java -jar java-crypto-kit-0.2.1.jar api hash generate --algorithm sha256 --in sample.jar

# 입력 파일의 해시 계산
java -jar java-crypto-kit-0.2.1.jar api hash gen --alg=sha256 --in sample.jar
```

| 입력·출력 | 대화형 | 스크립트·CI |
|---|---|---|
| 비밀 입력 | 필요한 값만 묻습니다. 키·토큰·비밀번호는 숨김 입력입니다. | 비밀번호·키·토큰은 보호 파일로 지정합니다. 해시와 인코딩의 일반 데이터도 파일로 제공할 수 있습니다. |
| 민감 결과 | 기본은 새 출력 경로를 입력합니다. `--show`를 지원하는 명령에서는 `SHOW` 확인 뒤 화면에 표시할 수 있습니다. | 새 경로를 `--out`으로 지정합니다. 인증은 `--admin-pass-file`을 사용합니다. |
| 공개 결과 | 출력 경로를 생략하면 stdout을 사용합니다. | 표준 출력에 결과가 오고, 진단은 stderr입니다. 바이너리는 새 `--out`에 씁니다. |

| 결과 | stdout | stderr | 종료 코드 |
|---|---|---|---|
| 검증 일치 | `OK` | — | 0 |
| 검증 불일치 또는 토큰 거부 | `FAIL` | JWT·OAuth 검증은 원인 코드와 선택한 언어의 안내 | 1 |
| 옵션·권한·입력 파일·통신 오류 | 비어 있음 | 문제가 있는 옵션 또는 오류 사유 | 1 |
| `needs-rehash` / OAuth `active:false` | 정상 판단값. OAuth 결과는 지정한 보호 파일 또는 승인한 화면 | — | 0 |

대화형 실행은 이미 지정된 입력을 다시 묻지 않습니다. 필요한 키 원문·Passphrase·토큰은 숨김 입력으로 받고, 공개키·개인키 파일이 필요한 곳에서는 파일 경로를 묻습니다. 선택 옵션을 생략하면 명령별 Help의 기본값이 적용됩니다. JWT 검증 대상은 직접 제공하거나 질문에 입력하세요. 대상 일치를 생략하는 정책은 `--any-audience`로 명시합니다.

대화형에서 결과 파일이 완성되면 stderr에 `[OK]`와 파일명만 표시합니다. RSA·EC 키쌍은 공개키와 개인키를 구분합니다. 비대화형 출력과 파일의 기계 판독 형식은 기존과 같습니다.

비밀 텍스트 파일은 UTF-8로 읽으며 선두 BOM 하나와 끝 LF 또는 CRLF 하나를 제거합니다. 바이너리 입력은 원본 바이트를 보존합니다. 출력 위치는 하드 링크를 지원하는 기존 폴더여야 합니다. POSIX 새 파일은 600으로 생성하며, 민감 입력은 다른 사용자(other)의 읽기·쓰기를 거부합니다. Windows는 대상 폴더 ACL을 상속합니다. [실패 원인과 조치](../reference/troubleshooting.md#api-cli-errors)

| 기능군 | 명령·옵션·예제 |
|---|---|
| `api aes` | [직접 AES-GCM과 Passphrase](java-encryption.md#api-aes) |
| `api rsa` | [RSA-OAEP](java-encryption.md#api-rsa) |
| `api hybrid` | [Hybrid 암복호화](java-encryption.md#api-hybrid) |
| `api hmac` | [HMAC](data-integrity.md#api-hmac) |
| `api hash` | [해시 생성과 비교](data-integrity.md#api-hash) |
| `api signature` | [전자서명](data-integrity.md#api-signature) |
| `api request-auth` | [RequestAuth](data-integrity.md#api-request-auth) |
| `api encode` | [인코딩](security-utilities.md#api-encode) |
| `api decode` | [디코딩](security-utilities.md#api-decode) |
| `api random` | [난수와 UUID](security-utilities.md#api-random) |
| `api password` | [앱 비밀번호 해시](security-utilities.md#api-password) |
| `api kdf` | [키 파생](security-utilities.md#api-kdf) |
| `api jwt` | [JWT 및 JWKS](authentication.md#api-jwt) |
| `api oauth` | [OAuth 2.0](authentication.md#api-oauth) |
| `api otp` | [일회용 코드](authentication.md#api-otp) |
| `api certificate` | [인증서 정보](certificates-keystores.md#api-certificate) |
| `api keyconvert` | [PEM·DER 변환](certificates-keystores.md#api-keyconvert) |
| `api keygen` | [시험용 키 생성](key-management.md#api-keygen) |

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
