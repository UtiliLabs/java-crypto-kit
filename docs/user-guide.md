# java-crypto-kit 사용자 가이드

java-crypto-kit의 **정식 상세 사용자 매뉴얼**입니다. 모든 명령·옵션의 의미, 허용값·기본값, 선택 기준, Windows/Linux 예제, 결과와 오류 조치를 기능별로 설명합니다. 처음 실행해 보는 세 명령은 [README](../README.md)에 짧게 있고, 실행 중에는 `java -jar <JAR> help`(한국어·영어)로 같은 내용을 요약해 볼 수 있습니다.

**이 문서의 표기**

- `java-crypto-kit-0.1.0.jar`: 공개 배포 JAR(체험용 내장 예제 키가 들어 있음). 실제로 받은 파일 이름으로 바꿔 실행합니다.
- `java-crypto-kit-0.1.0-configured.jar`: `config embed-key`·`config set`이 만든 결과 JAR(사용자 지정 키 등을 내장). 같은 계열 JAR를 다시 바꾸면 `-configured-2.jar`, `-configured-3.jar`처럼 번호가 올라갑니다.
- `<JAR>`: 위 둘 중 지금 쓰는 JAR. Windows PowerShell은 `.\`, Linux는 `./`로 시작합니다.
- 예제의 키ID(`key01`), 키 파일(`example.key`), 수정자 ID(`example-admin`), 경로·URL은 모두 예시 값입니다.

## 목차

1. [개요와 준비](#1-개요와-준비) — [지원 기능](#11-지원-기능) · [준비물과 내려받기](#12-준비물과-내려받기) · [체험용 키와 운영용 키](#13-체험용-내장-키와-운영용-사용자-지정-키)
2. [CLI 명령](#2-cli-명령) — [공통 규칙](#21-공통-규칙) · [명령 목록](#22-명령-목록) · 명령별 설명(2.3~2.18)
3. [Tomcat JNDI 연동](#3-tomcat-jndi-연동) — 적용 순서 · Pool 선택 · Resource를 넣을 파일 · Resource 속성 · 조회 코드 · JVM 공통 범위
4. [Connection Pool 설정](#4-connection-pool-설정) — 기본 옵션 · 고급 옵션
5. [키 공급원과 설정 적용](#5-키-공급원과-설정-적용) — 키 공급원 선택 · 설정을 두는 곳과 우선순위 · 외부 Properties 지정
6. [Java API](#6-java-api) — API 목록 · 문자열 · `byte[]` · 민감정보·오류 · 외부 설정
7. [파일 암복호화](#7-파일-암복호화)
8. [Vault와 AWS KMS (선택)](#8-vault와-aws-kms-선택)
9. [운영 변경과 장애 대응](#9-운영-변경과-장애-대응) — DB 비밀번호 변경 · 키 교체 · 오류 코드별 조치
10. [설정 사전](#10-설정-사전) — `crypto.*` 설정 25개
11. [지원 범위와 배포 점검](#11-지원-범위와-배포-점검) — 검증 상태 · 다른 WAS · 배포 전 점검표

---

## 1. 개요와 준비

### 1.1 지원 기능

java-crypto-kit은 **AES-256-GCM 기반 암복호화 라이브러리**입니다. Tomcat JNDI에 적은 암호화된 DB 비밀번호를 풀어 Tomcat 공식 Connection Pool에 넘기고, 같은 엔진을 CLI와 일반 Java API에서도 씁니다.

| 대상 | 지원 동작 | 범위·제약 |
|---|---|---|
| Tomcat | JNDI `DataSource`의 비밀번호(필요하면 계정도) 복호화 후 DBCP2 또는 Tomcat JDBC Pool에 전달 | Tomcat 전용 Factory. 웹 애플리케이션의 JNDI 조회 코드는 바꾸지 않음 |
| CLI | 암호화·검증·복호화, 키 생성·비교·교체, JAR 내장 설정 변경·이력, 진단, 파일 암복호화 | 평문을 입력하는 명령은 실제 터미널에서 실행 |
| Java API | 텍스트·바이트·파일 암복호화, 검증 | 공개 진입점은 `CredentialCrypto` 하나. JAR를 클래스패스에 추가 |
| Vault KV v2 / AWS KMS | Vault Secret의 AES 키 조회 / KMS가 보호한 데이터 키 복원 | Vault Transit 아님. AWS는 선택형 SDK 묶음 필요 |
| 다른 WAS | Java API·CLI 사용 가능 | WebLogic·JEUS 등의 자체 JDBC Pool 자동 복호화 기능은 없음 |

**암호문 형식:** 문자열은 `ENC[v1:<키ID>:<IV>:<암호문>]`입니다. 설정 `crypto.output.encoding=base64`이면 이것을 한 번 더 포장한 `B64[...]`로 출력합니다(포장일 뿐 암호 강도는 같음). 파일은 별도 바이너리 형식 `JCKF v1`을 씁니다. 같은 평문도 매번 새 IV를 쓰므로 암호문이 달라지는 것이 정상이며, 암호문이 위·변조되면 복호화가 실패합니다.

### 1.2 준비물과 내려받기

**준비물:** Java 8 이상(JRE도 가능, `java -version`으로 확인). Tomcat에 적용하려면 Tomcat과 DB의 JDBC 드라이버 JAR, AWS KMS를 쓰려면 선택형 SDK 묶음이 더 필요합니다.

**내려받기:** [GitHub Releases](https://github.com/freeangelsun/java-crypto-kit/releases)

| 파일 | 용도 |
|---|---|
| `java-crypto-kit-<버전>.jar` | 기본 JAR. CLI·Java API·Tomcat Factory가 모두 들어 있으며 보통 이것 하나면 됩니다 |
| `java-crypto-kit-aws-kms-lib-<버전>.zip` | AWS KMS를 쓸 때만 추가하는 AWS SDK 묶음(이 라이브러리 코드는 없음) |
| `SHA256SUMS.txt` | 위 파일들의 SHA-256 |

정식 릴리스는 `v<버전>` 태그입니다. `dev-<커밋>` 사전 릴리스는 main 브랜치 자동 빌드로 시험용입니다.

**SHA-256 확인:** 같은 Release의 `SHA256SUMS.txt`와 JAR를 같은 폴더에 받은 뒤, 출력된 해시가 **기대 해시와 일치하는지** 판단합니다. 일치하지 않으면 사용하지 않습니다.

```bash
# Linux: 받은 파일만 검사(선택형 ZIP을 받지 않았으면 그 항목은 건너뜀). 받은 JAR에 대해 OK가 나와야 합니다.
sha256sum --ignore-missing -c SHA256SUMS.txt
```

```powershell
# Windows PowerShell: $jar를 실제 JAR 이름으로 바꿉니다.
$jar = 'java-crypto-kit-0.1.0.jar'
$line = Get-Content .\SHA256SUMS.txt | Where-Object { $_ -match ('(?i)^[0-9a-f]{64}\s+\*?' + [regex]::Escape($jar) + '$') } | Select-Object -First 1
if (-not $line) { throw '해당 JAR 해시 없음' }
$expected = ($line -split '\s+')[0]
if ((Get-FileHash -LiteralPath $jar -Algorithm SHA256).Hash -ine $expected) { throw 'SHA256 FAIL' }
'SHA256 PASS'
```

사용자 지정 키를 내장한 JAR는 공개 원본과 해시가 다른 것이 정상이므로 사용 환경의 배포 정책에 따라 따로 관리합니다.

**소스에서 빌드:** 저장소 루트에서 Windows `gradlew.bat clean build`, Linux `./gradlew clean build`를 실행하면 `build/libs/java-crypto-kit-<버전>.jar`와 `build/distributions/java-crypto-kit-aws-kms-lib-<버전>.zip`이 만들어집니다(테스트 포함). Gradle Wrapper 8.14.3의 공식 빌드 JDK는 8~24입니다.

### 1.3 체험용 내장 키와 운영용 사용자 지정 키

공개 JAR에는 체험용 **내장 예제 키**(키ID `default`)가 들어 있어 키를 만들지 않고 바로 실행해 볼 수 있습니다. 이 키는 소스와 함께 공개된 값이므로 누구나 복호화할 수 있습니다.

| 구분 | 체험(기능 확인) | 운영(실제 비밀번호·비밀값) |
|---|---|---|
| 키 | 공개 JAR의 내장 예제 키 `default` | 사용자 지정 키(JAR 내장 또는 `file`·`env`·`vault`·`aws-kms`) |
| 준비 | 없음(`keygen` 불필요) | 새 키가 필요할 때만 `keygen` → `config embed-key`, 또는 외부 키 공급 설정 |
| 알아보는 법 | 암호문의 키ID가 `default`, `doctor`와 로그에 공개 키 WARNING | 지정한 키ID(예: `key01`), 공개 키 WARNING 없음 |
| 쓸 수 있는 데이터 | 시험 데이터만 | 실제 DB 비밀번호·비밀값 |

**운영 준비 순서(사용자 지정 키를 JAR에 내장하는 경우)**

1. 새 키가 필요하면 [`keygen`](#26-keygen--새-키-파일-만들기)으로 키 파일을 만듭니다. 이미 쓰는 키가 있으면 이 단계는 없습니다.
2. [`config embed-key`](#27-config-embed-key--사용자-지정-키-내장)로 키 내장 JAR를 만듭니다. 원본 JAR는 그대로 남습니다. JAR 대신 키를 외부에 두려면 [5장](#5-키-공급원과-설정-적용)을 봅니다.
3. 결과 JAR로 [`config show`](#210-config-show--jar-내장값-조회)·[`fingerprint`](#28-fingerprint--키가-같은지-비교)(JAR와 키 파일의 지문 일치)·[`doctor`](#214-doctor--설정과-키-진단)(FAIL 0)를 확인합니다.
4. 결과 JAR로 [`encrypt`](#23-encrypt--문자열-암호화)를 실행해 DB 비밀번호 암호문을 만듭니다.
5. **같은 결과 JAR**를 WAS에 배포합니다([3장](#3-tomcat-jndi-연동)).

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\jck-secure" | Out-Null
java -jar .\java-crypto-kit-0.1.0.jar keygen --out "$HOME\jck-secure\example.key"
java -jar .\java-crypto-kit-0.1.0.jar config embed-key --from-file "$HOME\jck-secure\example.key" --key-id key01 --operator example-admin
java -jar .\java-crypto-kit-0.1.0-configured.jar config show
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint --key-file "$HOME\jck-secure\example.key"
java -jar .\java-crypto-kit-0.1.0-configured.jar doctor
java -jar .\java-crypto-kit-0.1.0-configured.jar encrypt
```

```bash
mkdir -p -m 700 ~/jck-secure
java -jar ./java-crypto-kit-0.1.0.jar keygen --out ~/jck-secure/example.key
java -jar ./java-crypto-kit-0.1.0.jar config embed-key --from-file ~/jck-secure/example.key --key-id key01 --operator example-admin
java -jar ./java-crypto-kit-0.1.0-configured.jar fingerprint --key-file ~/jck-secure/example.key
java -jar ./java-crypto-kit-0.1.0-configured.jar doctor
java -jar ./java-crypto-kit-0.1.0-configured.jar encrypt
```

키 파일과 키 내장 JAR는 비밀 파일입니다. Git 저장소 밖의 보호된 곳에 보관·백업하고, 둘 다 잃으면 그 키로 만든 암호문을 복구할 수 없습니다.

---

## 2. CLI 명령

### 2.1 공통 규칙

- **형식:** `java [-D<설정>=<값> ...] -jar <JAR> <명령> [옵션]`. 체험은 공개 JAR, 운영은 키 내장 JAR(또는 외부 키 설정)로 실행합니다.
- **`-Dcrypto.*`** 는 `java`와 `-jar` **사이**에 둡니다. PowerShell은 따옴표로 감쌉니다(예: `java "-Dcrypto.lang=en" -jar .\java-crypto-kit-0.1.0-configured.jar info`).
- **`--lang ko|en`** 은 그 실행 한 번의 언어만 바꿉니다. 기본 언어는 설정 `crypto.lang`(기본 `ko`)입니다.
- **`--help`** 또는 **`-h`** 는 명령 사용법을 보여 줍니다. 도움말은 키 파일·DB가 없어도 실행됩니다.
- **옵션 값:** 값을 받는 옵션은 `--옵션 값`과 `--옵션=값` 모두 됩니다. 값을 받는 옵션과 `config set`의 `<설정>=<값>`은 같은 것을 두 번 쓰면 오류로 멈춥니다. 플래그(`--yes`·`--replace`·`--offline`)는 값 없이 쓰며(`--yes=true`처럼 쓰면 오류) 두 번 써도 한 번으로 처리합니다. `--lang`을 여러 번 쓰면 마지막 값이 적용됩니다. 각 명령 표에 있는 옵션만 쓸 수 있습니다.
- **대화형 입력:** `encrypt`·`decrypt`와 `--value` 없이 실행한 `verify`·`rekey`는 입력을 화면에 보이지 않게 받으므로 실제 PowerShell·명령 프롬프트·Linux 터미널(ssh)에서 실행합니다. IDE 콘솔·파이프·리다이렉트·스크립트에서는 입력을 숨길 수 없어 실행하지 않습니다.
- **비밀값은 인자로 넘기지 않습니다.** 평문 비밀번호·AES 키·Vault 토큰을 받는 명령 옵션이나 `-D`는 없습니다.
- **종료 코드:** 0 = 성공, 1 = 실패. `doctor`는 WARN만 있으면 0이므로 운영 준비 판단에 단독으로 쓰지 않습니다.
- **오류 형식:** 표준 오류에 한 줄로 `[java-crypto-kit] [사유: 코드] 원인 조치: 확인할 내용`(영어 `[reason: CODE] ... Action: ...`)을 출력합니다. 코드별 조치는 [9.3절](#93-오류-코드별-조치)에 있습니다.

### 2.2 명령 목록

`config`, `file`, `kms`는 명령 그룹이며 아래 하위 명령으로 실행합니다.

| 구분 | 명령 | 용도 |
|---|---|---|
| 문자열 | [`encrypt`](#23-encrypt--문자열-암호화) · [`decrypt`](#24-decrypt--확인-후-평문-표시) · [`verify`](#25-verify--복호화-가능-여부-확인) | DB 비밀번호 등 암호화 / 확인 후 평문 표시 / 평문 없이 검증 |
| 키 | [`keygen`](#26-keygen--새-키-파일-만들기) · [`config embed-key`](#27-config-embed-key--사용자-지정-키-내장) · [`fingerprint`](#28-fingerprint--키가-같은지-비교) · [`rekey`](#29-rekey--기존-암호문을-새-키로-바꾸기) | 새 키 파일 / 키 내장 JAR 만들기 / 키 비교 / 새 키로 재암호화 |
| JAR 설정 | [`config show`](#210-config-show--jar-내장값-조회) · [`config history`](#211-config-history--설정-변경-이력) · [`config set`](#212-config-set--jar-기본-설정-변경) | 내장값 조회 / 변경 이력 / 기본 설정 변경 |
| 점검 | [`info`](#213-info--실행-시-적용-설정과-출처) · [`doctor`](#214-doctor--설정과-키-진단) | 최종 적용 설정과 출처 / 설정·키·암복호화 진단 |
| 파일 | [`file encrypt`](#215-file-encrypt--파일-암호화) · [`file decrypt`](#216-file-decrypt--파일-복호화) | CSV·PDF·이미지 등 파일 암복호화 |
| AWS KMS | [`kms datakey`](#217-kms-datakey--aws-kms-데이터-키-파일-만들기) | KMS가 보호하는 데이터 키 파일 만들기 |
| 도움말 | [`help`, `config help` 등](#218-도움말-명령) | 전체 명령, 설정 목록, 주제별 안내 |

### 2.3 `encrypt` — 문자열 암호화

**언제 쓰나:** DB 비밀번호(필요하면 DB 계정도)를 `ENC[...]`로 바꿔 Tomcat Resource 등에 넣을 때. 운영에서는 **WAS가 쓰는 것과 같은 키·키ID를 가진 JAR(또는 같은 외부 설정)** 로 실행합니다.

```text
java -jar <JAR> encrypt [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | WAS와 같은 외부 설정 파일로 암호화할 때. 생략하면 JAR 내장 설정(또는 `-Dcrypto.config.file`·`CRYPTO_CONFIG_FILE`) |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0.jar encrypt              # 체험: 공개 JAR(키ID default)
java -jar .\java-crypto-kit-0.1.0-configured.jar encrypt   # 운영: 키 내장 JAR
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar encrypt
java -jar ./java-crypto-kit-0.1.0-configured.jar encrypt --config /etc/java-crypto-kit/app.properties
```

**결과:** 평문을 화면에 보이지 않게 입력하면 `ENC[v1:key01:...]`(설정이 `base64`면 `B64[...]`) 한 줄이 나오고, 이어서 다음 할 일(Tomcat Resource의 `password`에 대괄호까지 전체를 넣기)이 안내됩니다. 같은 평문도 매번 다른 암호문이 나오는 것이 정상입니다.

**오류·주의:** IDE 콘솔·파이프에서 실행하면 대화형 터미널 오류로 거부합니다. 키 파일 누락 등 `KEY_SOURCE` 오류는 `doctor`로 원인을 확인합니다. 평문을 명령 인자로 받는 옵션은 없습니다(셸 기록·프로세스 목록 노출 방지).

### 2.4 `decrypt` — 확인 후 평문 표시

**언제 쓰나:** 암호문의 실제 값을 꼭 확인해야 할 때만. 복호화 가능 여부만 보려면 [`verify`](#25-verify--복호화-가능-여부-확인)를 씁니다.

```text
java -jar <JAR> decrypt [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 키 내장 JAR와 다른 외부 키 공급 설정으로 복호화할 때 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar decrypt
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar decrypt
```

**결과:** 위험 안내 → `SHOW`를 그대로 입력(그 밖의 입력은 취소) → `ENC[...]`/`B64[...]` 암호문을 화면에 보이지 않게 입력 → 암호문의 무결성 검증(AES-GCM 인증 태그)에 성공하면 평문을 표시합니다. 암호문을 명령 인자로 받지 않습니다. `SHOW`는 평문을 화면에 표시할지 확인하는 절차이며 **본인 인증이 아닙니다**(터미널 접근 통제는 운영 환경에서 합니다).

**오류·주의:** 화면 공유·녹화·터미널 기록에 평문이 남을 수 있으므로 필요한 승인과 통제 아래에서만 씁니다. `crypto.warning.enabled=false`로 바꿔도 이 확인 절차는 없어지지 않습니다. `INTEGRITY`·`KEY_ID_MISMATCH`는 키나 암호문이 다른 경우이므로 [`fingerprint`](#28-fingerprint--키가-같은지-비교)로 키부터 비교합니다.

### 2.5 `verify` — 복호화 가능 여부 확인

**언제 쓰나:** 암호문이 현재 키로 복호화되는지 평문을 보여 주지 않고 확인할 때(배포 전 점검, 자동화 점검).

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
java -jar .\java-crypto-kit-0.1.0-configured.jar verify
# 자동화에서만: 셸 기록에 암호문이 남습니다
java -jar .\java-crypto-kit-0.1.0-configured.jar verify --value 'ENC[v1:key01:실제IV:실제암호문]'
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar verify
```

**결과:** 키·키ID·AES-GCM 인증 태그가 맞으면 성공(종료 0)이며 평문은 표시하지 않습니다. DB 계정·비밀번호가 실제 DB에 맞는지는 검사하지 않습니다.

**오류·주의:** `KEY_ID_MISMATCH`면 키 내장 JAR와 암호문의 키ID를 비교하고, `INTEGRITY`면 키 지문과 암호문 변조 여부를, `INVALID_TOKEN`이면 암호문 전체를 다시 복사했는지 확인합니다.

### 2.6 `keygen` — 새 키 파일 만들기

**언제 쓰나:** 운영용 새 AES-256 키가 필요할 때만 씁니다. **암복호화의 필수 선행 단계가 아닙니다**(체험은 내장 예제 키로, 이미 키가 있으면 그 키로 합니다). 운영 키를 잃었다고 새 키를 만들어도 **기존 암호문은 복구되지 않습니다**.

```text
java -jar <JAR> keygen --out <새 키 파일> [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--out <경로>` | 예 | 32바이트 난수 키를 Base64 한 줄로 저장할 **새 파일**. 상위 폴더가 있어야 하고, 같은 이름의 파일이 있으면 덮어쓰지 않음 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# Windows PowerShell: 상위 폴더를 먼저 만듭니다. example.key는 새로 만들 파일 이름이지 키 값이 아닙니다.
New-Item -ItemType Directory -Force -Path "$HOME\jck-secure" | Out-Null
java -jar .\java-crypto-kit-0.1.0.jar keygen --out "$HOME\jck-secure\example.key"
```

```bash
# Linux(키 내장용, 본인 폴더)
mkdir -p -m 700 ~/jck-secure
java -jar ./java-crypto-kit-0.1.0.jar keygen --out ~/jck-secure/example.key
# Linux 서버(파일 키로 사용, Tomcat 실행 계정이 읽음 - root로 실행, 계정 이름은 환경에 맞게)
install -d -m 750 -g tomcat /etc/java-crypto-kit
java -jar ./java-crypto-kit-0.1.0.jar keygen --out /etc/java-crypto-kit/example.key
chown tomcat:tomcat /etc/java-crypto-kit/example.key
```

**결과:** "키 파일이 생성됐습니다. 키 지문: <64자리>"와 다음 할 일을 안내합니다. 키 원문은 화면에 출력하지 않습니다. Linux·macOS에서는 파일을 소유자 전용 권한(600)으로 만들고, Windows에서는 저장 폴더의 NTFS 권한을 그대로 물려받습니다. 사용자 프로필 아래 폴더는 기본으로 본인·관리자만 접근하지만, `C:\` 바로 아래에 만든 폴더(예: `C:\secure`)는 기본 상속으로 다른 로컬 사용자도 읽을 수 있으므로 `icacls`로 상속을 끊고 필요한 계정(운영자, Tomcat 서비스 계정)만 허용합니다.

**다음 단계:** JAR에 내장하려면 [`config embed-key`](#27-config-embed-key--사용자-지정-키-내장), 외부 파일 키로 쓰려면 `crypto.key.source=file`과 `crypto.key.file`을 설정합니다([5장](#5-키-공급원과-설정-적용)).

**오류·주의:** 폴더가 없거나 같은 이름의 파일이 있으면 다른 출력 경로를 지정합니다. 키 파일은 운영 환경의 보안 정책에 따라 보관·백업합니다.

### 2.7 `config embed-key` — 사용자 지정 키 내장

**언제 쓰나:** 외부 키 파일을 따로 배포하지 않고 **사용자 지정 키를 내장한 JAR 하나**로 운영할 때. JAR에서 키를 추출할 수 있으므로 결과 JAR도 비밀 파일로 관리합니다.

```text
java -jar <입력 JAR> config embed-key --from-file <키 파일> --key-id <새 키ID> --operator <수정자>
    [--source embedded] [--reason <사유>] [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--from-file <경로>` | 예 | `keygen`으로 만든 AES-256 키 파일. 키 문자열을 인자로 받지 않음 |
| `--key-id <ID>` | 예 | 영문·숫자·`_`·`-`, 1~64자. **현재 키ID와 이력에 나온 키ID는 다시 쓸 수 없음** |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자). 기록용이며 본인 인증이 아님 |
| `--source embedded` | 조건부 | 대상 JAR의 `crypto.key.source`가 `embedded`가 아닐 때만 필요: `embedded`로 **명시적으로 전환**하며 키를 내장. 이미 `embedded`(기본값)이면 생략해도 진행되고, `embedded`가 아닌데 생략하면 오류로 멈추며 JAR는 바뀌지 않음 |
| `--reason <사유>` | 아니요 | 이력에 남길 변경 사유(한 줄, 200자 이하) |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로. 생략하면 `<이름>-configured.jar`, 이미 바꾼 JAR면 `-configured-2.jar` 등. 기존 파일은 덮어쓰지 않음 |
| `--replace` | 아니요 | 새 파일 대신 `<이름>.bak-<UTC>` 백업 후 원본 교체. `--out`과 함께 쓸 수 없고, 실행 중인 JAR는 교체하지 않음 |
| `--yes` | 아니요 | 키 변경 확인(`CHANGE` 입력)을 생략. 사전 승인된 자동화에서만 사용 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0.jar config embed-key --from-file "$HOME\jck-secure\example.key" --key-id key01 --operator example-admin
java -jar .\java-crypto-kit-0.1.0-configured.jar config show
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint --key-file "$HOME\jck-secure\example.key"
```

```bash
java -jar ./java-crypto-kit-0.1.0.jar config embed-key --from-file ~/jck-secure/example.key --key-id key01 --operator example-admin --reason "initial key"
java -jar ./java-crypto-kit-0.1.0-configured.jar config history
```

**결과:** 변경 영향을 안내한 뒤 `CHANGE` 입력을 받으면(또는 `--yes`) 원본 JAR는 그대로 두고 **결과 JAR**를 새로 만들고, 다음 단계(첫 적용이면 그 JAR로 `encrypt`, 이전 키의 암호문이 있으면 `rekey`)를 안내합니다. `config show`의 키ID, `config history`의 변경 기록, **결과 JAR와 키 파일의 지문 일치**를 확인합니다.

**오류·주의:** 키ID가 겹치면 새 ID를 씁니다. `--source embedded`를 요구하면 그대로 붙입니다. 이미 운영 중인 암호문이 있으면 JAR만 바꾸지 말고 [`rekey`](#29-rekey--기존-암호문을-새-키로-바꾸기)로 먼저 재암호화합니다. 공개 예제 키나 현재와 같은 키는 내장할 수 없습니다. 결과 JAR(이름을 `--out`으로 정한 경우 포함)와 키 파일은 Git·공개 저장소에 올리지 않습니다.

### 2.8 `fingerprint` — 키가 같은지 비교

**언제 쓰나:** 키 파일과 키 내장 JAR, 또는 여러 서버의 키가 같은지 키 원문 없이 비교할 때.

```text
java -jar <JAR> fingerprint [--config <외부 Properties>] [--lang ko|en]
java -jar <JAR> fingerprint --key-file <키 파일> [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 그 설정이 실제로 쓰는 키의 지문. Vault·KMS면 원격 키를 실제로 조회할 수 있음 |
| `--key-file <경로>` | 아니요 | `keygen` 형식 키 파일 자체의 지문. `--config`와 함께 쓸 수 없음 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint --key-file "$HOME\jck-secure\example.key"
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar fingerprint --config /etc/java-crypto-kit/app.properties
```

**결과:** 키 공급 방식, 키ID, 64자리 키 지문(SHA-256 기반)을 출력합니다. 비교할 양쪽의 지문 줄이 같으면 같은 키입니다. 지문은 키 비교용일 뿐 인증·키 보관 수단이 아니며, 같은 키라도 키ID가 다르면 이전 암호문과 맞지 않을 수 있습니다.

**오류·주의:** `KEY_SOURCE`면 실제 키 공급원과 실행 계정의 권한을 확인합니다.

### 2.9 `rekey` — 기존 암호문을 새 키로 바꾸기

**언제 쓰나:** 운영 중인 암호문이 있는 상태에서 키를 교체할 때. 기존 암호문을 자동으로 고치지 않으므로 **이전 키와 이전 키 내장 JAR를 보존한 채** 진행합니다([9.2 키 교체](#92-키-교체)).

```text
java -jar <실행 JAR> rekey [--from-config <이전 설정> | --from-jar <이전 JAR>]
    [--to-config <새 설정> | --to-jar <새 JAR>] [--value <기존 암호문>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--from-config <경로>` | 선택 | 이전 키 쪽: 실행 JAR 내장값 + 지정 Properties(JVM `-D`·환경변수 우선순위는 섞지 않음) |
| `--from-jar <JAR>` | 선택 | 이전 키 쪽: 그 JAR의 내장 설정만 사용 |
| `--to-config <경로>` | 선택 | 새 키 쪽: 실행 JAR 내장값 + 지정 Properties |
| `--to-jar <JAR>` | 선택 | 새 키 쪽: 그 JAR의 내장 설정만 사용 |
| `--value <암호문>` | 아니요 | 기존 암호문을 인자로 전달. 생략하면 화면에 보이지 않게 입력 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**조합 규칙:** `--from-*`와 `--to-*` 중 **적어도 한쪽**을 지정합니다. 같은 쪽에 `--from-config`와 `--from-jar`(또는 `--to-config`와 `--to-jar`)를 함께 줄 수 없습니다. 지정하지 않은 쪽은 실행 JAR의 최종 설정을 씁니다. 이전 키와 새 키는 **서로 다른 키와 키ID**여야 합니다.

**예제**

```powershell
# 새 키 내장 JAR로 실행하고, 이전 키 내장 JAR를 이전 키로 지정
java -jar .\java-crypto-kit-0.1.0-configured-2.jar rekey --from-jar .\java-crypto-kit-0.1.0-configured.jar
```

```bash
# 이전 키·새 키를 각각 설정 파일로 지정
java -jar ./java-crypto-kit-0.1.0-configured.jar rekey --from-config /secure/old.properties --to-config /secure/new.properties
```

**결과:** 기존 암호문을 입력하면 이전 키로 인증·복호화 → 새 키와 새 IV로 재암호화 → 새 키로 검증한 뒤 **새 암호문만** 출력합니다. 평문은 출력하지 않으며 Resource XML도 자동으로 바꾸지 않습니다.

**배포 순서:** Resource에 쓰는 **모든** 기존 암호문을 재암호화 → 새 키 내장 JAR와 새 암호문을 함께 배포 → WAS 재기동 후 실제 SQL 확인 → 이전 JAR·암호문은 원복용으로 보관. 이전 키를 잃었다면 `rekey`로 복구할 수 없으므로 DB 비밀번호 평문을 승인 절차에 따라 다시 `encrypt`해야 합니다.

**오류·주의:** 같은 키·같은 키ID면 새 키·새 ID를 준비합니다. `KEY_ID_MISMATCH`는 이전 키 쪽 설정을, `INTEGRITY`는 이전 키가 맞는지와 암호문 손상을 확인합니다. `--value`는 셸 기록에 남으므로 대화형 입력을 권장합니다.

### 2.10 `config show` — JAR 내장값 조회

**언제 쓰나:** JAR 안에 저장된 기본 설정과 최근 변경 요약을 확인할 때.

```text
java -jar <실행 JAR> config show [--jar <조회할 JAR>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--jar <경로>` | 아니요 | 다른 JAR의 내장 설정을 볼 때. 생략하면 실행 중인 JAR |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config show
java -jar .\java-crypto-kit-0.1.0.jar config show --jar .\java-crypto-kit-0.1.0-configured.jar
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config show
```

**결과:** 내장 키 공급원·키ID·언어·경고·출력 형식·Pool 기본값과 수정자·수정 시각·변경 횟수를 보여 줍니다. 키 원문은 보여 주지 않습니다.

**주의:** 외부 Properties와 JVM `-D`는 반영하지 않습니다. WAS가 실제로 쓰는 값은 [`info`](#213-info--실행-시-적용-설정과-출처)로 확인합니다. 이력이 손상된 JAR는 정상으로 표시하지 않고 오류로 끝납니다.

### 2.11 `config history` — 설정 변경 이력

**언제 쓰나:** JAR 내장 설정이 언제·누가·무엇을 바꿨는지 확인할 때.

```text
java -jar <실행 JAR> config history [--jar <조회할 JAR>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--jar <경로>` | 아니요 | 다른 JAR의 변경 이력을 볼 때. 생략하면 실행 중인 JAR |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar config history
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar config history
```

**결과:** 변경 순번, UTC 시각, 수정자(`--operator`), 명령, 사유(`--reason`), 설정별 이전 값 → 변경 값을 보여 줍니다. 키 값은 `(비공개) -> (교체됨)`처럼 가리고 키ID 변경은 표시합니다. 새 결과 JAR와 `--replace` 후에도 이력은 그대로 이어집니다. 한 번도 바꾸지 않은 JAR는 "변경 이력 없음"이 정상입니다.

**주의:** 해시 체인은 단순 수정·손상을 찾는 용도이며 **수정자가 위변조할 수 없는 감사 로그가 아닙니다**. 이력을 믿을 수 없으면 `--replace`나 ZIP 수정으로 복구하려 하지 말고 검증된 이전 JAR로 돌아갑니다.

### 2.12 `config set` — JAR 기본 설정 변경

**언제 쓰나:** WAS마다 외부 Properties나 `-D`를 반복하지 않고 JAR의 기본 설정(언어, 경고, 키 공급원, Pool 종류 등)을 바꿀 때. 실행 중인 프로세스의 설정을 바꾸는 명령이 아니며, 바뀐 결과 JAR를 다시 배포해야 적용됩니다.

```text
java -jar <입력 JAR> config set <설정>=<값> [<설정>=<값> ...] --operator <수정자>
    [--reason <사유>] [--jar <대상 JAR>] [--out <결과 JAR> | --replace] [--yes] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `<설정>=<값>` | 예 | 한 개 이상. 설정·기본값·허용값은 [10장](#10-설정-사전). 키 원문 `crypto.key.embedded`는 이 명령으로 바꿀 수 없음(`config embed-key` 사용) |
| `--operator <ID>` | 예 | 변경 이력에 남길 수정자 식별자(문자·숫자·`.`·`_`·`@`·`-`, 1~64자) |
| `--reason <사유>` | 아니요 | 이력에 남길 변경 사유(한 줄, 200자 이하) |
| `--jar <JAR>` | 아니요 | 실행 중인 JAR 대신 다른 JAR를 바꿀 때 |
| `--out <JAR>` | 아니요 | 결과 JAR 경로. 생략하면 `-configured.jar`(이미 바꾼 JAR면 다음 번호). 같은 이름의 파일이 있으면 오류 |
| `--replace` | 아니요 | 백업을 만든 뒤 대상 JAR 교체. `--out`과 함께 쓸 수 없음 |
| `--yes` | 아니요 | 키·공급원처럼 기존 암호문에 영향을 주는 변경의 `CHANGE` 확인 생략 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 키 내장 JAR를 바꾸면 -configured-2.jar가 새로 만들어집니다(원본 그대로).
java -jar .\java-crypto-kit-0.1.0-configured.jar config set crypto.lang=en --operator example-admin --reason "English messages"
java -jar .\java-crypto-kit-0.1.0-configured-2.jar config show
# Tomcat JDBC Pool 사용(JVM의 모든 Resource에 적용)
java -jar .\java-crypto-kit-0.1.0-configured.jar config set crypto.pool.factory=org.apache.tomcat.jdbc.pool.DataSourceFactory --operator example-admin
```

```bash
# 안내 WARNING 끄기: 운영 환경의 보안 정책을 확인한 뒤 적용합니다(위험 자체는 사라지지 않음).
java -jar ./java-crypto-kit-0.1.0-configured.jar config set crypto.warning.enabled=false --operator example-admin
```

**결과:** 출력된 **결과 JAR 경로**가 다음 실행·배포 대상입니다. 바꾼 뒤 전체 설정을 실행 시와 같은 규칙으로 다시 검증하고, 결과 JAR를 다시 읽어 확인한 뒤에만 자리에 둡니다. `config show`는 그 JAR의 내장값, `config history`는 누적 이력, `info`는 외부 Properties·허용된 `-D`까지 반영한 실제 값을 보여 줍니다.

**오류·주의:** 결과 파일이 이미 있으면 다른 `--out` 경로를 씁니다. 잘못된 설정 이름·값은 [10장](#10-설정-사전)을 확인합니다. 키 공급원·키ID 변경은 기존 암호문에 영향을 줍니다. 실행 중인 JAR·서명된 JAR·이력이 손상된 JAR는 바꾸지 않습니다.

### 2.13 `info` — 실행 시 적용 설정과 출처

**언제 쓰나:** 이번 실행에서 실제로 적용된 설정 값과 그 출처(JAR·외부 파일·JVM)를 확인할 때.

```text
java -jar <JAR> info [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--config <경로>` | 아니요 | 특정 외부 Properties를 썼을 때의 최종 설정과 출처 확인 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar info
java -jar .\java-crypto-kit-0.1.0-configured.jar info --config C:/secure/app.properties
```

```bash
java -Dcrypto.config.file=/etc/java-crypto-kit/app.properties -jar ./java-crypto-kit-0.1.0-configured.jar info
```

**결과:** 알고리즘, 키ID, 키 공급원, 키 위치(비밀값 제외), 설정별 출처, 적용·무시한 `-D` 이름, 경고·언어·Pool, 키 지문을 보여 줍니다. 키·비밀값은 출력하지 않습니다.

**오류·주의:** 실제 키를 읽지 못하면 실패(종료 1)합니다. CLI를 실행한 계정의 환경변수와 Tomcat **서비스 계정**의 환경변수는 다를 수 있습니다.

### 2.14 `doctor` — 설정과 키 진단

**언제 쓰나:** WAS 기동 전에 설정·키·암복호화가 정상인지 한 번에 점검할 때.

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
java -jar .\java-crypto-kit-0.1.0-configured.jar doctor
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar doctor --config /etc/java-crypto-kit/app.properties
java -jar ./java-crypto-kit-0.1.0-configured.jar doctor --offline
```

**결과**

| 표시 | 뜻·조치 |
|---|---|
| `PASS` | 해당 항목 정상(키 조회, 암복호화 자체 검증 등) |
| `WARN` | 주의 필요(예: 공개 예제 키 사용). **WARN만 있으면 종료 0**이므로 운영 승인 기준으로 단독 사용하지 않음 |
| `FAIL` | 키 파일 누락·형식 오류·설정 오류 등. 원인을 고친 뒤 다시 실행(종료 1) |
| `INFO` | 참고 정보: 변경 이력, 설정 출처, 언어·경고 설정, 키 공급원·키ID, 사용자 지정 내장 키 사용 안내(JAR를 비밀 파일로 관리) |
| `SKIP` | `--offline` 등으로 실행하지 않은 확인. PASS로 보지 않음 |

**주의:** `doctor`는 Tomcat JNDI와 실제 DB 연결을 검증하지 않습니다. 운영 준비는 **사용자 지정 키·지문 확인 + `doctor` FAIL 0 + 애플리케이션의 실제 JNDI 조회·SQL 확인**으로 판단합니다.

### 2.15 `file encrypt` — 파일 암호화

**언제 쓰나:** CSV·PDF·JSON·이미지·압축 파일 등 내용 형식과 관계없이 파일 전체를 암호화할 때. 자세한 형식은 [7장](#7-파일-암복호화).

```text
java -jar <JAR> file encrypt --in <원본 파일> [--out <출력 파일>] [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--in <경로>` | 예 | 암호화할 일반 파일 |
| `--out <경로>` | 아니요 | 생략하면 `<입력 파일>.jck`. 출력 파일이 이미 있으면 덮어쓰지 않음 |
| `--config <경로>` | 아니요 | 외부 키 공급 설정을 쓸 때 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar file encrypt --in 'C:/data/report.pdf'
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar file encrypt --in /data/export/users.csv --out /secure/users.csv.jck
```

**결과:** 예를 들어 `report.pdf.jck`가 만들어지고 원본 `report.pdf`는 그대로 남습니다. 출력은 문자열 ENC/B64가 아니라 청크 기반 바이너리 `JCKF v1`이며, 큰 파일도 스트리밍으로 처리합니다.

**오류·주의:** 출력 파일이 이미 있거나 입력이 없거나 입력과 출력이 같으면 거부합니다. 처리 중에는 입력 파일을 바꾸지 않습니다. 복호화에는 같은 키·키ID가 필요하므로 키(또는 키 내장 JAR)를 백업합니다. 평문 원본은 별도 보관·폐기 정책에 따라 관리합니다.

### 2.16 `file decrypt` — 파일 복호화

**언제 쓰나:** `file encrypt`(또는 Java API `encryptFile`)로 만든 `JCKF v1` 파일을 원래 파일로 되돌릴 때.

```text
java -jar <JAR> file decrypt --in <암호화 파일> [--out <복원 파일>] [--config <외부 Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--in <경로>` | 예 | `JCKF v1` 암호화 파일(보통 `.jck`) |
| `--out <경로>` | 조건부 | `.jck` 파일이면 확장자를 뗀 이름이 기본. `.jck`가 아닌 이름이면 **필수**. 출력 파일이 있으면 덮어쓰지 않음 |
| `--config <경로>` | 아니요 | 파일 암호화에 쓴 키 공급 설정 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# 원본 report.pdf가 같은 폴더에 아직 있으면 실패하므로 다른 복원 경로를 지정합니다.
java -jar .\java-crypto-kit-0.1.0-configured.jar file decrypt --in 'C:/data/report.pdf.jck' --out 'C:/restore/report.pdf'
```

```bash
java -jar ./java-crypto-kit-0.1.0-configured.jar file decrypt --in /secure/users.csv.jck --out /restore/users.csv
```

**결과:** 모든 청크의 인증이 끝난 파일만 최종 경로에 만듭니다. 인증에 실패하면 최종 파일을 만들지 않고 임시 파일을 지웁니다.

**오류·주의:** `INTEGRITY`는 손상·변조 또는 다른 키, `KEY_ID_MISMATCH`는 다른 키ID, `INVALID_TOKEN`은 `JCKF` 형식이 아닌 파일입니다. **결과는 평문**이므로 보호된 출력 폴더를 고릅니다(Windows는 출력 폴더의 권한을 상속).

### 2.17 `kms datakey` — AWS KMS 데이터 키 파일 만들기

**언제 쓰나:** 키 공급원 `aws-kms`를 처음 준비할 때 한 번. 기본 JAR만으로는 AWS SDK를 쓸 수 없으므로 선택형 `aws-kms-lib/*.jar`를 실행 클래스패스에 함께 넣습니다(Tomcat에서도 같음). 자세한 준비는 [8.2절](#82-aws-kms).

```text
java -cp '<JAR>;aws-kms-lib/*' io.javacryptokit.cli.CryptoCli kms datakey --out <데이터 키 파일> [--from-file <기존 키 파일>] [--config <KMS Properties>] [--lang ko|en]
```

| 옵션 | 필수 | 의미·기본값 |
|---|---|---|
| `--out <경로>` | 예 | KMS로 암호화된 데이터 키 파일 위치. 기존 파일은 덮어쓰지 않음 |
| `--from-file <키 파일>` | 아니요 | 기존 AES 키를 KMS `Encrypt`로 감싸 **계속 쓸 때**(기존 암호문 유지). 생략하면 KMS `GenerateDataKey`로 새 키 생성 |
| `--config <경로>` | 조건부 | KMS 키 ID·리전·`crypto.key.id` 등을 외부 파일로 줄 때. JAR 내장 설정에 모두 있으면 생략 |
| `--lang ko\|en` | 아니요 | 이번 실행의 메시지 언어 |

**예제**

```powershell
# Windows: 클래스패스 구분자는 ; (현재 폴더에 JAR와 aws-kms-lib 폴더가 있다고 가정)
java -cp 'java-crypto-kit-0.1.0-configured.jar;aws-kms-lib/*' io.javacryptokit.cli.CryptoCli kms datakey --out C:/secure/prod.datakey --config C:/secure/kms.properties
```

```bash
# Linux: 클래스패스 구분자는 :
java -cp 'java-crypto-kit-0.1.0-configured.jar:aws-kms-lib/*' io.javacryptokit.cli.CryptoCli kms datakey --out /secure/prod.datakey --config /secure/kms.properties
```

**결과:** 암호화된 데이터 키 파일만 만들고, KMS `Decrypt`로 복원까지 확인한 뒤 키 지문을 출력합니다. **WAS를 재기동할 때마다 다시 실행하지 않습니다.** 같은 파일에서 같은 데이터 키를 복원해야 기존 암호문이 유지됩니다.

**권한·오류:** 새 키 생성은 `kms:GenerateDataKey`·`kms:Decrypt`, 기존 키 감싸기는 `kms:Encrypt`·`kms:Decrypt`가 필요합니다. SDK가 없으면 클래스패스를, `AccessDenied`면 IAM·키 정책을, 자격증명·리전·키 ID 누락이면 설정을 확인합니다. 실제 AWS 연동은 사용하는 계정·IAM·네트워크에서 따로 검증해야 합니다.

### 2.18 도움말 명령

| 알고 싶은 것 | 명령 | 내용 |
|---|---|---|
| 어떤 기능이 있나 | `help` | 전체 명령과 처음 해 보기 |
| 설정 값 | `config help` | `crypto.*` 설정 25개의 기본값·허용값·설정 위치·예제 |
| Tomcat 설정 | `help tomcat` | JAR 배치, Resource 예제, Pool 선택, 오류 해결 |
| Vault·KMS | `help vault`, `help aws-kms` | 키 공급 설정·자격증명·설치 요건 |
| 명령 하나의 옵션 | `<명령> --help` | 그 명령이 받는 옵션과 예제 |

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar help
java -jar .\java-crypto-kit-0.1.0-configured.jar config help
java -jar .\java-crypto-kit-0.1.0-configured.jar help tomcat
java -jar .\java-crypto-kit-0.1.0-configured.jar config set --help --lang en
```

---

## 3. Tomcat JNDI 연동

### 3.1 적용 순서

1. **운영 키 준비:** 공개 예제 키 대신 사용자 지정 키를 씁니다([1.3절](#13-체험용-내장-키와-운영용-사용자-지정-키)).
2. **설치:** 키 내장 JAR(또는 외부 키를 쓰는 공개 JAR)와 DB의 JDBC 드라이버 JAR를 `CATALINA_BASE/lib`에 복사합니다. `lib`에는 java-crypto-kit JAR를 **하나만** 둡니다.
3. **암호화:** Tomcat과 같은 JAR·설정으로 `encrypt`를 실행해 DB 비밀번호 암호문을 만듭니다.
4. **Resource 작성:** 실제 Context 파일에 `factory`와 암호문 `password`를 넣은 `<Resource>`를 둡니다([3.3절](#33-resource를-넣을-파일)·[3.4절](#34-resource-주요-속성)).
5. **재시작과 확인:** Tomcat을 재시작한 뒤 애플리케이션에서 JNDI 조회·`getConnection()`·실제 SQL을 확인합니다([3.5절](#35-애플리케이션의-조회-코드)).

```powershell
Copy-Item .\java-crypto-kit-0.1.0-configured.jar C:/tomcat/lib/
```

```bash
cp ./java-crypto-kit-0.1.0-configured.jar /opt/tomcat/lib/ && chown tomcat:tomcat /opt/tomcat/lib/java-crypto-kit-0.1.0-configured.jar
```

### 3.2 DBCP2와 Tomcat JDBC Pool 선택

| 판단 기준 | DBCP2 | Tomcat JDBC Pool |
|---|---|---|
| 언제 선택 | **신규·일반 DB 연결(기본값)** | 이미 Tomcat JDBC Pool을 쓰거나 `jdbcInterceptors` 등 전용 기능이 필요할 때 |
| Pool JAR | `tomcat-dbcp.jar`(Tomcat에 포함) | `tomcat-jdbc.jar`(없으면 Tomcat 버전에 맞게 추가) |
| 선택 방법 | 아무 설정 없음(`crypto.pool.factory` 기본값) | `crypto.pool.factory=org.apache.tomcat.jdbc.pool.DataSourceFactory` |
| 최대 연결 | `maxTotal` | `maxActive` |
| 최대 대기(ms) | `maxWaitMillis` | `maxWait` |
| 예제 | [dbcp2-context.xml](tomcat/dbcp2-context.xml) | [jdbc-pool-context.xml](tomcat/jdbc-pool-context.xml) |

두 예제의 `factory`는 같은 복호화 Factory입니다. Pool 종류는 Resource 속성이 아니라 설정 `crypto.pool.factory`로 정하며 **한 Tomcat JVM의 모든 Resource에 함께 적용됩니다**. 설정 방법은 JAR 내장값(`config set crypto.pool.factory=... --operator <ID>`, [2.12절](#212-config-set--jar-기본-설정-변경)), 외부 Properties, `CATALINA_OPTS`의 `-Dcrypto.pool.factory=...` 중 하나입니다. Pool 속성 이름은 Pool마다 다르므로 섞어 쓰지 않습니다.

### 3.3 Resource를 넣을 파일

| 위치(Tomcat이 실제로 읽는 파일) | 적용 범위 | 언제 쓰나 |
|---|---|---|
| `<웹앱>/META-INF/context.xml` | 그 웹앱 | 웹앱별 Resource를 배포본과 함께 관리(일반적) |
| `CATALINA_BASE/conf/Catalina/localhost/<앱>.xml` | 지정한 앱 | WAS 운영자가 Context를 배포본과 분리해 관리 |
| `CATALINA_BASE/conf/context.xml` | 모든 웹앱의 기본 Context | 공통 설정이 꼭 필요할 때만. 웹앱마다 Pool이 따로 생기고 모든 앱에 비밀번호가 적용되므로 주의 |
| `conf/server.xml`의 `GlobalNamingResources` + 앱의 `ResourceLink` | 전역 정의 후 앱별 연결 | 여러 앱이 Resource 하나를 명시적으로 함께 쓰도록 설계했을 때 |

**예제 파일 이름은 설명용입니다.** 저장소의 `docs/tomcat/dbcp2-context.xml`·`jdbc-pool-context.xml`을 그 이름 그대로 두어도 Tomcat은 읽지 않습니다. 이미 있는 Context 파일이면 `<Context>` 안에 `<Resource ... />` 하나만 붙여 넣습니다(파일 전체를 바꾸지 않음).

### 3.4 Resource 주요 속성

| 속성 | 기본·예제 값 | 선택 판단 |
|---|---|---|
| `name` | `jdbc/myDB` | 앱에서 `java:comp/env/jdbc/myDB`로 조회할 이름 |
| `auth` | **`Container`(일반)** / `Application` | 리소스 인증 책임 선언. 앱이 리소스 관리자에 직접 인증하는 별도 설계가 아니면 `Container` |
| `type` | `javax.sql.DataSource` | 이 Factory가 지원하는 타입(Tomcat 10.1·11에서도 `javax.sql`) |
| `factory` | `io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory` | **항상 이 복호화 Factory**를 써야 ENC/B64 비밀번호를 처리 |
| `driverClassName` | `org.mariadb.jdbc.Driver` | 실제 DB 드라이버 클래스 |
| `url` | `jdbc:mariadb://...` | 대상 DB의 실제 JDBC URL |
| `username` | 평문 계정 또는 `ENC[...]` | 계정 암호화는 선택 |
| `password` | 사용자 지정 키로 만든 `ENC[...]`/`B64[...]` | 평문은 거부. 암호문의 키·키ID가 Tomcat에 배포한 JAR(또는 설정)과 같아야 함 |

`auth="Container"`는 Tomcat이 리소스 관리자에 로그인할 책임을 갖는 일반적인 선언이고, `auth="Application"`은 웹앱 코드가 인증 책임을 갖는다는 선언입니다. 이 값만 바꿔 다른 DB 계정으로 자동 접속되지는 않으며, `getConnection(user, password)` 같은 방식은 Pool의 지원 여부와 업무 코드 설계를 함께 판단해야 합니다. 공식 값과 범위는 [Tomcat Context의 Resource 정의](https://tomcat.apache.org/tomcat-11.0-doc/config/context.html)를 참고합니다.

**선택형 JNDI 속성**은 보통 생략하고 기본값을 유지합니다.

| 속성 | 허용값·기본 | 언제 바꾸나 |
|---|---|---|
| `scope` | `Shareable`(기본) / `Unshareable` | 연결 공유를 제한하는 특수 설계에서만. 일반 DB Pool은 기본 유지 |
| `singleton` | `true`(기본) / `false` | JNDI 조회마다 새 객체가 필요할 때만 `false`. DataSource JMX 등록에는 `true` 필요 |
| `description` | 설명 문자열(선택) | 운영자가 Resource 용도를 구분할 때 |
| `closeMethod` | 인자 없는 메서드 이름, `""`이면 비활성 | 특별한 종료 정책이 필요할 때만. 일반 DataSource는 기본 `close` 유지 |

그 밖의 Pool 속성은 [4장](#4-connection-pool-설정)을 봅니다.

### 3.5 애플리케이션의 조회 코드

기존에 JNDI DataSource를 쓰는 애플리케이션이라면 **업무 코드를 바꿀 필요가 없습니다.** 아래는 연결 확인용 예제이며 `SELECT 1`은 MariaDB 기준입니다.

```java
javax.naming.Context context = new javax.naming.InitialContext();
javax.sql.DataSource ds = (javax.sql.DataSource) context.lookup("java:comp/env/jdbc/myDB");
try (java.sql.Connection conn = ds.getConnection();
     java.sql.PreparedStatement ps = conn.prepareStatement("SELECT 1");
     java.sql.ResultSet rs = ps.executeQuery()) {
    if (!rs.next()) throw new IllegalStateException("DB connection check failed");
}
```

### 3.6 JVM 공통 범위와 재시작

- **키 공급원·키ID·Pool 종류는 한 Tomcat JVM에 하나입니다.** Resource마다 다른 키나 Pool이 필요하면 Tomcat 인스턴스(`CATALINA_BASE`)를 나눕니다. 여러 서버에는 같은 키 내장 JAR를 배포하고 `fingerprint`로 같은 키인지 확인합니다.
- **설정과 키는 DataSource를 만들 때 읽습니다**(실행 중 자동 반영 없음). 설정·키·암호문을 바꾸면 Tomcat을 재시작합니다. `initialSize`가 0보다 크면 기동할 때 첫 연결을 만들므로 비밀번호 오류가 바로 로그에 나타납니다.
- **외부 설정을 쓰는 경우(콘솔·스크립트로 실행):** Linux는 `bin/setenv.sh`에 `CATALINA_OPTS="$CATALINA_OPTS -Dcrypto.config.file=/etc/java-crypto-kit/app.properties"`, Windows를 `startup.bat`·`catalina.bat`으로 실행할 때는 `bin/setenv.bat`에 `set "CATALINA_OPTS=%CATALINA_OPTS% -Dcrypto.config.file=C:/secure/app.properties"`를 둡니다.
- **Windows 서비스로 실행하는 경우:** 서비스는 `setenv.bat`을 읽지 않습니다. Tomcat 서비스 설정 도구(예: `tomcat9w.exe`의 Java 탭 Java Options)에 `-Dcrypto.config.file=C:/secure/app.properties`를 한 줄로 추가하거나, 명령으로 `tomcat9.exe //US//Tomcat9 ++JvmOptions=-Dcrypto.config.file=C:/secure/app.properties`처럼 바꾼 뒤 서비스를 재시작합니다(실행 파일·서비스 이름은 설치한 Tomcat에 맞게). Windows 서비스 실행은 실서버에서 검증하지 않았습니다.
- **키 환경변수**(`crypto.key.source=env`)는 Tomcat을 실행하는 계정·서비스에 전달되어야 합니다(Linux systemd `Environment=`, Windows 서비스의 환경 설정). CLI를 실행한 계정의 환경변수와 다를 수 있습니다.
- **로그의 비밀값 정제 범위:** Factory는 DataSource를 만드는 동안의 오류에서 비밀번호·키·암호문을 지우고 원인 유형만 남깁니다. 그 뒤 `getConnection()` 단계에서 Pool·JDBC 드라이버가 직접 내는 예외·로그는 이 라이브러리 범위 밖입니다.

---

## 4. Connection Pool 설정

**원칙:** java-crypto-kit은 일반 Resource 속성을 Tomcat 공식 Pool Factory에 그대로 넘깁니다. **넘긴다고 모든 속성이 적용된다는 뜻은 아닙니다.** 값·범위·지원 여부는 대상 Tomcat과 Pool 버전을 따릅니다.

### 4.1 먼저 볼 기본 옵션

| 역할 | DBCP2 | Tomcat JDBC Pool | 판단 기준 |
|---|---|---|---|
| 최초 연결 | `initialSize` | 동일 | 기동 시 미리 여는 연결 수. 많으면 DB 세션 증가 |
| 최대 연결 | `maxTotal` | `maxActive` | DB 연결 한도와 WAS 노드 수에 맞춤 |
| 최소·최대 유휴 | `minIdle`, `maxIdle` | 동일 | 트래픽이 적을 때 유지할 연결 수 |
| 대기 시간(ms) | `maxWaitMillis` | `maxWait` | Pool이 가득 찼을 때 기다리는 한도 |
| 검사 SQL | `validationQuery` | 동일 | DBMS에 맞는 읽기 전용 SQL(MariaDB `SELECT 1`) |
| 검사 제한 시간(초) | `validationQueryTimeout` | 동일 | 검사 SQL이 오래 걸릴 때의 한도 |
| 빌려줄 때 검사 | `testOnBorrow` | 동일 | 오래된 연결 재사용 오류 방지. 검사 비용 고려 |
| 유휴 검사 | `testWhileIdle` | 동일 | 아래 검사 주기와 함께 설정 |
| 검사 주기(ms) | `timeBetweenEvictionRunsMillis` | 동일 | 검사 부하를 고려해 설정 |

예제의 `maxTotal=20`, `maxActive=20`, `maxWait=5000` 등은 **범용 최적값이 아닙니다.** DB 최대 세션, WAS 노드 수, 트래픽, 연결을 오래 쓰는 업무가 있는지 확인한 뒤 정합니다.

### 4.2 문제가 생겼을 때 볼 고급 옵션

| 증상 | DBCP2 | Tomcat JDBC Pool | 주의 |
|---|---|---|---|
| 연결 누수 | `removeAbandonedOnBorrow`, `removeAbandonedOnMaintenance` | `removeAbandoned` | 정상 장기 트랜잭션도 끊을 수 있음. 먼저 앱의 `close()` 확인 |
| 누수 판단 시간(초) | `removeAbandonedTimeout` | 동일 | 정상 최장 처리 시간 고려 |
| 진단 로그 | `logAbandoned` | 동일 | 로그량·스택 정보 주의 |
| 검사 빈도 | Pool 자체 정책 | `validationInterval`(ms) | Tomcat JDBC Pool 전용 |
| JDBC 인터셉터 | 해당 없음 | `jdbcInterceptors` | Tomcat JDBC Pool 전용 |
| 세션 초기화 SQL | `connectionInitSqls` 등 | `initSQL` | DBMS·Pool별 구문 확인 |

**증상별 우선 확인:** Pool 포화는 최대 연결·대기 시간, 유휴 후 연결 실패는 검사 SQL·빌려줄 때 검사, DB 세션 과다는 **노드 수 × Resource 수 × Pool 최대값**부터 봅니다. DB 접속 성공만으로 Pool 옵션이 적용됐다고 판단하지 말고 Pool 지표·JMX·공식 설정 정보를 함께 확인합니다.

공식 문서: [Tomcat JNDI Resources(DBCP2)](https://tomcat.apache.org/tomcat-11.0-doc/jndi-resources-howto.html) · [Tomcat JDBC Pool](https://tomcat.apache.org/tomcat-11.0-doc/jdbc-pool.html). 운영 중인 Tomcat 버전의 문서를 확인합니다.

---

## 5. 키 공급원과 설정 적용

### 5.1 키 공급원 선택

| 공급원 | 이럴 때 | 준비·주의 |
|---|---|---|
| `embedded` | **키 내장 JAR 하나로 배포**(기본값) | 키를 JAR에서 추출할 수 있으므로 JAR 파일 권한·배포를 통제 |
| `file` | JAR와 키를 분리할 때 | 보호된 키 파일, Tomcat 서비스 계정의 읽기 권한 |
| `env` | 배포 환경이 환경변수로 비밀값을 안전하게 넣어 줄 때 | 실제 키 값을 `.properties`나 `-D`에 적지 않음 |
| `vault` | Vault KV v2 운영 체계가 이미 있을 때 | TLS·권한·토큰, Secret 버전 고정([8.1절](#81-vault-kv-v2)) |
| `aws-kms` | AWS IAM·KMS로 데이터 키를 보호할 때 | 선택형 SDK, 암호화된 데이터 키 파일 보존([8.2절](#82-aws-kms)) |

**AES 키가 꼭 필요한가요?** 복호화할 수 있는 AES-256-GCM 암호화에는 비밀키가 필요하지만, **키 파일을 매번 만들거나 명령마다 입력할 필요는 없습니다.** 이미 준비된 키를 위 공급원 중 하나로 씁니다. `keygen`은 *새 AES 키가 필요할 때만* 실행합니다. 공개 JAR의 예제 키는 동작 확인용이며 실제 비밀값 보호에는 쓰지 않습니다.

| 질문 | 답 |
|---|---|
| 키 파일 없이 쓸 수 있나요? | 예. JAR에 사용자 지정 키가 이미 내장되어 있거나 환경변수·Vault·KMS가 키를 주면 키 파일을 따로 만들 필요가 없습니다. |
| Salt만으로 암호화·복호화할 수 있나요? | 아니요. Salt는 비밀키가 아닙니다. 비밀번호 기반 암호화(PBE)는 *비밀번호 + Salt + 키 파생 함수*로 실제 AES 키를 만드는 방식입니다. |
| 비밀번호와 Salt로 키를 만드는 기능이 있나요? | 현재 **미지원**입니다(PBKDF2·Argon2 등 키 파생 기능 없음). |
| 사용자 로그인 비밀번호를 보관하려면? | 원문 복원이 필요 없으므로 AES 양방향 암호화가 아니라 Salt를 쓰는 **단방향 비밀번호 해시**를 별도 인증 모듈에서 씁니다. |

**키를 가져오지 못하면 다른 키로 자동 전환하지 않습니다(Fail Closed).** 키 파일·환경변수·Vault·KMS 설정이 있는데 `crypto.key.source`가 없으면 오류로 중단합니다.

### 5.2 설정을 두는 곳과 우선순위

**최종값 우선순위:** CLI 1회 옵션(`--lang`) → 허용된 JVM `-D` → 외부 Properties → JAR 내장값. `crypto.jvm.override.enabled=false`이면 개별 `-D`는 무시합니다(설정 파일 경로 `-Dcrypto.config.file`은 예외로 항상 동작). 설정은 객체(또는 DataSource)를 만들 때 한 번 읽으므로, 실행 중인 WAS에 반영하려면 재시작합니다.

| 두는 곳 | 바꾸는 방법 | 언제 쓰나 | 반영 |
|---|---|---|---|
| JAR 내장값 | `config set ... --operator <ID>`, 키는 `config embed-key` | 여러 서버·실행에 같은 기본값을 영구 적용 | **결과 JAR**를 CLI·WAS에 다시 배포 |
| 외부 Properties | `.properties` 파일([5.3절](#53-외부-properties-지정)) | 서버마다 키 공급원·키 경로·Vault 경로를 다르게 둘 때 | WAS에 설정 경로 전달 후 재시작 |
| JVM `-D` | `-Dcrypto.<이름>=<값>`(허용된 이름만) | 운영 정책이 허용하고 **프로세스 전체**에 같은 값을 줄 때 | 그 JVM 재시작 |
| Tomcat `<Resource>` 속성 | Context XML의 `maxTotal`·`validationQuery` 등 | 그 JNDI Resource의 연결·Pool 옵션 | 해당 앱·Tomcat 재시작 |
| CLI 1회 옵션 | `--lang`, `--in`, `--out` 등 | 그 명령 한 번 | 그 실행에만 |

`auth`·`maxTotal` 같은 Resource 속성은 `crypto.*` 설정이 아니고, 반대로 `crypto.key.source`·`crypto.lang`·`crypto.pool.factory`는 XML 속성이 아닙니다. 키 원문 `crypto.key.embedded`는 `-D`로 지정하면 오류로 중단합니다(프로세스 목록·로그 노출 방지). JAR 내장값은 `config embed-key`로만 바꾸며, 외부 Properties에 적어 공급할 수도 있지만 키 원문이 파일에 남으므로 권장하지 않습니다(키를 JAR 밖에 두려면 `file`·`env`를 씁니다).

| 확인 명령 | 보여 주는 것 |
|---|---|
| `config show` | **JAR 내장값만**(외부 Properties·`-D` 미반영) |
| `config history` | JAR 설정 변경 이력(기록용, 신원 인증 아님) |
| `info` | 이번 실행에서 최종 적용된 값과 출처, 적용·무시한 `-D` |
| `doctor` | 설정·키·암복호화 자체 진단(**DB 연결 시험 아님**) |

**기본 언어:** `crypto.lang=ko`(허용 `ko`·`en`·`auto`). 출력 형식 `crypto.output.encoding=enc|base64`는 ENC/B64 **표현만** 바꿉니다. 전체 25개 설정은 [10장](#10-설정-사전)에 있습니다.

### 5.3 외부 Properties 지정

외부 설정 파일의 경로는 다음 순서로 하나를 고릅니다. 아무것도 지정하지 않으면 JAR 내장값만 씁니다.

1. CLI `--config <파일>`(Java API는 `CredentialCrypto.fromConfigFile(path)`)
2. JVM 속성 `-Dcrypto.config.file=<파일>`
3. 환경변수 `CRYPTO_CONFIG_FILE`

경로를 지정했는데 비어 있으면(빈 `--config`·빈 `-D`·빈 환경변수) 미지정으로 보지 않고 오류로 중단합니다. 외부 파일에 없는 설정 이름(오타)이나 `crypto.config.file`이 있으면 오류로 중단하고, 비슷한 정식 이름이 확실하면 함께 안내합니다(값은 출력하지 않음). 이 라이브러리 영역의 `-Dcrypto.*` 오타(예: `crypto.key.soruce`)도 같은 이유로 오류로 중단합니다.

예제 파일: [java-crypto-kit.example.properties](config/java-crypto-kit.example.properties). 이 예제는 Linux 경로의 파일 키(예 1)가 켜진 상태이므로, 그대로 쓰면 키 파일이 없는 서버에서 `KEY_SOURCE` 오류가 나는 것이 정상입니다. 자신의 OS 경로·키ID·실제 키 파일로 바꾼 뒤 `doctor`로 확인합니다. Windows 경로는 `C:/secure/app.key`처럼 `/`로 적습니다.

---

## 6. Java API

공개 진입점은 **`io.javacryptokit.CredentialCrypto`** 하나입니다. `core`·`config` 등 하위 패키지는 내부 구현이므로 직접 쓰지 않습니다. 배포 JAR를 클래스패스에 추가하면 CLI·Tomcat과 같은 엔진·설정 규칙으로 문자열·바이트·파일을 처리합니다. 저장소에서 테스트로 관리하는 예제는 `src/test/java/example/ApiUsageExample.java`입니다.

### 6.1 API 목록

| 구분 | 메서드 | 입력 → 반환 | 참고 |
|---|---|---|---|
| 생성 | `fromDefaultConfiguration()` / `fromConfigFile(Path)` | 설정 → `CredentialCrypto` | WAS와 같은 설정 탐색 규칙 / 지정한 외부 설정 |
| 문자열 암호화 | `encryptText(String)` / `encryptText(char[])` | 평문 → `String` 암호문 | 출력 형식은 설정 `crypto.output.encoding`(기본 ENC) |
| 문자열 복호화 | `decryptText(String)` | `ENC[...]`·`B64[...]` → `String` | 두 형식을 자동 인식. 잘못된 UTF-8은 오류 |
| 바이트 암호화 | `encryptBytes(byte[])` | 바이트 → **`String` 암호문** | 이름은 입력 타입을 뜻함 |
| 바이트 복호화 | `decryptBytes(String)` | 암호문 → **`byte[]`** | 원래 바이트를 그대로 복원 |
| 검증·판별 | `verify(String)` / `isToken(String)` | 암호문 → `boolean` | `isToken`은 접두어만 검사하며 복호화 가능·무결성 확인이 아님 |
| 상태 | `keyId()` / `keySource()` | 없음 → `String` | 키 원문은 반환하지 않음 |
| 파일 | `encryptFile(Path, Path)` / `decryptFile(Path, Path)` | 입력·출력 경로 → 없음 | 원본 보존, 출력 덮어쓰기 금지, 대용량 스트리밍 |

`B64[...]`가 필요하면 설정 `crypto.output.encoding=base64`를 씁니다. 원시 AES 결과를 `byte[]`로 주고받는 공개 API는 없습니다.

### 6.2 문자열 암복호화와 직접 실행

```java
import io.javacryptokit.CredentialCrypto;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
        String token = crypto.encryptText("example-only-secret");   // ENC[v1:...] (설정이 base64면 B64[...])
        String plain = crypto.decryptText(token);                    // ENC·B64 모두 복호화
        boolean ok = crypto.verify(token);                           // 평문 없이 검증
        if (!ok || !"example-only-secret".equals(plain)) throw new IllegalStateException("Mismatch");
    }
}
```

**Java 8로 직접 실행:** 위 코드를 `CryptoExample.java`로 저장하고 배포 JAR와 같은 폴더에서 실행합니다(Gradle·Tomcat 불필요).

```powershell
# Windows PowerShell(클래스패스 구분자 ;)
javac -cp .\java-crypto-kit-0.1.0-configured.jar .\CryptoExample.java
java -cp '.;java-crypto-kit-0.1.0-configured.jar' CryptoExample
```

```bash
# Linux(클래스패스 구분자 :)
javac -cp ./java-crypto-kit-0.1.0-configured.jar CryptoExample.java
java -cp '.:java-crypto-kit-0.1.0-configured.jar' CryptoExample
```

이 코드는 예시 값의 일치 여부만 확인하며 평문이나 키를 출력하지 않습니다. 공개 JAR로 실행하면 공개 예제 키 WARNING이 나오는 것이 정상입니다. 실제 서비스에서는 사용자 지정 키를 내장한 JAR나 외부 키 설정을 쓰고, 암호화하는 쪽과 복호화하는 쪽이 같은 키·키ID를 써야 합니다.

### 6.3 `byte[]` 입력과 출력

아래 조각은 6.2절의 `crypto` 객체를 그대로 씁니다. 따로 쓸 때는 `CredentialCrypto.fromDefaultConfiguration()`으로 먼저 만듭니다.

```java
byte[] input = new byte[] {0, 1, (byte) 255};
String token = crypto.encryptBytes(input);       // 입력은 byte[], 결과는 String 암호문
byte[] restored = crypto.decryptBytes(token);    // 결과가 byte[]
try {
    if (!java.util.Arrays.equals(input, restored)) throw new IllegalStateException("Mismatch");
} finally {
    java.util.Arrays.fill(restored, (byte) 0);
}
```

`encryptBytes(byte[])`는 **입력이 바이트 배열**이고 반환값은 `String` 암호문입니다. `decryptBytes(String)`의 결과가 `byte[]`입니다. 문자열 암호문에는 길이 제한이 있으므로 큰 데이터는 파일 API를 씁니다.

### 6.4 민감정보와 오류 처리

```java
char[] password = "example-only".toCharArray();
try {
    String token = crypto.encryptText(password);
    if (!crypto.verify(token)) throw new IllegalStateException("Bad token");
} finally {
    java.util.Arrays.fill(password, '\0');
}
```

`String`은 JVM 메모리에서 확실히 지울 수 없으므로 민감한 입력에는 `char[]`를 고려합니다. `encryptText(char[])`는 **입력 배열을 지우지 않으므로 호출자가 지웁니다.** `decryptText()` 결과(`String`)는 오래 보관하거나 로그에 남기지 않습니다. 오류는 `CredentialCryptoException#getReason()`으로 `KEY_SOURCE`·`KEY_ID_MISMATCH`·`INTEGRITY`·`INVALID_TOKEN` 등을 구분하며, 예외 메시지에는 평문·키·암호문이 들어가지 않습니다.

### 6.5 외부 설정과 설정을 읽는 시점

```java
CredentialCrypto crypto = CredentialCrypto.fromConfigFile(
        java.nio.file.Paths.get("/etc/java-crypto-kit/app.properties"));
```

설정은 객체를 만들 때 읽습니다. 내장·파일·환경변수 키는 호출할 때마다 읽고, Vault·KMS 원격 키는 객체마다 처음 한 번 조회한 뒤 재사용합니다. 설정이나 키를 바꾸면 새 객체를 만듭니다(운영 WAS는 해당 Resource 재생성 또는 재시작). 객체는 여러 스레드에서 함께 써도 됩니다.

---

## 7. 파일 암복호화

문자열 `ENC`/`B64`와 파일 `JCKF v1`은 다른 형식입니다. CSV·PDF·JSON·이미지 등 **내용 형식을 해석하지 않고 바이너리로 암호화**하며, 큰 파일도 한 번에 메모리에 올리지 않고 스트리밍으로 처리합니다.

| 하려는 작업 | 명령 | 기본 결과·주의 |
|---|---|---|
| 파일 암호화 | `file encrypt --in <원본>` | `<원본>.jck` 생성. 원본 보존, 결과 파일 덮어쓰기 금지 |
| 파일 복호화 | `file decrypt --in <원본>.jck` | `.jck`를 뗀 이름으로 복원. 같은 이름의 파일이 있으면 실패 |
| 다른 이름으로 복원 | `file decrypt --in <암호화 파일> --out <복원 경로>` | 보호된 출력 폴더 지정, 기존 파일 덮어쓰기 금지 |

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar file encrypt --in 'C:/data/report.pdf'
java -jar .\java-crypto-kit-0.1.0-configured.jar file decrypt --in 'C:/data/report.pdf.jck' --out 'C:/restore/report.pdf'
```

복호화는 전체 인증이 끝나기 전에는 최종 평문 파일을 만들지 않습니다. 실패하면 `INTEGRITY`(변조·키 불일치), `KEY_ID_MISMATCH`(다른 키ID), 파일 존재 오류(다른 출력 경로 지정)를 확인합니다. 결과 평문 파일의 접근 권한은 출력 경로의 OS 정책을 따릅니다.

옵션과 Linux 예제는 [2.15절](#215-file-encrypt--파일-암호화)·[2.16절](#216-file-decrypt--파일-복호화), Java 코드는 [6장](#6-java-api)의 `encryptFile`·`decryptFile`을 봅니다.

---

## 8. Vault와 AWS KMS (선택)

**중앙 키 관리 체계를 이미 쓰는 경우에만 필요합니다.** 키 내장 JAR나 파일·환경변수 키로 운영한다면 이 장은 건너뜁니다.

| 방식 | 실제 동작 | 주의 |
|---|---|---|
| Vault KV v2 | Vault Secret에 저장한 AES 키를 조회 | 버전 고정, TLS·토큰 권한. Transit 직접 암호화가 아님 |
| AWS KMS | KMS가 보호한 **암호화 데이터 키**를 복원 | KMS 마스터 키는 반출하지 않음. 선택형 SDK 설치 필요 |

### 8.1 Vault KV v2

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
java -jar ./java-crypto-kit-0.1.0-configured.jar doctor --config /etc/java-crypto-kit/vault.properties --offline
java -jar ./java-crypto-kit-0.1.0-configured.jar doctor --config /etc/java-crypto-kit/vault.properties
java -jar ./java-crypto-kit-0.1.0-configured.jar fingerprint --config /etc/java-crypto-kit/vault.properties
```

**결과 판단:** `--offline`은 네트워크 확인을 건너뜁니다(SKIP). `--offline` 없는 `doctor`는 TLS·토큰·KV v2 키 조회까지 확인합니다. 403이면 토큰 권한뿐 아니라 **mount·path 오타**도 확인합니다(정책 밖 경로도 Vault는 권한 부족으로 답함). 404면 Secret·버전·KV v2 여부를 확인합니다. 토큰·CA·네트워크 문제는 내장 키로 대체하지 않고 실패합니다. Tomcat은 **실제 서비스 계정**으로 Secret을 읽어야 하며, 키는 DataSource를 만들 때 조회하므로 설정·Secret을 바꾸면 재시작합니다. 재시도는 연결 실패·시간 초과·429/5xx에만 하고 리다이렉트는 따르지 않습니다.

### 8.2 AWS KMS

**이럴 때:** IAM 역할과 KMS 운영 정책이 준비되어 있고, 키 평문 파일을 계속 두기보다 **KMS가 보호한 데이터 키 파일**을 재사용하려는 경우. java-crypto-kit은 KMS 마스터 키를 반출하지 않습니다.

1. AWS SDK 2.x 선택형 묶음(`aws-kms-lib/*.jar`)을 준비합니다. **기본 JAR에는 AWS SDK가 없습니다.**
2. KMS 키 ID·ARN·alias, 리전, 키ID(`crypto.key.id`)를 설정합니다. 자격증명은 AWS SDK 표준 체계(IAM 역할 우선)를 씁니다.
3. [`kms datakey`](#217-kms-datakey--aws-kms-데이터-키-파일-만들기)를 **처음 한 번** 실행해 데이터 키 파일을 만듭니다. 기존 암호문을 유지하려면 `--from-file`로 **현재 AES 키를 KMS로 감쌉니다.** 생략하면 새 키가 만들어져 기존 암호문과 맞지 않습니다.
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
# Linux: 배포 JAR와 aws-kms-lib 폴더가 현재 폴더에 있다고 가정
# 새 데이터 키를 만드는 예입니다. 이미 쓰는 AES 키가 있으면 --from-file /secure/example.key를 붙여야 기존 ENC가 유지됩니다.
java -cp 'java-crypto-kit-0.1.0-configured.jar:aws-kms-lib/*' io.javacryptokit.cli.CryptoCli kms datakey --out /etc/java-crypto-kit/prod.datakey --config /etc/java-crypto-kit/kms.properties
java -cp 'java-crypto-kit-0.1.0-configured.jar:aws-kms-lib/*' io.javacryptokit.cli.CryptoCli doctor --config /etc/java-crypto-kit/kms.properties
```

Windows는 `-cp 'java-crypto-kit-0.1.0-configured.jar;aws-kms-lib/*'`처럼 세미콜론을 씁니다. AWS SDK가 필요한 실행에서는 `java -jar`와 `-cp`를 함께 쓰지 않습니다. 필요한 권한은 새 키 생성 `kms:GenerateDataKey`+`kms:Decrypt`, 기존 키 감싸기 `kms:Encrypt`+`kms:Decrypt`, WAS 복원 `kms:Decrypt`입니다. 암호화 컨텍스트는 `java-crypto-kit:key-id=<crypto.key.id>`로 고정됩니다.

**장애 시:** `AccessDenied`는 IAM·키 정책, `InvalidCiphertext`는 데이터 키 파일 손상 또는 키ID(암호화 컨텍스트) 불일치, `NotFound`는 KMS 키·리전, SDK 누락은 선택형 라이브러리 설치를 확인합니다. 데이터 키 파일과 KMS 키를 잃거나 삭제하면 기존 암호문을 복구할 수 없습니다. 실제 AWS 계정에서의 KMS 연동은 로컬 모의 시험과 따로 검증해야 합니다.

---

## 9. 운영 변경과 장애 대응

운영 중 변경은 **키를 유지하는지**부터 정합니다. DB 비밀번호만 바꾸면 `encrypt`, AES 키 자체를 바꾸면 `rekey`가 필요합니다. 명령의 전체 옵션은 [2장](#2-cli-명령)에 있습니다.

### 9.1 키는 그대로, DB 비밀번호만 변경

1. **이미 운영 중인 키 내장 JAR**(또는 같은 외부 설정)로 `encrypt`를 실행해 새 DB 비밀번호의 암호문을 만듭니다.
2. 해당 `<Resource password="...">` 값만 바꿉니다(키·키ID는 그대로).
3. Resource를 다시 만들거나 Tomcat을 재시작한 뒤 실제 SQL이 성공하는지 확인합니다.

```powershell
java -jar .\java-crypto-kit-0.1.0-configured.jar encrypt
```

키를 그대로 쓰는 비밀번호 변경에는 `keygen`·`config embed-key`·`rekey`가 필요 없습니다.

### 9.2 키 교체

| 순서 | 작업 | 확인 |
|---|---|---|
| 1. 보존 | **이전 키 내장 JAR·이전 키·기존 모든 Resource 암호문**을 안전하게 백업 | JAR와 암호문을 같은 시점으로 되돌릴 수 있음 |
| 2. 준비 | 새 `keygen` → 새 키ID로 `config embed-key` | 새 JAR·새 키ID 확인 |
| 3. 재암호화 | Resource의 기존 암호문 **각각** `rekey --from-jar <이전 JAR>` | 새 `ENC[...]`의 키ID 확인 |
| 4. 전환 | 새 JAR와 **모든 Resource의 새 암호문을 함께** 적용 | `lib`에 JAR 하나, 각 Resource SQL 성공 |
| 5. 원복 | 장애 시 이전 JAR·이전 암호문·이전 키 설정을 **한 세트로** 복원 | 이전 상태의 SQL 성공 |

```powershell
# 새 키 내장 JAR로 실행합니다. 새 JAR 이름은 config embed-key 출력에서 확인합니다.
java -jar .\java-crypto-kit-0.1.0-configured-2.jar rekey --from-jar .\java-crypto-kit-0.1.0-configured.jar
```

`rekey`는 XML을 자동으로 바꾸지 않습니다. **이전 키를 이미 잃었다면 기존 암호문은 복구할 수 없습니다.** Vault 최신 버전이나 KMS 새 데이터 키를 무심코 쓰면 기존 암호문이 깨질 수 있으므로 Vault는 `crypto.vault.ver`로 버전을 고정합니다.

### 9.3 오류 코드별 조치

**먼저 세 가지를 구분합니다.** `config show`는 **JAR 내장값**, `info`는 **실제 적용값과 출처**, `doctor`는 **설정·키 진단**입니다. **DB 연결 성공**은 WAS의 실제 JNDI 조회와 SQL로 따로 확인합니다.

| 현상·오류 | 흔한 원인 | 우선 조치 |
|---|---|---|
| `PLAINTEXT_PASSWORD` | Resource에 평문 비밀번호를 넣음 | 키 내장 JAR로 `encrypt`한 `ENC[...]` 전체로 바꿈 |
| `MISSING_PASSWORD` | Resource에 `password`가 없음 | 암호문 `password="ENC[...]"` 속성 추가 |
| `KEY_ID_MISMATCH` | JAR의 키ID와 암호문의 키ID가 다름 | `config show`·이전 JAR·Resource 암호문 비교 |
| `INTEGRITY` | 키가 다르거나 암호문 손상 | `fingerprint`로 키 비교 후 원본 암호문 대조 |
| `KEY_SOURCE` | 파일·환경변수·Vault·KMS 키를 읽지 못함 | **Tomcat 서비스 계정**의 권한·환경변수·TLS·IAM 확인 |
| `POOL_FAILURE` | DB 로그인·Pool 초기화 실패 | 원인 유형의 SQLState(28000 = 로그인 거부), JDBC URL·계정, Pool별 속성 이름, `lib`의 Pool·드라이버 JAR |
| `UNSUPPORTED_RESOURCE` | DataSource가 아닌 JNDI Resource | `type="javax.sql.DataSource"`인지 확인 |
| `CRYPTO_PROVIDER` | JDK 암호화 Provider 오류. 구형 Oracle JDK 8(8u161 미만)의 AES-256 정책 제한이 흔한 원인 | 실제 JDK 버전·보안 정책 확인([11.1절](#111-검증-상태)의 JDK 8 정책) |
| `CONFIGURATION` / `USAGE` | 설정·옵션 이름 오타, 값 누락·형식 오류 | [10장 설정 사전](#10-설정-사전)·[2장 명령](#2-cli-명령) 확인 |
| `INVALID_TOKEN` / `INVALID_INPUT` | 암호문 형식·경로·크기 오류 | 암호문을 끝까지 복사했는지, 파일 경로·기존 출력 파일 확인 |
| `IO_ERROR` | 파일 잠금·권한·경로 | 실행 중인 JAR 교체 여부, 쓰기 권한 확인 |
| JNDI 이름 오류·`NoInitialContextException` | 앱 밖에서 JNDI 호출, Context 등록 오류 | JNDI 이름·앱별 Context·`ResourceLink` 확인 |
| Pool 소진·대기 지연 | 최대 연결 부족 또는 연결 누수 | `maxTotal`/`maxActive`, `maxWaitMillis`/`maxWait`, 앱의 `close()` 확인 |
| `doctor` 종료 0 + WARN | 실패는 아니지만 공개 키 등 주의 | **사용자 지정 키 확인 후** 실제 DB 연결 확인 |

**장애 확인 순서:** (1) 배포한 최종 JAR 확인 → (2) `config show`와 `info`의 값·출처 비교 → (3) `doctor` → (4) Tomcat·DB 로그의 오류 코드와 Pool 종류 확인 → (5) 실제 SQL로 재확인.

티켓·로그에는 비밀번호·키·토큰 전문을 남기지 않습니다. Factory의 비밀값 정제는 DataSource를 만드는 과정에만 적용되며, 앱이 연결을 얻은 뒤 JDBC 드라이버가 내는 오류까지 정제하지는 않습니다.

---

## 10. 설정 사전

설정 이름·기본값·허용값을 정확히 확인하거나 설정 오류를 고칠 때 봅니다. 두는 곳과 우선순위는 [5.2절](#52-설정을-두는-곳과-우선순위)에 있고, 실행 중에는 `config help`로 같은 목록을 볼 수 있습니다.

### 10.1 키와 암호화 (6개)

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 잘못 쓰면 |
|---|---|---|---|
| `crypto.key.source` | `embedded` / `embedded`·`file`·`env`·`vault`·`aws-kms` | 키를 JAR에 둘지, 파일·환경변수·원격에서 받을지 **공급원 선택** | 외부 키가 없으면 오류(Fail Closed), 내장 키로 자동 전환 없음 |
| `crypto.key.id` | `default` / 영문·숫자·`_`·`-`, 1~64자 | 암호문이 어떤 키로 만들어졌는지 구별. **새 키마다 새 ID** | 암호문의 키ID와 다르면 복호화 실패 |
| `crypto.key.file` | 없음 / 키 파일 경로 | `crypto.key.source=file`일 때 | 파일·권한·Base64 키(32바이트) 확인 |
| `crypto.key.env` | `CRYPTO_KEY` / 환경변수 이름 | `crypto.key.source=env`일 때 WAS에 전달할 변수 이름 | 키 값을 적는 항목이 아님. 서비스 계정 환경에 실제 값 필요 |
| `crypto.key.embedded` | 공개 예제 키 / 32바이트 표준 Base64(44자) | **사용자 지정 키를 JAR에 넣을 때**(`crypto.key.source=embedded`). JAR 내장값은 `config embed-key`로만 바꿈 | `config set`으로는 못 바꾸고 `-D`는 오류. 외부 Properties에도 둘 수 있으나 키 원문이 파일에 남으므로 비권장(`file`·`env` 권장). 키 원문은 이력·로그·진단에 나오지 않음 |
| `crypto.algorithm` | `AES/GCM/NoPadding`만 | 알고리즘 확인(고정) | 다른 알고리즘 선택 불가 |

### 10.2 동작과 Tomcat 정책 (6개)

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.lang` | `ko` / `ko`·`en`·`auto` | 메시지 언어. `auto`는 JVM Locale(한국어가 아니면 영어) | 외부 제품(Tomcat·JDBC 드라이버 등) 메시지는 번역하지 않음 |
| `crypto.warning.enabled` | `true` / `true`·`false` | 공개 키·내장 키 안내 WARNING 출력 여부 | **`false`여도 오류·FAIL은 그대로이고 공개 키 위험도 그대로** |
| `crypto.output.encoding` | `enc` / `enc`·`base64` | 암호화 결과를 `ENC[...]` 또는 `B64[...]`로 출력 | `B64[...]`는 ENC의 추가 포장이지 추가 암호화가 아님 |
| `crypto.jvm.override.enabled` | `true` / `true`·`false` | 허용된 `-Dcrypto.*`가 설정을 덮어쓰게 할지 | 이 항목 자체는 `-D`로 바꿀 수 없음. `-Dcrypto.config.file`은 항상 동작 |
| `crypto.pool.factory` | DBCP2 / 공식 Factory 클래스 2종 | Tomcat Resource가 쓸 Pool 선택(**JVM 전체 공통**) | 두 Factory 외 임의 클래스 불가 |
| `crypto.require.encrypted.password` | `true`만 | Resource의 평문 DB 비밀번호 거부 | 보안상 `false` 허용 안 함 |

`crypto.pool.factory`의 허용값은 `org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory`(DBCP2, 기본)와 `org.apache.tomcat.jdbc.pool.DataSourceFactory`(Tomcat JDBC Pool)입니다. 이 Factory 클래스도 이 라이브러리를 로딩한 클래스로더에서만 찾으므로, 웹앱에 같은 이름의 클래스를 넣어도 쓰이지 않습니다.

### 10.3 Vault KV v2 (9개)

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.vault.url` | 없음 / HTTPS URL | `crypto.key.source=vault`일 때 Vault 서버 | HTTP·TLS 검증 우회 불가 |
| `crypto.vault.mount` | `secret` / KV v2 마운트 | 마운트가 기본과 다를 때 | KV v1·Transit이 아니라 **KV v2** 경로여야 함 |
| `crypto.vault.path` | 없음 / Secret 상대 경로 | 키가 저장된 Secret 지정 | 403이면 경로 오타도 확인 |
| `crypto.vault.field` | `key` / Secret 필드 이름 | 키를 `key`가 아닌 필드에 저장했을 때 | 값은 Base64 **AES-256 키** |
| `crypto.vault.ver` | 없음(최신) / 버전 번호 | 재기동해도 **같은 키**를 받게 버전 고정 | 최신을 읽으면 다음 기동 때 다른 키가 될 위험 |
| `crypto.vault.token.env` | `VAULT_TOKEN` / 환경변수 이름 | 토큰을 환경변수로 줄 때 | **토큰 값을 Properties에 적지 않음** |
| `crypto.vault.token.file` | 없음 / 토큰 파일 경로 | Vault Agent·서비스 계정 전용 파일을 쓸 때 | 지정하면 환경변수보다 우선. 읽기 권한 필요 |
| `crypto.vault.ca.file` | 없음(JVM 신뢰 저장소) / PEM 경로 | Vault가 사설 CA를 쓸 때 | 인증서 검증을 건너뛰는 옵션이 아님 |
| `crypto.vault.timeout.ms` | `5000` / 100~60000 | 네트워크 지연 시 대기 한도 | 시도당 시간. 재시도까지 포함한 총시간 고려 |

### 10.4 AWS KMS (4개)

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.aws.region` | 없음(AWS SDK 기본 체계) / 리전 | 키와 리전을 명시적으로 묶을 때 | KMS 키 ARN의 리전과 같아야 함 |
| `crypto.aws.kms.key.id` | 없음 / 키 ID·ARN·alias | **데이터 키를 보호할 KMS 키** | KMS 마스터 키를 반출하지 않음 |
| `crypto.aws.kms.data-key.file` | 없음 / 데이터 키 파일 경로 | `kms datakey`로 만든 파일을 재사용 | 재기동마다 새 데이터 키를 만들면 기존 암호문 복호화 불가 |
| `crypto.aws.kms.timeout.ms` | `10000` / 500~120000 | KMS 호출 전체 대기 한도 | SDK 재시도·인증·네트워크 시간 고려 |

AWS Access Key·Secret Key·Session Token은 **설정 항목이 아닙니다.** IAM 역할 등 AWS SDK 표준 자격증명 체계를 씁니다. 기본 JAR만으로는 KMS가 동작하지 않으며 선택형 SDK 묶음이 필요합니다.

---

## 11. 지원 범위와 배포 점검

### 11.1 검증 상태

아래는 실제로 실행한 시험을 기준으로 한 상태입니다. 시험 통과가 모든 운영 환경의 호환을 보장하지는 않습니다.

| 항목 | 상태 | 근거·비고 |
|---|---|---|
| Java | 8 이상 | 클래스 파일 Java 8(major 52). JDK 8·17·21·25에서 빌드·단위 시험 통과(공식 빌드 JDK는 Gradle 8.14.3 기준 8~24) |
| Tomcat 11.0(Java 17+) / 10.1(Java 11+) / 9.0(Java 8+) | 지원 | DBCP2·Tomcat JDBC Pool 모두 Docker 컨테이너의 실제 Tomcat에서 JNDI 조회 → 연결 → SQL 실행 확인(시험 Java: 9.0은 8, 10.1·11.0은 21). 괄호는 그 Tomcat이 요구하는 최소 Java |
| Tomcat 8.5(Java 8+) | 레거시 | 같은 방식으로 확인했지만(시험 Java 8) Apache 지원 종료(2024-03-31) 계열이라 신규 도입은 권장하지 않음 |
| 구형 Oracle JDK 8 | 주의 | 8u161 미만은 AES-256에 무제한 암호 정책이 필요합니다. 8u151~8u160은 `java.security`의 `crypto.policy=unlimited`, 그 이전은 JCE Unlimited Strength 정책 파일을 적용합니다. 없으면 `CRYPTO_PROVIDER`로 실패합니다. 8u161 이후(현재 배포되는 OpenJDK 계열 포함)는 기본 허용 |
| DB | MariaDB 실증 | 다른 DB도 해당 JDBC 드라이버로 같은 방식으로 설정할 수 있지만 실증하지 않음 |
| Vault KV v2 | 시험 완료 | 모의 TLS 서버 단위 시험 + Docker의 실제 Vault 컨테이너 시험 |
| AWS KMS | 모의 시험만 | 실제 AWS 계정의 KMS 연동은 검증하지 않음 |
| 미검증 | — | Windows 서비스형 Tomcat, 실제 운영 서버, MariaDB 외 DB, 실제 AWS KMS |

### 11.2 다른 WAS와 프레임워크

| 환경 | 가능한 사용 | 안 되거나 별도 설계가 필요한 부분 |
|---|---|---|
| **외부 Tomcat** | Tomcat JNDI 전용 Resource Factory로 ENC/B64 자동 복호화, 업무 코드 수정 없음 | 실제 Tomcat·DB 버전은 대상 환경에서 확인 |
| **WebLogic·JEUS** | JAR를 애플리케이션 클래스패스에 넣어 **Java API·CLI** 사용 | Tomcat용 `factory` 설정을 자체 JDBC Pool 설정에 복사해도 동작하지 않음 |
| **WebLogic JDBC Pool 자체** | WebLogic 관리 콘솔의 자체 비밀번호 보호 사용 | `ENC[...]`를 비밀번호란에 넣어 자동 복호화하는 기능은 **없음** |
| **Spring Boot 내장 Tomcat** | Java API 사용 가능 | 기본 HikariCP에 Tomcat JNDI Factory가 자동 적용되지 않음 |

### 11.3 배포 전 점검표

- [ ] 공개 예제 키가 아닌 **사용자 지정 키**와 올바른 키ID를 쓴다.
- [ ] 최종 JAR가 Tomcat `lib`에 **한 개만** 있고 JDBC 드라이버(·Tomcat JDBC Pool이면 `tomcat-jdbc.jar`)도 있다.
- [ ] `crypto.pool.factory`와 Resource의 Pool 속성 이름이 맞고, XML의 암호문에 자리표시자가 남아 있지 않다.
- [ ] 키를 만든 쪽의 키와 WAS의 키가 같다는 것을 `fingerprint`로 확인했다.
- [ ] `doctor`의 WARN 의미를 확인했고 **실제 JNDI 조회·SQL**로 연결을 검증했다.
- [ ] 키 내장 JAR(`--out`으로 정한 이름 포함)·키 파일·토큰·`--replace` 백업을 Git·공개 저장소에 올리지 않았다.
- [ ] 배포·백업·키 파일·복호화 출력 폴더의 접근 권한을 운영 환경의 정책으로 통제한다.
- [ ] 키를 바꿨다면 **이전 JAR·이전 암호문·이전 키 설정**으로 원복할 수 있다.
- [ ] 공식 배포물은 같은 Release의 `SHA256SUMS.txt`로 무결성을 확인했다([1.2절](#12-준비물과-내려받기)).
