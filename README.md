# Java Crypto Kit (JCK)

Java Crypto Kit는 Java 애플리케이션에서 데이터 암복호화, 요청 서명, 인증 토큰 검증, 키 관리를 수행하는 범용 암호화·보안 라이브러리입니다. 같은 JAR를 명령줄 도구로 실행할 수 있고, Tomcat에서는 기존 JNDI DataSource에 저장한 DB 접속정보를 복호화합니다.

**Java 8 이상 · 실행형 JAR 1개 · Apache License 2.0**

<a name="api-cli-빠른-시작"></a>
## 빠른 시작

[배포 JAR](https://github.com/UtiliLabs/java-crypto-kit/releases)를 준비하고 JAR가 있는 폴더에서 실행하세요. 배포 원본에는 암호화 키가 없습니다. Windows와 Linux에서 같은 명령을 사용합니다. 설정 후에도 파일명과 경로는 같습니다.

```powershell
# 최초 한 번 관리자 비밀번호를 두 번 입력. 같은 JAR에 독립 랜덤 pass·AES 키 생성
java -jar java-crypto-kit-0.2.1.jar admin setup

# JDBC 비밀번호를 숨김 입력해 기본 pass 키로 암호화
java -jar java-crypto-kit-0.2.1.jar enc

# 필요할 때 관리자 인증 후 암호문 한 줄 전체를 입력해 복호화
java -jar java-crypto-kit-0.2.1.jar dec
```

최초 설정은 파일명과 경로를 유지하며 작업자 옵션을 생략하면 `SYSTEM`으로 기록합니다. 공식 배포 SHA-256은 설정 전에 비교하세요. 최초 설정 이후에는 JAR 내부가 갱신되므로 공식 배포본과 SHA-256이 달라지는 것이 정상입니다.

암호문을 평문 표시 없이 확인하려면 같은 JAR로 `verify`를 실행하세요. 설정 JAR를 안전하게 백업하고 같은 암호문을 읽는 서버에 같은 키와 ID를 배치하세요. 내장 Passphrase 원문은 사후 조회할 수 없습니다. 원문이 필요하면 최초 설정 때 `--pass-export`로 보호된 복원 파일을 만드세요. 명시적 외부 키를 쓰는 Java·Tomcat 및 호출자가 키를 주는 독립 Java API는 CLI 관리자 등록 없이 동작합니다.

## 주요 특징

- **서비스가 가진 키로 호출** · 암호화 키, 신뢰할 서명 키, 검증 정책을 애플리케이션에서 직접 전달할 수 있습니다.
- **CLI와 서버가 같은 암호문 사용** · 관리형 암호문과 파일에는 키 ID가 기록됩니다. 서버에 여러 키를 등록해 키 교체 전후의 데이터를 함께 읽을 수 있습니다.
- **필요한 의존성만 배치** · 기본 JAR는 JDK의 암호 기능을 사용합니다. JDBC 드라이버는 Tomcat에 별도로 배치하고, AWS KMS를 쓸 때만 선택 SDK를 추가합니다.

## 제공 기능과 업무 적용

| 업무 | Java API | CLI |
|---|---|---|
| 관리형 문자열·파일 암복호화 | [CredentialCrypto](docs/guide/java-encryption.md#topic-java-api) | [문자열](docs/guide/cli.md#topic-cli) · [파일](docs/guide/file-encryption.md) |
| 직접 키·Passphrase, AES-GCM·RSA-OAEP·Hybrid | [암복호화 API](docs/guide/java-encryption.md) | [`api aes`, `api rsa`, `api hybrid`](docs/guide/java-encryption.md#api-cli-guide) |
| 체크섬·전자서명·HMAC·요청 서명 | [데이터 무결성 API](docs/guide/data-integrity.md) | [해시·서명·요청 검증 명령](docs/guide/data-integrity.md#api-cli-guide) |
| 비밀번호 해시·난수·키 파생·인코딩 | [보안 유틸리티 API](docs/guide/security-utilities.md) | [유틸리티 명령](docs/guide/security-utilities.md#api-cli-guide) |
| OTP·JWT·JWKS·OAuth 2.0 | [인증 API](docs/guide/authentication.md) | [토큰·OTP 명령](docs/guide/authentication.md#api-cli-guide) |
| 키 생성·변환, X.509 인증서 정보 | [PEM 키와 인증서 API](docs/guide/certificates-keystores.md) | [시험용 키 생성](docs/guide/key-management.md#api-keygen) · [키 변환·인증서](docs/guide/certificates-keystores.md#api-cli-guide) |
| PKCS12/JKS 읽기·PKIX 검증·안전 비교 | [키 저장소·인증서](docs/guide/certificates-keystores.md) · [안전 비교](docs/guide/security-utilities.md#topic-encoding) | — |
| 키 등록·백업·회전, Vault·KMS | [관리형 키 공급원 설정](docs/guide/external-key-providers.md) | [키·설정 관리](docs/guide/key-management.md) |
| Tomcat JDBC | [JNDI Factory 연동](docs/guide/tomcat-jdbc.md) | [배포용 암호문 준비](docs/guide/cli.md#topic-cli-encryption--첫-실행-예제) |

## 암호화 방식과 키 선택

JCK의 관리형 암복호화는 `pass`와 `key` 두 가지 키 준비 방식을 제공합니다. 두 방식 모두 **AES-256-GCM**으로 암호화하며, 서로 다른 암호화 알고리즘이 아닙니다.

| 방식 | 특징 및 활용 |
|---|---|
| `pass` (Passphrase) | 비밀 문자열에서 PBKDF2로 AES 키를 파생합니다. 사람이 관리하는 비밀 문자열을 사용하거나 기존 Passphrase를 기반으로 키를 구성할 때 사용합니다. |
| `key` (AES 키) | 32바이트 AES 키를 직접 사용합니다. 새 무작위 키를 생성하거나 기존 AES 키를 사용할 때 적합합니다. |

키를 JAR에 내장하거나 파일·환경변수·Vault·AWS KMS에서 공급할 수 있습니다. 암호문에 기록된 키 ID로 복호화할 키를 선택합니다.

[키 유형·공급원 선택 및 관리](docs/guide/key-management.md#choose-key-material) · [직접 키 주입과 독립 AES·RSA 사용법](docs/guide/java-encryption.md)

## CLI — 코드 없이 암호화 및 키 관리

JAR를 직접 실행해 DB 계정·비밀번호나 설정값을 암복호화하고, 파일을 보호하거나 복원할 수 있습니다. 두 파일 명령에서 결과 경로(`--out`)를 지정합니다. 새 키 생성·등록·조회·백업·복구·교체, JAR 설정 변경 및 진단도 CLI로 수행합니다. 최초 관리자 비밀번호 설정 후 사용하며, 민감 명령은 매 실행 시 인증합니다.

[CLI 첫 실행](docs/guide/cli.md#topic-cli-encryption--첫-실행-예제) · [전체 명령·옵션](docs/guide/cli.md#topic-cli--22-명령-목록) · [키 관리 절차](docs/guide/key-management.md) · [파일 처리](docs/guide/file-encryption.md)

## Tomcat — JDBC 접속정보 암호화 연동

기존 JNDI Resource에 저장하는 DB 접속정보를 암호문으로 바꾸고 JCK Factory에서 복호화합니다. `pass` 또는 `key`로 CLI에서 암호문을 준비하고, 같은 키를 사용할 수 있는 JAR·설정을 Tomcat에 배포합니다. XML의 `cryptoPool`로 Resource마다 DBCP2 또는 Tomcat JDBC Pool을 고릅니다. 두 Pool을 같은 Context에서 함께 사용하며 기존 JNDI 조회 코드를 유지할 수 있습니다.

[Tomcat JDBC 연동 전체 절차 및 두 Pool 설정 예제](docs/guide/tomcat-jdbc.md)

## Java API — 애플리케이션에서 보안 기능 호출

관리형 키로 CLI·Tomcat과 동일한 암호문을 처리하거나, 애플리케이션이 키를 직접 공급할 수 있습니다. AES-128/256 및 AAD, RSA-OAEP, Hybrid 암호화, HMAC·전자서명, 비밀번호 해시·난수·키 파생, OTP·JWT·OAuth, 인증서·키 저장소 등의 독립 API도 제공합니다. 범용 API는 관리형 키나 CLI 인증과 독립적으로 사용하며, 각각의 입력 키·정책은 호출자가 준비합니다.

[Java API 선택 기준](docs/reference/api-selection.md) · [Java 암복호화 예제](docs/guide/java-encryption.md) · [메서드·Builder·반환값](docs/reference/java-api-reference.md#api-members)

## 다운로드

[**GitHub Releases에서 JAR 다운로드**](https://github.com/UtiliLabs/java-crypto-kit/releases) · [배포 파일과 사용 준비](docs/reference/getting-started.md)

일반 기능은 JAR 하나면 됩니다. 업무 키 등록과 이전은 [사용자 지정 키](docs/guide/key-management.md#topic-key-selection)를 사용하세요. CLI 사용 시 최초 관리자 인증 설정이 필요하지만 Java API와 Tomcat 기동에는 필요하지 않습니다.

> 이 문서는 현재 소스 버전 0.2.1을 기준으로 작성되었습니다. 공개 릴리스보다 앞선 기능은 이 소스에서 Gradle Wrapper로 빌드해 확인할 수 있습니다.
>
> 받은 JAR의 버전은 `java -jar java-crypto-kit-0.2.1.jar help` 결과의 첫 줄(`java-crypto-kit CLI 0.2.1 - ...`)에서 확인합니다. 최초 설정 전에도 실행할 수 있습니다.

## 지원 환경

| 구분 | 지원 및 검증 범위 |
|---|---|
| Java | Java 8 이상 · JDK 8/21/25 실행 검증 |
| 빌드 | Gradle 8.14.8 · JDK 8~24 (Gradle 지원 범위) |
| Tomcat | 9.0 / 10.1 / 11.0 · 8.5 레거시 검증 |
| Connection Pool | DBCP2 / Tomcat JDBC Pool · MariaDB 실연동 |
| 외부 연계 | Vault·Keycloak 실연동 · AWS KMS 모의 시험 |

[상세 호환성 및 검증 범위](docs/reference/compatibility.md)

## 문서 및 개발

[**전체 사용자 가이드**](docs/user-guide.md) — 업무별 상세 목차와 가이드

[설정 사전](docs/reference/configuration.md) · [오류 해결](docs/reference/troubleshooting.md) · [Java API 공통 규칙](docs/reference/java-api-reference.md) · [보안 및 운영 참고](docs/reference/security.md)

[기술 명세](docs/reference/technical-specification.md) · [변경 이력](CHANGELOG.md) · [개발·QA 규칙](AGENTS.md) · [소스 빌드 안내](docs/reference/getting-started.md#topic-getting-started--12-준비물과-내려받기) · [Apache License 2.0](LICENSE)
