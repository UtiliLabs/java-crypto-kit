# Java Crypto Kit (JCK)

Java Crypto Kit는 Java 애플리케이션에서 데이터 암복호화, 요청 서명, 인증 토큰 검증, 키 관리를 수행하는 범용 암호화·보안 라이브러리입니다. 같은 JAR를 명령줄 도구로 실행할 수 있고, Tomcat에서는 기존 JNDI DataSource에 저장한 DB 접속정보를 복호화합니다.

**Java 8 이상 · 실행형 JAR 1개 · Apache License 2.0**

## 주요 특징

- **서비스가 가진 키로 호출** · 암호화 키, 신뢰할 서명 키, 검증 정책을 애플리케이션에서 직접 전달할 수 있습니다.
- **CLI와 서버가 같은 암호문 사용** · 관리형 암호문과 파일에는 키 ID가 기록됩니다. 서버에 여러 키를 등록해 키 교체 전후의 데이터를 함께 읽을 수 있습니다.
- **필요한 의존성만 배치** · 기본 JAR는 JDK의 암호 기능을 사용합니다. JDBC 드라이버는 Tomcat에 별도로 배치하고, AWS KMS를 쓸 때만 선택 SDK를 추가합니다.

## 제공 기능과 업무 적용

필요한 작업에서 바로 상세 사용법으로 이동할 수 있습니다. 가이드에는 기능 선택, 입력·옵션·출력, 예제 및 오류 처리 방법을 설명합니다.

| 기능 | 언제 활용하나요? | 사용 가이드 |
|---|---|---|
| 문자열·바이트 암복호화 | DB 컬럼의 개인정보, 설정 비밀값 등 나중에 원문이 필요한 데이터. 문자열은 CLI·Java, 바이트 배열은 Java API로 처리 | [관리형 암복호화](docs/guide/java-encryption.md#topic-java-api) |
| 직접 키 주입 | 서비스가 키 또는 Passphrase를 별도로 관리하며 JCK 설정과 독립적으로 암복호화 | [직접 키 API](docs/guide/java-encryption.md#topic-direct-key) |
| AES-GCM 및 AAD | AES-128/256 원시 형식, 레코드 ID 같은 업무 값과 암호문을 함께 인증 | [AES-GCM](docs/guide/java-encryption.md#topic-aes) |
| RSA-OAEP·Hybrid | 상대 공개키로 짧은 비밀값 또는 더 긴 업무 메시지를 보호 | [RSA](docs/guide/java-encryption.md#topic-rsa) · [Hybrid](docs/guide/java-encryption.md#topic-hybrid) |
| 파일 암복호화 | CSV·PDF·이미지 등 정산/전송 파일을 스트리밍으로 보호·복원(CLI 또는 Java API) | [파일 처리](docs/guide/file-encryption.md) |
| Tomcat JDBC | 기존 JNDI DataSource의 DB 비밀번호(필수)·계정(선택)을 암호화하고 DBCP2/JDBC Pool 연결 | [Tomcat 연동](docs/guide/tomcat-jdbc.md) |
| CLI 및 키 관리 | 코드 없이 암복호화, 키 생성·등록·선택·조회·백업·복구·교체, 설정·진단·변경 이력 | [CLI](docs/guide/cli.md) · [키 관리](docs/guide/key-management.md) |
| Vault·AWS KMS | 기존 외부 키 관리 체계를 관리형 암복호화와 연결 | [외부 키 관리](docs/guide/external-key-providers.md) |
| HMAC·요청 인증 | 공유 비밀키로 API 전문 또는 웹훅 인증, 시각·서명 확인과 애플리케이션의 nonce 재사용 검사 | [HMAC](docs/guide/data-integrity.md#topic-hmac) · [요청 인증](docs/guide/data-integrity.md#topic-request-auth) |
| SHA 해시·전자서명·PEM | 파일 체크섬 비교, 개인키 서명 및 공개키 검증, 키 읽기·변환 | [SHA](docs/guide/data-integrity.md#topic-hash) · [전자서명·PEM](docs/guide/data-integrity.md#topic-signature) |
| 비밀번호 해시 | 회원 비밀번호를 원문 복원 없이 저장·확인하고 기존 해시 갱신 | [비밀번호 해시](docs/guide/security-utilities.md#topic-password) |
| 난수·UUID·키 파생·인코딩 | 랜덤 문자열·보안 토큰·Nonce, 키 분리 및 파생, Base64·Hex 등 변환과 안전 비교 | [난수](docs/guide/security-utilities.md#topic-random) · [키 파생](docs/guide/security-utilities.md#topic-key-derivation) · [인코딩](docs/guide/security-utilities.md#topic-encoding) |
| HOTP·TOTP | 인증 앱의 일회용 코드 생성·검증 | [OTP](docs/guide/authentication.md#topic-otp) |
| JWT·JWKS | 서명 토큰 발급·검증, 신뢰하는 공개키 목록 해석 | [JWT·JWKS](docs/guide/authentication.md#topic-jwt) |
| OAuth 2.0 | JWT 접근 토큰 검증, opaque 토큰 상태 조회, 서버 간 접근 토큰 발급 요청 | [OAuth 검증](docs/guide/authentication.md#topic-oauth) · [Introspection](docs/guide/authentication.md#topic-oauth-introspection) · [Client Credentials](docs/guide/authentication.md#topic-oauth-client-credentials) |
| 인증서·키 저장소 | X.509 정보 및 신뢰 체인 검증, PKCS12/JKS에서 키·인증서 읽기 | [인증서와 키 저장소](docs/guide/certificates-keystores.md) |

위 기능 중 관리형 문자열·파일 암복호화, 키·설정 관리는 CLI를 제공합니다. 나머지 범용 보안 API는 Java 코드에서 사용합니다. [전체 가이드 목차](docs/user-guide.md)

## 암호화 방식과 키 선택

JCK의 관리형 암복호화는 `pass`와 `key` 두 가지 키 준비 방식을 제공합니다. 두 방식 모두 **AES-256-GCM**으로 암호화하며, 서로 다른 암호화 알고리즘이 아닙니다.

| 방식 | 특징 및 활용 |
|---|---|
| `pass` (Passphrase) | 비밀 문자열에서 PBKDF2로 AES 키를 파생합니다. 사람이 관리하는 비밀 문자열을 사용하거나 기존 Passphrase를 기반으로 키를 구성할 때 사용합니다. |
| `key` (AES 키) | 32바이트 AES 키를 직접 사용합니다. 새 무작위 키를 생성하거나 기존 AES 키를 사용할 때 적합합니다. |

공개 JAR는 두 유형의 체험용 키(`pass-default`, `default`)를 기본 제공하므로 별도 키 생성 없이 시험할 수 있습니다. 공개 키는 누구나 알 수 있으므로 실제 데이터에는 사용자 지정 키가 필요합니다. 키를 JAR에 내장하거나 파일·환경변수·Vault·AWS KMS에서 공급할 수 있습니다. 암호문에 기록된 키 ID로 복호화할 키를 선택합니다.

[키 유형·공급원 선택 및 관리](docs/guide/key-management.md#choose-key-material) · [직접 키 주입과 독립 AES·RSA API](docs/guide/java-encryption.md)

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

일반 기능은 JAR 하나면 됩니다. 실제 업무에서는 공개 예제 키 대신 [사용자 지정 키](docs/guide/key-management.md#topic-key-selection)를 사용하세요. CLI 사용 시 최초 관리자 인증 설정이 필요하지만 Java API와 Tomcat 기동에는 필요하지 않습니다.

> 이 문서는 현재 소스 버전 0.1.0을 기준으로 작성되었습니다. 공개 릴리스에 필요한 기능이나 파일이 없으면 이 소스에서 Gradle Wrapper로 빌드한 JAR를 사용하세요. 파일명이 같아도 빌드가 다를 수 있습니다.

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

[개발·QA 규칙](AGENTS.md) · [소스 빌드 안내](docs/reference/getting-started.md#topic-getting-started--12-준비물과-내려받기) · [Apache License 2.0](LICENSE)
