# 지원 환경과 배포 점검

[README](../../README.md) · [사용자 가이드](../user-guide.md)

아래 표는 0.1.0의 기존 실행 기록에서 확인한 JDK, Tomcat, Connection Pool 및 외부 연계 범위입니다. 같은 버전 이름으로 다시 빌드한 JAR를 배포한다면, 실제 검증한 산출물과 배포할 파일의 SHA-256도 대조하세요.

**목차**

- [11.1 검증 상태](#111-검증-상태)
- [11.2 다른 WAS와 프레임워크](#112-다른-was와-프레임워크)
- [11.3 배포 전 점검표](#113-배포-전-점검표)

<a name="11-지원-범위와-배포-점검"></a>

## 11.1 검증 상태

아래는 실제로 실행한 시험을 기준으로 한 상태입니다. 시험 통과가 모든 운영 환경의 호환을 보장하지는 않습니다.

| 항목 | 상태 | 근거·비고 |
|---|---|---|
| Java | 8 이상(실행 확인: 8·21·25) | 클래스 파일 Java 8(major 52). 0.1.0에서 실제로 실행한 것: JDK 8·JDK 21 전체 빌드(Windows·Linux `clean build`: 단위 시험·selfTest·JAR·KMS 묶음), Tomcat 실서버 시험의 Java 8·21·25 런타임(Passphrase 키 파생 결과가 JDK 간 같은지 포함). **JDK 25(LTS)**: 배포 JAR 실행, 기존 단위 시험 전체를 JDK 25 JVM에서 실행, 공개 API 예제를 JDK 25 `javac`(기본 release 25)로 컴파일·실행, CLI(관리자 설정·키 생성·내장·암복호화·파일)·범용 보안 API 교차 확인, Tomcat 11.0 실제 DB 연동까지 확인. 이 저장소를 JDK 25로 **빌드**하는 것은 지원하지 않음(Gradle 8.14.8 실행 JDK는 8~24, JDK 25 빌드에는 Gradle 9.1 이상 필요). 그 밖의 JDK(17 등)는 이 버전에서 미검증(CI 구성에는 JDK 17 포함) |
| Tomcat 11.0(Java 17+) / 10.1(Java 11+) / 9.0(Java 8+) | 지원 | DBCP2·Tomcat JDBC Pool 모두 Docker 컨테이너의 실제 Tomcat에서 pass·key 암호문으로 JNDI 조회 → 연결 → SQL 실행 확인(시험 Java: 9.0은 8, 10.1은 21, 11.0은 21·25). 괄호는 그 Tomcat이 요구하는 최소 Java |
| Tomcat 8.5(Java 8+) | 레거시 | 같은 방식으로 확인했지만(시험 Java 8) Apache 지원 종료(2024-03-31) 계열이라 신규 도입은 권장하지 않음 |
| JAR를 `lib`과 웹앱 `WEB-INF/lib`에 함께 둠 | 동작 확인 | Docker의 Tomcat 9.0·11.0에서 Resource 위치별 처리 JAR, 개발자 API 클래스로더(문자열·파일 암복호화), 키·설정 독립, 교차 복호화 차단, JVM 공통 설정 간섭과 JAR별 회피(`crypto.jvm.override.enabled=false`)를 확인([3.7절](../guide/tomcat-jdbc.md#topic-tomcat--37-jar를-lib과-웹앱에-함께-둘-때)). 권장 배치는 `lib` 하나 |
| 구형 Oracle JDK 8 | 주의 | 8u161 미만은 AES-256에 무제한 암호 정책이 필요합니다. 8u151~8u160은 `java.security`의 `crypto.policy=unlimited`, 그 이전은 JCE Unlimited Strength 정책 파일을 적용합니다. 없으면 `CRYPTO_PROVIDER`로 실패합니다. 8u161 이후(현재 배포되는 OpenJDK 계열 포함)는 기본 허용 |
| CLI 명령어집 | 실행 확인 | [5.6절](../guide/key-management.md#topic-key-recovery--56-자동-생성한-passkey-보관재등록복구)과 [부록 A](../guide/cli.md#topic-cli--부록-a-실무-명령어집)의 명령을 Windows PowerShell 5.1(JDK 8, 실제 콘솔)과 Linux bash(JDK 21, 의사 터미널)에서 실행(사유 질문·`CHANGE`·생성값 1회 표시·백업 복원·예전 암호문 복호화 포함) |
| DB | MariaDB 실증 | 다른 DB도 해당 JDBC 드라이버로 같은 방식으로 설정할 수 있지만 실증하지 않음 |
| Vault KV v2 | 시험 완료 | 모의 TLS 서버 단위 시험 + Docker의 실제 Vault 컨테이너 시험(`crypto.key.*`의 AES 키, 키 목록의 pass 키 프로필) |
| AWS KMS | 모의 시험만 | 실제 AWS 계정의 KMS 연동은 검증하지 않음 |
| 범용 보안 Java API | 시험 완료 | JDK 8·21·25 단위 시험(RFC·NIST 등 표준 벡터, 변조·경계·오류 경로), Python `cryptography`·OpenSSL·Node.js와의 양방향 교차 확인(AES-GCM·HMAC·HKDF·PBKDF2·비밀번호 해시·서명·RSA-OAEP·Hybrid·JWT·OTP·PKCS12 등, JDK 8·21·25), 독립 JVM 여러 개의 발급·검증·복호화, Docker Tomcat 웹앱에서의 사용과 다른 JAR 불변 확인. OAuth는 로컬 HTTPS 모의 서버 시험 + Keycloak 컨테이너 실연동(Client Credentials·JWKS·Access Token·ID Token 거부·Introspection). Keycloak 26.0.5의 시험 구성에서는 RFC 9068 `at+jwt` 발급이 확인되지 않아 RFC 9068 실연동은 별도 검증 범위 |
| 미검증 | — | Windows 서비스형 Tomcat, 실제 운영 서버, MariaDB 외 DB, 실제 AWS KMS, Keycloak 외 OAuth 인증 서버(Microsoft Entra ID 등) |

## 11.2 다른 WAS와 프레임워크

| 환경 | 가능한 사용 | 안 되거나 별도 설계가 필요한 부분 |
|---|---|---|
| **외부 Tomcat** | Tomcat JNDI 전용 Resource Factory로 ENC/B64 자동 복호화, 업무 코드 수정 없음 | 실제 Tomcat·DB 버전은 대상 환경에서 확인 |
| **WebLogic·JEUS** | JAR를 애플리케이션 클래스패스에 넣어 **Java API·CLI** 사용 | Tomcat용 `factory` 설정을 자체 JDBC Pool 설정에 복사해도 동작하지 않음 |
| **WebLogic JDBC Pool 자체** | WebLogic 관리 콘솔의 자체 비밀번호 보호 사용 | `ENC[...]`를 비밀번호란에 넣어 자동 복호화하는 기능은 **없음** |
| **Spring Boot 내장 Tomcat** | Java API 사용 가능 | 기본 HikariCP에 Tomcat JNDI Factory가 자동 적용되지 않음 |

## 11.3 배포 전 점검표

- [ ] 공개 예제 키(`pass-default`·`default`)가 아닌 **사용자 지정 키**와 올바른 키ID를 쓴다(`info`의 기본 유형·기본 키 확인).
- [ ] 최종 JAR가 Tomcat `lib`에 **한 개만** 있고 JDBC 드라이버(·Tomcat JDBC Pool이면 `tomcat-jdbc.jar`)도 있다.
- [ ] Resource의 `cryptoPool`(생략 시 `crypto.pool.factory`)과 Pool 속성 이름이 맞고, XML의 암호문에 자리표시자가 남아 있지 않다.
- [ ] 키를 만든 쪽의 키와 WAS의 키가 같다는 것을 `fingerprint`로 확인했다.
- [ ] `doctor`가 `결과: PASS`이고 키 상태가 `사용자 지정`이며, **실제 JNDI 조회·SQL**로 연결을 검증했다.
- [ ] 키 내장 JAR(`--out`으로 정한 이름 포함)·키 파일·토큰·`--replace` 백업을 Git·공개 저장소에 올리지 않았다.
- [ ] 배포·백업·키 파일·복호화 출력 폴더의 접근 권한을 운영 환경의 정책으로 통제한다.
- [ ] 키를 바꿨다면 **이전 JAR·이전 암호문·이전 키 설정**으로 원복할 수 있다.
- [ ] 공식 배포물은 같은 Release의 `SHA256SUMS.txt`로 무결성을 확인했다([1.2절](getting-started.md#topic-getting-started--12-준비물과-내려받기)).

---

[전체 가이드 목차](../user-guide.md) · [README](../../README.md)
