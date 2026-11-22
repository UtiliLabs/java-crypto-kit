# java-crypto-kit

Java 8 이상에서 쓰는 **AES-256-GCM 암호화·복호화 라이브러리**입니다. JAR 하나로 명령줄(CLI), Java API, Tomcat JNDI DataSource 비밀번호 복호화를 지원합니다.

- 같은 값도 매번 다른 암호문(`ENC[v1:...]`)이 나오고, 암호문이 위·변조되면 복호화가 실패합니다.
- Tomcat은 웹 애플리케이션 코드를 바꾸지 않고 Resource의 `password`에 암호문을 적으면 됩니다(DBCP2·Tomcat JDBC Pool).
- 키는 JAR 내장·파일·환경변수·HashiCorp Vault·AWS KMS 중에서 고릅니다.

**문서:** 상세 사용법은 [사용자 가이드](docs/user-guide.md), 실행 중 요약은 `java -jar <JAR> help`(한국어·영어), 기여 규칙은 [AGENTS.md](AGENTS.md)에 있습니다.

## 1. 암호화·복호화 — 바로 해 보기

Java 8 이상과 배포 JAR([GitHub Releases](https://github.com/freeangelsun/java-crypto-kit/releases))만 있으면 됩니다. JAR에 **체험용 내장 키**가 들어 있어 키를 따로 만들 필요가 없습니다. 아래 `java-crypto-kit-0.1.0.jar`는 받은 파일 이름으로 바꾸고, Linux에서는 `.\` 대신 `./`를 씁니다.

**암호화** — 입력한 값은 화면에 보이지 않고, `ENC[v1:default:...]` 한 줄이 나옵니다.

```powershell
java -jar .\java-crypto-kit-0.1.0.jar encrypt
```

**복호화** — 경고가 나오면 `SHOW`를 입력하고, 위 암호문 전체(대괄호 포함)를 입력하면 원래 값이 나옵니다.

```powershell
java -jar .\java-crypto-kit-0.1.0.jar decrypt
```

**검증** — 평문을 보여 주지 않고 복호화할 수 있는지만 알려 줍니다(성공 시 종료 코드 0).

```powershell
java -jar .\java-crypto-kit-0.1.0.jar verify
```

세 명령은 실제 PowerShell·명령 프롬프트·Linux 터미널에서 실행합니다(IDE 콘솔·파이프에서는 입력을 숨길 수 없어 실행하지 않음). 옵션과 오류 조치: [가이드 2장](docs/user-guide.md#2-cli-명령).

> **주의:** 내장 키(키ID `default`)는 소스와 함께 공개된 **예제 키**라 누구나 복호화할 수 있습니다. 체험에만 쓰고 실제 비밀번호에는 쓰지 마세요. 운영에서는 [4장 사용자 지정 키](#4-운영용-사용자-지정-키)를 씁니다.

## 2. Java API

JAR를 클래스패스에 추가하면 CLI·Tomcat과 같은 엔진과 설정 규칙을 씁니다.

```java
import io.javacryptokit.CredentialCrypto;

CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
String token = crypto.encryptText("example-value");   // ENC[v1:...]
String plain = crypto.decryptText(token);
boolean ok   = crypto.verify(token);                  // 평문 없이 검증
```

`byte[]`·파일 암복호화, 외부 설정, 예외 처리, 직접 컴파일·실행 방법: [가이드 6장](docs/user-guide.md#6-java-api).

## 3. Tomcat JNDI DataSource

> 운영 배포 전에 [4장](#4-운영용-사용자-지정-키)의 사용자 지정 키를 먼저 적용합니다. 암호화한 JAR(키)와 Tomcat에 둔 JAR(키)가 같아야 복호화됩니다.

1. 키 내장 JAR와 DB의 JDBC 드라이버 JAR를 `CATALINA_BASE/lib`에 복사합니다(java-crypto-kit JAR는 하나만).
2. 같은 JAR로 `encrypt`를 실행해 DB 비밀번호 암호문을 만듭니다.
3. 웹 애플리케이션의 `META-INF/context.xml`처럼 Tomcat이 읽는 Context 파일의 `<Context>` 안에 Resource를 넣습니다.
4. Tomcat을 재시작하고 애플리케이션에서 JNDI 조회 → `getConnection()` → 실제 SQL을 확인합니다(`doctor`는 DB 연결을 확인하지 않음).

```xml
<Resource name="jdbc/myDB" auth="Container" type="javax.sql.DataSource"
          factory="io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory"
          driverClassName="org.mariadb.jdbc.Driver"
          url="jdbc:mariadb://db.example.com:3306/mydb"
          username="app_user" password="ENC[v1:key01:...실제 encrypt 출력...]"
          maxTotal="20" maxWaitMillis="5000" validationQuery="SELECT 1" testOnBorrow="true" />
```

- URL·계정·암호문은 예시입니다. `password`에는 `encrypt` 출력 전체를 넣습니다.
- Pool은 기본이 DBCP2이고, Tomcat JDBC Pool은 설정 `crypto.pool.factory`로 고릅니다. 키·Pool 설정은 한 Tomcat JVM의 모든 Resource에 공통입니다.
- 저장소의 [dbcp2-context.xml](docs/tomcat/dbcp2-context.xml)·[jdbc-pool-context.xml](docs/tomcat/jdbc-pool-context.xml)은 예제 파일입니다. Tomcat은 이 파일들을 직접 읽지 않습니다.

넣을 위치·속성·Pool 옵션·장애 조치: [가이드 3장](docs/user-guide.md#3-tomcat-jndi-연동)·[4장](docs/user-guide.md#4-connection-pool-설정).

## 4. 운영용 사용자 지정 키

`keygen`은 **새 키가 필요할 때만** 씁니다. 이미 키가 있으면 그 키 파일로 바로 내장하거나, 키를 JAR 밖(파일·환경변수·Vault·AWS KMS)에 둘 수 있습니다.

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\jck-secure" | Out-Null
java -jar .\java-crypto-kit-0.1.0.jar keygen --out "$HOME\jck-secure\example.key"
java -jar .\java-crypto-kit-0.1.0.jar config embed-key --from-file "$HOME\jck-secure\example.key" --key-id key01 --operator example-admin
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint
java -jar .\java-crypto-kit-0.1.0-configured.jar fingerprint --key-file "$HOME\jck-secure\example.key"
java -jar .\java-crypto-kit-0.1.0-configured.jar doctor
java -jar .\java-crypto-kit-0.1.0-configured.jar encrypt
```

Linux는 `mkdir -p -m 700 ~/jck-secure`로 폴더를 만든 뒤, 같은 명령에서 경로만 `~/jck-secure/example.key`로 바꿉니다.

- `keygen`은 상위 폴더가 있어야 하고 기존 파일을 덮어쓰지 않습니다. 사용자 프로필 아래 폴더는 기본으로 본인·관리자만 접근하지만, `C:\` 바로 아래에 만든 폴더는 다른 로컬 사용자도 읽을 수 있으므로 `icacls`로 권한을 줄입니다.
- `config embed-key`는 원본을 그대로 두고 `-configured.jar`를 새로 만듭니다(그 JAR를 다시 바꾸면 `-configured-2.jar`). 이 결과 JAR로 암호화하고 같은 JAR를 Tomcat에 배포합니다.
- 두 `fingerprint`(결과 JAR 자체, 키 파일)의 지문 줄이 같고 `doctor`에 FAIL이 없어야 합니다. `example.key`는 새로 만들 파일 이름이지 키 값이 아닙니다.
- 이미 운영 중인 암호문이 있으면 키를 바꾸기 전에 `rekey`로 다시 암호화합니다.

전체 순서·외부 키 공급·키 교체: [가이드 1.3절](docs/user-guide.md#13-체험용-내장-키와-운영용-사용자-지정-키)·[5장](docs/user-guide.md#5-키-공급원과-설정-적용)·[9장](docs/user-guide.md#9-운영-변경과-장애-대응).

## 5. 기능 한눈에 보기

| 목적 | 명령 | 가이드 |
|---|---|---|
| 문자열 암호화·복호화·검증 | `encrypt`, `decrypt`, `verify` | [2장](docs/user-guide.md#2-cli-명령) |
| 키 생성·내장·비교·교체 | `keygen`, `config embed-key`, `fingerprint`, `rekey` | [2장](docs/user-guide.md#2-cli-명령) · [9장](docs/user-guide.md#9-운영-변경과-장애-대응) |
| JAR 내장 설정·변경 이력 | `config show`, `config history`, `config set`, `config help` | [2장](docs/user-guide.md#2-cli-명령) · [10장 설정 사전](docs/user-guide.md#10-설정-사전) |
| 실행 설정 확인·진단 | `info`, `doctor` | [2장](docs/user-guide.md#2-cli-명령) |
| 파일 암복호화 | `file encrypt`, `file decrypt` | [7장](docs/user-guide.md#7-파일-암복호화) |
| Vault·AWS KMS 키 | `kms datakey`, `help vault`, `help aws-kms` | [8장](docs/user-guide.md#8-vault와-aws-kms-선택) |
| 오류 코드별 조치 | `[사유: 코드]`가 붙은 오류 | [9.3절](docs/user-guide.md#93-오류-코드별-조치) |

## 6. 지원·검증 범위

| 항목 | 상태 |
|---|---|
| Java | 8 이상에서 실행(Java 8 클래스 파일). JDK 8·17·21·25에서 빌드·단위 시험 통과 |
| Tomcat 11.0(Java 17+) / 10.1(Java 11+) / 9.0(Java 8+) | 지원: DBCP2·Tomcat JDBC Pool을 Docker의 실제 Tomcat에서 JNDI 조회 → 연결 → SQL까지 확인 |
| Tomcat 8.5(Java 8+) | 레거시: 같은 방식으로 확인했지만 Apache 지원 종료 계열이라 신규 도입 비권장 |
| 구형 Oracle JDK 8 | 8u161 미만은 AES-256용 무제한 암호 정책을 켜야 함(없으면 `CRYPTO_PROVIDER` 오류). 8u161 이후(현재 배포되는 OpenJDK 계열 포함)는 기본 허용. [가이드 11.1절](docs/user-guide.md#111-검증-상태) |
| DB | MariaDB로 실증. 다른 DB는 해당 JDBC 드라이버로 설정할 수 있으나 미검증 |
| 키 공급 | 내장·파일·환경변수, Vault KV v2(실제 Vault 컨테이너 시험), AWS KMS(모의 시험만, 실제 AWS 미검증) |
| 다른 WAS | Java API·CLI만 사용 가능. WebLogic·JEUS 등 자체 Pool의 자동 복호화는 지원하지 않음 |

시험 통과가 모든 운영 환경의 호환을 보장하지는 않습니다. 세부: [가이드 11장](docs/user-guide.md#11-지원-범위와-배포-점검).

## 7. 보안 주의

- 공개 예제 키로 만든 암호문은 누구나 복호화할 수 있습니다. `doctor`는 이를 WARN으로 알리지만 종료 코드는 0입니다.
- `crypto.warning.enabled=false`는 안내 WARNING 출력만 끕니다. **공개 키·내장 키의 위험은 그대로 남습니다.**
- 키 내장 JAR(`-configured*.jar`, `--out`으로 정한 임의 이름 포함)·키 파일·토큰·`--replace` 백업(`*.jar.bak-*`)은 비밀 파일입니다. Git·공개 저장소에 올리지 마세요(`.gitignore`와 CI가 추적 여부를 검사하지만 직접 확인이 우선).
- 평문·키·Vault 토큰은 명령 인자나 `-D`로 넘기지 않습니다. `decrypt`만 `SHOW` 확인 후 평문을 보여 줍니다.
- Tomcat에서 비밀값을 지우는 오류 정제는 DataSource를 만드는 동안에만 적용됩니다. 이후 `getConnection()` 단계에서 JDBC 드라이버가 내는 메시지는 범위 밖입니다.
- 설정·키는 시작할 때 읽습니다. 바꾼 뒤에는 Tomcat을 재시작합니다.

## 8. 내려받기·빌드·기여

- **내려받기:** Release에는 기본 JAR(`java-crypto-kit-<버전>.jar`), AWS KMS용 선택 묶음(`java-crypto-kit-aws-kms-lib-<버전>.zip`), `SHA256SUMS.txt`가 있습니다. 해시 확인 방법은 [가이드 1.2절](docs/user-guide.md#12-준비물과-내려받기)에 있습니다. `dev-<커밋>` 사전 릴리스는 시험용입니다.
- **빌드:** Windows `gradlew.bat clean build`, Linux/macOS `./gradlew clean build`(Gradle Wrapper 8.14.3, 공식 빌드 JDK 8~24). 결과는 `build/libs/`와 `build/distributions/`에 생깁니다.
- **실서버 통합 시험(Docker):** `bash src/test/integration/run-tomcat-integration.sh --help`. Tomcat Factory·키·Pool 코드를 바꿨거나 릴리스 전에 실행합니다.
- **기여:** 코드·문서를 바꾸기 전에 [AGENTS.md](AGENTS.md)의 규칙과 변경별 필수 시험을 확인합니다.
- **라이선스:** [Apache License 2.0](LICENSE)
