# 다운로드와 사용 준비

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

<a name="topic-getting-started"></a>

<a name="topic-getting-started--다운로드-및-사용-준비"></a>
<a name="topic-getting-started--1-개요와-준비"></a>
## 1. 개요와 준비

**문서의 표기와 예제 읽는 법**

- `java-crypto-kit-0.1.0.jar`: 공개 배포 JAR(체험용 내장 예제 키가 들어 있고 CLI 관리자 비밀번호는 미설정). 실제로 받은 파일 이름으로 바꿔 실행합니다. CLI로는 [1.4절](../guide/cli.md#topic-admin--14-cli-관리자-비밀번호)의 최초 설정에만 씁니다.
- `java-crypto-kit-0.1.0-configured.jar`: 관리자 비밀번호를 설정한 JAR(`admin setup` 결과, 키는 배포 JAR와 같음). 이 문서의 CLI 예제는 이 JAR로 실행합니다.
- `java-crypto-kit-0.1.0-configured-2.jar`, `-configured-3.jar`: 위 JAR를 `config embed-key`·`config key add`·`config set` 등으로 다시 바꾼 결과 JAR(사용자 지정 키 등 내장, 관리자 비밀번호는 그대로 이어짐). 같은 계열 JAR를 바꿀 때마다 번호가 올라갑니다.
- **관리자 인증:** 복호화·키 관리·설정 조회 같은 민감 명령([2.2절](../guide/cli.md#topic-cli--22-명령-목록)의 `*`)은 실행할 때마다 `관리자 비밀번호(입력 숨김):`를 먼저 묻습니다. 예제 화면에 이 줄이 있으면 관리자 비밀번호를 입력하는 자리입니다.
- **이 문서의 버전:** 소스 버전 0.1.0 기준입니다. [GitHub Releases](https://github.com/UtiliLabs/java-crypto-kit/releases)에 게시된 바이너리는 같은 버전 번호라도 이 소스와 기능이 다를 수 있습니다.

  같은 버전 이름만으로 동일한 JAR라고 판단하지 말고 배포된 파일의 해시와 기능을 확인하세요. 현재 소스 기능을 체험하려면 저장소에서 빌드한 JAR를 씁니다.

  **이전 형식**은 관리자 인증 및 이중 키 체계가 도입되기 전의 JAR와 그 설정을 말합니다(`crypto.key.type`·pass 키·키 목록·CLI 관리자 비밀번호·`obf1` 저장이 없는 JAR). 이 문서의 호환 설명([9.4절](troubleshooting.md#94-이전-형식-설정jar에서-올리기))은 그 JAR·설정·암호문에 대한 것입니다.
- **키 유형:** `pass`(Passphrase에서 AES 키를 파생)와 `key`(32바이트 AES 키). CLI `--type pass|key`, 설정 `crypto.key.type=pass|key`, Java `KeyType.PASS`/`KeyType.KEY`로 적습니다.
- `<JAR>`: 위 둘 중 지금 쓰는 JAR. 예제는 현재 폴더의 JAR를 `.\`(PowerShell)·`./`(Linux)로 적었지만 `java -jar` 뒤에서는 생략해도 됩니다(도움말 예제는 생략).
- 예제의 키ID(`key01`·`app-pass`), 키 파일(`example.key`), Passphrase 파일(`app.pass`), 수정자 ID(`example-admin`), 경로·URL은 모두 예시 값입니다.

<a name="topic-getting-started--11-지원-기능"></a>
## 1.1 지원 기능

java-crypto-kit은 **AES-256-GCM 기반 암복호화 라이브러리**이며, 외부 라이브러리 없이 쓰는 **범용 보안 Java API**도 함께 제공합니다.

Tomcat JNDI에 적은 암호화된 DB 비밀번호를 풀어 Tomcat 공식 Connection Pool에 넘기고, 같은 엔진을 CLI와 일반 Java API에서도 씁니다.

키는 두 유형을 한 JAR에서 함께 씁니다: **`pass`**(Passphrase에서 PBKDF2-HMAC-SHA256으로 AES 키를 파생, 유형을 정하지 않은 새 암호화의 기본)와 **`key`**(32바이트 AES 키). 두 유형 모두 같은 엔진·같은 암호문 형식이며, 복호화는 암호문에 든 키 ID로 키를 자동으로 고릅니다.

| 대상 | 지원 동작 | 범위·제약 |
|---|---|---|
| Tomcat | JNDI `DataSource`의 비밀번호(필요하면 계정도) 복호화 후 DBCP2 또는 Tomcat JDBC Pool에 전달 | Tomcat 전용 Factory. 웹 애플리케이션의 JNDI 조회 코드는 바꾸지 않음 |
| CLI | 암호화·검증·복호화, 키 생성·비교·교체, JAR 내장 키 목록(추가·기본 키 변경·제거)·설정 변경·이력, 진단, 파일 암복호화 | 평문·Passphrase를 입력하는 명령은 실제 터미널에서 실행 |
| Java API | 텍스트·바이트·파일 암복호화, 검증, 유형·키 ID 선택, 등록된 키 조회, 애플리케이션이 준 키로 같은 형식 암복호화 | 공개 진입점은 `CredentialCrypto`(유형 `KeyType`, 키 정보 `KeyInfo`, 직접 키는 [6.7절](../guide/java-encryption.md#topic-direct-key--67-개발자가-직접-키를-주는-api)). JAR를 클래스패스에 추가 |
| 범용 보안 Java API | 직접 키 AES-GCM(AES-128/256·업무 AAD), HMAC·API 요청 인증, 해시·비밀번호 해시·키 파생, 보안 난수·인코딩·안전 비교, 전자서명·PEM 키·X.509 인증서·PKCS12/JKS 읽기, RSA-OAEP·Hybrid 암호화, HOTP·TOTP, JWT·OAuth Access Token 검증·Introspection·Client Credentials | 관리형 키·설정·변경 이력·CLI 관리자 비밀번호와 무관(키·정책은 호출자가 줌). 선택 기준 [1.5절](api-selection.md#topic-api-selection--15-업무별-java-api-선택-가이드), 상세 [13장](java-api-reference.md#topic-security-api--13-범용-보안-java-api) |
| Vault KV v2 / AWS KMS | Vault Secret의 AES 키 또는 Passphrase 조회 / KMS가 보호한 데이터 키 복원 | Vault Transit 아님. AWS는 선택형 SDK 묶음 필요 |
| 다른 WAS | Java API·CLI 사용 가능 | WebLogic·JEUS 등의 자체 JDBC Pool 자동 복호화 기능은 없음 |

**암호문 형식:** 문자열은 `ENC[v1:<키ID>:<IV>:<암호문>]`입니다(pass·key 유형 공통). 설정 `crypto.output.encoding=base64`이면 이것을 한 번 더 포장한 `B64[...]`로 출력합니다(포장일 뿐 암호 강도는 같음). 파일은 별도 바이너리 형식 `JCKF v1`을 씁니다.

같은 평문도 매번 새 난수 IV를 쓰므로 암호문은 일반적으로 달라지며, 암호문이 위·변조되면 복호화가 실패합니다.

<a name="topic-getting-started--12-준비물과-내려받기"></a>
## 1.2 준비물과 내려받기

**준비물:** Java 8 이상(JRE도 가능, `java -version`으로 확인). Tomcat에 적용하려면 Tomcat과 DB의 JDBC 드라이버 JAR, AWS KMS를 쓰려면 선택형 SDK 묶음이 더 필요합니다.

필요한 릴리스 자산이 보이지 않으면 아래 **소스에서 빌드** 절차로 현재 작업 트리의 JAR를 만드세요.

**내려받기:** [GitHub Releases](https://github.com/UtiliLabs/java-crypto-kit/releases)

| 파일 | 용도 |
|---|---|
| `java-crypto-kit-<버전>.jar` | 기본 JAR. CLI·Java API·Tomcat Factory가 모두 들어 있으며 보통 이것 하나면 됩니다 |
| `java-crypto-kit-aws-kms-lib-<버전>.zip` | AWS KMS를 쓸 때만 추가하는 AWS SDK 묶음(이 라이브러리 코드는 없음) |
| `SHA256SUMS.txt` | 위 파일들의 SHA-256 |

정식 릴리스(`v<버전>`)는 관리자가 확인한 뒤 GitHub Releases에 **수동으로** 게시합니다. 자동으로 게시되는 사전 릴리스는 없습니다. main 브랜치의 CI는 빌드·시험만 하고, 그 결과물은 Release가 아니라 Actions 아티팩트(14일 보관)로만 남습니다.

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

**소스에서 빌드:** 저장소 루트에서 Windows `gradlew.bat clean build`, Linux `./gradlew clean build`를 실행하면 `build/libs/java-crypto-kit-<버전>.jar`와 `build/distributions/java-crypto-kit-aws-kms-lib-<버전>.zip`이 만들어집니다(테스트 포함). Gradle Wrapper 8.14.8의 공식 빌드 JDK는 8~24입니다(JDK 25는 빌드가 아니라 실행만 확인, [11.1절](compatibility.md#111-검증-상태)).

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
