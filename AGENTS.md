# AGENTS.md — java-crypto-kit 개발·보안 변경 통제

> 적용 범위: 저장소 전체. Codex/Claude/기타 자동화 도구와 기여자는 작업 전에 반드시 읽는다.
> 이 문서는 코드 리뷰와 자동 검사(테스트·CI)에서 지켜야 할 요구사항이다. 문서 자체가 보안을 보증하거나 실행을 차단하는 기술적 장치는 아니다.
> 사용 방법은 `README.md`(한국어 소개·첫 사용), `docs/user-guide.md`(한국어 정식 상세 사용자 매뉴얼), CLI Help(한국어·영어, 실행 중 참고)가 맡고, 이 문서는 바꾸면 안 되는 규칙과 변경 절차만 다룬다(사용자 매뉴얼이 아니다).

## 빠른 안내(기여자)

| 하려는 일 | 명령·위치 |
|---|---|
| 전체 빌드(JUnit·selfTest·JAR·KMS ZIP) | Windows `gradlew.bat clean build`, Linux/macOS `./gradlew clean build` |
| 테스트 하나만 실행 | `gradlew.bat test --tests io.javacryptokit.cli.DocsConsistencyTest`(Linux는 `./gradlew`) |
| 실서버 통합 시험(Docker) | `bash src/test/integration/run-tomcat-integration.sh`(`--help`에 시험 구성·결과 읽는 법·실패 조사 순서) |
| 결과물 | `build/libs/java-crypto-kit-<버전>.jar`, `build/distributions/java-crypto-kit-aws-kms-lib-<버전>.zip`, 통합 시험 로그 `build/qa-integration/<UTC 시각>/` |
| 사용자 문서 | `README.md`(첫 사용), `docs/user-guide.md`(상세 매뉴얼), `src/main/resources/io/javacryptokit/i18n/help/<en\|ko>/`(CLI Help), 예제 `docs/config/`·`docs/tomcat/` |
| 변경별로 고칠 곳과 필수 시험 | §5 유지보수 가이드 표. 보안·호환 규칙은 §2, 테스트·문서 게이트는 §3 |

## 0. 프로젝트 정체성과 구조

- `java-crypto-kit` = **WAS JDBC Connection Pool 접속정보 암호화(최우선) + 일반 Java용 범용 암복호화 API·CLI**. 공식 저장소: https://github.com/freeangelsun/java-crypto-kit
- 최우선 기능은 Tomcat JNDI DataSource 연동이다. 범용 기능(파일 암호화·Vault·KMS·JAR 내부 설정 등) 때문에 JAR 설치 → 암호문 생성 → `factory`·`password` 지정 → 기동·DB 확인이라는 기본 흐름이 복잡해지거나 깨지면 안 된다. WAS 애플리케이션 Java 코드 수정을 요구하지 않는다.
- WAS가 제공하는 Connection Pool만 사용하며 자체 Pool을 구현하지 않는다. 산출물은 실행 가능한 일반 JAR 1개다(fat JAR·WAR·모듈별 다중 JAR 금지, Tomcat Pool·JDBC 드라이버·AWS SDK 포함 금지). 예외로 AWS KMS 사용자만 추가 설치하는 서드파티 묶음 ZIP(`java-crypto-kit-aws-kms-lib-<버전>.zip`, AWS SDK JAR만 포함, 이 라이브러리 코드 없음)을 함께 만든다.
- 이름 원칙: 프로젝트·JAR·로그 태그는 `java-crypto-kit`, Java 패키지·Gradle group은 `io.javacryptokit`. JDBC·Tomcat 전용 기능에만 JDBC 이름을 쓴다. Java 패키지·Gradle group에는 GitHub 계정명을 넣지 않는다.

| 패키지 | 클래스 | 역할 | 공개 여부 |
|---|---|---|---|
| `io.javacryptokit` | `CredentialCrypto`, `CredentialCryptoException` | 일반 Java용 공개 API(값·`byte[]`·파일 암복호화) | **공개 API** |
| `io.javacryptokit.core` | `CredentialCipher`, `TokenCodec`, `CryptoService` | AES-256-GCM v1 엔진(유일), ENC/B64 Codec, 공통 서비스(키 캐시·진단) | 내부 |
| `io.javacryptokit.file` | `FileCipher` | 파일 암호화 JCKF v1(스트리밍) | 내부 |
| `io.javacryptokit.key` | `KeyProvider`, `KeyResolver`, `LocalKeyProviders`, `Diagnostic`, `SecretFiles`, `DefaultKeyWarning` | 키 공급 계약·고정 등록부, embedded/file/env, 비밀 파일 읽기, 키·설정 위험 안내 | 내부 |
| `io.javacryptokit.key.vault` | `VaultKeyProvider`, `MiniJson` | HashiCorp Vault KV v2(JDK HTTPS) | 내부 |
| `io.javacryptokit.key.aws` | `AwsKmsKeyProvider`, `AwsKmsSupport` | AWS KMS Envelope Encryption(SDK 타입은 `AwsKmsSupport`에만) | 내부 |
| `io.javacryptokit.config` | `CryptoSettings`, `SettingCatalog`, `SafeMessageException` | 설정 정의(단일 원본)·로딩·우선순위·검증 | 내부 |
| `io.javacryptokit.i18n` | `Messages` | 한국어·영어 메시지 번들, 언어 결정 | 내부 |
| `io.javacryptokit.cli` | `CryptoCli`, `CliCommands`, `CliHelp`, `ConfigCommand`, `ConfigHistory`, `JarConfigEditor`, `KeyCommands`, `DoctorCommand`, `FileCommand` | `java -jar` 명령(Manifest Main-Class), 도움말, JAR 내부 설정·이력 | 진입점 |
| `io.javacryptokit.jdbc.tomcat` | `EncryptedDataSourceFactory` | Tomcat JNDI ObjectFactory(핵심 어댑터) | 진입점 |

- 내부 패키지 클래스가 `public`인 것은 Java 8에서 패키지 사이 호출을 하기 위해서다. 공개 API로 문서화하지 않는다.
- 엔진·키 로딩·설정 해석은 한 곳에만 둔다. CLI·Tomcat 어댑터·공개 API는 모두 `core.CryptoService`를 거치고, 설정 원본(내장·외부 Properties, JVM 속성, 환경변수의 설정 경로)은 `config.CryptoSettings`만 읽는다. 다른 클래스가 `System.getProperty`·파일로 설정을 따로 읽어 결과가 달라지게 하지 않는다.
- 설정 항목의 이름·그룹·형식·허용값·`-D` 허용 여부·비밀 여부는 `config.SettingCatalog` 한 곳에서 정의한다. 검증·`config help`·`config show`·`info`·`doctor`가 모두 이 정의를 쓴다. 설명 문구는 `i18n/settings(_ko).properties`의 `setting.<이름>.*`에 둔다.
- Tomcat factory는 `io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory` 하나다. 다른 패키지에 같은 역할의 별칭 Factory 클래스를 추가하지 않는다.
- `core`·`key`·`config`·`file`·`i18n`은 `javax.naming`·Tomcat 클래스에 의존하지 않는다. `crypto.pool.factory`는 Tomcat 어댑터 전용 설정이며 `config`에서는 문자열 허용 목록만 검사한다. AWS SDK 클래스는 `key.aws.AwsKmsSupport`에서만 참조한다(기본 JAR만 있는 환경에서 다른 기능이 SDK 없이 동작해야 함).

## 1. 프로젝트 원칙

1. **이름**: 프로젝트·Gradle `rootProject.name`·JAR는 `java-crypto-kit`(`java-crypto-kit-<버전>.jar`), Gradle group과 기본 패키지는 `io.javacryptokit`.
2. **설정 이름 표준(별칭 없음)**: 모든 설정은 소문자 `crypto.<영역>.<항목>` 형식이다. 파일 경로는 `.file`, 환경변수 이름은 `.env`, 시간은 `.ms`로 끝나고 여러 단어는 `-`로 잇는다(예: `crypto.key.file`, `crypto.key.env`, `crypto.vault.timeout.ms`, `crypto.aws.kms.data-key.file`). 외부 설정 경로는 `--config`(CLI) · `-Dcrypto.config.file` · 환경변수 `CRYPTO_CONFIG_FILE` 각각 이름 하나뿐이다. 키 환경변수 기본 이름 `CRYPTO_KEY`, Vault 토큰 환경변수 기본 이름 `VAULT_TOKEN`, 기본 키ID `default`, 로그·오류 태그 `[java-crypto-kit]`. 최초 공개 전에 이름을 표준화했으므로 이전 이름의 별칭·호환 코드는 두지 않는다. 공개 후 이름을 바꾸려면 별칭·마이그레이션 계획·사용자 승인이 필요하다.
3. **최소 Java**: 실행·빌드 하한은 **JDK/JRE 8**(클래스 파일 major 52). JDK 10 이상은 `--release 8`, JDK 8은 source/target 8. Gradle Wrapper 8.14.3 공식 빌드 JDK는 8~24이며, JDK 25에서 빌드가 된다는 사실과 공식 지원을 혼동하지 않는다. Java 7 지원, Java/Gradle 최소 버전 상향은 사전 승인 없이 하지 않는다.
4. **OS**: Windows에서 개발·빌드하고 Linux WAS에서 같은 JAR·같은 설정 방식으로 운영할 수 있어야 한다. Windows 전용 API·명령·경로에 의존하지 않는다. `gradlew`·`*.sh`는 LF, `gradlew.bat`은 CRLF(`.gitattributes`)이고 `gradlew`는 git에 실행 권한(100755)으로 기록한다. Properties의 Windows 경로는 `/` 사용을 안내한다.
5. **인코딩·주석**: Java/XML/Gradle/Properties/Markdown·도움말 텍스트는 UTF-8. Java 클래스·메서드·복잡한 분기·보안 판단에는 알아보기 쉬운 한글 주석을 유지한다.
6. **빌드**: 표준 Gradle Wrapper 하나로 빌드한다(Windows `gradlew.bat clean build`, Linux/macOS `./gradlew clean build`). 두 OS가 같은 `build.gradle`을 쓰며 OS별 대체 빌드 스크립트(`*.ps1`·`*.sh` 래퍼 등)를 추가하지 않는다. 예외는 빌드 래퍼가 아닌 Docker 실서버 통합 시험 도구 `src/test/integration/run-tomcat-integration.sh` 하나다(빌드된 JAR를 시험만 하며 Gradle `test`에서 자동 실행하지 않는다. 다른 시험 스크립트를 따로 늘리지 않는다). `build`에는 `test`(JUnit 5)·`selfTest`·`jar`·KMS 선택 묶음 ZIP이 모두 포함되어야 한다.
7. **문서**: `README.md`는 **한국어 하나만** 둔다(영어 README 없음). 역할은 다음과 같이 나누고 서로 모순되지 않게 한다. README는 범용 사용자의 첫 사용(기본 `encrypt` → `decrypt` → `verify`), Java API·Tomcat·사용자 지정 키의 짧은 소개, 기능 지도, 필수 보안 경고, 지원·검증 범위를 간결하게 담고 세부는 사용자 가이드의 해당 절로 연결한다. `docs/user-guide.md`(한국어)는 **정식 상세 사용자 매뉴얼**로 모든 명령·옵션·허용값·기본값·선택 기준·Windows/Linux 예제·결과·오류 조치, 설정 25개, Java API, Tomcat/Pool, 키 공급·교체·복구, Vault/KMS를 기능별 목차·절로 설명한다. CLI Help(한국어·영어)는 실행 중 참고용으로 같은 명령·옵션을 담는다. 같은 설명을 여러 문서에 길게 복제하지 않고, 가이드의 옵션·허용값·기본값·예제는 삭제하지 않는다(중복만 통합, 기능 자체를 없앤 경우만 제외). `keygen`은 필수 단계가 아니며 내장 예제 키 체험과 운영용 사용자 지정 키를 구분해 안내한다. 직무별 업무 분장이나 특정 조직의 정책을 사용 절차로 강요하지 않는다. CHANGELOG·요구사항(Steering)·추가 매뉴얼 문서는 저장소에 쌓지 않는다. `docs/`에는 사용자 가이드, 예제 설정(`docs/config/java-crypto-kit.example.properties`), Tomcat 예제(`docs/tomcat/dbcp2-context.xml`·`jdbc-pool-context.xml`)만 두며, 예제 파일 이름과 Tomcat이 읽는 실제 파일(`conf/context.xml`·`META-INF/context.xml`)을 README·가이드·Help·예제 주석에서 구분해 안내한다. 명령·옵션·설정·문서 제목을 바꾸면 README·가이드·두 언어 Help·예제 주석·`DocsConsistencyTest`를 함께 고친다.
8. **범용 제품**: 코드·로그·문서·예제에 특정 조직의 업무 분장·내부 배포 절차를 필수 사용 절차처럼 넣지 않는다. 예시 값은 `example.key`·`key01`·`example-admin`처럼 범용 식별자를 쓰고 실제 비밀값은 쓰지 않는다.

## 2. 암호화·키 관리 불변 요구사항

1. **암호화**: AES-256-GCM, 키 32바이트, IV 12바이트를 매 암호화마다 `SecureRandom`으로 생성, 인증 태그 128비트. 같은 평문도 다른 암호문. ECB/CBC 무인증 방식, DES/RC4, MD5/SHA-1 기반 키 유도, 임의 transformation·Provider 로딩으로의 회귀 금지. `crypto.algorithm`은 `AES/GCM/NoPadding`만 허용한다. 비밀번호·Salt로 키를 만드는 PBE(PBKDF2 등)는 지원하지 않으며, 추가하려면 새 키 처리 방식으로 사전 승인을 받는다.
2. **암호문 포맷**: `ENC[v1:<keyId>:<ivBase64Url>:<cipherBase64Url>]` 고정(AAD `v1:<keyId>`). 기존 v1 암호문은 계속 복호화되어야 한다(고정 회귀 벡터 테스트 유지). 포맷·AAD·키ID 규칙을 바꾸려면 새 버전(`ENC[v2:...]`)·마이그레이션 안내·테스트를 함께 만든다. `B64[...]`(`crypto.output.encoding=base64`)는 ENC 문자열의 추가 외부 포장일 뿐 새 포맷·암호화가 아니며, 기본 출력은 항상 ENC다. 임의 포맷·일반 Base64·평문을 암호문으로 추측해 복호화하지 않는다.
3. **파일 포맷(JCKF v1)**: 헤더 `"JCKF" | 버전 0x01 | 청크 크기 65536 | 키ID 길이 | 키ID`, 청크마다 `표시(중간 0x00/마지막 0x01) | IV 12바이트(SecureRandom) | 암호문+태그`, AAD = 헤더 전체 + 청크 번호(8바이트) + 표시. 청크 수는 2^32 미만. 복호화 결과는 모든 청크 인증이 끝난 뒤에만 최종 파일로 옮기고(접근 제한 임시 파일 → move), 실패하면 임시 파일을 지운다. 원본은 바꾸지 않고 출력 파일이 있으면 덮어쓰지 않는다. 형식을 바꾸려면 새 버전과 회귀 테스트를 만든다.
4. **설정 제한**: `crypto.require.encrypted.password`는 `true`, `crypto.warning.enabled`·`crypto.jvm.override.enabled`는 소문자 `true|false`, `crypto.output.encoding`은 `enc|base64`, `crypto.lang`은 `ko|en|auto`(기본 `ko`)만 허용하고 다른 값·빈 값은 안전하게 실패한다. 각 항목의 형식(키ID·URL·경로·숫자 범위 등)은 `SettingCatalog`·`CryptoSettings`에서 검사한다. 최종값 우선순위는 **CLI 1회 옵션(`--lang`) > JVM 개별 속성(`-D`, 허용된 이름만) > 외부 Properties > JAR 내부 값**이다. 외부 설정 경로는 직접 지정 → JVM 속성 → 환경변수 순서로 고른다. 경로를 지정했지만 비어 있으면(빈 `-D`·`--config`·환경변수, 빈 `Path`) 미지정으로 보지 않고 오류로 중단한다. 외부 Properties에 지원하지 않는 항목 이름(오타)이나 `crypto.config.file`이 있으면 오류로 중단한다(이름은 안전한 형식일 때만, 값은 출력 금지, 비슷한 정식 이름은 확신할 때만 안내). `-Dcrypto.*` 중 이 라이브러리 설정 영역(지원 항목에서 나온 `crypto.key.*`·`crypto.vault.*`·`crypto.aws.*`·`crypto.config.*`·`crypto.lang` 등)의 모르는 이름이나 정식 이름과 편집 거리 2 이하인 이름은 오타로 보고 오류로 중단한다(예: `crypto.key.soruce`를 무시하면 공개 내장 키로 동작). 이 검사는 경고 정책·JVM 덮어쓰기 정책과 무관하게 항상 동작한다. 그 밖의 `crypto.*`(예: `crypto.policy`)와 무관한 JVM 속성에는 영향을 주지 않는다. 설정은 객체 생성 시 한 번 읽으므로(Hot Reload 없음) 실행 중인 WAS 반영에는 재기동이 필요하다고 문서화한다.
5. **키 공급**: `embedded`·`file`·`env`·`vault`·`aws-kms`를 같은 JAR에서 선택 지원한다(내장 키 제거·외부 키 강제 금지). 공급원은 `key.KeyProvider` 계약을 구현하고 `KeyResolver`의 **고정 등록부**에만 추가한다. 설정값으로 임의 클래스를 이름으로 로딩하지 않는다. 외부 Properties 사용은 외부 키 강제가 아니며 `embedded` 명시도 허용한다. 지정한 외부 설정·외부 키·원격 키가 없거나 잘못되면 **Fail Closed**, 내장 키로 자동 전환하지 않는다. 키 파일·키 환경변수·Vault·AWS KMS 설정이 있는데 `crypto.key.source`가 없으면 오류로 중단한다. 원시 키·비밀번호·Vault 토큰을 CLI 인자나 `-D`로 받지 않는다. 원격 키는 `CryptoService` 인스턴스마다 한 번 읽어 캐시한다.
6. **공개 기본 키**: 내장 기본 키는 누구나 추출할 수 있는 공개 값이다. 실제 값은 바꾸지 않는다(기존 암호문 호환). 공급 방식과 관계없이 공개 키를 쓰면 탐지하고, 교체한 내장 키도 추출 위험을 안내한다. 이 안내 WARNING은 `crypto.warning.enabled` 기본값 `true`에서 출력하고 `false`이면 출력하지 않는다(Properties와 `-Dcrypto.warning.enabled` 양쪽에서 지정 가능, 종류별 JVM당 1회, 출력 전에 최종값 확정). `false`는 **비차단 안내 로그만** 끄며(우회 안내문도 남기지 않음) 키·암호문·설정 오류, `decrypt` 확인 절차, CLI `info`·`doctor`처럼 사용자가 직접 요청한 진단, WAS·JDK·다른 라이브러리 로그에는 영향을 주지 않는다. 전역 로깅 설정을 바꾸지 않는다. 경고를 꺼도 위험이 사라지지 않는다는 사실을 README에서 삭제하지 않는다. 공개 배포 JAR(GitHub Release)에는 공개 예제 키만 들어 있어야 하며 사용자 지정 키가 든 JAR를 만들거나 게시하지 않는다.
7. **비밀정보 보호**: 평문·실제 키·Vault 토큰·기밀 파일 내용은 로그, 예외(메시지·cause·suppressed), 테스트 리포트, 커밋, ZIP, Issues/PR에 넣지 않는다. 하위 라이브러리 예외(하위 Pool Factory의 `Error` 포함, JVM 장애 `VirtualMachineError`·`ThreadDeath`만 그대로 전달)는 원인·suppressed를 붙이지 않고 원인 유형(클래스 이름·표준 5자리 SQLState)만 남겨 정제한다. 이 정제는 Factory가 DataSource를 만드는 동안의 실패에만 적용되며, 이후 `getConnection()`에서 Pool·드라이버가 내는 예외·로그는 범위 밖이라고 문서화한다(포괄적으로 과장하지 않는다). 오류 메시지는 `[java-crypto-kit] [사유: <코드>] <원인> 조치: <확인할 설정>`(영어 `[reason: <코드>] ... Action: ...`) 한 형식으로 쓴다. 코드는 공개 API `Reason` 이름(`CONFIGURATION`·`KEY_SOURCE`·`INVALID_INPUT`·`INVALID_TOKEN`·`KEY_ID_MISMATCH`·`INTEGRITY`·`CRYPTO_PROVIDER`)을 그대로 쓰고, 그 분류에 없는 경우만 Factory 전용(`PLAINTEXT_PASSWORD`·`MISSING_PASSWORD`·`POOL_FAILURE`·`UNSUPPORTED_RESOURCE`)과 CLI 전용(`USAGE`·`IO_ERROR`)을 쓴다(별도 오류 체계를 만들지 않음, 코드는 번역하지 않음). 원인·조치 문구는 `CredentialCryptoException`과 메시지 번들에서 만들어 CLI·Java API·JNDI가 같은 의미를 갖게 한다. 경로 전체·입력값·설정값·키·암호문은 넣지 않는다(파일 이름·설정 이름은 허용). `decrypt` CLI만 사용자가 대화형 터미널에서 경고 후 `SHOW`를 입력했을 때 평문을 표시한다. `verify`·`rekey`는 평문 미출력, `encrypt`·`decrypt`에는 평문을 명령행으로 받는 옵션 금지.
8. **키 생성·읽기·지문**: `keygen`은 보안 난수 키를 만들고 기존 파일을 덮어쓰지 않으며 POSIX에서는 600으로 만든다. 키 파일·토큰 파일은 일반 파일만 허용(폴더·장치·FIFO 거부, 심볼릭 링크는 대상이 일반 파일이면 허용)하고 크기를 미리 조회하지 않은 채 상한+1까지만 읽는다(키 파일 512바이트). 키 지문은 `SHA-256("java-crypto-kit/key-fingerprint/v1" || 0x00 || 키)` 64자 16진수이며 키 비교용일 뿐 인증·소유 증명이 아니다. 파일/환경변수 키 주입을 유지하되 비밀관리시스템과 직접 연동된 것처럼 과장하지 않는다.
9. **JNDI Factory**: 비밀번호가 암호문이 아니면 거부, 위조·손상·키ID 불일치·키 오류 시 실패(평문 fallback 금지), 원본 Reference 불변, `username`은 선택 암호화. Tomcat 공식 Pool(DBCP2 기본, Tomcat JDBC Pool 선택) 외 임의 Factory를 로딩하지 않는다. 공식 Pool Factory는 이름만 믿지 않고 **이 라이브러리를 로딩한 클래스로더에서만** 찾으며, 정의한 로더가 그 로더 또는 부모 체인인지 확인한다(스레드 컨텍스트·웹앱 클래스로더 사용 금지: 같은 이름의 가짜 Factory가 평문 비밀번호를 받을 수 있음). Pool 생성 실패 메시지에는 실제로 쓴 Pool 이름(DBCP2·Tomcat JDBC Pool)을 쓴다. WAS 운영자에게 Java 코드 작성이나 JAR 재빌드를 요구하지 않는다. Pool 종류는 JVM 전역 설정 `crypto.pool.factory` 하나로 정한다(한 Tomcat JVM의 모든 Resource 공통). Resource별 Pool 선택 속성처럼 Factory 전용 JNDI 속성을 추가하는 것은 사전 승인 대상이다.
10. **JVM 개별 속성(`-D`)**: `SettingCatalog`에서 `-D` 허용으로 정한 항목(`CryptoSettings.JVM_OVERRIDABLE_KEYS`: `crypto.key.embedded`·`crypto.jvm.override.enabled`를 뺀 모든 설정)만 같은 이름의 `-D`로 덮어쓴다. 덮어쓰기 허용 정책 `crypto.jvm.override.enabled`(기본 `true`)는 JAR 내부 값·외부 Properties에서만 정하고 `-D` 값은 읽지 않는다(정책 우회 금지). 키 원문 `crypto.key.embedded`의 `-D` 지정은 정책과 무관하게 오류로 중단한다(프로세스 목록·Tomcat 기동 로그 노출 방지). 설정 파일 경로 `-Dcrypto.config.file`은 정책과 무관하게 동작한다. `-D` 값에도 같은 허용값 검증·모호성 검사·Fail Closed를 적용한다. CLI `info`는 값의 출처(JAR·외부 파일·JVM)와 적용·무시한 `-D` 이름만 보여 주고 키·비밀값은 출력하지 않는다.
11. **메시지 언어**: 모든 라이브러리 메시지(CLI·도움말·Java API 예외·Tomcat Factory·Vault/KMS 오류·경고)는 `i18n` 번들(`core`·`cli`·`settings`와 `_ko`, 도움말 `help/<en|ko>/<주제>.txt`)에서 가져온다. 언어는 `crypto.lang`(JAR 내부 값·외부 Properties·`-D`)으로 정하고 기본은 `ko`, `auto`는 JVM Locale(한국어가 아니면 영어), 지원하지 않는 언어는 영어다. CLI `--lang en|ko`는 그 실행에만 적용한다. WAS 안에서는 스레드 범위로만 언어를 바꾸고 JVM 기본 Locale·전역 설정을 바꾸지 않는다. 사유 코드·PASS/WARN/FAIL·명령·옵션·설정 이름은 번역하지 않는다. Tomcat·JDBC 드라이버·AWS SDK 등 외부 제품 메시지는 번역하지 않는다. 메시지를 추가하면 두 언어 번들에 같은 키로 넣는다(`I18nTest`).
12. **Vault KV v2**: HTTPS만 허용하고 TLS 인증서·호스트 이름 검증을 끌 수 없다(사설 CA는 `crypto.vault.ca.file`). 리다이렉트를 따르지 않는다. 토큰은 토큰 파일(`crypto.vault.token.file`) 또는 환경변수(`crypto.vault.token.env`)로만 받으며 JAR 내부 Properties·외부 Properties·`-D`에 토큰 값을 쓰는 기능을 만들지 않는다. 제한 시간·재시도(연결 실패·시간 초과·429/5xx만)를 두고 인증 실패·권한 부족·Secret 없음·TLS 오류를 구분해 알린다(정책 밖 경로는 Vault가 권한 부족으로 답한다는 점도 안내). 실패 시 다른 키로 대체하지 않는다. Vault Transit은 지원하지 않는다.
13. **AWS KMS**: AWS 공식 SDK for Java 2.x만 쓴다(SigV4·자격증명 체계를 직접 구현하지 않음). SDK는 `compileOnly`이며 기본 JAR에 넣지 않고 선택 묶음 ZIP으로만 제공한다(`kms`·`url-connection-client`·`sts`와 그 의존성, apache-client·apache5-client·netty 제외 - HTTP 클라이언트 구현은 url-connection-client 하나만 둔다). 자격증명은 SDK 기본 자격증명 체계(IAM 역할 등)만 쓰고 Access Key·Secret Key를 하드코딩하거나 설정 항목으로 받지 않는다. 암호화 컨텍스트 `java-crypto-kit:key-id=<crypto.key.id>`를 고정한다. 모의 KMS 테스트와 실제 AWS 검증을 구분하며, 실제 AWS KMS를 호출하지 않았으면 KMS 연동 PASS로 보고하지 않는다. SDK 버전 갱신은 `build.gradle`의 `awsSdkVersion` 한 곳에서 하고 KMS 테스트를 다시 실행한다.
14. **JAR 내부 설정·변경 이력**: `config set`·`config embed-key`는 소스 수정·재빌드·외부 Properties 없이 JAR 내부 설정을 바꾼다. 기본은 원본을 두고 `<이름>-configured.jar`를 새로 만들고, 이미 바꾼 JAR(`-configured`, `-configured-<N>`)는 접미사를 겹치지 않고 `-configured-<N+1>.jar`로 만든다(기본 이름의 파일이 있으면 덮어쓰지 않고 확인 질문 전에 멈추며 `--out` 이름을 안내). `--out`은 지정한 이름, `--replace`는 `<이름>.bak-<UTC>` 백업 후 원자적으로 교체한다(실행 중인 JAR·서명된 JAR·이력이 손상된 JAR는 수정하지 않음). 바꾼 뒤 전체 설정을 실행 시와 같은 규칙으로 다시 검증하고, 결과 JAR를 다시 읽어 확인한 뒤에만 자리에 둔다. 내장 키는 `config embed-key`(키 파일)로만 바꾸며 공개 키·현재와 같은 키·**현재 키ID와 이력에서 쓰인 키ID의 재사용**은 거부하고 `rekey` 재암호화를 안내한다. 변경 이력(`config history`)에는 성공한 변경만 순번·UTC 시각·수정자·명령·사유·설정별 이전 값→변경 값으로 남기고, 비밀 항목은 `(비공개) -> (교체됨)`만 남긴다(키ID 변경은 표시). 새 JAR·`--replace` 후에도 이력을 모두 옮긴다. 해시 체인·Manifest 설정 지문으로 손상·이력 없는 수정을 탐지해 오류로 알리되, **위변조 방지 감사 로그가 아니라고** 문서화한다. 수정자 ID는 기록용이며 인증이 아니다.

## 3. 테스트·문서 변경 게이트

- [ ] `gradlew clean build`가 JDK 8과 17/21에서 성공(표준 `test`=JUnit 5, `selfTest`=독립 자체 검증, `jar`, KMS 묶음 ZIP 모두 실행). 실제로 돌리지 않은 JDK·OS는 미검증으로 표시
- [ ] Java 8 클래스 파일 major 52, JAR에 테스트·모의 클래스·외부 라이브러리(AWS SDK 포함) 없음
- [ ] AES-GCM 암복호화, 한글 UTF-8, 같은 평문 다른 암호문, IV·태그·키ID(AAD) 변조 실패, v1 고정 회귀 벡터, B64 왕복·손상 거부
- [ ] JCKF 파일 왕복(청크 경계 크기), 같은 파일도 매번 다른 결과, 헤더·청크 변조·순서 바꾸기·잘라내기·덧붙이기 거부, 공개 API의 원본 보존·덮어쓰기 거부·임시 파일 정리, 키 읽기 전 키ID 확인(`FileCipherTest`)
- [ ] embedded/file/env × `crypto.warning.enabled` true/false, 공개 키의 file/env 공급 탐지, 외부 설정·키 누락 Fail Closed, 설정 경로 우선순위·빈 경로 거부(`KeyModeWarningMatrixTest`·`ConfigResolutionTest`)
- [ ] JVM `-D` 단독·외부 Properties 단독·혼합 우선순위, `crypto.jvm.override.enabled` true/false, `-D`로 정책 우회 불가, 키 원문 `-D` 거부, `-D` 잘못된 값·오타 거부, 무관한 `crypto.policy` 무영향, 모든 설정의 `-D` 분류(`JvmOverrideTest`·`SettingCatalogTest`)
- [ ] Tomcat factory를 클래스 이름으로 로딩·DBCP2/Tomcat JDBC Pool 위임, 하위 Pool 예외(Error 포함) 평문 비노출(`PoolFailureSanitizationTest`), 컨텍스트 클래스로더의 같은 이름 가짜 Pool Factory가 평문을 받지 못함(`PoolFactoryTrustBoundaryTest`), 시나리오(`DataSourceFactoryScenarioTest`·`FactoryEntryPointTest`)
- [ ] Vault 모의 TLS 서버(인증 실패·권한 부족·Secret 없음 구분, TLS 검증·리다이렉트 거부, 재시도·시간 초과, 토큰 공급 방식, 내장 키 fallback 없음, `VaultKeyProviderTest`), KMS 모의 클라이언트(`AwsKmsKeyProviderTest`·`KmsDataKeyCliTest`), AWS SDK 없는 기본 JAR 동작(`ConfigJarTest`)
- [ ] CLI `encrypt`·`verify`·`decrypt`(SHOW)·`file encrypt/decrypt`·`keygen`·`fingerprint`·`rekey`·`info`·`doctor`·`config show/history/set/embed-key`·`kms datakey`·`help`의 출력·종료 코드·평문 비노출(`CryptoCliTest`·`KeyCommandsTest`·`DoctorAndHelpTest`·`ConfigJarTest`)
- [ ] 메시지 두 언어 키 일치·기본 `ko`·`--lang` 1회 적용·Locale fallback(`I18nTest`)
- [ ] 도움말 두 언어의 옵션·설정 이름 일치, 도움말 예제 명령·옵션이 실제 정의와 일치(`DoctorAndHelpTest`). README 예제 명령·옵션·설정 이름·명령 목록, 사용자 가이드의 명령별 절·명령별 옵션·설정 25개·공개 Java API·예제 명령 유효성, 예제 Properties(주석 예제 포함)·예제 XML 2종, 웹 페이지(JSP·WAR) 부재, LICENSE 원문 해시(`DocsConsistencyTest`)
- [ ] 기본 Properties의 모든 항목에 기본값·허용값·의미·제약·변경 영향 주석 유지
- [ ] 제품 JAR·`docs/`·`src/main`에 웹 페이지(JSP·WAR·`WEB-INF`)를 두지 않는다(`DocsConsistencyTest`·CI JAR 검사). 실서버 시험용 웹앱은 `src/test/integration/run-tomcat-integration.sh`가 실행 중에만 만들어 컨테이너 안에 복사하고, 포트를 공개하지 않으며 시험 후 지운다
- [ ] 키 내장 JAR·키·토큰·백업이 저장소에 들어가지 않게 한다: `.gitignore`(`*.jar`, Gradle Wrapper JAR만 예외, `*.key`·`*.token`·`*.datakey`·`*.jar.bak-*`)와 CI의 `git ls-files` 검사. `--out`으로 정한 임의 이름도 같은 주의를 README에 둔다 `.gitignore`는 만능 보호가 아니므로 추적 파일과 새 미추적 파일을 함께 점검한다.
- [ ] README·AGENTS·사용자 가이드의 상대 링크와 제목 링크(다른 문서의 제목 포함)가 실제 파일·제목으로 이어지고, 옮기기 전 경로가 문서·도움말·CI·하니스에 남지 않는다(`DocsConsistencyTest`)
- [ ] Tomcat Factory·키 공급·Pool·설정 해석 코드를 바꿨거나 Release 전이면 `bash src/test/integration/run-tomcat-integration.sh`가 종료 코드 0(RESULT: PASS)이어야 한다(시험 FAIL은 1, 실행 환경 문제는 2)(Vault 코드를 바꿨으면 `--with-vault` 추가). 일반 변경마다 필수는 아니다
- [ ] Tomcat 8.5/9.0/10.1/11.0 × DBCP2·Tomcat JDBC Pool은 실제로 실행한 환경과 결과가 있을 때만 검증으로 표기한다(JNDI 조회 → `getConnection()` → 실제 DB SQL 실행). Tomcat 8.5는 Apache 지원이 끝난 레거시 계열로 구분해 표기한다. 모의 테스트·컨테이너 시험·실운영 서버를 구분해 적는다
- [ ] DB는 실제 연동을 검증한 MariaDB만 검증으로 적는다. 다른 DB(Oracle·PostgreSQL 등)는 일반 JDBC 드라이버로 설정할 수 있다는 설명만 하고 검증 완료·공식 지원으로 표시하지 않는다. README에는 DB별 상세 호환성 표를 만들지 않으며, 세부 시험 환경·PASS/FAIL 매트릭스는 QA 보고에만 둔다
- [ ] JEUS·WebLogic·WebSphere/Liberty·JBoss/WildFly 등은 구현과 실서버 검증 전에는 지원 완료로 표기하지 않음
- [ ] Docker 통합 시험은 시험 전용 이름·라벨로만 자원을 만들고, 끝나면(실패·중단 포함) 그 컨테이너·네트워크·볼륨·새로 받은 이미지·임시 파일만 지운다. 기존 자원과 다른 프로젝트 자원은 건드리지 않으며 `docker system prune`·`docker volume prune` 같은 일괄 삭제를 쓰지 않는다. 시험 전후 자원 목록을 비교해 잔여 자원이 없음을 확인하고, 결과 로그에는 비밀번호·키·토큰을 남기지 않는다

## 4. 변경 승인 및 공개 규칙

- **현재 구현에 포함된 승인 기능(유지 대상)**: §0·§1의 이름·패키지 구조, 공개 API `CredentialCrypto`(`encryptFile`·`decryptFile` 포함), 설정 이름 표준, JVM 개별 속성 덮어쓰기와 `crypto.jvm.override.enabled`, `crypto.warning.enabled`, `crypto.output.encoding`(B64 추가 포장), `crypto.lang`(한국어 기본·영어), JAR 내부 설정(`config set`·`config embed-key`)과 변경 이력, `keygen`·`fingerprint`·`rekey`·`doctor`, 파일 암호화(JCKF v1), Vault KV v2·AWS KMS 키 공급(AWS SDK 2.x 선택 의존성), `KeyProvider` 확장 구조, JUnit 5(테스트 전용)·GitHub Actions CI/CD. 이 기능을 없애거나 의미를 바꾸는 변경은 아래 사전 승인 항목과 같이 다룬다.
- 확정된 규칙은 이 문서에, 사용 방법은 README(요약)·사용자 가이드(상세)·CLI Help(실행 중 참고)에 반영한다. 요구사항 문서를 저장소에 따로 쌓지 않는다.
- **사전 승인 필요**: 암호화 알고리즘·키 길이·암호문/파일 포맷·키 처리 방식·로그 정보 범위·지원 Java 최소 버전·Gradle 메이저 버전 변경, WAS별 연동 어댑터 추가, JNDI Resource 전용 속성 추가·Pool 선택 방식 변경, 모듈(JAR) 분리, 공개 API 확장, 새 외부 의존성·네트워크 호출·텔레메트리(도입 전에 용도와 위험 설명), 새 키 공급원(다른 KMS·HSM 등).
- **Git·배포**: Git commit/push, 태그 생성, GitHub Release 게시, 저장소 이름·로컬 프로젝트 폴더 이름 변경은 사용자 승인 없이 하지 않는다. CI/CD는 외부 Action을 커밋 SHA로 고정하고 기본 권한을 읽기 전용으로 둔다. main push 성공 시 개발용 Pre-release `dev-<커밋>`, `v*` 태그는 Gradle 버전과 같을 때만 정식 Release(JAR·KMS 묶음·SHA256SUMS)를 게시하며 기존 Release를 덮어쓰지 않는다. Pull Request에서는 게시하지 않는다.
- 테스트 통과를 이유로 실제 WAS 운영 호환을 단정하지 않는다.
- 결함을 발견하면 원인·재현·최소 수정·영향·관련 회귀 결과를 함께 보고하고, 실행하지 않은 검증을 PASS로 적지 않는다. 다른 도구가 만든 변경도 이 문서 기준으로 검토하고, 승인 없이 들어간 기능은 사용자에게 보고해 결정을 받는다.
- 공개 저장소에는 실제 키·비밀번호·토큰·사용자 지정 키 내장 JAR·사내 URL·고유 업무 경로를 넣지 않는다. 내장 예제 키는 비밀이 아님을 명시한다.
- 라이선스는 Apache License 2.0이다. `LICENSE`는 apache.org 원문을 그대로 두고(내용 수정 금지, `DocsConsistencyTest`가 해시 확인), 저작권자 표기·NOTICE 추가는 소유권자가 정한다. 선택 설치 KMS 묶음의 서드파티 라이선스는 각 JAR의 고지를 따른다.

## 5. 유지보수 가이드(변경 위치와 회귀 테스트)

| 하려는 일 | 바꾸는 곳 | 꼭 추가·실행할 테스트 |
|---|---|---|
| 새 암호화 방식(예: v2) | `core.CredentialCipher`(새 버전 분기), `core.TokenCodec`, 도움말 | v1 고정 벡터 계속 PASS, v2 왕복·변조·버전 혼동 거부 (사전 승인 필요) |
| 파일 포맷 변경 | `file.FileCipher`(새 버전 번호, v1 읽기 유지) | v1 파일 계속 복호화, 새 버전 왕복·변조 거부 (사전 승인 필요) |
| 새 키 공급원 | `key.KeyProvider` 구현, `key.KeyResolver` 고정 등록부, `SettingCatalog`(허용값·설정), 기본 Properties·도움말 | Fail Closed(내장 키 fallback 없음), `doctor`·`--offline` 진단, 정제된 오류, 모의 서버 테스트 (사전 승인 필요) |
| 새 설정 옵션 | `config.SettingCatalog`(형식·허용값·`-D` 허용 여부 - 비밀값·정책 항목은 제외), `config.CryptoSettings`(검증), `i18n/settings(_ko).properties`, 기본·예제 Properties(`[JVM -D]` 주석), CLI `info`·도움말, 사용자 가이드 10장, 필요 시 README | 기본값·외부 우선·`-D` 우선·잘못된 값 거부, `JvmOverrideTest.everyJarPropertyIsClassifiedForJvmOverride`, `SettingCatalogTest`, `DoctorAndHelpTest` |
| 메시지·도움말 수정 | `i18n/*.properties`(두 언어 같은 키), `i18n/help/<en|ko>/`, 사용자 가이드의 해당 절 | `I18nTest`, `DoctorAndHelpTest`, `DocsConsistencyTest` |
| 사용자 가이드 수정 | `docs/user-guide.md`(목차·절 번호·제목 링크), README·Help·예제 주석의 참조 | `DocsConsistencyTest`(링크·제목·명령별 옵션·설정 25개·예제 명령) |
| CLI 명령 변경 | `cli.CliCommands`(명령·옵션 정의), 해당 명령 클래스, 두 언어 도움말, 사용자 가이드 2장, README 기능 표 | `CryptoCliTest`·`DoctorAndHelpTest`의 출력·종료 코드·평문 비노출, 도움말 예제 검사 |
| JAR 내부 설정·이력 변경 | `cli.JarConfigEditor`, `cli.ConfigHistory`, `cli.ConfigCommand` | `ConfigJarTest`(새 JAR·연속 변경 결과 이름·충돌·`--out`·`--replace`·백업·잠금·서명 JAR·이력 유지·변조 탐지·키ID 재사용 거부) |
| 실서버 통합 시험 변경 | `src/test/integration/run-tomcat-integration.sh`(시험 전용, 저장소에 웹앱 파일을 두지 않음) | 8개 조합 RESULT: PASS, 실패 시 종료 코드 1과 실패 항목, 환경 오류 2, Docker 정리 확인 |
| 문서·예제 파일 위치 변경 | 파일 이동 + `DocsConsistencyTest`의 경로 상수, README·AGENTS 링크, CI | `DocsConsistencyTest`(링크·옛 경로 0건·`docs/`는 가이드·예제만) |
| 새 WAS 어댑터 | 새 패키지 `io.javacryptokit.jdbc.<was>`에서 `core.CryptoService`만 사용(엔진 복사 금지) | 모의 위임·예외 정제·원본 불변, 실서버 검증 결과 별도 표기 (사전 승인 필요) |
| 설정 이름 변경(공개 후) | 기존 이름은 유지하고 새 이름을 별칭으로 추가, 마이그레이션 안내 | `ConfigResolutionTest`, `FactoryEntryPointTest` (사용자 승인 필요) |
