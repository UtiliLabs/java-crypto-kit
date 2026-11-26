# AGENTS.md — java-crypto-kit 개발·QA 불변 규칙

> 적용: 저장소 전체 / 개발·QA 에이전트 및 기여자 공통. 개발 기준이며 검증 완료 증명이 아니다.
> 역할: 변경 금지 원칙, 호환성·보안 경계, 작업·검증 게이트. **사용 절차·전체 옵션·복사 예제는 `docs/user-guide.md`에서 연결되는 업무별 가이드**, 제품 소개는 `README.md`, 사용 예제는 기능별 가이드, 간단 명령 설명은 CLI Help에서 관리한다.
> 규칙이 현행 코드와 다르면 임의로 옛 규칙에 맞추지 말고 차이를 보고·수정한다. 승인된 추가 요건과 충돌하면 **최신 사용자 확정 요구**를 우선하되, 보안·호환성 위험은 보고한다.


**규칙 탐색:** [제품 범위](#1-제품-범위와-작업-원칙) · [암호화 형식](#2-암호화-형식키-유형-절대-호환) · [범용 API](#8-범용-보안-java-api-범위-동결) · [검증](#9-문서ux검증-게이트) · [변경 통제](#10-변경-통제완료-보고) · [기술 명세](docs/reference/technical-specification.md)

## 작업 전 확인

공개 기능·알고리즘·데이터 형식·설정·인증·오류·CLI 별칭·배포 계약을 변경할 때는 [기술 명세](docs/reference/technical-specification.md)와 영향받는 사용자 가이드·Help·Examples·API Reference를 함께 확인한다. 기술 명세는 상세 동작·호환 규격, API Reference는 공개 시그니처, 기능별 가이드는 사용 절차, 명령 등록 및 Help는 실행 옵션, CHANGELOG는 버전 이력의 기준이다.

실제 변경된 계약과 관련 절·명령·테스트만 갱신한다. 소스와 문서가 어긋나면 기존 승인 계약과 대조하고, 보안·호환성 계약 변경에는 승인을 받는다. 새 CLI 경로는 기존 등록·인증·입출력을 재사용하고 영향 범위의 시험을 수행한다.

| 판단 항목 | 적용 원칙 |
|---|---|
| 변경 범위 | 승인된 제품 기능·보안 결함·문서 정합성만 수정 |
| 검증 | 기존 통합 증거 재사용, 변경 영향 범위만 표적 실행 |
| 문서 역할 | README = 첫 사용·기능 안내, User Guide = 업무별 목차, guide = 사용 절차, reference = 옵션·기술 사전, AGENTS = 개발 규칙 |
| Git·배포 | 사용자 승인 전 변경 작업을 원격에 반영하지 않음 |


---

## 1. 제품 범위와 작업 원칙

**제품**

`java-crypto-kit` / Java 패키지·Gradle group `io.javacryptokit`. 최우선 용도는 **Tomcat JNDI JDBC Connection Pool 비밀번호 복호화**이고, 같은 엔진을 일반 Java API·CLI·파일 기능에서도 쓴다.

WAS 업무 Java 소스 수정이나 별도 자체 Connection Pool은 요구하지 않는다.

CLI는 관리자 비밀번호로 사용을 통제한다(§7.1, CLI 전용). 같은 JAR에 외부 라이브러리 없는 **범용 보안 Java API**(`io.javacryptokit.security`·`jwt`·`oauth`, §8)를 함께 제공한다.

**산출물**

Java 8 호환 실행형 일반 JAR **1개**(fat JAR, WAR, 자체 Pool, JDBC 드라이버, AWS SDK 내장 금지). AWS KMS 사용자를 위한 기존 선택형 AWS SDK 의존성 ZIP은 유지한다.

Java 7 지원, 별도 서버·신규 모듈·새 암호 라이브러리는 승인 없이 추가하지 않는다.

**단일 구현**

- AES-GCM 처리(IV·태그·보안 난수)는 `core.Gcm`, Passphrase 정규화·PBKDF2 계산은 `core.Kdf`, JSON 해석·작성은 `json.StrictJson`이 관리형 키·직접 키·범용 API·Vault·JWT·OAuth 공통 기준이다(별도 GCM·KDF·JSON 구현 금지). 관리형 키 선택은 `core.CryptoService`, 설정 해석은 `config.CryptoSettings`, 설정 항목의 정의와 유효성은 `config.SettingCatalog`, 메시지는 `i18n`을 단일 기준으로 유지한다.
- CLI·Java API·Tomcat 어댑터에 키 처리·설정 우선순위 로직을 중복 구현하지 않는다.
- CLI 명령의 관리자 비밀번호 정책은 `cli.CliCommands` 명령 정의의 `Access`(OPEN·SETUP·ADMIN)가 정본이고, 인증은 `CryptoCli`가 명령 본 처리 전에 한 곳에서 한다(명령별 인증 호출·별도 명령 목록을 두지 않음). JAR 상태·무결성 판단은 `cli.AdminPassword.statusOf` 하나로 한다.
- 키 공급원은 `KeyProvider`와 `KeyResolver`의 고정 등록부만 사용하고, 설정값으로 임의 클래스를 로딩하지 않는다.

**공개 호환성**

기존 `io.javacryptokit.CredentialCrypto` API, `CredentialCryptoException.Reason`, Tomcat `io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory` 이름과 JNDI 설정, CLI 명령·옵션, 설정명, 기존 암호문·파일을 임의로 제거·변경하지 않는다.

신규 API 확장은 승인된 `KeyType`·`KeyInfo`·Key ID 선택, 직접 키(`fromRawKey`·`fromPassphrase`)와 §8 범용 보안 API 범위에서만 한다(범위 동결, 그 밖의 신규 기능·API는 사전 승인).

**최소 변경**

기능과 테스트를 지우거나 이름을 바꾸어 PASS를 만드는 행위 금지. 신규 기능 제안 **OPT-01~OPT-07은 개발 범위에서 제외**한다. 운영 파일 백업·재처리 시스템, 별도 `inspect`·`dry-run`·감사 서버, 전체 코드 난독화도 만들지 않는다.

**빌드**

Gradle Wrapper(Windows `gradlew.bat clean build`, Linux `./gradlew clean build`), 최소 JDK 8 / 클래스 major 52, Windows·Linux 동일 소스. 암호 로직에 신규 외부 라이브러리를 추가하지 않는다.

기존 AWS KMS 선택 SDK는 예외다.


## 2. 암호화 형식·키 유형 (절대 호환)

**관리형·직접 키 암호문(ENC v1·JCKF) 엔진**

`AES/GCM/NoPadding`, AES 키 32바이트(256비트), 매 암호화 `SecureRandom` IV 12바이트, 인증 태그 128비트. 변조·키 불일치 시 평문 반환·출력 금지. ECB/CBC 무인증 등 대체 알고리즘 사용 금지.

**토큰 형식**

`ENC[v1:<keyId>:<ivBase64Url>:<cipherBase64Url>]`, AAD=`v1:<keyId>`. B64 출력은 기존 ENC의 외부 포장일 뿐 새 암호화 형식이 아니다. 기존 `ENC v1` 고정 암호문은 그대로 복호화한다.

**파일 형식**

SEC-01에 따라 신규 파일은 `JCKF v2`로 쓴다. 헤더의 파일별 128비트 난수 식별자를 모든 청크의 AAD에 포함하고, 기존 `JCKF v1` 암호문의 복호화와 스트리밍 처리를 유지한다. [JCKF 호환 규격](docs/reference/technical-specification.md#jckf-v2) 실패·무결성 오류 시 불완전한 최종 평문 파일을 남기지 않으며 기존 원본·대상 파일을 임의 덮어쓰지 않는다. CLI의 `file encrypt`·`file decrypt`는 `--out`을 요구하고 Java API는 기존 출력 Path를 사용한다. 별도 업무 백업·복구 기능은 추가하지 않는다.

**키 유형**

`pass` = Passphrase를 KDF로 변환한 AES 키, `key` = 32바이트 원시 AES 키. CLI는 `--type pass|key`, Java API Enum은 `KeyType.PASS|KEY`. **신규 JAR에서 Type 생략 시 실제 신규 암호화 기본값은 `pass`**(생성뿐 아니라 `encrypt`, `file encrypt`, API 등). 기존 AES 전용 `keygen`·`kms datakey` 명령의 원래 용도는 유지한다.

**Passphrase 파생(관리형 `pass` 키)**

Java 8 표준 `PBKDF2WithHmacSHA256`, NFC 정규화·UTF-8 입력, Salt 16바이트(사용자 키마다 보안 난수), 반복 기본 600,000회(허용 범위 100,000~5,000,000), 결과 32바이트. 과거 키 재현에는 **원문 + 원래 Key ID + Salt + KDF 알고리즘·반복 횟수 + 정규화 규칙**이 필요하다.

KDF·Salt를 변경하면 별도 키로 취급한다.

Argon2·scrypt·외부 Provider 추가 금지. 직접 키 `fromPassphrase`와 범용 API는 PBKDF2-HMAC-SHA256/SHA512를 `Pbkdf2Algorithm`으로 고르며 같은 정규화·`core.Kdf`를 쓴다.

**공개 예제 키**

기존 AES `default`와 신규 Passphrase `pass-default`를 **동일한 신규 공식 JAR에서 함께 제공**한다. 기존 `default` 실제 AES 키 및 회귀 벡터는 변경하지 않는다. 두 키는 공개값이며 운영 비밀키가 아니다.

새 Passphrase 공개 기본값의 원문·Salt·KDF는 기존 승인 설계의 고정 상수로 유지한다.

**복호화**

Type을 요구하지 않고 ENC/JCKF의 **Key ID로 해당 키 하나만 선택**한다. 다른 키를 순차 시험하거나 실패 시 공개 키로 fallback 금지. 원래 Key ID가 등록되지 않으면 `KEY_ID_MISMATCH`, 인증 실패는 `INTEGRITY` 등 기존 Reason 사용.


## 3. Keyring·공급원·설정 호환

**한 JAR에서 둘 다**

기본 `pass`·기본 `key`와 추가 사용자 키를 동시에 등록·사용할 수 있어야 한다. 한 유형의 키 추가·변경·삭제가 다른 유형의 키·이력·기존 암호문을 변경하거나 삭제해서는 안 된다.

**선택 규칙**

① Type·ID 미지정 → 설정상 기본 Type(신규 JAR 기본 `pass`)의 활성 키. ② Type만 지정 → 해당 유형의 활성 키. ③ **Key ID만 지정 → ID로 유형 자동 인식**. ④ Type+ID 지정 → 유형 일치 검증. 키 추가 시 기본 키 자동 전환 금지(`--active` 또는 `config key use` 명시). 목록의 첫 키를 암묵적 기본으로 선택하지 않는다.

**기존 AES 호환**

기존 `crypto.key.*`는 기존 AES 슬롯·기존 설정 의미를 유지한다. 이전 형식 JAR/외부 Properties의 AES 암호문·사용자 키를 계속 사용할 수 있어야 한다.

레거시 형식에서 새 Type 항목이 없다고 사용자 지정 AES를 공개 `default`로 대체하면 안 된다. 새 JAR에서는 두 기본 키를 제공한다.

`config embed-key`는 AES만 변경하고 다른 pass/key 프로필을 보존한다(구형 JAR 편집은 기존 형식 호환).

**Key ID**

전체 Keyring에서 고유해야 한다. 공개 기본 ID `default`, `pass-default`는 예약. 다른 키로 ID를 재사용하는 것은 거부한다.

**정확히 같은 기존 키를 복원**하는 경우에만 전체 키 지문·유형·필요한 KDF 메타데이터가 일치함을 검증하고 같은 ID 복원 허용. ID가 다르면 기존 토큰 자동 복호화가 불가능하다는 점을 명확히 안내한다.

재사용 판단 기준은 **그 JAR의 키 목록과 변경 이력**이다(이력의 마지막 키 기록과 유형·64자 전체 지문, pass는 KDF·반복 횟수·Salt 지문까지 비교). 이력이 없는 새 JAR에는 비교할 기록이 없으므로 같은 키인지는 지문·실제 복호화로 확인하도록 안내한다.

**설정 구조**

기존 `crypto.key.*`와 추가 `crypto.keys.<id>.<항목>`을 공존시킨다. 설정 계층 간 키 목록은 합집합이며 외부 설정 추가를 이유로 기존 프로필을 소거하지 않는다.

바깥 계층은 허용된 위치 항목만 덮어쓸 수 있고 `type`·KDF·Salt·내장 키·고정 지문 등 키 정체성을 몰래 바꿀 수 없다.

**설정 전체 목록·값 형식·`-D` 가능 여부는 `SettingCatalog`가 정본**이며 이 파일에 설정 개수를 하드코딩하지 않는다.

**설정 우선순위**

CLI 1회 옵션 > 허용된 JVM `-D` > 외부 Properties > JAR 내부. 외부 설정 경로 직접 지정 > JVM 속성 > 환경변수. 지정된 빈 경로·오타·무효값은 조용히 무시하지 않고 오류. `crypto.jvm.override.enabled` 정책을 `-D`로 우회할 수 없고 비밀 원문 `-D` 공급을 허용하지 않는다.

기존 `-D` 지원과 외부 설정 동작을 보존한다.

**공급원**

`embedded`, `file`, `env`, HashiCorp Vault KV v2, AWS KMS. 둘 다 동일한 Keyring 관리 대상이다.

외부 비밀 공급 실패·지문 불일치·TLS/권한 오류 시 **Fail Closed**; 공개/내장 키로 자동 대체 금지. 신규 프로필의 외부 공급원은 등록 시 정한 전체 지문을 고정하고 변경 시 새 Key ID로 회전한다.

원격 조회·KDF 결과 캐시는 키 프로필·JVM/ClassLoader 격리를 깨지 않게 관리한다.

**Vault**

HTTPS 인증서·호스트 이름 검증 유지, 토큰은 파일·환경변수로만 주입, 리다이렉트·무단 TLS 우회 금지. KV v2의 오류·재시도·타임아웃 처리와 기존 설정 유지. Vault Transit을 임의 추가하지 않는다.

**KMS**

AWS SDK for Java 2.x 선택 설치 구조, 기본 자격증명 체계, 기존 암호화 컨텍스트 `java-crypto-kit:key-id=<키 ID>`와 데이터 키 파일 형식 보존. `pass`는 **파생 AES 키를 기존 KMS 방식으로 보호**한다.

KMS 마스터키 원문 표시·내보내기 기능 추가 금지.

**공개 기본 키 경고**

- 실제 암복호화에 공개 예제 키가 사용되면 공급원과 관계없이 `[WARN] 공개 기본 키 사용 중 (별도 키 설정 권장)` 성격의 안내를 **JVM당 최대 1회**(경고 설정이 켜진 경우)만 출력한다.
- `info`·`doctor`·`fingerprint`·`config show`·`config key show`·Java `keys()` 등 명시적 조회는 자동 경고 없이 상태만 표시. 자동 경고를 다른 이름의 안내로 우회하지 않는다.
- 일반 `fingerprint`와 관리자 인증 뒤의 `config show`·`config history`·`config key show`는 전체 64자리(관리정보 마스킹 없음), 인증 없이 쓰는 `info`·`doctor`와 변경 결과 화면은 단축 지문을 사용한다.


## 4. 생성값 표시·보관·재등록·복구

**자동 생성 원문 표시**

- `pass`·`key`의 모든 자동 생성 경로(`config key add --generate`, 기존 `keygen` 포함)에서 **대화형 콘솔에 별도 `--show` 없이 성공 직후 원문 전체를 딱 한 번 표시**한다.
- `pass`는 실제 Passphrase 문자열, `key`는 32바이트 AES 키의 **표준 Base64 한 줄**(`keygen`·AES 키 파일과 동일). 지문·마스킹·JAR 난독화값을 생성 원문으로 대신 보여주지 않는다.
- 복사할 원문 한 줄에 라벨·공백·중간 줄바꿈을 섞지 않는다.
- `config key add --source aws-kms --generate`(key)도 이 규칙대로 KMS가 만든 데이터 키 원문을 표시한다.
- 기존 AES 전용 `kms datakey`는 이전 형식 계약대로 KMS가 보호하는 데이터 키 파일만 만들고 데이터 키 원문을 표시하지 않는다(복구는 같은 데이터 키 파일과 KMS 키·권한).

**표시 안내**

Key ID(등록된 경우), 유형, 형식, 원문 전체와 함께 “생성값을 별도 보관하세요. 일반 조회·History에서는 원문 재확인이 불가능합니다.” 수준으로 짧게 안내한다. 직접 입력한 Passphrase를 다시 에코하지 않는다.

공개 기본 키의 원문도 일반 조회에서 표시하지 않는다. 등록된 키 원문의 재확인은 §7.1의 `config key show`(관리자 인증 + `SHOW`)로만 한다.

**대화형/자동화 구분**

비밀 원문을 일반 stdout/stderr·로그·CI 결과에 자동 노출하지 않는다. 비대화형에서 보관할 수단 없이 자동 생성하면 **생성·KMS 호출·JAR 변경 전에 실패**한다.

`--export`는 지원하고, 대화형 화면 표시와 파일 저장 동시 사용 가능. 파일은 기존 경로를 덮어쓰지 않고 권한을 제한한다.

**key 재등록**

화면에 보이는 표준 Base64 전체 = `keygen`/`--export`의 AES 키 파일 한 줄이어야 한다. 복사한 값을 UTF-8 한 줄 파일로 보관해 `--from-file`로 재등록할 수 있어야 한다.

기존 Key ID·실제 키가 같으면 기존 ENC/JCKF 암호문도 복호화됨을 **전체 64자리 지문 및 실제 복호화**로 확인한다.

지문 계산식 `SHA-256("java-crypto-kit/key-fingerprint/v1" || 0x00 || 32바이트 키)`와 기존 단축 표시(앞 12자+뒤 8자)는 변경하지 않는다. 지문이나 KMS 암호화 데이터키 파일을 원시 AES 키 파일로 혼동하지 않는다.

**pass 재등록**

화면에 보인 문자열은 새 키 생성에 재사용 가능하지만 **같은 문자열만으로 과거 암호문 복구는 보장되지 않는다**. 원본 JAR이 있으면 `--from-jar`로 Key ID·파생 키·KDF 메타데이터를 이관한다.

원본 JAR이 없어도 복구할 수 있도록 `--export` 백업에 **Passphrase 원문 + Key ID + 원 Salt + KDF·반복 횟수 + 지문**을 보존하고, `--from-file`이 복원 형식을 식별·검증해 과거 암호문을 복호화할 수 있어야 한다.

기존 Passphrase 원문 한 줄 파일도 새 Salt로 신규 등록하는 용도로 계속 지원한다.

**입력 형식**

UTF-8 검증, 기존 파일 크기 상한(key 파일 512바이트, pass 파일 1KiB), 기존 키 파일의 표준 Base64 계약 유지. Windows PowerShell 5.1의 BOM이 복사·재등록을 막지 않도록 **파일 맨 앞 BOM 하나**를 허용하되, 잘못된 실제 키 재료를 추측·자동 수정하거나 원문을 조용히 바꾸면 안 된다(key 파일에 라벨·지문 등이 섞이면 형식 오류로 거부. pass 한 줄 파일은 모든 글자를 Passphrase로 읽으므로 섞인 글자를 탐지할 수 없어 문서로 안내). pass 복원 백업은 머리줄 `# java-crypto-kit pass-key-backup v1`, 항목(key-id·kdf·kdf.iterations·salt·fingerprint·passphrase) 각 1회, Passphrase 1KiB + 메타데이터 512바이트 이내이며, 등록 시 다시 파생한 키의 지문이 백업 지문과 같아야 한다. pass 정규화와 저장 형식·신뢰할 수 없는 백업 데이터 검증은 일관되게 구현한다.

**비밀 보관 범위**

JAR에 Passphrase **원문**을 넣지 않는다(파생 AES 키만 내장 가능, 원문 표시를 위해 가역 저장하지 않음). 일반 조회·History·로그에는 원문이 없어야 한다.

`--export` 복구 파일은 실제 비밀자료이므로 접근 권한·백업·이관 방법을 User Guide에서 상세히 안내한다. 원본 JAR을 가진 사람이 파생 키를 추출할 수 있다는 사실을 숨기거나 '절대 복구 불가능'으로 표현하지 않는다.


## 5. 변경 사유·확인·History

**사유 필수**

독립 생성 `keygen`, `kms datakey`부터 `config key add|use|remove`, `config embed-key`, 키·활성 키에 영향을 주는 `config set`까지 **모든 생성·등록·변경·교체·기본 키 전환·삭제에 `--reason` 필수**(한 줄 1~200자, 비밀값 금지). 대화형에서 빠졌다면 입력 없이 끝나는 검사(옵션·Key ID·경로) 뒤, 재료 입력·생성·KMS 호출·JAR 변경 전에 사유 질문; 비대화형 누락은 실행·외부 호출 전에 오류. 공백 사유 거부. `--yes`는 사유 의무를 면제하지 않는다.

조회·일반 암복호화 등 비변경 작업에는 요구하지 않는다.

**CHANGE 확인**

**실제 키 또는 활성 키/유형 선택이 바뀌면 새 JAR 생성·`--replace` 모두** 변경 전후, 기존 암호문 복호화 영향, 사유를 짧게 표시하고 `CHANGE` 입력을 받는다.

기존 `--yes` 자동 승인 방식 유지. 이전 키가 남아 있으면 과거 암호문도 계속 복호화할 수 있으며, 제거하면 그 JAR에서는 불가능할 수 있음을 정확히 설명한다. 신규 키 등록·프로필 삭제도 비밀값 변경과 별개로 `CHANGE` 확인 대상이다.

키와 무관한 설정 변경에는 확인 절차를 강요하지 않는다.

**원자적 보존**

확인 전 취소·오류·파일 충돌 시 대상/원본 JAR·기존 키·History를 변경하지 않는다.

기존 `--out`·`--replace`·서명/잠금 JAR 거부·백업 및 검증 후 원자적 교체 계약 유지. `config embed-key`는 다른 키 프로필을 자동 삭제하지 않는다.

POSIX에서 CLI가 새로 만드는 결과 JAR·`--replace` 백업은 소유자만(600, 관리자 검증값·사용자 키 포함), `--replace`로 바꾼 운영 JAR는 원래 권한을 유지한다(Windows는 폴더 ACL 상속, 배포 권한은 문서로 안내).

**History 기본 조회**

`config history` = `pass` 이력, `config history --type pass` = pass, `--type key` = key, `--all` = **해당 JAR에 저장된 두 유형, 일반 설정, 관리자 비밀번호 기록(`[관리자]`) 전체 이력**. 관리자 기록을 pass·key로 분류하지 않는다.

조회 자체에 관리자 인증이 필요하다(§7.1). `--all`+`--type` 동시 지정 거부. 이전 형식 기존 AES 기록을 pass로 오분류하거나 불명 항목을 버리지 않는다. 필터링 전에 **전체 해시 체인 무결성을 검증**하고 기존 순번 유지.

**History 내용**

- 작업 UTC 시각·작업자·명령/작업 유형·타입·Key ID·공급원·변경 전후 ID·전체 지문·기본 키 전후·사유·비밀 아닌 KDF 정보(KDF·반복 횟수·Salt·Salt SHA-256). 관리자 인증 뒤 **마스킹 없이** 표시하되 기록에 없는 값(이전 형식의 Salt 줄 등)은 지어내지 않고 `(기록 없음)`으로 구분한다.
- 삭제된 키의 메타 이력도 유지하고, **원문 Passphrase·AES 키·Vault 토큰·관리자 비밀번호·인증 검증값·비밀 백업 내용은 절대 기록하지 않으며** 기존 이력에 비밀값을 소급 추가하지 않는다(키 기록에는 같은 키 복원 확인용 64자 전체 지문·KDF·반복 횟수·Salt의 SHA-256을 남긴다). 외부에서 실제로 발생했는지 관측하지 못한 Vault/KMS 회전을 이력에 남겼다고 주장 금지.

**독립 생성 이력의 경계**

`keygen`·`kms datakey`처럼 JAR이 갱신되지 않는 독립 생성은 사유를 필수 입력받지만, **JAR History에 자동 저장되지 않는다**. 별도 감사 파일/서버는 사용자 승인 없이 만들지 않는다.

생성 화면·User Guide에서 '사유 입력됨'과 '영구 감사 기록됨'을 혼동하지 않는다.

**이력 무결성**

기존 해시 체인·Manifest/설정 지문·구형 이력 읽기·재편집·이관 동작 보존. 자체 수정 탐지 기능을 외부 공격자로부터의 완전한 위변조 방지 감사 시스템으로 과장하지 않는다.


## 6. JAR 데이터 경량 난독화 (보안 기능으로 과장 금지)

**목적·범위**

JAR을 `unzip`/압축 해제해 자원 파일을 열었을 때 **내장 키 값과 변경 이력 본문이 일반 텍스트로 즉시 읽히지 않게** 한다.

`*.embedded` 키 자료(공개 키 포함 가능)와 JAR 내부 `META-INF/java-crypto-kit/config-history.properties` 본문만 대상으로 한다.

Java 소스/클래스 전체 난독화, 안티디버깅, 임의 새 암호 알고리즘, 외부 복원 암호·별도 제품은 도입하지 않는다.

**구현·호환**

- Java 8 표준 기능의 경량 **버전 식별 가능한 가역 난독화**로 저장하되, 복원 로직이 같은 JAR에 있으므로 **기밀성·접근통제·키 추출 방지 수단은 아니다**. 구형 평문 자원 JAR과 신형 난독화 JAR 모두 읽고, 편집 후에는 필요한 엔트리를 난독화 저장. 단, obf1을 읽지 못하는 이전 버전 JAR(코드에 `config.LightObfuscation` 없음)를 새 CLI로 편집할 때는 그 JAR가 계속 동작하도록 기존 형식(표준 Base64 내장 키·평문 이력)으로 쓴다.
- 채택 형식은 `obf1:` + Base64url(패딩 없음)이며, 본문은 [`SHA-256(ASCII("java-crypto-kit/obf1/check") || 0x00 || 원래 바이트)`의 앞 4바이트 + 원래 바이트]를 SHA-256 기반 고정 키 스트림과 XOR한 값이다(이력 파일은 `obf1:` 한 줄). 모르는 버전(`obf<n>:`)·확인값 불일치·형식 오류는 Fail Closed. 기존 실제 키 바이트·Key ID·지문·ENC v1·JCKF v1·이력 해시 체인(복원한 본문으로 계산)은 바뀌지 않는다.

**조회와 회귀**

`config history`, `info`, `doctor`, `fingerprint`, Java API 및 Tomcat은 기존처럼 정상 동작. `unzip -p`/`strings`로 사용자 내장 키 및 고유 History 사유가 그대로 노출되지 않는지 확인. `obf1` 등 실제 채택한 난독화 포맷 표식·버전·체크값의 처리 규칙을 문서·테스트에 일치시킨다.

원본 구형/신형 JAR 수정·재수정과 구형 History 검증을 통과해야 한다. 가벼운 처리의 성능 영향은 필요한 범위에서 실측 보고한다.


## 7. Tomcat·예외·운영 경계

**Tomcat**

기존 JNDI `EncryptedDataSourceFactory` 하나로 공식 DBCP2·Tomcat JDBC Pool을 위임한다. XML Resource의 `cryptoPool`은 정확히 `dbcp2` 또는 `tomcat-jdbc`를 받으며 생략한 경우 유효한 공통 `crypto.pool.factory`를 사용한다. 선택값을 복호화 전에 검사하고 위임 Reference에 전달하지 않는다. `pass`·`key` 암호문 모두 Key ID로 복호화하며 업무 코드 변경 없이 JNDI 접속이 가능해야 한다.

비암호문 비밀번호, 인증 실패, 키 공급 실패에서 평문 fallback 금지. Reference 원본 불변, 하위 Factory 오류의 비밀값·원인 객체 노출 방지. 신뢰할 수 있는 Tomcat Pool Factory만 라이브러리를 로딩한 ClassLoader/부모 체인에서 확인(임의 웹앱 가짜 클래스 로딩 금지).

**이중 JAR 실연동**

동일 Tomcat `lib`에 인프라 전용 JAR A, 웹앱 `WEB-INF/lib`에 다른 키의 JAR B. **각각 `pass`와 `key` 모두 사용**. 전역/Context Resource Factory의 실제 클래스 로딩 위치, 개발자 Java API와 파일, 각 키/지문·설정 격리, 공통 `-D`·환경변수 간섭(재현, 그리고 JAR별 `crypto.jvm.override.enabled=false`로 `-D`를 피하는 방법), 실제 DB 연결·SQL, 교차 복호화 차단을 실행해 확인한다.

Tomcat 클래스 로딩의 예상 결과를 실행 증거 없이 PASS로 단정 금지. 실패해도 패키지 리로케이션·별도 제품 분리는 임의 진행하지 않는다.

**예외·출력**

- 기존 `CredentialCryptoException.Reason`과 CLI/Factory 오류 코드 체계를 유지하고 원인·조치를 한 번만 짧게 알린다(CLI 전용 코드 `ADMIN_SETUP`·`ADMIN_AUTH`·`ADMIN_PASSWORD` 추가, 공개 `Reason`은 그대로). 비밀값·암호문·환경변수 원문·경로 전체·내부 cause/suppressed로 새지 않게 한다.
- 실제 오류를 숨기지 않는다.
- `decrypt`만 성공 시 평문 출력(관리자 인증 뒤), `verify`·`rekey`는 평문 미출력. **키 원문 표시 예외는 둘뿐**: §4의 자동 생성 직후 대화형 콘솔 표시, §7.1의 `config key show --show`(관리자 인증 + 노출 경고 + `SHOW` 정확히 입력, 대화형 콘솔에만)·`--export`(새 파일).


### 7.1 CLI 관리자 비밀번호 (CLI 사용 통제, 보안 기능으로 과장 금지)

**최초 설정 게이트**

배포·빌드 JAR은 미설정 상태다.

명령 목록·기능별 Help·Examples와 전체 Help의 버전 정보는 모든 JAR에서 공개 조회할 수 있다. 조회는 인증·키·설정 내용을 읽거나 외부에 접속하지 않는다. Examples는 안내를 고를 때 JAR 엔트리 이름만 확인할 수 있다. 미설정 JAR에서 실제 기능을 실행하려면 먼저 `admin setup`을 해야 한다(대화형이면 작업자 ID → 새 비밀번호 2회로 바로 설정해 `<이름>-cfg.jar`를 만들고 요청 명령은 실행하지 않음, 비대화형이면 변경 없이 `ADMIN_SETUP`). 공통 기본 비밀번호는 두지 않는다.

설정은 늘 새 JAR이며 실행 중인 JAR·원본은 바꾸지 않는다.

**적용 범위**

**CLI 전용.** Java API(`CredentialCrypto`)·Tomcat `EncryptedDataSourceFactory`는 관리자 검증값을 읽지 않고 미설정·손상과 무관하게 이전과 똑같이 동작한다(서버 기동 중 입력 금지). 관리자 비밀번호는 데이터 키와 별개이며, 바꿔도 키·Key ID·Salt·KDF·암호문·이력이 바뀌지 않고 키를 바꿔도 관리자 비밀번호는 이어진다.

**인증 대상**

- 실행할 때마다 확인 — `decrypt`, `file decrypt`, `rekey`, `keygen`, `kms datakey`, `config show`, `config history`(모든 형태), `config set`, `config embed-key`, `config key add|use|remove|show`, `admin password change`(현재 비밀번호). 묻지 않음(설정만 필요) — `encrypt`, `file encrypt`, `verify`, `fingerprint`, `info`, `doctor`, 도움말. 순서는 사전 검사(인자 형식·옵션 조합·결과 경로·대화형 여부만, 대상 JAR의 키·설정·이력과 키 파일·암호문은 읽지 않음) → 관리자 인증(본 처리 전 한 곳) → 대상 JAR 기준 판단(키 등록 여부·Key ID 충돌 등) → 사유 → 재료·생성·KMS → `CHANGE` → 쓰기이며 인증 실패 시 부작용 0건(인증 전 응답으로 키 등록 여부를 알 수 없음). `--yes`는 관리자 인증·사유를 대신하지 않는다.
- CLI는 민감 명령이 인증 없이 성공하면 실패로 끝낸다(방어적 단언, 누락 방지).

**다른 JAR**

바꾸거나 조회하는 `--jar`, 키를 꺼내 쓰는 `--from-jar` JAR이 관리자 비밀번호를 쓰면 그 JAR의 비밀번호로 따로 확인한다(실행 중인 JAR 인증으로 대체 금지, 같은 비밀번호면 한 번만). 미설정 JAR은 대상 거부. `rekey --to-jar`(암호화만, 변경 없음)는 묻지 않되 손상된 JAR는 쓰지 않는다.

관리자 기능이 없는 이전 형식 JAR은 실행 중인 JAR 인증으로 편집하고 그 JAR에 관리자 정보를 쓰지 않는다(소급 적용을 주장하지 않음).

**비밀번호 규칙**

10~128자, 인쇄 가능한 ASCII만, 영문자(A–Z·a–z)·숫자(0–9)·ASCII 특수문자(32개) 각 1자 이상(대소문자 각각은 요구하지 않음, 공백·비ASCII·제어문자 불가). 최초 설정·변경·비밀번호 파일에 같게 적용하고 위반 항목을 구체적으로 알린다.

최초 설정·변경은 새 비밀번호 2회 일치 확인, 변경은 현재 비밀번호 확인 뒤 현재와 같은 새 비밀번호 거부.

**저장**

- JAR 전용 항목 `META-INF/java-crypto-kit/admin.properties`(설정 아님 → `-D`·외부 Properties로 변경 불가)에 PBKDF2WithHmacSHA256(목적 표지 + 16바이트 보안 난수 Salt, 600,000회, 32바이트) 결과만 둔다.
- 원문·가역·`obf1` 표현으로 비밀번호를 저장하지 않고, 입력은 늘 다시 파생해 일정 시간 비교한다(저장값을 비밀번호로 써도 통과 금지). 다음은 손상으로 CLI Fail Closed(`INTEGRITY`, 실행 중인 JAR·`--jar`·`--from-jar`·`--to-jar` 공통, 관리정보·원문·내보내기·새 JAR 생성 없음): 검증값 형식 손상·모르는 버전·반복 횟수 범위 밖, 검증값은 있는데 이력 없음(이력 삭제)·이력의 관리자 기록이 최초 설정 1건 + 그 뒤 변경이 아님, 이력에 설정 기록이 있는데 항목 없음(삭제 의심), 모든 JAR의 이력 손상(해시 체인·형식·설정 지문). 이력 해시 체인은 키 없는 SHA-256이므로 이 탐지를 위변조 방지 감사로 과장하지 않는다(HMAC·서명·외부 감사 서버는 범위 밖). 관리자 비밀번호·검증값·인증용 Salt는 어떤 조회·이력·로그·오류에도 내보내지 않는다.

**입력**

대화형은 화면 비표시 입력(한 실행 3번, 영구 잠금·계정 잠금 아님). 비대화형은 `--admin-pass-file <파일>`(UTF-8 한 줄, 1KiB, BOM 하나·끝 줄바꿈 하나 허용) 하나로 최초 설정과 민감 명령 인증을 하며 파일 내용을 검증값과 실제로 대조한다.

명령행 인자·환경변수·`-D` 공급 금지, 인증 생략 경로 금지. POSIX에서는 other 읽기·쓰기 권한이 있는 비밀번호 파일을 내용을 읽기 전에 거부한다(600·400, 통제된 그룹 640·440 허용, 심볼릭 링크는 최종 대상 권한). Windows는 검사하지 않고 폴더 ACL로 보호하도록 문서화한다.

`admin password change`는 대화형 전용.

**원문 조회(`config key show`)**

관리정보는 인증 뒤 마스킹 없이 표시. 원문은 명시 요청만: `--show`는 대화형 전용으로 노출 경고 뒤 `SHOW`를 정확히 입력해야 콘솔에만 표시, `--export`는 새 파일(덮어쓰기 금지, 600)에 key는 keygen 한 줄·pass는 복원 백업. pass 원문은 공급원(file·env·vault)에 실제로 보관된 경우에만 다루고, 파생 키만 있는 pass(embedded·aws-kms)는 원문 복원 불가로 안내한다(파생 키에서 복원한다고 안내 금지). 조회는 JAR를 바꾸지 않아 이력에 남지 않는다.

**분실·이전 JAR**

원문 조회·인증 없는 초기화 기능은 만들지 않는다. 비밀번호 변경 뒤에도 이전 JAR은 이전 비밀번호로 열리며 자동 폐기되지 않는다는 점, JAR 복사 시 검증값도 복사된다는 점, 분실 시 키 백업으로 새 JAR에 재등록하는 절차를 User Guide에 정확히 둔다.

**한계 표현**

CLI 인증은 JAR 소지자의 키 추출, 검증값 교체, 같은 JVM 코드의 Java API 호출을 막지 못한다. 이를 키 추출 방지·접근 통제·감사 시스템으로 과장하지 않는다.


## 8. 범용 보안 Java API (범위 동결)

**범위**

`security`(`AesGcm`·`Hmac`·`RequestAuth`·`SecureRandoms`·`Digests`·`Passwords`·`Hkdf`·`Pbkdf2`·`Encoding`·`Bytes`·`Signatures`·`PemKeys`·`Certificates`·`Hotp`·`Totp`·`RsaOaep`·`HybridEncryption`·`KeyStoreReader`), `jwt`(`Jwt`·`JwtKey`·`JwtVerifier`·`Jwks`), `oauth`(`AccessTokenVerifier`·`AccessTokens`·`TokenIntrospector`·`ClientCredentials`)와 그 결과·열거형·예외 클래스. 범위는 동결이며 신규 기능·API·런타임 의존성은 사전 승인 없이 추가하지 않는다(Java 8 표준 기능만). 기술적으로 구현할 수 있다는 이유만으로 추가하지 않고, 실제 활용성·기능 완결성·외부 구현 부담·비용을 먼저 판단한다.

**독립성**

JAR 내장 키·Keyring·설정·`-D`·History·CLI 관리자 비밀번호를 읽거나 바꾸지 않고 History·관리자 인증·`--reason`·`CHANGE`와 연결하지 않는다. 키·정책은 호출자가 주며 넘긴 배열은 바꾸지 않는다.

**상태를 저장하지 않는다**(사용 기록·카운터·폐기 목록·순번·토큰 캐시·자동 재시도·스케줄러는 애플리케이션 몫). 만든 객체는 불변·스레드 안전.

**취소 범위**

영속 시퀀스 기반 ID·범위 할당·공급, Prefix별/일별/월별/연도별 순번 관리, Nonce·OTP 재사용 상태 관리, HOTP 영속 카운터, JWT 폐기 상태 및 결정적 IV용 영속 카운터는 개발하지 않는다. 기존 독립 난수 생성과 외부 연계는 유지한다.

취소 기능의 소스·테스트·현행 문서·배포 산출물 잔재를 제거하되 역사적 증거와 정상 공통 기능은 보존한다.

**알고리즘**

열거형 허용 목록(`AesKeySize`·`Pbkdf2Algorithm`·`HmacAlgorithm`·`DigestAlgorithm`·`SignatureAlgorithm`·`RsaOaepAlgorithm`·`OtpAlgorithm`·`KeyStoreType`·`JwtAlgorithm`)만, 임의 알고리즘 문자열 금지. MD5·SHA-1 해시/서명·DES·ECB·무인증 CBC·RSA PKCS#1 v1.5 암호화·OAEP SHA-1·JWT `none` 금지(SHA-1은 HOTP/TOTP 표준 연동만). 최소 강도: HMAC 새 키 32바이트(기존 외부 비밀 연동 `ofExternalKey`만 예외), RSA 2048비트, EC P-256, JWT HS256 비밀 32바이트, PBKDF2 반복 100,000~5,000,000.

**형식(호환 고정)**

`AesGcm` = `IV(12)‖암호문‖태그(16)`(헤더·Key ID 없음, ENC·JCKF와 별개, AES-128/256). `RsaOaep` = OAEP SHA-256 또는 SHA-512 + 같은 해시의 MGF1, 빈 label. `HybridEncryption` = JCKH v1 `"JCKH"|ver 1|suite 1|N(2바이트 big-endian, 256~1024)|RSA-OAEP-SHA256으로 보호한 메시지별 32바이트 DEK|IV(12)|AES-256-GCM 암호문‖태그`, GCM AAD = 헤더 전체 ‖ uint32(업무 AAD 길이) ‖ 업무 AAD, 평문 64MiB·업무 AAD 64KiB 상한, JWE 아님. `Passwords` = `$pbkdf2-sha256$v=1$i=<반복>$<Salt>$<해시>`(SHA512도 같은 형식). `RequestAuth` 서명 원본 = `"JCK-REQ-AUTH-v1\n"` + 시각 + `"\n"` + Nonce + `"\n"` + 요청 바이트(재전송 방지 없음).

**실패 처리**

복호화 실패는 원인 구분 없이 `INTEGRITY`(키·AAD·변조·DEK 복원 실패가 같은 경로), 형식 오류 `INVALID_TOKEN`, 입력 오류 `IllegalArgumentException`이며 공개 `Reason` 목록은 그대로다.

실패 시 부분 평문·클레임을 돌려주지 않는다. MAC·서명 불일치는 `false`. 오류 문구는 한국어 고정(`core` 번들의 KO·EN 키·자리표시자 동일 유지)이고 키·평문·토큰·비밀번호·경로를 넣지 않는다.

**JWT·OAuth**

- 서명 검증 뒤에만 Payload 해석, kid·알고리즘으로 키 하나 선택(순차 시험 금지), `exp` 필수·허용 오차 기본 0초(최대 300초)·미래 `iat` 거부 기본값을 약화하지 않는다.
- `jku`·`x5u`·`jwk`·`x5c`로 키를 가져오지 않고 JWKS는 호출자가 준 문자열만 쓴다(네트워크·캐시 없음). Access Token은 토큰 종류 조건 없이 대상 일치만으로 통과시키지 않는다(ID Token 오인 방지). OAuth 호출은 `https`만, 리다이렉트 미추종, JDK 호스트명 검증 유지(끄는 기능 금지), 연결·읽기 시간·응답 크기 상한, 고정 길이 스트리밍(JVM 전역 `Authenticator`로 자격 증명이 새지 않게), 토큰·비밀을 URL·로그에 넣지 않는다.

**키 저장소**

`KeyStoreReader`는 읽기 전용(생성·수정·변환 금지), 지정 형식과 파일 앞 표식 확인, 저장소 비밀번호 null 거부, 보호 알고리즘을 약하게 바꾸지 않는다.

**시험·문서**

표준 벡터(RFC·NIST)·독립 구현 교차 확인·변조·경계, 독립 JVM 여러 개의 발급·검증·복호화(`ha.MultiJvmTest`). 예제 `example.SecurityApiExample`·`TokenApiExample`은 컴파일·실행 시험하고 가이드 예제 블록과 글자 그대로 같아야 하며, 공개 타입과 오버로드는 `docs/reference/java-api-reference.md`, 업무별 사용법은 `docs/guide/`에 수록하고 `docs/reference/api-selection.md`에서 해당 절을 연결한다(`DocsConsistencyTest`). Keycloak 실연동은 OAuth 연동의 직접 영향이 있을 때 필요한 범위만 실행하고, 실행하지 않은 인증 서버(Entra ID 등)를 PASS로 보고하지 않는다.


## 9. 문서·UX·검증 게이트

**README**

한국어 제품 소개·업무별 기능·다운로드 안내·지원 환경·문서 탐색을 유지한다. 분량 자체를 제한하지 않는다.

첫 실행 예제는 `docs/guide/cli.md`, `docs/guide/java-encryption.md`, `docs/guide/tomcat-jdbc.md`에서 제공한다. CLI는 관리자 비밀번호 설정부터 시작하며, 기본 `pass`, 명시 `key`, 자동 복호화와 Java API·Tomcat 사용법을 포함한다. 공개 Release 버전과 문서의 소스 버전이 다르면 그 사실을 밝힌다.

상세 사용법과 실행 예제는 가이드에 둔다. README에서 해당 가이드의 실제 절로 직접 연결한다.

**User Guide**

`docs/user-guide.md`는 목차와 탐색 진입점이다. 상세 내용은 `docs/guide/`에 업무 영역별 완결형 가이드로 구성한다. 관련 기능을 같은 문서에 배치하고, 해당 업무의 CLI·Java API 예제와 옵션을 함께 제공한다. CLI 전용 명령과 Java API 전용 기능을 구분한다. 공통 설정·API 규칙은 `docs/reference/`에 둔다. CLI Help에서 인용하는 장·절 번호와 기존 링크 앵커를 보존한다. 공개 오버로드·Builder·결과 객체는 참조 문서에서 인수·기본값·결과를 확인할 수 있어야 하며, 업무 가이드에는 선택 기준과 성공 판정이 있는 예제를 둔다. README와 가이드 목차는 실제 상세 문서에 직접 연결한다. 설명과 명령어집을 중복하지 않는다.

`pass`/`key` 생성·원문 보관·Base64 파일·Passphrase 복원 백업·Salt/KDF 재현·`--from-file`/`--from-jar`·지문 비교·기존 암호문 복구, `--reason`/`CHANGE`, History 타입별 조회, 난독화 한계, 외부 공급원·Tomcat 배포, CLI 관리자 비밀번호(최초 설정·변경·인증 대상·비대화형·분실·한계)와 `config key show`를 자세히 설명. PowerShell과 bash 한 줄 복사 명령, 입력 프롬프트, 기대 결과·오류 해결을 포함한다.

**CLI Help/i18n**

한국어·영어 모두 같은 명령·옵션·메시지, 출력은 간결하고 가독성 있게(가능하면 80열 이내, 불가피한 복사용 명령만 좁은 예외). 상세 배경 설명을 Help에 복제하지 않는다.

CLI에는 Key ID·유형·생성값 전체(생성 시 한정)·변경 사유·기존 암호문 영향이 **정렬되고 직관적으로** 보이게 한다.

**설정 예제·테스트**

기본·예제 Properties, Tomcat DBCP2/JDBC Pool XML, `AGENTS.md`, `DocsConsistencyTest`, JUnit·CI·Docker 하니스와 실제 명령을 동기화. 정적 숫자(설정 개수 등)와 현행과 다른 “PBE 미지원/단일 키/새 JAR 확인 불필요/생성값 출력 금지” 같은 문구를 두지 않는다.

**실제 구현·실행 여부와 문서 주장을 일치**시킨다.

**테스트 분담**

- JUnit에서 AES/Pass KDF 벡터·키 선택·Key ID 충돌·오류·복원·History·변조·i18n·문서 정합성, 관리자 비밀번호(규칙 경계 9/10/128/129자·조합, 최초 설정·변경·실패·취소, 명령별 인증과 부작용 0건, 다른 JAR 인증, 손상 Fail Closed, Java API 무관, SHOW·내보내기·재등록 복구) 등 상세 검증. 기존 CLI 시험은 인증 호출을 기록하는 시험 창구로 명령별 동작과 인증 호출 여부를 함께 확인한다(제품 코드에 인증 생략 구현 금지). 명령 정책(OPEN 목록)과 민감 명령 전체의 인증 실패·부작용 0건 범위는 명령 정의와 대조해 새 명령이 빠지면 실패하게 한다.
- 관리자 상태·이력 손상(삭제·빈 파일·잘림·해시 변조·관리자 기록 규칙·설정 지문)과 인증 전 Key ID 응답 일관성은 `AdminIntegrityTest`, POSIX 권한 시험은 Linux에서 실행한다.
- 실제 이전 버전 바이너리 호환은 `RealLegacyJarTest`(환경변수 `JCK_LEGACY_JAR`에 실제 이전 형식 JAR 경로, 없으면 건너뜀 — JAR는 저장소에 두지 않음)로 확인한다.
- Docker 하니스는 실제 Tomcat+MariaDB, 두 Pool, 단일 JAR 두 방식 및 이중 JAR을 중심으로 실행(단위 검증을 불필요하게 반복하지 않음). 기존 원격 CI 정책은 유지한다.
- 문서만 바뀐 변경은 문서 정합성 시험만 도는 경량 작업을 쓴다. 문서 분리 시 DocsConsistencyTest의 검색 범위·링크 검증을 실제 구조에 맞게 갱신하되, 기존 검증 의미와 코드 예제 검증을 유지한다.
- 기존 전체 통합검증 이후 보완 변경에는 **영향 기반 표적 검증**만 수행한다. 문서 변경은 해당 문서 정합성 검증만 실행하고, 이미 검증한 API·Docker·CLI 명령어집을 다시 실행하지 않는다.
- 먼저 변경 클래스와 직접 영향을 받는 기존 시험을 선택하고, 필요한 컴파일 및 최종 JAR 스모크를 수행한다.
- 무관한 전체 JUnit 매트릭스·CLI 명령어집·교차 구현·Docker 통합시험의 반복 실행은 금지한다.
- Tomcat·공통 암호 엔진·키 포맷 등의 변경으로 실제 영향이 확인되는 경우에만 해당 조합의 검증을 추가한다.
- 전체 릴리스 검증이 필요한 변경은 근거와 범위를 보고하고 사용자 결정에 따른다.
- Vault/KMS 모의시험과 실제 외부 시스템 호출은 구분한다.

**실행 환경·증거**

실제 실행한 OS/JDK/Tomcat/Pool/DB 조합만 PASS 보고. Tomcat 기동만으로 DB 연동 PASS 금지(`getConnection`·SQL 필요). Docker 시험은 시험용 컨테이너·네트워크·볼륨만 정리하고 다른 자원은 건드리지 않는다.

결과 로그·증거에 사용자 비밀값을 남기지 않는다.

**CLI 사용성 QA**

실제 PowerShell/ConPTY와 bash 콘솔 화면에서 관리자 비밀번호 최초 설정·변경·인증 프롬프트, `pass`/`key` 생성·원문 복사·보관 안내, 사유 프롬프트, `CHANGE`, `SHOW`, 키 상태·History·오류의 정렬·줄바꿈·표현을 검수한다.

**실행하지 않은 검사를 PASS로 보고하지 않는다.**


### 독립 API CLI 확장 절차

`CliCommands.Spec`을 사용하는 `ApiCommands`에서 명령 경로·옵션과 `Access`를 등록합니다. `CryptoCli`가 인증을 수행하고 해당 업무 처리 클래스에 전달합니다. 처리 클래스는 기존 공개 API와 `ApiInput`의 검증·입출력을 재사용합니다. 키 목록·History·외부 서버 설정을 통해 비밀을 찾지 않습니다. 단축 명령과 옵션은 `CliCommands`의 등록부에 추가하고, 정규화 뒤 같은 Spec·인증·검증·처리를 사용합니다. 한·영 Help/Examples, 관련 사용 가이드와 정규화·인증 경계 시험을 함께 갱신합니다.

한·영 `cli*.properties`의 명령 도움말과 예제를 추가하고 관련 업무 가이드 및 CLI 목차를 갱신합니다. 등록 옵션, 인증 실패 시 부작용, 예제 연결, 기존 CLI 파서에 영향을 주는 범위를 표적 시험합니다. 비밀 출력은 권한을 제한한 새 파일 또는 `SHOW` 확인을 거친 터미널입니다.

## 10. 변경 통제·완료 보고

**사전 승인 없는 변경 금지**

암호 알고리즘·포맷·최소 Java·공개 API 계약·설정 이름·키 공급원·WAS 어댑터·의존성·제품 산출물 구성·키/History 보안 범위 변경, 신규 기능/API 추가. 충돌 시 실제 소스 위치·재현 방법·보안/호환 영향·최소 대안을 보고한다.

**Git/배포**

사용자 명시 승인 전 `git add`·`git commit`·`git push`·Tag·GitHub Release·브랜치 생성·저장소/프로젝트 이름 변경 금지. 로컬 정본을 변경하는 pull·rebase·reset도 금지한다.

CI는 빌드·시험용이며 릴리스 자동 게시 금지. 공개 릴리스에는 사용자 지정 비밀키/사용자 지정 키 내장 JAR/비밀 백업·토큰을 넣지 않는다. `LICENSE`(Apache-2.0) 원문은 임의 수정하지 않는다.

**완료 보고**

요구별 **구현/미구현/보류**, 실제 수행한 JUnit/JDK/CLI/문서/Docker 결과(PASS/FAIL/미실행), 기존 기능 회귀, 수정 파일, 재현·로그 위치와 남은 위험을 분리해 보고한다. 문서만 고치고 구현 검증을 완료한 것처럼 주장하지 않는다.
