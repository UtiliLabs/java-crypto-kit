# 오류 해결 및 이전 버전

[README](../../README.md) · [사용자 가이드](../user-guide.md)

오류 코드별 조치, 이전 형식 JAR·설정 호환과 실무 대응.

**목차**

- [9. 운영 변경과 장애 대응](#9-운영-변경과-장애-대응)
- [9.1 키는 그대로, DB 비밀번호만 변경](#91-키는-그대로-db-비밀번호만-변경)
- [9.3 오류 코드별 조치](#93-오류-코드별-조치)
- [9.4 이전 형식 설정·JAR에서 올리기](#94-이전-형식-설정jar에서-올리기)
- [A.14 이전 형식 외부 설정을 그대로 쓰기](#a14-이전-형식-외부-설정을-그대로-쓰기)
- [A.15 자주 보는 오류](#a15-자주-보는-오류)

## 9. 운영 변경과 장애 대응

운영 중 변경은 **키를 유지하는지**부터 정합니다. DB 비밀번호만 바꾸면 `encrypt`, AES 키 자체를 바꾸면 `rekey`가 필요합니다. 명령의 전체 옵션은 [2장](../guide/cli.md#topic-cli--2-cli-명령)에 있습니다.

## 9.1 키는 그대로, DB 비밀번호만 변경

1. **이미 운영 중인 키 내장 JAR**(또는 같은 외부 설정)로 `encrypt`를 실행해 새 DB 비밀번호의 암호문을 만듭니다.
2. 해당 `<Resource password="...">` 값만 바꿉니다(키·키ID는 그대로).
3. Resource를 다시 만들거나 Tomcat을 재시작한 뒤 실제 SQL이 성공하는지 확인합니다.

```powershell
# 입력한 값을 활성 키로 암호화
java -jar .\java-crypto-kit-0.2.1.jar enc
```

키를 그대로 쓰는 비밀번호 변경에는 `keygen`·`config embed-key`·`rekey`가 필요 없습니다.

## 9.3 오류 코드별 조치

**먼저 세 가지를 구분합니다.** `config show`는 **JAR 내장값**, `info`는 **실제 적용값과 출처**, `doctor`는 **설정·키 진단**입니다. **DB 연결 성공**은 WAS의 실제 JNDI 조회와 SQL로 따로 확인합니다.

| 현상·오류 | 흔한 원인 | 우선 조치 |
|---|---|---|
| `ADMIN_SETUP` | CLI 관리자 비밀번호를 설정하지 않은 JAR로 실행함(비대화형), 이미 설정된 JAR에 `admin setup`, 대상 JAR(`--jar`·`--from-jar`)이 미설정, 클래스 폴더에서 CLI 실행 | 배포 JAR로 `admin setup`(비대화형은 `--admin-pass-file`, 작업자 기본 `SYSTEM`) 뒤 같은 JAR로 실행([1.4절](../guide/cli.md#topic-admin--14-cli-관리자-비밀번호)). 설정 직후 "요청한 명령은 실행하지 않았습니다"는 같은 경로의 JAR로 다시 실행 |
| `ADMIN_AUTH` | 관리자 비밀번호 3번 불일치·입력 취소, 비대화형인데 `--admin-pass-file` 없음, 비밀번호 파일 없음·내용 불일치·다른 사용자도 읽을 수 있는 권한(Linux·macOS), 대상 JAR의 비밀번호가 다름 | 비밀번호 확인. 비대화형은 `--admin-pass-file`(한 줄 파일, `chmod 600`). 다른 JAR의 비밀번호가 다르면 대화형으로 실행. 분실은 [12.8절](security.md#128-cli-관리자-인증의-범위와-한계) |
| `ADMIN_PASSWORD` | 새 관리자 비밀번호가 규칙(10~128자, 영문자·숫자·특수문자 각 1자, ASCII만)에 맞지 않음, 두 입력 불일치, 현재와 같음, 3번 실패 | 오류의 위반 항목(예: `특수문자 없음`)을 고쳐 다시 실행([1.4절](../guide/cli.md#topic-admin--14-cli-관리자-비밀번호)) |
| `PLAINTEXT_PASSWORD` | Resource에 평문 비밀번호를 넣음 | 키 내장 JAR로 `encrypt`한 `ENC[...]` 전체로 바꿈 |
| `MISSING_PASSWORD` | Resource에 `password`가 없음 | 암호문 `password="ENC[...]"` 속성 추가 |
| `KEY_ID_MISMATCH` | 암호문의 키ID가 이 JAR·설정의 키 목록에 없음 | `config show`·`info`의 키 목록·이전 JAR·Resource 암호문 비교 |
| `INTEGRITY` | 키가 다르거나 암호문 손상. CLI에서는 JAR 이력 손상(해시 체인·설정 지문), 관리자 비밀번호 검증값 손상·알 수 없는 버전·삭제 의심, 검증값은 있는데 이력이 없거나 관리자 기록이 맞지 않음(실행 중인 JAR·`--jar`·`--from-jar`·`--to-jar` 모두)도 이 코드 | `fingerprint`로 키 비교 후 원본 암호문 대조. 이력·관리자 검증값 손상은 신뢰하는 백업·원본 JAR로 다시 준비([12.8절](security.md#128-cli-관리자-인증의-범위와-한계), Java API·Tomcat은 관리자 검증값과 무관) |
| `KEY_SOURCE` | 파일·환경변수·Vault·KMS 키를 읽지 못함, 외부 키의 지문이 등록할 때와 다름 | **Tomcat 서비스 계정**의 권한·환경변수·TLS·IAM 확인. 지문 불일치는 외부 값이 바뀐 것이므로 원래 값으로 되돌리거나 새 키 ID로 회전([9.2절](../guide/key-management.md#topic-key-rotation--92-키-교체)) |
| `CONFIGURATION`과 `cryptoPool` 안내 | XML Pool 선택 오류 | 대소문자를 포함해 `dbcp2` 또는 `tomcat-jdbc`를 한 번만 지정합니다. 생략하면 공통 기본값을 사용합니다. |
| `POOL_FAILURE` | DB 로그인·Pool 초기화 실패 | 원인 유형의 SQLState(28000 = 로그인 거부), JDBC URL·계정, Pool별 속성 이름, `lib`의 Pool·드라이버 JAR |
| `UNSUPPORTED_RESOURCE` | DataSource가 아닌 JNDI Resource | `type="javax.sql.DataSource"`인지 확인 |
| `CRYPTO_PROVIDER` | JDK 암호화 Provider 오류. 구형 Oracle JDK 8(8u161 미만)의 AES-256 정책 제한이 흔한 원인 | 실제 JDK 버전·보안 정책 확인([11.1절](compatibility.md#111-검증-상태)의 JDK 8 정책) |
| `CONFIGURATION` / `USAGE` | 설정·옵션 이름 오타, 값 누락·형식 오류, 등록되지 않은 키 ID·유형 불일치로 키를 고르지 못함, 잘못된 키 목록 항목 | [10장 설정 사전](configuration.md#10-설정-사전)·[2장 명령](../guide/cli.md#topic-cli--2-cli-명령)·[5.5절](../guide/key-management.md#topic-key-management--55-키-목록과-유형-선택) 확인 |
| `INVALID_TOKEN` / `INVALID_INPUT` | 암호문 형식·경로·크기 오류 | 암호문을 끝까지 복사했는지, 파일 경로·기존 출력 파일 확인 |
| 파일 오류 한 줄에 최초 사유와 임시 파일 삭제 안내가 함께 표시됨 | 공개 전 오류에 정리 오류가 겹침 | 최초 사유 코드로 문제를 진단합니다. 출력 폴더에서 표시된 임시 파일만 삭제합니다. |
| 파일 작업에 `INVALID_INPUT`과 결과 파일 완성 안내가 함께 표시됨 | 최종 파일 공개 후 임시 이름 정리 실패 | 완성된 결과를 보관하고 메시지에 나온 임시 이름만 삭제합니다. [파일 상태별 조치](../guide/file-encryption.md#file-result) |
| `IO_ERROR` | 파일 잠금·권한·경로 | 실행 중인 JAR 교체 여부, 쓰기 권한 확인 |
| JNDI 이름 오류·`NoInitialContextException` | 앱 밖에서 JNDI 호출, Context 등록 오류 | JNDI 이름·앱별 Context·`ResourceLink` 확인 |
| Pool 소진·대기 지연 | 최대 연결 부족 또는 연결 누수 | `maxTotal`/`maxActive`, `maxWaitMillis`/`maxWait`, 앱의 `close()` 확인 |
| 공개된 기본 키 사용 거부 | 공개된 기본 AES 키, 공개된 기본 Passphrase로 파생한 키 또는 외부 공급원의 공개된 기본 Passphrase 선택 | 격리된 환경에서 이전 버전 JAR로 복호화한 뒤 새 키로 다시 암호화 |
| 등록된 키 없음 | 원본 JAR 또는 선택 유형의 활성 키 미설정 | 설정 JAR를 배치하거나 유효한 외부 키 지정 |
| `doctor`의 `[WARN] ... 무시된 -D` | `crypto.jvm.override.enabled=false`라 지정한 `-D`가 적용되지 않음 | 그 `-D`를 지우거나 값을 외부 Properties·JAR 설정에 지정 |

**장애 확인 순서:** (1) 배포한 최종 JAR 확인 → (2) `config show`와 `info`의 값·출처 비교 → (3) `doctor` → (4) Tomcat·DB 로그의 오류 코드와 Pool 종류 확인 → (5) 실제 SQL로 재확인.

티켓·로그에는 비밀번호·키·토큰 전문을 남기지 않습니다. Factory의 비밀값 정제는 DataSource를 만드는 과정에만 적용되며, 앱이 연결을 얻은 뒤 JDBC 드라이버가 내는 오류까지 정제하지는 않습니다.

## 9.4 이전 형식 설정·JAR에서 올리기

| 상황 | 그대로 되는 것 | 바뀐 점·할 일 |
|---|---|---|
| 사용자 지정 키로 만든 기존 암호문 | 외부 설정이나 읽을 수 있는 이전 JAR에서 같은 키 재료와 ID를 공급하면 복호화 가능. 사용자 AES 키를 `default`에 등록했다면 ID만으로 공개 키로 판정하지 않음 | 외부 `crypto.key.*` 또는 기존 `crypto.keys.<ID>.*` 정의를 유지. PASS는 원래 키 ID·파생 키 또는 원 Passphrase·Salt·KDF·반복 횟수를 보존 |
| 공개된 기본 키(AES 키·Passphrase)로 만든 기존 암호문 | 없음(복호화되지 않음). 암호문의 키 ID가 등록되어 있지 않으면 `KEY_ID_MISMATCH`, 그 키 ID로 실제 공급된 키가 차단 대상 공개 키이면 `KEY_SOURCE`로 실패 | 격리된 환경에서 이전 버전 JAR로 복호화한 뒤 새 키로 다시 암호화([12.1절](security.md#121-공개-기본-키-경고)) |
| `crypto.key.*`에 사용자 지정 AES 키를 둔 외부 Properties | `--type key`(Java `KeyType.KEY`)와 `crypto.key.type=key`는 활성 KEY를 선택함 | 외부 AES 키를 기본으로 쓰려면 `crypto.key.type=key`를 설정하고 `crypto.key.active.key`를 외부 키 ID로 맞춤. 해당 키만 쓸 때는 `--key-id <외부 키 ID>` 또는 Java API의 `withKeyId(...)` 사용 |
| 이전 키 내장 JAR | 이전 JAR는 키 조회 및 `rekey --from-jar`의 원본으로 사용. 내부 갱신은 예약 영역이 있는 지원 JAR에서만 가능 | 일반 ID는 대상에서 `config key add --from-jar <이전 JAR> --key-id <ID>`로 이관할 수 있음. `default`·`pass-default`는 신규 등록에 예약되어 있으므로 이미 그 ID로 쓰던 사용자 키는 기존 정의로 읽거나 `rekey`로 새 ID의 키에 이전 |
| `rekey` 자동화 | 대상 유형을 정하지 않으면 **기존 암호문과 같은 유형**의 기본 키로 다시 암호화(AES 암호문 → AES 기본 키) | 유형을 바꾸려면 `--type`·`--key-id` |
| CLI 키 생성·변경 자동화(`keygen`, `kms datakey`, `config embed-key`, 키 관련 `config set`) | 결과 줄의 형식은 같음(사유 등 줄이 추가됨) | 키를 만들거나 바꾸는 명령에는 `--reason`을 붙임(빠지면 아무것도 바꾸기 전에 `USAGE`). `CHANGE` 확인을 받으므로 무인 실행은 `--yes`를 붙임 |
| `config history` | 이전 형식 이력을 그대로 읽고 검증 | 기본 조회가 pass 이력이므로 이전 형식의 `crypto.key.*` 변경은 `--type key`나 `--all`로 봄 |
| CLI 관리자 비밀번호 | 이전 형식 JAR 자체는 관리자 비밀번호를 모르므로 그 JAR로 실행하는 CLI에는 이 규칙이 적용되지 않음(소급 적용 불가). Java API·Tomcat은 버전과 관계없이 비밀번호 없음 | 새 버전 CLI는 먼저 [`admin setup`](../guide/cli.md#topic-admin--222-admin-setup--관리자-비밀번호-최초-설정)으로 설정. 예약 영역이 없는 이전 형식 JAR는 읽기 및 이관의 원본으로 사용. 설정을 마친 새 버전 JAR에서 위의 ID별 이관 절차를 따름. 이전 형식 JAR의 이력은 그 JAR에 그대로 남고 새 JAR에는 이관 기록부터 쌓임. 이관한 뒤 이전 형식 JAR은 관리자 비밀번호 없이 CLI를 쓸 수 있으므로 보관·폐기를 정함 |
| CLI 자동화(스크립트·CI) | 결과 형식은 같음 | 민감 명령(복호화·키 관리·`config show`·`config history` 등)에 `--admin-pass-file <파일>`을 붙이고, 설정된 JAR로 실행 |
| JAR 안 내장 키·이력의 저장 형식 | 이전 형식의 평문 내장 키·이력을 그대로 읽음 | 예약 영역이 있는 JAR를 갱신하면 내장 키와 이력 본문을 `obf1`로 저장([12.7절](security.md#127-jar-내장값의-경량-난독화obf1)) |

올린 뒤에는 `info`의 `기본 유형`·`pass 기본`·`key 기본` 줄과 키 목록으로 새 암호화가 쓸 키를 확인하고, `doctor`로 모든 키가 `PASS`인지 봅니다.

## A.14 이전 형식 외부 설정을 그대로 쓰기

이전 형식의 `crypto.key.*` 설정은 추가 설정 없이 기존 암호문을 복호화합니다. 새 암호화에서 그 AES 키를 기본으로 쓰려면 `crypto.key.type=key`를 설정하고, 다른 활성 KEY가 이미 있으면 `crypto.key.active.key`를 외부 키 ID로 맞춥니다. 명령마다 고르려면 `--key-id`를 사용합니다([9.4절](#94-이전-형식-설정jar에서-올리기)).

```properties
crypto.key.type=key
crypto.key.source=file
crypto.key.id=key01
crypto.key.file=C:/Users/me/jck-secure/example.key
```

```powershell
# 적용된 설정과 활성 키 조회
java -jar .\java-crypto-kit-0.2.1.jar info --config "$SECURE\app.properties"

# 평문 표시 없이 암호문의 무결성 확인
java -jar .\java-crypto-kit-0.2.1.jar verify --config "$SECURE\app.properties" --value 'ENC[v1:key01:...]'
```

```bash
# 적용된 설정과 활성 키 조회
java -jar ./java-crypto-kit-0.2.1.jar info --config "$SECURE/app.properties"

# 평문 표시 없이 암호문의 무결성 확인
java -jar ./java-crypto-kit-0.2.1.jar verify --config "$SECURE/app.properties" --value 'ENC[v1:key01:...]'
```

```text
기본 유형 : key [외부 설정 파일]
key 기본  : key01 [외부 설정 파일]
OK
```

`'ENC[v1:key01:...]'`는 [A.4](../guide/key-management.md#topic-key-selection--a4-운영-aes-키key를-jar에-넣기)에서 key01로 만든 암호문으로 바꿉니다.

## A.15 자주 보는 오류

아래 첫 묶음은 오류 화면을 보여 주려고 일부러 틀리게 적은 **실패 시연**입니다(`'ENC[v1:file-pass:...]'`는 A.6의 `file-pass` 암호문으로 바꿔 실행).

```powershell
# 입력한 값을 활성 키로 암호화
java -jar .\app-aes.jar enc --key-id nope

# 입력한 값을 활성 키로 암호화
java -jar .\app-aes.jar enc --type pass --key-id key01

# 평문 표시 없이 암호문의 무결성 확인
java -jar .\app-pass-v3.jar verify --value 'ENC[v1:file-pass:...]'

# 설정 변경 이력과 작업 사유 확인
java -jar .\use.jar config history --type key --all

# 독립 구성으로 사용할 JAR 복사본 준비
Copy-Item -LiteralPath .\app-pass-v3.jar -Destination reuse.jar

# 키 파일 또는 복원 백업에서 키 등록
java -jar reuse.jar config key add --key-id app-pass --type key --from-file "$SECURE\example.key" --operator example-admin --reason "ID 재사용 시험" --yes
```

```bash
# 입력한 값을 활성 키로 암호화
java -jar ./app-aes.jar enc --key-id nope

# 입력한 값을 활성 키로 암호화
java -jar ./app-aes.jar enc --type pass --key-id key01

# 평문 표시 없이 암호문의 무결성 확인
java -jar ./app-pass-v3.jar verify --value 'ENC[v1:file-pass:...]'

# 설정 변경 이력과 작업 사유 확인
java -jar ./use.jar config history --type key --all

# 독립 구성으로 사용할 JAR 복사본 준비
cp ./app-pass-v3.jar reuse.jar

# 키 파일 또는 복원 백업에서 키 등록
java -jar reuse.jar config key add --key-id app-pass --type key --from-file "$SECURE/example.key" --operator example-admin --reason "ID 재사용 시험" --yes
```

```text
[java-crypto-kit] [사유: CONFIGURATION] ... 키 ID nope에 해당하는 PASS (Passphrase) 또는 KEY (AES Key) 프로필이 없습니다. ID와 설정을 확인하세요.
[java-crypto-kit] [사유: CONFIGURATION] ... 키 ID key01는 key 유형 키입니다(--type pass와 다름). 조치: ...
[java-crypto-kit] [사유: KEY_ID_MISMATCH] 암호문의 키 ID에 해당하는 PASS (Passphrase) 또는 KEY (AES Key) 프로필이 없습니다. 원래 키 ID와 키 재료를 사용하세요.
[java-crypto-kit] [사유: USAGE] --type과 --all은 함께 쓸 수 없습니다(--type: 그 유형, --all: 전체).
[java-crypto-kit] [사유: USAGE] 키 ID app-pass은(는) 이 JAR의 변경 이력(config history)에서 다른 키에 쓰였습니다(다른 항목: 유형, 키 지문). 같은 키를 되살릴 때만 다시 쓸 수 있으니 새 키에는 새 --key-id를 지정하세요.
```

키 선택 오류는 평문을 묻기 전에 끝나고, 이력에 쓰인 키 ID에 다른 키를 넣으려 하면 JAR를 바꾸지 않습니다. 아래는 스크립트·CI(대화형 터미널 아님)에서 실행했을 때의 실패 시연입니다.

모두 관리자 인증 실패나 키 생성·JAR 변경 전에 끝납니다(첫 줄은 비밀번호 파일 없음, 나머지는 A.1의 비밀번호 파일로 인증한 뒤의 오류).

```powershell
# JAR에 저장된 키 목록과 설정 조회
java -jar .\use.jar config show

# 새 AES-256 키 생성
java -jar .\java-crypto-kit-0.2.1.jar keygen --out "$SECURE\ci.key" --admin-pass-file "$SECURE\admin.pw"

# 독립 구성으로 사용할 JAR 복사본 준비
Copy-Item -LiteralPath .\java-crypto-kit-0.2.1.jar -Destination ci.jar

# 현재 JAR에 키 프로필 등록
java -jar ci.jar config key add --key-id ci-pass --generate --operator example-admin --reason "CI 키" --yes --admin-pass-file "$SECURE\admin.pw"

# 독립 구성으로 사용할 JAR 복사본 준비
Copy-Item -LiteralPath .\use.jar -Destination use2.jar

# 등록한 키를 해당 유형의 기본 키로 지정
java -jar use2.jar config key use --key-id gen-pass --operator example-admin --reason "CI 전환" --admin-pass-file "$SECURE\admin.pw"
```

```bash
# JAR에 저장된 키 목록과 설정 조회
java -jar ./use.jar config show

# 새 AES-256 키 생성
java -jar ./java-crypto-kit-0.2.1.jar keygen --out "$SECURE/ci.key" --admin-pass-file "$SECURE/admin.pw"

# 독립 구성으로 사용할 JAR 복사본 준비
cp ./java-crypto-kit-0.2.1.jar ci.jar

# 현재 JAR에 키 프로필 등록
java -jar ci.jar config key add --key-id ci-pass --generate --operator example-admin --reason "CI 키" --yes --admin-pass-file "$SECURE/admin.pw"

# 독립 구성으로 사용할 JAR 복사본 준비
cp ./use.jar use2.jar

# 등록한 키를 해당 유형의 기본 키로 지정
java -jar use2.jar config key use --key-id gen-pass --operator example-admin --reason "CI 전환" --admin-pass-file "$SECURE/admin.pw"
```

```text
[java-crypto-kit] [사유: ADMIN_AUTH] config show은(는) 관리자 비밀번호 확인이 필요합니다. 조치: 대화형 터미널에서 실행하거나 --admin-pass-file <파일>을 지정하세요.
[java-crypto-kit] [사유: USAGE] keygen에는 사유가 필요합니다. --reason "<사유>"를 지정하세요(대화형 터미널에서는 물어봅니다).
[java-crypto-kit] [사유: USAGE] 비대화형 실행에서는 생성값을 화면에 보여 줄 수 없어 --generate에 --export <파일>이 필요합니다. 생성 전에 중단했습니다.
[java-crypto-kit] [사유: USAGE] 키 변경은 확인이 필요합니다. 대화형 터미널에서 CHANGE를 입력하거나 --yes를 지정하세요(도움말: config key use --help). JAR는 바뀌지 않았습니다.
```

관리자 비밀번호와 관련된 오류는 다음과 같습니다(코드별 조치: [9.3절](#93-오류-코드별-조치)).

```text
[java-crypto-kit] [사유: ADMIN_SETUP] 이 JAR(java-crypto-kit-0.2.1.jar)은 관리자 비밀번호가 설정되지 않아 CLI 기능을 쓸 수 없습니다. 조치: ...
[java-crypto-kit] [사유: ADMIN_AUTH] 관리자 비밀번호가 맞지 않습니다(3번 실패). 아무것도 하지 않았습니다. 분실했다면 사용자 가이드 12.8을 보세요.
[java-crypto-kit] [사유: ADMIN_AUTH] --admin-pass-file 파일의 관리자 비밀번호가 맞지 않습니다. 아무것도 하지 않았습니다.
[java-crypto-kit] [사유: ADMIN_AUTH] --admin-pass-file 파일을 다른 사용자도 읽거나 쓸 수 있습니다(권한 rw-r--r--). chmod 600 <파일>로 소유자만 읽게 한 뒤 다시 실행하세요. 아무것도 하지 않았습니다.
[java-crypto-kit] [사유: ADMIN_PASSWORD] 새 관리자 비밀번호를 정하지 못했습니다(3번 실패, 마지막: 두 입력이 다릅니다.). 아무것도 바꾸지 않았습니다.
[java-crypto-kit] [사유: INTEGRITY] 관리자 비밀번호 검증값이나 변경 이력을 신뢰할 수 없어 CLI를 멈췄습니다: 관리자 비밀번호 검증값은 있는데 변경 이력이 없습니다(이력 삭제 의심). Java API·Tomcat은 영향을 받지 않습니다. 조치: ...
```

---

[전체 가이드 목차](../user-guide.md) · [README](../../README.md)

<a name="api-cli-errors"></a>
### 독립 보안 API CLI의 오류

| 상황 | 확인 방법 |
|---|---|
| `USAGE` | 지정한 명령의 `--help`에서 인증·필수 옵션·배타 옵션을 확인합니다. |
| `INVALID_INPUT` | 파일 형식과 지정 인코딩, 알고리즘, 데이터 길이·키 길이를 맞춥니다. |
| stdout의 `FAIL` (종료 1) | MAC·서명·해시·OTP가 일치하지 않거나 검증한 JWT/OAuth 토큰이 거부됐습니다. 토큰 거부 사유 코드는 stderr에 표시됩니다. |
| JWT·OAuth 토큰 거부 | `KEY_NOT_FOUND`는 키·kid, `SIGNATURE`는 키와 서명, `EXPIRED`는 만료, `SCOPE`는 권한을 확인합니다. |
| 보호 파일 권한 오류 | 표시된 실제 옵션(`--in`, `--key-file` 등)의 POSIX other 읽기·쓰기 권한을 제거합니다. |
| OAuth 상태 조회 한도 | 16,384자(ASCII 16 KiB) 이내에 발급된 토큰을 사용합니다. 로컬 JWT의 64 KiB 한도와 구분합니다. |
| OAuth `CLIENT_AUTH`, `TIMEOUT`, `TLS`, 응답 오류 | 서버 상태 및 오류 코드를 보고 권한·TLS 신뢰 저장소·시간 제한을 확인합니다. |
| 결과 파일 저장 실패 | 새 파일 이름과 상위 디렉터리 접근 권한·하드 링크 지원을 확인합니다. |

[독립 CLI 입출력·인증](../guide/cli.md#api-cli)
