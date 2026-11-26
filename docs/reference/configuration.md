# 설정 사전

[README](../../README.md) · [사용자 가이드](../user-guide.md)

전체 설정명, 기본값, 허용값, 적용 조건.

**목차**

- [10. 설정 사전](#10-설정-사전)
- [10.1 키와 암호화](#101-키와-암호화)
- [10.2 동작과 Tomcat 정책](#102-동작과-tomcat-정책)
- [10.3 Vault KV v2](#103-vault-kv-v2)
- [10.4 AWS KMS](#104-aws-kms)
- [10.5 키 목록 항목](#105-키-목록-항목)

## 10. 설정 사전

독립 `api` 명령의 키·토큰·검증값은 각 명령에서 입력합니다. 아래 설정은 관리형 키를 사용하며 JVM 언어 표시와 별도로 동작합니다. [독립 CLI 입출력](../guide/cli.md#api-cli)

설정 이름·기본값·허용값을 정확히 확인하거나 설정 오류를 고칠 때 봅니다. 두는 곳과 우선순위는 [5.2절](../guide/key-management.md#topic-key-management--52-설정을-두는-곳과-우선순위)에 있고, 실행 중에는 `config help`로 같은 목록을 볼 수 있습니다.

**JVM 옵션을 쓸 때** `-Dcrypto.config.file=<경로>`는 읽을 외부 Properties를 지정합니다. 고정 설정에서 `crypto.key.embedded`의 JVM 전달은 거부되며 `crypto.jvm.override.enabled` 정책 자체를 JVM 옵션으로 바꿀 수 없습니다. 나머지 고정 설정은 정책이 켜져 있을 때 허용된 값으로 덮어쓸 수 있습니다. 키별 프로필은 [위치 항목](#105-키-목록-항목)만 덮어쓸 수 있습니다. `crypto.key.env`와 `crypto.vault.token.env`에 지정하는 것은 환경변수 **이름**입니다.

## 10.1 키와 암호화

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 잘못 쓰면 |
|---|---|---|---|
| `crypto.key.type` | `pass` / `pass`·`key` | 유형·키 ID를 정하지 않은 새 암호화의 유형. JAR 설정에 없으면(이전 형식 JAR) `key` | 다른 값은 오류. 바꾸면 이후 새 암호화의 키가 바뀜(기존 암호문 복호화는 영향 없음) |
| `crypto.key.active.pass` | `pass-default` / 등록된 pass 키의 키 ID | `--type pass`와 기본 유형 pass가 쓰는 키 | 없는 키 ID·key 유형 키면 오류. 다른 키로 바꾸지 않음 |
| `crypto.key.active.key` | 빈 값(= `crypto.key.*` AES 키) / 등록된 key 키의 키 ID | `--type key`가 쓰는 키 | 없는 키 ID·pass 유형 키면 오류 |
| `crypto.key.source` | `embedded` / `embedded`·`file`·`env`·`vault`·`aws-kms` | `crypto.key.*` AES 키를 JAR에 둘지, 파일·환경변수·원격에서 받을지 **공급원 선택** | 외부 키가 없으면 오류(Fail Closed), 내장 키로 자동 전환 없음 |
| `crypto.key.id` | `default` / 영문·숫자·`_`·`-`, 1~64자 | 암호문이 어떤 키로 만들어졌는지 구별. **새 키마다 새 ID** | 암호문의 키ID와 다르면 복호화 실패 |
| `crypto.key.file` | 없음 / 키 파일 경로 | `crypto.key.source=file`일 때 | 파일·권한·Base64 키(32바이트) 확인 |
| `crypto.key.env` | `CRYPTO_KEY` / 환경변수 이름 | `crypto.key.source=env`일 때 WAS에 전달할 변수 이름 | 키 값을 적는 항목이 아님. 서비스 계정 환경에 실제 값 필요 |
| `crypto.key.embedded` | 공개 예제 키 / 32바이트 표준 Base64(44자) | **사용자 지정 키를 JAR에 넣을 때**(`crypto.key.source=embedded`). JAR 내장값은 `config embed-key`로 바꿈. 현행 JAR 내부의 `obf1:` 표현은 CLI에 입력할 키 파일 형식과 다름 | `config set`으로는 못 바꾸고 `-D`는 오류. 외부 Properties에도 둘 수 있으나 키 원문이 파일에 남으므로 비권장(`file`·`env` 권장). 키 원문은 이력·로그·진단에 나오지 않음 |
| `crypto.algorithm` | `AES/GCM/NoPadding`만 | 알고리즘 확인(고정) | 다른 알고리즘 선택 불가 |

## 10.2 동작과 Tomcat 정책

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.lang` | `ko` / `ko`·`en`·`auto` | 메시지 언어. `auto`는 JVM Locale(한국어가 아니면 영어) | 외부 제품(Tomcat·JDBC 드라이버 등) 메시지는 번역하지 않음 |
| `crypto.warning.enabled` | `true` / `true`·`false` | 공개 기본 키를 쓸 때의 WARN 한 줄(공급 방식 무관, JVM당 1회) 출력 여부. 이 경고 하나만 제어 | **`false`여도 오류·FAIL·`info`·`doctor`의 키 상태는 그대로이고 공개 키 위험도 그대로**([12.1절](security.md#121-공개-기본-키-경고)) |
| `crypto.output.encoding` | `enc` / `enc`·`base64` | 암호화 결과를 `ENC[...]` 또는 `B64[...]`로 출력 | `B64[...]`는 ENC의 추가 포장이지 추가 암호화가 아님 |
| `crypto.jvm.override.enabled` | `true` / `true`·`false` | 허용된 `-Dcrypto.*`가 설정을 덮어쓰게 할지 | 이 항목 자체는 `-D`로 바꿀 수 없음. `-Dcrypto.config.file`은 항상 동작 |
| `crypto.pool.factory` | DBCP2 / 공식 Factory 클래스 2종 | XML에서 `cryptoPool`을 생략한 Tomcat Resource의 기본 Pool | 두 Factory 외 임의 클래스 불가 |
| `crypto.require.encrypted.password` | `true`만 | Resource의 평문 DB 비밀번호 거부 | 보안상 `false` 허용 안 함 |

`crypto.pool.factory`의 허용값은 `org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory`(DBCP2, 기본)와 `org.apache.tomcat.jdbc.pool.DataSourceFactory`(Tomcat JDBC Pool)입니다.

XML의 [Resource별 `cryptoPool`](../guide/tomcat-jdbc.md#topic-tomcat--32-dbcp2와-tomcat-jdbc-pool-선택)이 우선합니다. 공통 설정의 유효성 검사는 그대로 적용됩니다.

이 Factory 클래스도 이 라이브러리를 로딩한 클래스로더에서만 찾으므로, 웹앱에 같은 이름의 클래스를 넣어도 쓰이지 않습니다.

## 10.3 Vault KV v2

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.vault.url` | 없음 / HTTPS URL | `crypto.key.source=vault`일 때 Vault 서버 | HTTP·TLS 검증 우회 불가 |
| `crypto.vault.mount` | `secret` / KV v2 마운트 | 마운트가 기본과 다를 때 | KV v1·Transit이 아니라 **KV v2** 경로여야 함 |
| `crypto.vault.path` | 없음 / Secret 상대 경로 | 키가 저장된 Secret 지정 | 403이면 경로 오타도 확인 |
| `crypto.vault.field` | `key` / Secret 필드 이름 | 키를 `key`가 아닌 필드에 저장했을 때 | 기존 AES 슬롯과 key 프로필은 표준 Base64 키, pass 프로필은 Passphrase 문자열 |
| `crypto.vault.ver` | 없음(최신) / 1~999999999, 앞에 0을 붙이지 않음 | 재기동해도 **같은 키**를 받게 버전 고정 | 최신을 읽으면 다음 기동 때 다른 키가 될 위험 |
| `crypto.vault.token.env` | `VAULT_TOKEN` / 환경변수 이름 | 토큰을 환경변수로 줄 때 | **토큰 값을 Properties에 적지 않음** |
| `crypto.vault.token.file` | 없음 / 토큰 파일 경로 | Vault Agent·서비스 계정 전용 파일을 쓸 때 | 지정하면 환경변수보다 우선. 읽기 권한 필요 |
| `crypto.vault.ca.file` | 없음(JVM 신뢰 저장소) / PEM 경로 | Vault가 사설 CA를 쓸 때 | 인증서 검증을 건너뛰는 옵션이 아님 |
| `crypto.vault.timeout.ms` | `5000` / 100~60000 | 네트워크 지연 시 대기 한도 | 시도당 시간. 재시도까지 포함한 총시간 고려 |

## 10.4 AWS KMS

| 설정 | 기본값 / 허용값 | 언제 쓰나 | 주의 |
|---|---|---|---|
| `crypto.aws.region` | 없음(AWS SDK 기본 체계) / 리전 | 키와 리전을 명시적으로 묶을 때 | KMS 키 ARN의 리전과 같아야 함 |
| `crypto.aws.kms.key.id` | 없음 / 키 ID·ARN·alias | **데이터 키를 보호할 KMS 키** | KMS 마스터 키를 반출하지 않음 |
| `crypto.aws.kms.data-key.file` | 없음 / 데이터 키 파일 경로 | `kms datakey`로 만든 파일을 재사용 | 재기동마다 새 데이터 키를 만들면 기존 암호문 복호화 불가 |
| `crypto.aws.kms.timeout.ms` | `10000` / 500~120000 | KMS 호출 전체 대기 한도 | SDK 재시도·인증·네트워크 시간 고려 |

AWS Access Key·Secret Key·Session Token은 **설정 항목이 아닙니다.** IAM 역할 등 AWS SDK 표준 자격증명 체계를 씁니다. 기본 JAR만으로는 KMS가 동작하지 않으며 선택형 SDK 묶음이 필요합니다.

## 10.5 키 목록 항목

키 목록의 키 하나는 `crypto.keys.<키 ID>.<항목>`으로 적습니다.

보통 `config key add`가 만들며, 외부 Properties에 직접 적어 등록할 수도 있습니다(위치 항목만 `-D`·바깥 계층에서 바꿀 수 있음, [5.5절](../guide/key-management.md#topic-key-management--55-키-목록과-유형-선택)). Vault·KMS의 연결 설정(`crypto.vault.url`·토큰·`crypto.aws.region` 등)은 10.3·10.4절의 공통 설정을 씁니다.

| 항목 | 필수·허용값 | 의미 | 바꿀 수 있나 |
|---|---|---|---|
| `type` | 필수 / `pass`·`key` | 키 유형(이 항목이 있으면 등록) | 아니요(정체 항목) |
| `source` | 필수 / `embedded`·`file`·`env`·`vault`·`aws-kms` | 공급원 | 아니요 |
| `embedded` | `embedded`면 필수 / 32바이트 표준 Base64 | 키(pass는 파생한 키). 비밀 항목: 화면·이력에 값이 나오지 않음 | 아니요 |
| `file` | `file`이면 필수 / 파일 경로 | AES 키 파일 또는 Passphrase 파일(UTF-8, Passphrase는 앞 BOM 하나와 끝 줄바꿈 하나 제외) | 예(위치) |
| `env` | `env`이면 필수 / 환경변수 이름 | 키 또는 Passphrase를 담은 환경변수 | 예(위치) |
| `vault.path` | `vault`이면 필수 / Secret 경로 | Vault KV v2 Secret | 예(위치) |
| `vault.field` | 선택 / 필드 이름(비우면 `crypto.vault.field`) | Secret의 필드 | 예(위치) |
| `vault.ver` | 선택 / 1~999999999, 앞에 0을 붙이지 않음(비우면 최신) | Secret 버전 고정 | 예(위치) |
| `aws.kms.data-key.file` | `aws-kms`면 필수 / 데이터 키 파일 경로 | KMS가 보호한 데이터 키(pass는 파생 키) | 예(위치) |
| `kdf` | pass면 필수 / `pbkdf2-sha256` | 키 파생 함수 | 아니요 |
| `kdf.iterations` | pass면 필수 / 100000~5000000(새 키 600000) | PBKDF2 반복 횟수 | 아니요(바꾸면 새 키) |
| `salt` | pass면 필수 / 16바이트 표준 Base64 | 키마다 다른 난수 Salt(비밀 아님) | 아니요(바꾸면 새 키) |
| `fingerprint` | `embedded`가 아니면 필수 / 16진수 64자 | 외부 키의 고정 지문(다르면 Fail Closed) | 아니요 |

key 유형에는 `kdf`·`kdf.iterations`·`salt`를 쓰지 않습니다. 공급원과 맞지 않는 위치 항목을 함께 적으면 의도와 다르게 동작할 수 있으므로 오류입니다.

---

[전체 가이드 목차](../user-guide.md) · [README](../../README.md)
