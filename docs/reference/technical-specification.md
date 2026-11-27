# Java Crypto Kit 기술 명세

이 명세는 v0.2.1의 실행 경계, 공개 동작, 영속 데이터 규격 및 호환성 유지 기준을 정의한다. 도입과 실행은 [사용자 가이드](../user-guide.md), 메서드와 오버로드는 [Java API Reference](java-api-reference.md#api-members), 설정값은 [설정 사전](configuration.md#10-설정-사전)을 기준으로 찾는다.

| 필요한 정보 | 바로가기 |
|---|---|
| 실행 경계와 코드 책임 | [1. 아키텍처](#architecture) |
| 기존 암호문·파일과의 호환 | [2. 암복호화 포맷](#formats) |
| 키 선택, 외부 저장, 회전 및 복구 | [3. Keyring과 설정](#keyring) |
| 관리자 설정, 이력과 JAR 편집 | [4. JAR 상태와 저장 포맷](#jar-state) |
| Java 동작과 인증 프로토콜 | [5. 보안 API](#java-security) · [6. 토큰·OTP·요청 인증](#authentication) |
| 명령, 실제 실행과 배포 | [7. CLI](#cli) · [8. 외부 연동](#integrations) · [9. 운영·배포·유지보수](#maintenance) |
| 기능별 근거와 호환 검증 설계 | [10. 요구사항 추적](#traceability) · [11. 교차 호환 검수](#interop) |

<a name="architecture"></a>

## 1. 아키텍처

| 진입점 | 처리 흐름과 책임 | 상태 및 인증 |
|---|---|---|
| 관리형 CLI | `cli.CryptoCli` → `CliCommands` → `core.CryptoService` 또는 JAR 편집·키 관리 명령 | 실제 실행 전 JAR 상태 확인, `ADMIN` 명령은 추가 인증 |
| 독립 `api` CLI | `CryptoCli` → `ApiCommands` → `ApiInput` → `ApiCrypto`·`ApiUtilities`·`ApiAuth`·`ApiOAuth` → 공개 API | CLI 게이트 사용. 관리형 Keyring 대신 입력으로 키·정책을 제공 |
| 관리형 Java API | `CredentialCrypto.fromDefaultConfiguration()` 또는 `CredentialCrypto.fromConfigFile(Path)` → `CryptoService` → `CryptoSettings`·`KeyResolver` → `KeyProvider` | 호출 시 스냅샷의 설정·키 사용. CLI 관리자 정보와 이력에 독립 |
| 직접 주입 Java API | `CredentialCrypto.fromRawKey`·`fromPassphrase` → `CryptoService` → ENC/JCKF. `security`·`jwt`·`oauth`는 호출자가 자료와 정책을 주입 | 키 복사본을 보유하는 직접 구성 또는 개별 호출. 관리형 설정·키·이력에 독립 |
| Tomcat JNDI | `jdbc.tomcat.EncryptedDataSourceFactory` → 관리형 복호화 → 선택한 Tomcat Pool Factory | CLI 인증 없이 WAS 기동. JNDI Resource와 허용된 Factory로 위임 |
| 키 공급원 | `io.javacryptokit.key`의 고정 공급원 등록부 → 키 자료 읽기·파생·지문 확인 | 프로필별 정책, 원격 공급 실패 시 호출 실패 |

공통 엔진은 `core.Gcm`, `core.Kdf`, `json.StrictJson`으로 유지한다. `config.SettingCatalog`는 설정 범위와 허용값, `i18n.Messages` 및 번들은 표시 언어, `SecretFiles`는 보호 파일과 안전한 파일명 표시를 담당한다. 업무 요청 데이터와 관리자 인증 자료는 서로 다른 경로와 수명으로 관리한다.

<a name="formats"></a>

## 2. 암복호화와 호환 데이터 포맷

표와 수식에서 `||`는 바이트 연결, `u8/u16/u32/u64`는 해당 비트 수의 부호 없는 빅엔디언 표현, `LF`는 `0x0a`, `NUL`은 `0x00`이다. `B64U`는 URL 안전 Base64를 패딩 없이 쓰는 표현이다. `C || T`는 GCM 암호문 뒤에 인증 태그를 연결한 값이다.

<a name="enc-v1"></a>

### 2.1 ENC v1과 B64 포장

| 항목 | 바이트 및 판정 규칙 |
|---|---|
| 봉투 | `ENC[v1:<id>:<B64U(IV)>:<B64U(C \|\| T)>]`. 대소문자 구분, 네 필드, ID는 ASCII `[A-Za-z0-9_-]{1,64}` |
| 암호 | AES/GCM/NoPadding, 키 32바이트, 매 호출 난수 IV 12바이트, 태그 16바이트 |
| AAD | `ASCII("v1:" + id)`. ID와 버전을 인증하며 외부 업무 AAD는 받지 않음 |
| 원본 | 텍스트는 엄격한 UTF-8, 바이너리는 바이트 그대로. 빈 원본도 GCM 태그 포함 |
| 크기·파싱 | ENC 16,384자 이하. 쓰기는 패딩 없는 정규 표현. 읽기는 JDK Base64URL 디코더를 사용해 문자와 길이를 검사하고 IV 12바이트 및 `C \|\| T` 16바이트 이상을 요구 |
| B64 | `B64[<B64U(ASCII(ENC))>]`. 상한은 `5 + ceil(16384 × 4/3)` 문자. 외부 표현도 정규 Base64URL 및 엄격 UTF-8을 요구하며 내부 ENC 포장 1회만 허용 |
| 실패 | 구문·길이 오류 `INVALID_TOKEN`, 선택 ID 불일치 `KEY_ID_MISMATCH`, 태그 불일치 `INTEGRITY`. 유효한 바이너리의 텍스트 디코딩 실패는 `INVALID_INPUT` |

관리형과 직접 주입 `CredentialCrypto` 모두 위 포맷을 공유한다. 같은 ID·실제 AES 키가 필요하다. 키 유형·Salt·반복 횟수는 봉투에 들어가지 않는다. 길이 제한은 입력 바이트 수와 ID에 따른 포장 길이를 반영한다. 공개된 기본 AES 키로 만든 고정 벡터는 `TokenCodecTest`와 `ApiUsageExampleTest`가 포맷 확인에 사용한다.

```text
ENC[v1:default:fiwaaeeeILgco85o:-uFGHK3H0eqZKIfj3MZhRG3cr9gLeQCjYJ7UHFdWCg4f4982fNx8]
```

<a name="jckf-v1"></a><a name="jckf-v2"></a>

### 2.2 JCKF 파일과 버전 호환

신규 관리형·직접 주입 파일 암호화는 JCKF v2를 쓴다. 복호화는 헤더의 버전 바이트로 v1 또는 v2를 한 번 선택한다. 지원하지 않는 버전은 거부하며 인증에 실패했을 때 다른 포맷을 다시 시도하지 않는다.

```text
fixed     = ASCII("JCKF") || u8(version) || u32(65536) || u8(id_length)
v2_header = fixed(version=2) || ASCII(id) || file_id[16]
v1_header = fixed(version=1) || ASCII(id)
record    = u8(flag) || IV[12] || ciphertext[plaintext_length] || tag[16]
AAD       = header || u64(record_index) || u8(flag)
```

| 필드 | 규칙 |
|---|---|
| Key ID | ASCII `[A-Za-z0-9_-]{1,64}`이며 `id_length`는 ID만 센다 |
| v2 파일 식별자 | 암호화 작업마다 SecureRandom으로 새 128비트 값을 생성한다. 헤더에 평문으로 기록하고 모든 청크의 AAD에 포함한다 |
| 레코드 번호와 IV | 번호는 0부터 증가하며 레코드 최대 개수는 마지막을 포함해 `2^32 − 1`이다. 각 IV는 별도 12바이트 난수 |
| `flag=0` | 중간 레코드는 65,536바이트의 평문을 암호화한다 |
| `flag=1` | 마지막 레코드는 EOF까지 0~65,536바이트를 암호화한다. 길이가 65,536의 배수인 파일은 마지막 전체 청크에 `1`을 지정한다. 빈 파일은 길이 0의 마지막 레코드 하나를 쓴다 |

헤더의 magic·버전·청크 크기·ID·필수 필드 길이를 검사한 뒤 ID로 키 하나를 정한다. 형식 오류는 `INVALID_TOKEN`, 키 ID 불일치는 `KEY_ID_MISMATCH`, 청크 인증 실패나 잘림·추가 데이터는 `INTEGRITY`로 처리한다. v2에서 파일 식별자가 바뀌거나 다른 파일의 청크가 섞인 경우에는 태그를 통과하지 못한다. 청크 순서 변경·중복·마지막 표시 위반도 검증한다. 각 청크의 인증이 끝난 평문만 접근 제한 임시 파일에 쓰고 EOF까지 검증·저장한 뒤 최종 이름을 확보한다. [공개·복구 계약](#file-io)

v1은 해당 파일을 구분하는 식별자 없이 헤더를 인증한다. 같은 키의 다른 v1 파일에서 온 청크를 파일 단위로 구분하지 못하므로 출처와 무결성이 별도로 확인된 경우에만 기존 파일을 복호화해 새 경로에 v2로 다시 암호화한다. v1 전용 프로그램은 신규 v2를 읽을 수 없다. v2 식별자는 서로 다른 파일의 레코드를 구분한다. 외부에서 어떤 완성된 파일을 기대했는지 증명하는 기능은 호출자에게 속한다.

합성 예제는 키 ID `x`, 파일 식별자 `000102030405060708090a0b0c0d0e0f`, 빈 입력을 가정한다.

```text
v2 header = 4a434b4602000100000178000102030405060708090a0b0c0d0e0f
v2 AAD    = 4a434b4602000100000178000102030405060708090a0b0c0d0e0f000000000000000001
v1 header = 4a434b4601000100000178
v1 AAD    = 4a434b4601000100000178000000000000000001
```

각 헤더 뒤에는 마지막 표시 `0x01`, 난수 IV 12바이트, 인증 태그 16바이트가 이어진다. 이전 배포 JAR로 생성한 v1 원본의 고정 벡터는 `FileCipherTest.readsLegacyV1FilesFromPreviousReleaseArtifact`에서 확인할 수 있다.

<a name="direct-crypto"></a>

### 2.3 Raw AES, RSA-OAEP, JCKH

| API | 데이터 표현과 경계 |
|---|---|
| `AesGcm` | AES128/256의 16/32바이트 키, 난수 IV 12바이트, 출력 `IV \|\| C \|\| T`, T 16바이트. 업무 AAD는 선택이고 복호화 시 동일한 바이트 필요. `null` AAD는 비어 있는 AAD와 동일. 결과에 키 ID나 파생 설정을 넣지 않음. 텍스트 API는 UTF-8과 지정 `Encoding` 사용 |
| `RsaOaep` | RSA 2048비트 이상. 모듈러스 바이트 `k=ceil(bits/8)`, 최대 평문 `k−2×hLen−2`, 출력 `k`바이트. OAEP SHA-256 기본 또는 SHA-512, 같은 해시로 MGF1, 비어 있는 레이블. RSA 2048에서 190/126바이트. 암호문 길이 오류 `INVALID_TOKEN`, 잘못된 키·OAEP 검증 실패 `INTEGRITY` |
| `HybridEncryption` | RSA-OAEP SHA-256으로 난수 32바이트 데이터 키를 래핑하고 AES-256-GCM으로 본문 암호화. RSA 모듈러스 표현 256~1,024바이트, 암호화 평문 64MiB 이하, 업무 AAD 64KiB 이하. 호출별 데이터 키·IV 생성. 구조 오류 `INVALID_TOKEN`, 키 래핑/태그/AAD 불일치 `INTEGRITY` |

```text
JCKH_header = ASCII("JCKH") || u8(1) || u8(1) || u16(N) || wrappedKey[N] || IV[12]
JCKH        = JCKH_header || C || T[16]
AAD         = JCKH_header || u32(aad_length) || aad
```

첫 `1`은 버전, 다음 `1`은 RSA-OAEP SHA-256/AES-256-GCM 조합이다. `null` 업무 AAD의 길이는 0이다. 읽기는 래핑 길이와 고정 필드를 확인하며 전체 봉투의 범위는 `8+256+12+16`부터 `8+1024+12+64MiB+16`까지다. 암호화 입력 상한과 전체 수신 봉투 상한의 단위가 다르다. RSA 2048이면 앞 8바이트가 `4a434b4801010100`이다. 항목별 메서드와 Encoding은 [암호화 API](java-api-reference.md#api-encryption)를 따른다.

<a name="pass-kdf"></a>

### 2.4 Passphrase 파생

| 사용처 | 알고리즘·Salt·출력 | 보관 및 검증 |
|---|---|---|
| 관리형 `pass` | PBKDF2-HMAC-SHA256(`pbkdf2-sha256`), Salt 16바이트, 600,000회 기본, 허용 100,000~5,000,000회, AES 32바이트 | 정규화한 Passphrase로 파생. 원래 ID·Salt·반복·알고리즘 및 전체 지문 보관 |
| `CredentialCrypto.fromPassphrase` | HMAC-SHA256 또는 SHA512, Salt 16~64바이트, 100,000~5,000,000회, AES 32바이트 | 지정 메타데이터로 직접 키를 만든 후 동일 ENC/JCKF 계약 사용 |
| `Pbkdf2.deriveKey` / `AesGcm.fromPassphrase` | 같은 KDF 범위. 일반 파생 16~64바이트, Raw AES는 16/32바이트 | `newSalt()`는 16바이트 난수. Raw 암호문에 Salt/파생 파라미터 미포함 |
| `Passwords` | 별도의 검증용 포맷과 검증 전용 반복 규칙 적용 | [비밀번호 저장 계약](#passwords) 참조 |

공통 문자 처리는 NFC와 UTF-8이다. 빈 값, 공백만인 값, 제어문자와 비정상 유니코드를 거부하며 정규화한 UTF-8의 상한은 1,024바이트다. 파일 제공자의 파일 크기 제한과 개별 자료의 정규화 후 길이 제한을 모두 적용한다. 관리형 `PassKdf` 캐시는 로딩한 ClassLoader 내부에 있으며 ID·Salt·반복 횟수·정규화 원문의 조합으로 분리된다. 독립 API는 관리형 캐시를 조회하지 않는다.

<a name="keyring"></a>

## 3. Keyring, 설정 및 키 생명주기

| 입력 선택 | 암호화에 사용하는 프로필 |
|---|---|
| Type·ID 생략 | 설정상 기본 유형의 활성 키. 신규 배포의 기본 유형은 `pass` |
| Type만 지정 | 해당 유형의 활성 ID |
| ID만 지정 | 등록된 ID로 유형과 키 결정 |
| Type·ID 함께 지정 | 등록 유형과 지정 유형의 일치 확인 후 사용 |
| 복호화 | 암호문의 ID를 조회하고 일치하는 키 하나 사용. 미등록이면 `KEY_ID_MISMATCH` |

- `crypto.key.*`의 AES 슬롯과 `crypto.keys.<id>.*` 키 프로필을 함께 읽는다. 계층별 키 목록은 합집합이다. 지정한 AES 슬롯을 다른 프로필이나 공개된 기본 키로 대체하지 않는다.
- 키 ID `default`와 `pass-default`는 예약 ID로 등록할 수 없다. 배포 원본의 내장 AES 슬롯과 활성 pass ID는 비어 있고 키 프로필은 0개다. 명시한 유형·ID로 외부 키만 사용하는 경우에도 다른 기본 유형으로 전환하지 않는다.
- 최초 설정은 CSPRNG로 128비트 ID 두 개, 독립 AES-256 키, 32자 난수 Passphrase와 16바이트 Salt를 생성한다. pass 파생은 PBKDF2-HMAC-SHA256 600,000회다. 각 ID는 유형 접두사와 소문자 Hex 32자리로 구성한다. 최초 설정은 배포 JAR와 동일 경로를 갱신하며, 이후 SHA-256이 공식 배포본과 다른 것이 정상이다.
- 키 지문은 `lowerhex(SHA-256(ASCII("java-crypto-kit/key-fingerprint/v1") || NUL || aes_key))` 64자다. 단축 표시는 앞 12자와 뒤 8자다. 명시 조회는 자동 경고 없이 상태를 반환한다. 관리형 공급원이 키를 반환하기 전에 실제 키의 SHA-256이 공개된 기본 AES 키의 SHA-256과 같으면 KEY_SOURCE로 거부한다. 직접 키 주입에는 적용하지 않는다.
- ID 재사용은 기존 기록의 전체 지문·유형과 `pass`의 KDF·반복·Salt 지문이 모두 일치할 때 허용한다. 새 JAR에 비교할 과거 기록이 없으면 전체 지문과 실제 복호화로 확인한다. 새 키 등록이 활성 키를 자동 전환하지 않는다. AES 슬롯의 `config set crypto.key.id`도 같은 ID·이력 복원 검사를 거친다. 슬롯 ID 변경을 History에 기록하고 읽을 수 있는 키의 전체 지문을 남긴다. 같은 ID의 활성 공급원·재료 선택 설정을 바꾸면 후보의 유형·전체 지문을 이력과 대조한다. 지문이 있는 슬롯의 키를 목록으로 이관할 때도 이 조건을 적용한다. 이력 지문이 없는 레거시 슬롯과 실행 시 외부 설정은 기존 규칙을 따른다. 이전 키와 원래 ID를 보존하면 해당 ID의 기존 토큰을 복호화할 수 있다. 제거 후 복구에는 같은 ID·실제 키가 필요하다.

### 3.1 설정 해석과 공급원

```text
허용된 CLI 1회 설정 > 허용 JVM -D > 외부 Properties > JAR Properties
외부 설정 경로       > 명시 --config > -Dcrypto.config.file > CRYPTO_CONFIG_FILE
```

`crypto.jvm.override.enabled`로 JVM 오버라이드를 제한한다. 기존 ID·타입·키 재료·KDF·고정 지문 등 프로필의 정체성을 외부 계층에서 임의 재정의할 수 없다. 허용되는 위치·일반 설정의 목록과 값 검사는 [설정 사전](configuration.md#10-설정-사전) 및 `SettingCatalog`가 기준이다. 빈 값이 명시된 경로, 알 수 없는 설정과 형식 오류는 진단한다. 비밀 원문은 `-D` 입력으로 받지 않는다.

파일·환경변수·Vault에서 읽은 관리형 Passphrase는 NFC 정규화 후 `PassKdf.isPublicPassphrase()`로 검사한다. 공개된 기본 Passphrase는 Salt·반복 횟수·고정 지문에 관계없이 파생 전에 거부한다. 직접 키 주입과 독립 API에는 관리형 정책을 적용하지 않는다.

| 공급원 | 자료 및 검증 |
|---|---|
| `embedded` | AES 32바이트의 표준 Base64 또는 [JAR obf1](#jar-obf1). `pass`는 파생 AES 키만 내장. 기존 AES 슬롯은 기존 설정명 사용 |
| `file` | `key`는 512바이트 이내의 표준 Base64 한 줄, `pass`는 1KiB 이내의 UTF-8 원문. 앞 BOM 하나와 파일 줄 끝 계약은 [키 관리](../guide/key-management.md) 참조 |
| `env` | 변수 이름을 설정하고 `key`는 표준 Base64, `pass`는 UTF-8 원문을 읽음 |
| `vault` | Vault KV v2에서 지정 필드 문자열을 읽어 `key`는 표준 Base64, `pass`는 파생용 원문으로 사용 |
| `aws-kms` | 보호된 데이터 키 파일을 KMS로 복구해 32바이트 AES 자료 사용. `pass`는 파생 AES 키를 KMS로 보호 |

키 자료 오류·원격 접속 실패·프로필 고정 지문 불일치는 해당 키 요청의 실패다. 다른 프로필이나 공개 키를 대체 조회하지 않는다. 원격 키 성공 결과는 `CryptoService` 인스턴스의 프로필 ID로 캐시하며 복사본을 반환한다. 설정이나 키를 바꾼 경우 적용하려는 스냅샷을 다시 로드한다. 관리형 `file`/`env` 조회와 암호화 키의 정확한 기능별 경계는 [키 관리](../guide/key-management.md)와 [외부 키 공급원](../guide/external-key-providers.md)을 따른다.

### 3.2 생성, 이전 및 복구

- 최초 설정 외에 명시적으로 요청한 관리형 자동 생성은 대화형 콘솔에서 원문 한 줄을 한 번 표시한다. `key`는 표준 Base64, `pass`는 Passphrase 원문이다. 비대화형에서 필요한 보관 대상이 없으면 생성·KMS 호출 전에 중단한다. `--export`는 새 보호 파일을 만들며 기존 파일을 덮어쓰지 않는다. 독립 `kms datakey`는 보호된 데이터 키 파일을 만들고 원시 데이터 키를 표시하지 않는다.
- `--reason`은 관리형 생성·키 변경에 필요한 한 줄 1~200자다. JAR 자체가 바뀌는 변경은 작업자와 이력을 남긴다. 사유와 `CHANGE` 확인은 실제 키·키 선택 및 프로필 변경 경계에 배치하고 `--yes`는 확인만 대체한다. `keygen`·`kms datakey`의 사유는 대상 JAR 이력에 자동 저장되지 않는다.
- `key`의 표준 Base64를 같은 ID로 재등록하면 기존 암호문을 복구할 수 있다. `pass`의 원문 한 줄 등록은 새 Salt를 만든다. 기존 데이터 복구는 원본 JAR에서 `--from-jar`로 동일 파생 키·메타데이터를 옮기거나 원래의 복구 파일을 써야 한다.
- `pass` 복구 파일의 첫 줄은 `# java-crypto-kit pass-key-backup v1`이다. `key-id`·`kdf`·`kdf.iterations`·`salt`·`fingerprint`·`passphrase` 항목이 각 한 번 필요하다. Passphrase 최대 1KiB와 메타데이터 512바이트 제한 및 다시 파생한 키의 지문 검증을 적용한다. UTF-8에 앞 BOM 하나를 허용하며 헤더 다음의 빈 줄·`#` 주석을 건너뛴다. 첫 `=`의 오른쪽을 값으로 읽으므로 Passphrase 안의 `=`는 유지한다. `kdf`는 `pbkdf2-sha256`, `salt`는 16바이트의 패딩 포함 정규 표준 Base64, `fingerprint`는 64자리 소문자 Hex다. 전체 복구 절차는 [키 관리](../guide/key-management.md)를 따른다.
- `config key show`의 원문은 명시 `--show` 뒤 콘솔의 `SHOW` 확인 또는 `--export`로만 요청할 수 있다. 내장·KMS `pass`처럼 파생 키만 있는 원본에서는 Passphrase를 복원할 수 없다. 백업 파일과 키 내장 JAR는 비밀 자료와 같은 권한으로 보관한다.

<a name="jar-state"></a>

## 4. 관리자 인증, History 및 JAR 편집

<a name="admin-verifier"></a>

### 4.1 CLI 관리자 상태와 검증값

`AdminPassword.statusOf`는 먼저 History와 설정 무결성을 검증한다. 관리자 클래스 표식이 없는 JAR는 이 확인 후 관리자 기능이 없는 JAR로 처리한다. 관리자 기능이 있는 JAR는 검증 엔트리와 최초 설정 기록이 둘 다 없으면 미설정이다. 설정 완료 상태는 유효한 관리자 엔트리와 `admin setup` 한 건에 이은 0건 이상의 `admin password change`를 요구한다. 검증값이나 이력만 삭제되거나, 검증값 형식·이력·상태가 어긋나면 실제 CLI 작업에서 `INTEGRITY`로 중단한다.

| 필드 | 예약 영역의 관리자 검증값 저장 계약 |
|---|---|
| 파일 | ASCII, 최대 4,096바이트, `name=value` 줄. LF로 쓰고 읽을 때 CRLF도 허용. 빈 줄과 `#` 주석을 제외하고 아래 항목은 각각 정확히 한 번 |
| `format.version` | `1` |
| `kdf` | `PBKDF2WithHmacSHA256` |
| `kdf.iterations` | 십진수, 생성 600,000, 읽기 허용 100,000~5,000,000 |
| `salt` | 난수 16바이트를 표준 Base64로 저장 |
| `verifier` | 파생 결과 32바이트를 표준 Base64로 저장 |

```text
effective_salt = ASCII("java-crypto-kit/cli-admin-password/v1") || NUL || salt
verifier       = PBKDF2-HMAC-SHA256(password, effective_salt, iterations, 32)
```

입력을 다시 파생해 `MessageDigest.isEqual`로 비교한다. 비밀번호는 인쇄 가능한 ASCII 10~128자이며 영문·숫자·특수문자를 각각 포함하고 공백은 허용하지 않는다. 최초 설정은 새 비밀번호 2회(작업자 기본 SYSTEM, --operator 선택), 변경은 현재 비밀번호 인증과 다른 새 비밀번호 2회를 요구한다. 대화형 인증은 숨김 입력으로 실행당 3회까지 허용한다. 변경은 대화형 전용이다. 보호된 `--admin-pass-file`은 UTF-8 한 줄, 파일 전체 1KiB, 앞 BOM 하나와 끝 LF 또는 CRLF 하나를 허용한다. 비밀 원문을 옵션 값·환경변수·`-D`로 받지 않는다.

현재 JAR 인증과 별개로 `--jar`·`--from-jar`의 대상이 관리자 기능을 쓰면 대상 검증값으로 확인한다. 동일 입력이 대상 비밀번호에도 일치하면 재입력은 생략할 수 있다. 미설정·손상 대상은 거부한다. `rekey --to-jar`는 복호화키를 꺼내는 작업이 아니므로 대상 인증을 묻지 않으며 대상 무결성은 확인한다. 예약 영역이 없는 대상은 읽기와 키 이관의 원본으로 지원한다. 내부 변경은 예약 영역이 있는 지원 JAR에 적용한다. 공개 Help·Examples·버전 조회, Java API, Tomcat의 실행 경계가 이 검증값과 독립이다.

<a name="history"></a>

### 4.2 History 저장 및 해시 체인

최초 설정은 verifier·두 키·활성 선택·이력 한 건을 같은 JAR에 기록한다. 기존 관리자 단일 요약과 신규 관리자 요약 + pass·key 생성 지문 기록을 모두 읽는다. 관리자 비밀번호 변경은 기존 키 설정 바이트를 보존한다. 선택한 `--pass-export`는 3.2의 기존 복원 형식을 사용한다.

History의 논리 형식은 UTF-8 Properties 본문이다(엔트리 이름 `META-INF/java-crypto-kit/config-history.properties`). 예약 영역이 있는 JAR는 현재 History를 `obf1` 표현으로 ZIP 로컬 헤더 예약 영역의 프레임([4.4절](#44-jar-내부-예약-영역-갱신))에 저장하며, 같은 이름의 JAR 엔트리는 배포 원본 그대로 둔다. 예약 영역이 없는 JAR는 그 엔트리 본문을 읽으며 `obf1:` 표시가 없는 평문 본문도 읽는다. 저장 입력 2MiB, 복원 본문 1MiB 상한을 적용한다. 기본 설정 및 수정 후 설정의 지문은 `"sha256:" + lowerhex(SHA-256(설정 엔트리 원본 바이트))[0:16]`이다. Properties 값만 정렬하거나 재직렬화해서 지문을 계산하면 일치하지 않는다.

| 위치 | 필드와 의미 |
|---|---|
| 문서 전역 | `format.version=1`, `build.time`, `base.version`, `base.settings`, `change.count` |
| 마지막 항목의 요약 | `last.modified`, `last.operator`, `last.command`, `last.keys`, `head.hash` |
| `entry.<n>.` | `time`(UTC ISO-8601, 쓰기 초 단위), `operator`, `command`, `reason`, `keys`, `settings`, `hash` |
| 항목별 변경 | `before.<key>`와 `after.<key>`. `keys`의 쉼표 목록 순서대로 기록하며 해시 단계에서 다시 정렬하지 않음 |
| 허용 명령 | `set`, `embed-key`, `key add`, `key use`, `key remove`, `admin setup`, `admin password change` |
| 작업자·이름 | 작업자 `[\p{L}\p{N}._@-]{1,64}`, 변경 이름 `[A-Za-z0-9._-]{1,80}` |

```text
previous = base.settings           # 첫 항목
previous = entry.<n-1>.hash        # 후속 항목
row       = key || NUL || before || NUL || after || LF
payload   = previous || LF || time || LF || operator || LF || command || LF
            || reason || LF || row[0] || ... || row[k-1] || settings
hash      = lowerhex(SHA-256(UTF-8(payload)))
```

`n`은 1부터이고 `settings` 뒤에 LF를 넣지 않는다. 해시는 Properties를 **읽은 값**에 대해 계산한다. 쓰는 줄의 값에서 역슬래시는 두 번, 맨 앞 공백은 역슬래시로 보호하고 LF로 줄을 끝낸다. `reason`이 없는 항목은 빈 문자열을 사용한다. 첫 `previous`는 배포 Manifest의 `Settings-Fingerprint`와 대응하는 `base.settings`다. 이력이 없고 Manifest 지문이 있으면 현재 설정 지문과 비교한다. 이력이 있으면 포맷, Manifest 기준값(있는 경우), 개수, 1부터 이어지는 항목 해시와 변경 값 연쇄, 추가 항목 표식, 최종 해시와 시각·작업자, 실제 설정의 최종 지문 순으로 확인한다. 전체 검증 후에만 유형별 필터를 적용한다.

- 비밀은 `[none]`, `[secret]`, `[replaced]` 표식으로만 추가·교체·삭제를 기록한다. 관리자 기록은 `admin.password` 한 행이며 최초 설정은 첫 표식에서 둘째, 변경은 둘째에서 셋째로 간다.
- `key.<id>` 요약은 `name=value` 항목을 세미콜론으로 잇는다. 기록 순서는 `type`, `source`, `origin`, `slot=yes`, `public=yes`, `kdf`, `iterations`, `salt-sha256`, `fingerprint`이고 값이 없으면 생략한다. 요약의 Salt 지문은 원본 Salt의 SHA-256 64자리다. 설정 변경 행에 기록 가능한 키 파생 Salt 메타데이터와 구별한다. 기록에 없는 값을 새로 추정해 쓰지 않는다.
- `config history`는 기본 `pass` 이력, `--type key`는 AES 슬롯을 포함한 `key` 이력을 반환한다. `--all`은 일반 변경·관리자 항목을 포함하며 `--type`과 배타다. 양쪽에 영향을 주는 변경은 조회 양쪽에 나타날 수 있다. 원래 순번을 유지한다.
- 체인은 키 없는 SHA-256이다. 파일이 없거나 일관성이 깨진 경우의 탐지와 JAR 전체에 다시 쓸 수 있는 주체의 위조 가능성을 구분한다. 영구 외부 감사 기록으로 사용하려면 별도의 신뢰 경계가 필요하다.

<a name="jar-obf1"></a>

### 4.3 JAR obf1

```text
check = SHA-256(ASCII("java-crypto-kit/obf1/check") || NUL || data)[0:4]
block[i] = SHA-256(ASCII("java-crypto-kit/obf1/pad") || NUL || u32(i))
body = (check || data) XOR prefix(block[0] || block[1] || ..., 4 + len(data))
value = "obf1:" + B64U(body)
```

`i`는 0에서 시작하며 32바이트 블록마다 1 증가한다. JAR 내장 키 값에는 이 문자열을 사용하고 History 엔트리는 같은 ASCII 문자열 뒤에 LF 하나를 쓴다. 복원은 접두어 식별 → URL 안전 Base64 디코딩 → 4바이트 이상 확인 → 같은 패드로 XOR → 도메인 구분 체크 재계산 순이다. 형식 오류·체크 불일치·인식한 미지원 버전은 거부한다. 읽기는 JDK URL 디코더를 사용한다. 내장 키는 `obf[0-9]{1,3}:` 접두어를 식별하고, History는 원본 바이트의 처음에서 `obf` 뒤 1~4자리 숫자와 콜론을 식별한 다음 ASCII 문자열의 끝 줄바꿈을 제거한다. `obf` 표식이 없는 자료는 표준 Base64 키 및 평문 History로 처리한다. 예약 영역이 없는 JAR는 읽기와 키 이관에 사용한다. 변환은 실제 AES 키·ID·해시 대상 이력 본문을 바꾸지 않으며 이 표현의 목적은 압축을 풀었을 때 즉시 읽히는 것을 줄이는 데 있다. 패드와 복원 로직은 공개되어 있다.

| 합성 입력 | 체크값 | 첫 패드 7바이트 | 출력 |
|---|---|---|---|
| `4a434b` | `37318eb3` | `85d01c3c061f5c` | `obf1:suGSj0xcFw` |

<a name="jar-edit"></a>

### 4.4 JAR 내부 예약 영역 갱신

Java 8 표준 I/O로 동일 파일을 갱신한다. Manifest의 JCK-State-Format=1과 META-INF/jck-state/ 운반 엔트리를 사용한다. ZIP 로컬 헤더의 0x4a43 extra field 본문만 쓰기 대상으로 삼는다. 매니페스트, ZIP 디렉터리, 클래스, 리소스 본문 및 CRC는 그대로 유지한다.

선택자 1바이트와 A/B 두 영역으로 구성한다. 영역당 60 KiB 세그먼트 39개(2,396,160바이트)다. 프레임은 SHA-256 32바이트, 빅 엔디언 길이 세 개, 설정·History·관리자 검증 바이트 및 0 패딩으로 구성한다. 기존 설정 256 KiB와 History 저장 2 MiB 및 관리자 검증값의 상한을 수용한다. Passphrase 원문은 저장하지 않는다.

명령은 인증 스냅샷의 SHA-256을 배타적 파일 잠금 아래 다시 확인한다. 비활성 영역을 쓰고 디스크 동기화 및 읽기 대조를 마친 뒤 선택자를 발행하고 동기화한다. 이전 영역은 0으로 지우고 다시 동기화한 뒤 성공을 반환한다. 발행 전 중단은 이전 상태, 발행 후 중단은 새 상태를 사용한다. 발행 후 정리 전 강제 종료의 경우 다음 승인된 갱신이 미사용 영역을 마저 덮어쓴다. 선택된 영역이 손상되면 실패 처리한다. 다른 영역을 복구 후보로 사용하지 않는다. 파일시스템의 스냅샷이나 물리 저장장치의 과거 사본 제거를 보장하지 않는다.

최초 설정 시 POSIX 권한 600을 사용한다. Windows는 원래 파일 ACL을 사용한다. 서명·동시 변경·쓰기 권한 부족·저장 상한 초과는 안전하게 실패한다. 예약 영역이 없는 JAR는 읽기·암호문 사용·키 이관의 원본으로 지원하며, 그 파일에는 새 저장 영역을 만들지 않는다.

<a name="java-security"></a>

## 5. 공개 Java 보안 API

[Java API Reference](java-api-reference.md#api-members)의 타입별 목록이 공개 시그니처, 오버로드와 결과 타입의 정본이다. 여기서는 결과를 저장하거나 다른 구현과 교환할 때 필요한 의미를 정의한다.

| 영역 | 입력·출력 및 검증 | 참조 |
|---|---|---|
| `CredentialCrypto`·`KeyInfo`·`KeyType` | 관리형 또는 직접 주입 상태와 [ENC/JCKF](#formats)를 사용. `verify`는 토큰 오류는 false, 설정·공급원 오류는 예외. `keyIdOf`는 포맷에서 ID를 읽고 인증 여부를 증명하지 않음 | [관리형·Tomcat API](java-api-reference.md#api-managed) |
| `Hmac` | HMAC-SHA256/512, 일반 대칭키 최소 32바이트. 기존 연동 전용 `ofExternalKey`는 1바이트 이상. 입력 바이트 순서를 유지하고 문자열은 UTF-8. 완전한 32/64바이트 MAC을 일정 시간 비교 | [무결성 API](java-api-reference.md#api-integrity) |
| `Digests`·`Bytes` | SHA-256/512. 파일 해시는 64KiB 버퍼 스트리밍, 문자열은 UTF-8. 해시는 기대 해시를 신뢰할 수 있을 때 비교용으로 사용. `Bytes`의 엄격 UTF-8과 일정 시간 비교·배열 지우기를 재사용 | [데이터 무결성](../guide/data-integrity.md) |
| `Encoding` | Hex는 두 자리씩 소문자로 쓰고 대·소문자를 읽음. Base64는 표준 알파벳의 정확한 패딩 형식을 쓰고 읽음. URL판은 URL 안전·무패딩 출력, 읽기는 정확한 패딩 또는 무패딩 정규 표현 허용. Base32는 `A–Z2–7` 무패딩 출력, 읽기에서 대소문자와 유효 패딩을 허용하고 남는 비트 확인 | [보안 유틸리티](../guide/security-utilities.md) |
| `SecureRandoms` | 바이트 1~65,536, 보안 토큰 16~1,024바이트(기본 32), Nonce 난수 16바이트를 Base64URL, UUID v4. 문자열 길이 1~1,024는 접두사 제외 무작위 부분으로 사용자·내장 알파벳에서 균일 선택. 난수의 절대 유일성은 보장 범위 밖 | [난수 API](java-api-reference.md#api-utilities) |
| `Pbkdf2`·`Hkdf` | PBKDF2는 [파생 계약](#pass-kdf). HKDF 기본 HMAC-SHA256 또는 SHA512. IKM은 비어 있지 않아야 한다. 추출 `PRK=HMAC(salt, IKM)`. 비어 있거나 `null` Salt는 해시 길이만큼의 0. 전개 `T(0)=empty`, `T(i)=HMAC(PRK,T(i−1) \|\| info \|\| u8(i))`. `info` 미지정은 빈 바이트, 문자열은 UTF-8. PRK 최소 해시 길이, 출력 1~255×해시 길이 | [KDF API](java-api-reference.md#api-utilities) |
| `Signatures`·`PemKeys` | RSA PKCS#1 v1.5 SHA-256 또는 P-256 ECDSA SHA-256. RSA 생성 기본 3072, 최소 2048. RSA 서명은 모듈러스 길이, ECDSA는 DER `SEQUENCE(INTEGER r, INTEGER s)`. 개인키 PKCS#8, 공개키 SubjectPublicKeyInfo, PEM 또는 DER. 키 파일 상한 64KiB. PKCS#1·SEC1·암호화 PEM은 변환이 필요 | [서명 API](java-api-reference.md#api-integrity) |
| `Certificates`·`KeyStoreReader` | 인증서 X.509 PEM/DER 최대 1MiB, 메타·SHA-256 지문·선택 시각 유효성 조회. 파싱·유효기간 확인과 호출자 신뢰 앵커를 쓰는 PKIX 검증은 별개. PKCS12/JKS 명시 형식, 최대 16MiB, 읽기 전용 alias·키·인증서 체인 조회. 저장소/항목 비밀번호와 JDK Provider 호환을 따름 | [인증서와 키 저장소](java-api-reference.md#api-certs) |
| `Hotp`·`Totp`, JWT·JWKS, OAuth, `RequestAuth` | [토큰·OTP·요청 인증 계약](#authentication)의 검증 순서와 판정을 따른다 | [인증 가이드](../guide/authentication.md) |

<a name="passwords"></a>

### 5.1 애플리케이션 비밀번호 저장

```text
$pbkdf2-sha256$v=1$i=<iterations>$<standard-base64-salt-no-pad>$<standard-base64-dk-no-pad>
$pbkdf2-sha512$v=1$i=<iterations>$<standard-base64-salt-no-pad>$<standard-base64-dk-no-pad>
```

생성에는 새 16바이트 Salt, 기본 SHA256 600,000회, SHA512 권장 210,000회, 생성 허용 100,000~5,000,000회를 사용한다. 결과 32/64바이트와 Salt를 그림의 형식에 맞춘다. 기존 문자열은 길이 256자 이하, Salt 16~64바이트, 반복 1,000~5,000,000회 및 알고리즘 일치 길이를 확인한다. 파생 전에 형식과 상한을 검증하고 일정 시간 비교한다. 해시 가능한 비밀번호가 다르거나 비밀번호 내용이 규칙에 맞지 않으면 `verify`는 false를 반환한다. 저장 문자열이 손상됐거나 비밀번호 인자가 null이면 입력 오류다. `needsRehash`의 목표 반복 횟수는 신규 해시와 같은 100,000~5,000,000회다. 올바른 목표 정책에서 알고리즘 변경 또는 저장 반복 횟수가 목표보다 낮으면 참을 반환한다. 애플리케이션은 일치 확인 후 새 해시로 교체할 수 있다. JAR의 [관리자 검증 엔트리](#admin-verifier)는 별개의 저장 포맷이다.

<a name="authentication"></a>

## 6. JWT, OAuth, OTP 및 요청 인증

<a name="jwt"></a>

### 6.1 JWT/JWKS

- `UTF-8 JSON header`와 `UTF-8 JSON claims`를 각각 B64U 한다. 서명 입력은 `ASCII(header_segment + "." + claims_segment)`, 최종 형식은 `header_segment.claims_segment.B64U(signature)`다. HS256은 HMAC-SHA256 키 32바이트 이상, RS256은 RSA 2048비트 이상과 PKCS#1 v1.5 SHA-256, ES256은 P-256 SHA-256이다. ES256 JOSE 서명은 32바이트 빅엔디언 `r`과 `s`를 왼쪽 0으로 채워 잇는 64바이트 표현이다. JCA DER ECDSA와 교환할 때 길이·정수 표현을 검증한다.
- 입력 전체 65,536자, 세 구간 모두 비어 있지 않고 무패딩 Base64URL 정규형, 엄격 UTF-8/JSON을 사용한다. `StrictJson`은 중복 멤버를 거부하고 JOSE 제한(깊이 16, 객체당 멤버 1,000, 배열당 원소 10,000, 문자열 65,536, 숫자 표기 64자)을 적용한다. 생성 시에도 자동 `iat`·`exp` 등을 포함한 최종 헤더·페이로드에 같은 상한을 적용한다. `alg`는 지원 목록으로 제한한다. `crit`·`b64`가 있는 형태, `none`·JWE·중첩 JWT는 지원하지 않는다. `typ`의 기본 허용은 생략 또는 `JWT`이며 정책으로 지정할 수 있다.
- 신뢰 키는 호출자 입력으로만 결정한다. `kid`는 인쇄 ASCII 최대 256자이며 허용 알고리즘과 일치하는 신뢰 키 하나를 선택한다. 같은 ID를 반복 등록하거나 키 없는 선택이 모호하면 거부한다. 토큰의 `jku`·`x5u`·`jwk`·`x5c`로 키를 읽지 않는다. `Jwks`는 제공한 JSON에서 최대 100개의 공개 키 후보를 읽고 RSA/P-256·사용 목적·알고리즘과 필드를 검증한다. 대칭·개인 키 자료와 자체 URL 조회는 JWKS 처리에 포함되지 않는다.
- 서명 확인 후 등록 Claim의 타입과 정책을 적용한다. `exp`·`nbf`·`iat`의 NumericDate는 기본적으로 0~253402300799 범위의 정수 초만 허용한다. Java 검증기에서 `JwtVerifier.Builder.allowFractionalTimes(true)`를 설정하면 같은 범위의 유한한 소수 초도 허용한다. ClockSkew는 기본 0초, 허용 0~300초의 정수다. 만료, 아직 유효하지 않음, 정책상 필수 `iat`와 미래 발급, issuer·subject·audience·필수/일치 Claim 및 typ 정책을 검증한다. `aud`는 문자열 하나 또는 문자열 배열을 읽고 설정한 대상과 대조한다. `inspect`는 구조·내용을 읽을 수 있으나 업무상 권한 증명으로 쓰려면 신뢰 키로 검증해야 한다. [검증 정책과 예제](../guide/authentication.md#api-jwt) · [JWT Builder 및 결과](java-api-reference.md#api-jwt)

<a name="oauth"></a>

### 6.2 OAuth 네트워크 호출과 로컬 접근 토큰

| 경로 | 요청 또는 판정 규칙 |
|---|---|
| `ClientCredentials` | HTTPS POST, `application/x-www-form-urlencoded`의 `grant_type=client_credentials`와 선택 `scope`(공백으로 연결). Basic 기본은 UTF-8 폼 인코딩한 ID와 Secret을 `:`로 잇고 표준 Base64를 붙인다. Post는 폼에 `client_id`·`client_secret` 사용. 성공은 비어 있지 않은 `access_token`과 대소문자를 무시한 `Bearer` 타입 필요. 선택 `expires_in`은 0 이상 정수(최대 10×366일), 선택 scope는 문자열 |
| `TokenIntrospector` | HTTPS POST, Basic만 사용. `token`과 선택 `token_type_hint`를 폼 인코딩. 토큰 1~16,384문자, 힌트 `[A-Za-z0-9_]{1,64}`. `active`는 JSON boolean 필수. `false`는 정상 응답이며 false 이외의 응답 필드는 결과에서 제거. `true`에서 대표 표준 Claim 타입을 검증하며 호출자가 추가 권한을 판단 |
| `AccessTokens`·RFC 9068 프로파일 | 로컬에서 서명/검증. `typ=at+jwt`, 필수 `iss exp aud sub client_id iat jti`, 서명·시간·정확한 issuer와 대상 audience 적용. 응용 정책에 필요한 `scope`·`roles`를 지정 가능 |
| `AccessTokenVerifier` 설정형 | 실제 제공자의 Claim 명칭·typ·issuer·audience·필수/값 일치/금지 Claim을 명시. 요구한 scope/roles가 모두 있어야 하고 지정 시 권한 Claim을 필수로 요구. `scope` 토큰과 `roles` 요소를 이름 단위로 비교. JWT 서명 및 기본 시간 검증을 우회하지 않음 |

두 HTTP 기능은 JVM 신뢰 저장소 또는 명시 `SSLContext`를 쓰고 기본 호스트명을 검증한다. HTTPS만 허용하고 사용자 정보가 들어간 URL과 리다이렉트를 거부한다. 연결/읽기 기본 5초/10초, 최소 1ms, 최대 60초/120초, 응답 기본 64KiB(1KiB~1MiB)다. 요청·응답은 엄격 인코딩·JSON을 사용하며 인증, HTTP 상태, TLS, Timeout, 응답 크기/형식, 알려진 OAuth 오류 코드를 구분한다. 발급 단계의 응답 크기 내에서 얻은 토큰도 16KiB를 초과하면 Introspection에 보내지 않는다. 64KiB JWT 상한은 로컬 JWT 구문·검증 경계다. 로컬 `oauth create`와 `verify`에는 HTTP 연결이나 Timeout이 없다. [OAuth 사용법](../guide/authentication.md#api-oauth) · [OAuth API](java-api-reference.md#api-oauth)

<a name="otp"></a>

### 6.3 HOTP/TOTP

- Secret은 최소 16바이트. HOTP는 HMAC-SHA1과 0 이상의 64비트 Counter, TOTP는 SHA1 기본 또는 SHA256/SHA512와 `floor(epochSecond / periodSeconds)`를 Counter로 사용한다. 시간 기준은 UTC Unix epoch, 기본 주기 30초, 허용 정수 15~300초다.
- 메시지는 빅엔디언 Counter 8바이트다. HMAC의 끝 바이트 하위 4비트를 오프셋으로, 그 지점의 4바이트를 빅엔디언 31비트 양수로 읽는다. `10^digits`로 나눈 나머지를 6~8자리(기본 6) 십진수로 왼쪽 0까지 유지한다. HOTP 선행 검색 0~100, TOTP 창은 현재 스텝 기준 ±0~10이며 음수 스텝은 제외한다.
- `api keygen --type otp`는 Base32만 출력한다. `otp` 실행은 Base32 자료로 읽는다. `otpauth://totp/` URI는 발행자·계정·Base32 Secret·알고리즘·자릿수·주기이며 URL 구성 요소를 인코딩한다. HOTP URI 생성, 지속 Counter, 사용 코드의 재사용 방지 저장소는 기능 범위에 없다. 고정 `--at 2026-11-26T00:00:00Z`는 재현 시험용이고 운영에서는 현재 시각을 사용한다. [TOTP 생성·검증 예제](../guide/authentication.md#api-otp) · [OTP API](java-api-reference.md#api-otp)

<a name="request-auth"></a>

### 6.4 RequestAuth

```text
input = ASCII("JCK-REQ-AUTH-v1") || LF || ASCII(timestamp) || LF
        || ASCII(nonce) || LF || raw_request_bytes
mac = B64U(HMAC(key, input))
```

`timestamp`는 서명 Clock의 Unix epoch 초를 십진 문자열로 표기하고 `nonce`는 매 서명에서 난수 16바이트의 B64U를 생성한다. 결과는 `timestamp`, `nonce`, `mac` 세 값을 함께 전달한다. CLI의 `--at`은 고정 Unix epoch 초를 지정하며 생략 시 현재 시각을 사용한다. `sign --out`의 JSON 파일은 세 문자열 필드를 저장하고 `verify --auth-file`에서 읽는다. 이 입력은 세 개의 개별 옵션과 배타다. 검증은 Timestamp 1~12자리 숫자, Nonce URL 안전 문자 16~128자, MAC 표현 1~128자와 알고리즘 길이 확인 → 현재와의 절대 초 차 확인 → 동일 원본으로 MAC 비교 순이다. 시간 기본 300초, 허용 1~900초. 결과는 `VALID`, `MALFORMED`, `TIMESTAMP_OUT_OF_RANGE`, `BAD_MAC`이다. 요청 바이트에는 임의 정규화를 적용하지 않으며 요청 URL/메서드 등을 인증하려면 양쪽이 원본 바이트 조합을 함께 정한다. 비밀키 보유 확인과 시간 허용 범위만 검사하므로 허용 창 내 재전송 방지는 호출자에게 속한다. [요청 인증 API](java-api-reference.md#api-integrity)

<a name="cli"></a>

## 7. CLI 실행·조회·출력 계약

| 유형 | 계약 |
|---|---|
| 공개 조회 | 두 JAR 상태 모두 전체·그룹·명령 Help, Examples 및 전체 Help의 버전 정보를 인증 없이 확인한다. 키·설정·외부 서비스 호출과 JAR 편집이 발생하지 않는다. Examples의 설정 여부 안내는 JAR 관리자 엔트리 **이름**의 존재만 확인한다 |
| 최신 미설정 배포본에서 실제 실행 | 대화형에서는 초기 설정 안내 및 설정으로 이동하고 원래 요청은 실행하지 않는다. 비대화형은 `ADMIN_SETUP`로 중단한다 |
| `SETUP` | `admin setup`만 해당. 미설정 JAR의 예약 영역을 같은 경로에서 갱신해 설정 완료 상태로 전환한다 |
| `OPEN` | 설정 완료 상태 확인 후 별도 비밀번호 질문 없이 실행한다 |
| `ADMIN` | 부작용 없는 인자·경로 사전 검사 후 인증한다. 그 뒤 파일 내용·키·기록 읽기, 대상 조건 확인, 사유·재료·확인 및 변경을 수행한다 |

관리형 `OPEN`은 `encrypt`, `verify`, `file encrypt`, `fingerprint`, `info`, `doctor`다. `ADMIN`은 `decrypt`, `file decrypt`, `rekey`, `keygen`, `config show/history/set/embed-key`, `config key add/use/remove/show`, `kms datakey`, `admin password change`다. 도움말 조회는 공개 경로에서 별도로 처리한다. 독립 `api`의 경로별 `ADMIN`과 `OPEN`은 [명령 및 옵션 가이드](../guide/cli.md#api-cli)와 `ApiCommands` 정의가 일치해야 한다. 명령별 실행 경로는 [추적표](#traceability)에 연결되어 있다.

### 7.1 명령과 옵션 정규화

`CliCommands.Spec`가 정식 이름·토픽·옵션·접근 정책을 한 번 정의한다. `CliCommands`는 명령 토큰과 옵션 이름을 정규화하고 동일 정식 정의로 분기한다. 옵션 값·입력 경로·입력 데이터는 별칭 치환 대상이 아니다. 같은 옵션의 정식명과 단축어를 함께 주면 중복이다. 미등록 명령·옵션, 필요한 값 누락, 적용되지 않는 조합을 거부한다. 기본값과 조건부 필수·배타 조건은 [관리형 명령 목록](../guide/cli.md#topic-cli--22-명령-목록), [독립 CLI](../guide/cli.md#api-cli) 및 연결된 기능 가이드의 개별 명령을 따른다.

- 경로 단축형은 관리형 및 `file`/`api aes`/`api rsa`/`api hybrid`의 `enc/dec`, `api keyconv`, `api hash gen`, `api otp gen`이다.
- 그룹 단축형은 `sig`, `cert`, `rand`, `req-auth`이며 조회와 실행에 같은 정식 그룹을 쓴다.
- 옵션 단축형은 `--alg --enc --in-enc --key-enc --fmt --pub-key --priv-key --len --iter --sig-file --iss --sub --aud --jti --iat --nbf --ttl`이다. 정식명 매핑과 지원 조합은 [CLI 별칭 표](../guide/cli.md#cli-aliases)를 따른다.
- Help는 한·영, 80열 기준으로 출력한다. 전체 `api --help`는 등록 정의에서 목적별 그룹과 기능 설명을 만든다. 명령별 Help는 조건·알고리즘·기본값 및 한도를 설명한다. Examples는 복사 가능한 한 줄과 설정 안내를 사용한다. `admin setup` 예제는 배포 JAR로, 일반 예제는 설정 완료 JAR로 안내한다. 기존 명령의 예제는 공식 단축형을 우선한다.

### 7.2 작업 입력과 결과

- 대화형에서는 필요한 입력을 묻고 적용 가능한 기본값을 안내한다. 비밀 입력은 화면에 표시하지 않는다. 비대화형에서는 명령이 요구하는 입력 파일·옵션을 준비한다. 누락 시 추측하거나 임의 파일을 읽지 않는다.
- 파일 크기는 읽기 전 검사하고 실제 읽기에도 상한을 적용한다. `--in` 등 데이터 파일은 바이트·UTF-8·인코딩 중 개별 기능의 규칙을 적용한다. RSA는 키 크기 기반 상한을 미리 확인한다. 보호 파일은 POSIX other의 읽기·쓰기 권한을 금지하며 심볼릭 링크 최종 대상 권한을 검사한다. Windows는 디렉터리 ACL 정책을 적용한다. 오류에 옵션 이름을 표시할 때 실제 검사 대상(`--in`, `--key-file` 등)을 사용한다.
- 비밀 결과는 신규 보호 파일이나 명시적이고 확인된 대화형 표시 정책으로 전달한다. 신규 파일은 기존 대상을 덮어쓰지 않는다. 파일 경로를 지정한 자동화와 대화형 저장 완료 메시지는 분리한다. stdout은 데이터·판정·일반적인 업무 결과, stderr는 오류·경고를 전달한다.
- 성공은 종료 0, 실패는 1이다. 정상 검증 성공/불일치 판정은 `OK`/`FAIL`을 사용한다. 독립 JWT·OAuth 검증의 불일치는 `FAIL`과 정제된 구체 사유를 함께 제공한다. 지원되지 않는 옵션, 잘못된 입력 파일, 인증 게이트, Provider 및 통신 오류는 실행 오류다. `Passwords.needsRehash`와 Introspection `active=false`처럼 업무 판단값이 false여도 성공 응답일 수 있다. [오류 코드별 조치](troubleshooting.md#93-오류-코드별-조치)

<a name="integrations"></a>

## 8. Tomcat과 외부 키 서비스

### 8.1 Tomcat JNDI

`Resource`의 Factory는 `io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory`다. `cryptoPool=dbcp2`는 `org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory`, `cryptoPool=tomcat-jdbc`는 `org.apache.tomcat.jdbc.pool.DataSourceFactory`에 위임한다. 생략 시 `crypto.pool.factory`의 유효한 값을 사용한다. Pool 선택은 복호화 전에 검사하고 위임 속성에는 `cryptoPool`을 빼며 원본 `Reference`는 변경하지 않는다. `crypto.require.encrypted.password`는 `true`만 허용한다. 비밀번호가 없거나 ENC/B64가 아니면 실패한다. `username`은 ENC/B64일 때만 복호화하며 평문 사용자명은 그대로 전달한다.

JNDI용 JAR는 `CATALINA_BASE/lib`에 둔다. 하위 Factory는 JCK를 로드한 ClassLoader 및 부모 체인에서만 허용한다. 신뢰 범위 밖의 웹앱 Factory나 임의 클래스를 로드하지 않는다. 관리형 키는 암호문 ID로 선택한다. 실패 시 DataSource를 구성하지 않으며 위임 예외의 민감 메시지·원인 객체를 노출하지 않는다. WAS 업무 소스 변경 없이 기존 JDBC Pool을 사용한다.

이중 배치에서는 서버 JNDI JAR와 `WEB-INF/lib`의 앱 JAR가 각자 관리형 설정·키·캐시를 가진다. 프로세스 전체 `-D`와 환경변수는 공유되므로 배포 시 설정 경계도 확인한다. 필요한 JAR는 내부 설정에서 JVM 오버라이드를 제한할 수 있다. 지원과 실제 JDK/Tomcat/DB 조합은 [지원 환경 및 검증 상태](compatibility.md#111-검증-상태), 실제 배치는 [Tomcat 가이드](../guide/tomcat-jdbc.md)를 따른다.

### 8.2 HashiCorp Vault KV v2

- 고정 등록된 `vault` 공급원만 사용한다. `GET <base>/v1/<mount>/data/<path>`에 선택적으로 `?version=<n>`을 붙이고 `X-Vault-Token`으로 인증한다. 응답의 `data.data` 아래 구성한 필드의 문자열을 읽는다. 프로필에 고정된 지문과 일치해야 한다. 진단은 필요 시 `GET /v1/auth/token/lookup-self`를 조회한다.
- 토큰은 지정 파일 우선 또는 이름으로 지정한 환경변수에서 읽는다. 토큰 파일 8KiB, 토큰 값 1~4,096개의 인쇄 ASCII, 응답 최대 64KiB, CA 파일 최대 1MiB다. HTTPS와 인증서·호스트 이름 검증을 유지하며 리다이렉트를 따라가지 않는다. 구성된 CA 또는 JVM 신뢰 저장소를 쓴다.
- 연결·읽기 기본 5초, 일시적인 네트워크 실패와 HTTP 429·500·502·503·504에 최대 3회 시도한다. TLS·권한·응답 오류와 미등록 버전의 자료를 기본 키로 대체하지 않는다. 키 자료의 캐시 범위는 [공급원 계약](#keyring)을 따른다. [Vault 설정과 운영](../guide/external-key-providers.md) · [설정 사전](configuration.md#10-설정-사전)

### 8.3 AWS KMS

`AwsKmsKeyProvider`는 SDK 설치 여부를 확인한 뒤 `AwsKmsSupport`를 호출한다. SDK 2.x 선택 ZIP을 JVM ClassPath 또는 WAS 공통 라이브러리 위치에 배치한다. 선택한 리전·KMS 키 ID 및 SDK 기본 자격증명 경로를 사용한다. 데이터 키 생성은 `GenerateDataKey(AES_256)`, 기존 파생/원시 AES 키 보호는 `Encrypt`, 복구는 `Decrypt`다. 각각 Encryption Context `{"java-crypto-kit:key-id":"<id>"}`를 동일하게 공급한다. CiphertextBlob의 표준 Base64 한 줄을 데이터 키 파일(최대 16KiB)로 보관하고 복구 자료는 32바이트와 프로필 지문을 확인한다. 생성 동작 중 복구 검증에 실패하면 결과 채택을 중단한다.

기본 API/소켓 시간 제한은 10초이며 연결은 설정값과 5초 중 짧은 값이다. SDK의 TLS·서명 및 자격증명 체계를 유지하고 예외를 정제한다. 기본 배포 JAR에는 SDK 클래스가 없다. 저장 파일이나 KMS 접근이 실패하면 해당 요청을 중단한다. [KMS 설치, 등록 및 운영](../guide/external-key-providers.md) · [설정 사전](configuration.md#10-설정-사전)

<a name="maintenance"></a>

## 9. 안전성, 배포 및 유지보수

<a name="file-io"></a>

### 9.1 파일 처리와 복구

입력은 기존 읽기 가능한 일반 파일이어야 하며 일반 파일을 가리키는 링크는 허용한다. 정규화한 동일 입출력과 이미 존재하는 출력(깨진 심볼릭 링크 포함)을 거부한다. 원본을 바꾸지 않고, 출력 디렉터리에 `.jck-tmp` 임시 파일을 POSIX 600 또는 Windows 상속 ACL로 만들어 스트리밍 처리한다. 쓰기를 닫고 `FileChannel.force(true)` 후 `Files.createLink(out,temp)`로 최종 이름을 확보한다. 같은 경로에 쓰는 프로세스 중 한 작업만 성공한다. 하드 링크가 지원되지 않으면 처리 실패이며 이동으로 대체하지 않는다.

| 상태 | 반환 및 운영 조치 |
|---|---|
| 공개 전 실패, 정리 성공 | 최초 실패 사유를 반환. 정상 결과 경로에는 새 파일이 없어야 함 |
| 공개 전 실패, 정리도 실패 | 최초 오류 코드와 원인을 보존. 안전한 임시 파일명과 정리 안내를 suppressed 예외로 연결하며 CLI도 정제해 표시. 프로세스 종료 확인 후 출력 폴더의 남은 임시 파일만 정리 |
| 최종 파일 공개 후 임시 이름 삭제 실패 | `INVALID_INPUT`과 함께 정상 결과가 완성됐음을 안내. 정상 결과를 보존하고 해당 임시 이름만 제거. 두 이름은 동일한 파일 내용을 가리킴 |

파일명은 표시용 basename을 사용하고 줄바꿈·제어문자 등은 출력 형식이 깨지지 않도록 처리한다. 정상 Unicode 문자와 실제 경로는 유지한다. 디렉터리 전원 장애 복구, 임의 외부 프로세스의 파일 변경 차단 및 디스크에서의 완전 삭제는 별도 경계다. [파일 가이드](../guide/file-encryption.md) · [복구·오류 안내](troubleshooting.md)

### 9.2 상태·성능·실패 처리

- 관리형 API는 로드 시 설정 스냅샷과 공급원 결과 범위를 유지한다. 공유 원격 키 캐시의 갱신은 서비스 내부에서 직렬화한다. `PassKdf` 캐시는 클래스 로딩 단위에서 동시 사용 가능하며 저장 키는 한도 초과 시 정리한다. 호출자 배열은 변경하지 않고 필요한 키는 복사한다. 암호화·서명·MAC의 JCA 엔진은 호출별로 사용한다. Builder 변경이나 같은 입출력 파일에 대한 응용 프로그램의 동시 수정은 별도 조율이 필요하다.
- JCKF와 파일 해시는 스트리밍이다. JWT/OAuth·PEM·KeyStore와 Raw/Hybrid 등 메모리 기능은 각 API/CLI의 크기 제한과 사용 가능한 메모리 영향을 받는다. 중간 비밀 배열은 가능한 범위에서 `finally` 등으로 정리하지만 Java `String`, GC, JCA Provider 내부 복사와 OS 파일 캐시는 애플리케이션이 완전히 지울 수 없다.
- `CredentialCryptoException.Reason`, JWT/OAuth의 타입별 Reason, CLI의 `ADMIN_SETUP`·`ADMIN_AUTH`·`ADMIN_PASSWORD` 및 업무 판정 경계를 유지한다. 비밀 입력, 내부 예외 원문, 토큰, 전체 민감 경로는 진단에 내보내지 않는다. 공개 Java 예외의 기존 계약을 유지하면서 CLI 사용자 안내는 `Messages`의 한·영 번들에서 처리한다. [공개 예외 규칙](java-api-reference.md#1321-예외와-실패-처리-요약) · [오류 코드별 조치](troubleshooting.md#93-오류-코드별-조치)

### 9.3 빌드와 공개 변경

Gradle Wrapper의 `gradlew.bat clean build` 또는 `./gradlew clean build`로 빌드하고 Java 8 실행 가능·major 52를 유지한다. 빌드 버전과 Manifest `Implementation-Version`은 `0.2.1`이다. `Main-Class`는 `io.javacryptokit.cli.CryptoCli`이며 `Build-Time`과 `Settings-Fingerprint`를 포함한다. 배포물은 실행형 기본 JAR `java-crypto-kit-0.2.1.jar`와 선택 의존성 `java-crypto-kit-aws-kms-lib-0.2.1.zip`이다. SHA-256은 `SHA256SUMS.txt`를 확인한다. 기본 JAR는 fat JAR·WAR·JDBC 드라이버·AWS SDK를 포함하지 않는다. Java 7, 자체 Pool, 새 서버 및 별도 보안 런타임은 지원 범위 밖이다. [빌드 및 배포 준비](getting-started.md) · [실행·검증 환경](compatibility.md) · [버전 이력](../../CHANGELOG.md)

기능 추가 시 기존 등록부의 목적·옵션·접근 정책을 정의하고 입력 계층, 공개 API 및 결과 처리의 공통 구조를 재사용한다. Help·Examples는 같은 정의에 연결한다. 변경된 계약의 문서와 표적 시험을 갱신한다. 공개 Reason·시그니처·명령·기본값·데이터 형식과 호환을 먼저 확인하며 호환성·보안 경계에 영향이 있는 변경에는 승인과 교차 호환 검증이 필요하다. 내부 리팩터링은 영향받는 계약만 검토한다. [개발·QA 규칙](../../AGENTS.md)

<a name="traceability"></a>

## 10. 요구사항 추적

표의 시험 이름은 기존 테스트 소스 및 QA 기록의 추적 경로다. 문서 검수에서 새로 실행한 검증은 제출 ZIP의 `build/qa/v0.2.1-QA.md`에서 확인한다. 명령 열의 경로에는 모두 `api` 접두어를 붙여 실행한다. R2 18개 영역에서 AES 두 요구사항은 같은 실행 경로를 공유한다. 좁은 화면에서는 표를 좌우로 움직여 구현·검증 근거 열을 확인할 수 있다.

### 10.1 독립 CLI와 공개 API

| 요구 ID · 실행 경로 | 계약 위치 | 구현 근거 | 수용 기준 | 검증 근거 |
|---|---|---|---|---|
| CLI-01/02 · `aes encrypt/decrypt` | [Raw/Pass/ENC](../guide/java-encryption.md#api-aes) | `ApiCrypto`, `CredentialCrypto`, `AesGcm`, `Pbkdf2` | Raw/ENC·키/Passphrase 정합. 길이·형식·AAD·키 불일치에서 평문 미출력 | `ApiCliTest`, `DirectKeyApiTest`, `AesGcmPasswordsTest` |
| CLI-03 · `rsa encrypt/decrypt` | [RSA](../guide/java-encryption.md#api-rsa) | `RsaOaep` | 허용 최대 길이까지 왕복, 한도·키·OAEP 오류 거부 | `RsaOaepHybridTest`, `ApiCliTest` |
| CLI-04 · `hybrid encrypt/decrypt` | [JCKH](#direct-crypto) · [CLI](../guide/java-encryption.md#api-hybrid) | `HybridEncryption` | 헤더·AAD·태그를 검증, 잘못된 개인키·변조 시 결과 미공개 | `RsaOaepHybridTest`, `ApiCliTest` |
| CLI-05 · `hmac sign/verify` | [MAC](../guide/data-integrity.md#api-hmac) | `Hmac`, `ApiUtilities` | 입력 바이트 일치 및 키 하한 적용. 다른 MAC은 FAIL | `DigestMacKdfTest`, `ApiCliTest` |
| CLI-06 · `hash generate/verify` | [해시](../guide/data-integrity.md#api-hash) | `Digests` | SHA-256/512 및 파일 스트리밍, 변조 FAIL | `DigestMacKdfTest`, `ApiCliTest` |
| CLI-07 · `encode`, `decode` | [인코딩](../guide/security-utilities.md#api-encode) | `Encoding`, `Bytes` | 바이너리 왕복, 잘못된 문자·길이·남는 비트 거부 | `EncodingRandomTest`, `ApiCliTest` |
| CLI-08 · `random bytes/token/string/nonce/uuid` | [난수](../guide/security-utilities.md#api-random) | `SecureRandoms` | 범위·바이트/문자 단위·알파벳·접두사 일치 | `EncodingRandomTest`, `ApiCliTest` |
| CLI-09 · `password hash/verify/needs-rehash` | [포맷](#passwords) · [CLI](../guide/security-utilities.md#api-password) | `Passwords` | 기존 허용 반복의 검증, 불일치와 잘못된 저장 형식 구분 | `AesGcmPasswordsTest`, `ApiCliTest` |
| CLI-10 · `kdf pbkdf2/hkdf` | [KDF](../guide/security-utilities.md#api-kdf) | `Pbkdf2`, `Kdf`, `Hkdf` | 지정 Salt/Info 및 길이로 재현, 경계 밖 거부 | `DigestMacKdfTest`, `PassKdfTest`, `ApiCliTest` |
| CLI-11 · `signature sign/verify` | [서명](../guide/data-integrity.md#api-signature) | `Signatures`, `PemKeys` | RSA/P-256 지원, 다른 키/입력의 판정 및 형식 오류 구분 | `SignaturesCertificatesTest`, `ApiCliTest` |
| CLI-12 · `certificate info` | [인증서](../guide/certificates-keystores.md#api-certificate) | `Certificates` | PEM/DER 정보와 날짜 조회. 조회 성공만으로 신뢰가 성립하지 않음 | `SignaturesCertificatesTest`, `ApiCliTest` |
| CLI-13 · `keygen` | [독립 CLI 명령 목록](../guide/cli.md#api-cli) | `ApiCrypto`, `SecureRandoms`, `Signatures`, `OtpAlgorithm` | 소비 기능과 맞는 출력. OTP 비 Base32는 생성 전 거부 | `ApiCliTest` |
| CLI-14 · `keyconvert` | [키 변환](../guide/certificates-keystores.md#api-keyconvert) | `PemKeys`, `ApiCrypto` | 지원 PEM/DER 왕복, PKCS#1·SEC1·암호화 키 거부 | `SignaturesCertificatesTest`, `ApiCliTest` |
| CLI-15 · `jwt create/inspect/verify` | [JWT](#jwt) · [CLI](../guide/authentication.md#api-jwt) | `Jwt`, `JwtVerifier`, `Jwks` | 세 알고리즘과 등록 신뢰키, issuer·audience·시간·Claim 일치 검증 | `JwtTest`, `StrictJsonTest`, `ApiCliTest` |
| CLI-16 · `oauth token/introspect/create/verify` | [OAuth](#oauth) · [CLI](../guide/authentication.md#api-oauth) | `ApiOAuth`, `ClientCredentials`, `TokenIntrospector`, `AccessTokens`, `AccessTokenVerifier` | TLS 제한, 비활성 응답, 로컬 RFC 9068/설정형 및 권한/토큰 크기 경계 | `OAuthTest`, `ApiCliTest` |
| CLI-17 · `otp generate/verify/uri` | [OTP](#otp) · [CLI](../guide/authentication.md#api-otp) | `Hotp`, `Totp`, `ApiAuth` | Base32 연계, 선택 시각과 앞 0 보존, 허용 창 및 URI의 한계 | `OtpRequestAuthTest`, `ApiCliTest` |
| CLI-18 · `request-auth sign/verify` | [요청 인증](#request-auth) · [CLI](../guide/data-integrity.md#api-request-auth) | `RequestAuth`, `ApiAuth` | 정해진 바이트·MAC·시간으로 확인, 변경 메시지나 범위 밖 시간 거부 | `OtpRequestAuthTest`, `ApiCliTest` |
| Java 전용 인증서·저장소 계약 | [인증서 API](java-api-reference.md#api-certs) | `Certificates`, `KeyStoreReader` | PKIX 신뢰 검증은 날짜 확인과 독립. PKCS12/JKS 읽기 권한·타입·비밀번호를 검증 | `KeyStoreReaderTest`, `SignaturesCertificatesTest` |
| 공개 타입·오버로드·결과·오류 | [타입별 호출 형식](java-api-reference.md#api-members) | `io.javacryptokit`, `security`, `jwt`, `oauth`, Tomcat Factory | 공개 생성자·오버로드·필드·중첩 타입을 참조할 수 있고 공개 Reason 유지 | `DocsConsistencyTest`, `TokenApiExampleTest`, `SecurityApiExampleTest` |

### 10.2 관리형 제품과 공통 요구사항

| 기능 | 계약 위치 | 구현 근거 | 수용 기준 | 검증 근거 |
|---|---|---|---|---|
| `encrypt/decrypt/verify/rekey`, 관리형·직접 Java API | [ENC](#enc-v1) · [관리형 API](java-api-reference.md#api-managed) | `CredentialCrypto`, `CredentialCipher`, `TokenCodec`, `CryptoService` | 기존 공개 AES 벡터 복호화. ID 불일치 및 인증 실패에서 평문 미공개. rekey 후 변경한 키로만 신규 결과 복호화 | `TokenCodecTest`, `CredentialCryptoApiTest`, `DirectKeyApiTest`, `CryptoCliTest` |
| `file encrypt/decrypt` 및 Java API | [JCKF](#jckf-v2) · [파일 공개](#file-io) | `FileCipher`, `FileCommand`, `SecretFiles` | v2 및 v1 호환, 빈 파일과 청크 경계, 혼합·중복·잘림·헤더 변경 거부, 출력 충돌 및 정리 실패 구분 | `FileCipherTest`, `CryptoCliTest` |
| `fingerprint`, `keygen`, `config key add/use/remove/show`, `config embed-key` | [Keyring](#keyring) · [키 관리](../guide/key-management.md) | `KeyResolver`, `KeyCommands`, `KeyringCommand`, `PassKdf` | pass/key 공존, 미등록 ID 거부, 보관·이전·활성 전환·이전 키 이력 유지 | `KeyringTest`, `ConfigKeyTest`, `KeyCommandsTest` |
| `config show/set/history`, `info`, `doctor` | [JAR 상태](#jar-state) · [설정](configuration.md#10-설정-사전) | `SettingCatalog`, `CryptoSettings`, `JarConfigEditor`, `ConfigHistory`, `LightObfuscation` | 설정 규칙과 이전 JAR 보존, 전체 체인 검증, 안전 진단 및 키·이력 표현 호환 | `ConfigJarTest`, `ConfigResolutionTest`, `JvmOverrideTest`, `LightObfuscationTest`, `DoctorAndHelpTest` |
| `admin setup/password change` · 공개 조회 · 별칭 | [관리자](#admin-verifier) · [CLI](#cli) | `AdminPassword`, `AdminCommand`, `CryptoCli`, `CliCommands`, `CliHelp`, `ApiHelp` | 무부작용 조회, 미/완료 설정 경계, 저장값 삭제·교체 탐지, 정식명 및 단축형 일치. 고정 TOTP 실무 예제 재현 | `AdminCliTest`, `AdminIntegrityTest`, `AdminPasswordTest`, `DoctorAndHelpTest`, `ApiCliTest`, 직전 Examples XML |
| Tomcat 공식 Pool과 이중 JAR | [Tomcat](#integrations) | `EncryptedDataSourceFactory`, `CryptoService` | 기존 Reference 및 키 격리, 평문 비밀번호·신뢰하지 않는 Factory 또는 복호화 오류 차단 | `FactoryEntryPointTest`, `PoolFactoryTrustBoundaryTest`, `PoolFailureSanitizationTest`, [실서버 검증 범위](compatibility.md#111-검증-상태) |
| Vault KV v2 및 KMS · `kms datakey` | [외부 서비스](#integrations) | `VaultKeyProvider`, `AwsKmsKeyProvider`, `AwsKmsSupport`, `KeyProvider` | 고정 계약 TLS·인증·컨텍스트·지문. 외부 실패 시 키 대체 금지. 기본 JAR에서 SDK 분리 | `VaultKeyProviderTest`, `AwsKmsKeyProviderTest`, `KmsDataKeyCliTest`, [검증 상태](compatibility.md#111-검증-상태) |
| 호환과 배포물 | [빌드](#maintenance) · [호환 가이드](compatibility.md) | `build.gradle`, 최종 JAR Manifest, `RealLegacyJarTest` | Java 8, 검사 가능한 SHA, 기존 AES 토큰과 JAR 수정 호환 | 기존 조립·비교·실행 기록, `BoundaryRegressionTest`, `RealLegacyJarTest` |
| OPT-01~OPT-07 및 R2 취소·제외 범위 | [제품 및 작업 원칙](../../AGENTS.md#1-제품-범위와-작업-원칙) · [배포 계약](#maintenance) | `CliCommands`, `ApiCommands`, 공개 패키지와 배포 범위 | `UniqueIds`·`SequenceRange`, 영속 시퀀스 및 날짜별 순번, Nonce·OTP 재사용 상태, HOTP 저장 Counter, JWT 폐기 상태, 결정적 GCM IV 카운터를 제외. PKCS12/JKS·PKIX·안전 비교 전용 CLI와 신규 Vault/KMS 관리 CLI를 제외. 별도 백업·재처리·inspect/dry-run·감사 서버·전체 난독화 제외 | 승인 범위 및 등록부 대조 |

### 10.3 이전 검증 ID 교차 참조

R2와 최종 QA 통합 보완 지시서의 ID는 서로 다른 번호 체계다. 아래는 해당 계약과 증거를 찾는 색인이다.

| 기존 ID | 연결되는 계약 및 증거 |
|---|---|
| R2 T01, T39~T40 · G13, G15 | [Java 8, Manifest, SHA-256](#maintenance) 및 최종 조립·산출물 기록 |
| R2 T02~T07, T31~T35 · G01~G05, G10 | [CLI 접근·입출력](#cli), [관리자 상태](#admin-verifier), [파일 공개](#file-io), 관리형·직접 격리, `AdminCliTest`·`ApiCliTest`·`FileCipherTest`·`DoctorAndHelpTest` |
| R2 T08~T21 · G06 | [CLI-01~14](#traceability)의 암복호화·무결성·보안 유틸리티 및 키·인증서 시험 |
| R2 T22~T24 · G07 | [JWT](#jwt), `JwtTest`·`ApiCliTest` |
| R2 T25~T27 · G08 | [OAuth](#oauth), `OAuthTest`와 이전 로컬 HTTPS 기록 |
| R2 T28~T30 · G09 | [일회용 코드](#otp) · [요청 인증](#request-auth), `OtpRequestAuthTest` 및 CLI 시험 |
| R2 T36~T38 · G11~G12, G14 | [Help·Examples](#cli), `DocsConsistencyTest` 및 기존 Examples·PowerShell·Bash 증거, [확장 기준](#maintenance) |
| 최종 QA F01, F05~F08 · G01, G03~G05 | [대화형·단축어·출력·오류·Help](#cli), `ApiCliTest`·`DoctorAndHelpTest` 및 직전 Examples XML |
| 최종 QA F02~F04 · G06 | [JWT inspect](../guide/authentication.md#api-jwt)의 미검증 텍스트, [HKDF Salt·Info](../guide/security-utilities.md#api-kdf)의 표현, 업무별 가이드와 `DocsConsistencyTest` |
| 최종 QA G02 | [설정 JAR 명명·호환](#jar-edit), `AdminCliTest`·`ConfigJarTest` |
| 최종 QA F09 · G07~G08 | [빌드·배포 검수](#maintenance) 및 실제 영향도 시험 원본·최종 SHA-256 대조 |

<a name="interop"></a>

## 11. 교차 호환 검수 절차

| 규격 | 재현 순서 | 필수 음성 케이스 |
|---|---|---|
| ENC/B64 | [공개 AES 벡터](#enc-v1)의 버전·ID·IV·본문 구간을 읽고 같은 키·AAD 바이트로 열기. 새 ENC를 B64로 포장해 같은 원본 비교 | 다른 ID·IV/본문·AAD, 네 필드 위반, 중첩 B64 |
| JCKF | [합성 헤더](#jckf-v2)와 레코드 AAD를 계산한 뒤 길이 0·65,536·65,537의 파일을 양쪽 구현에서 생성·읽기 | 다른 v2 파일의 청크, 순서·표식·식별자·끝자락 변조, 최종 이름 충돌, 공개 전후 정리 실패 |
| Raw AES·JCKH·RSA | [포맷](#direct-crypto)의 IV/태그·OAEP digest·MGF1·래핑 길이를 따르고 명시 AAD/비어 있는 AAD 각각 확인 | 단독 AES와 ENC 혼용, 긴 RSA 평문, 다른 개인키·AAD |
| obf1·History | [합성 obf1 벡터](#jar-obf1) 검산 후 평문/obf1의 동일 본문 확인. 빈 이력에서 첫 단계와 다음 단계의 [해시 입력](#history) 생성 | 비밀값 표식 위반, 원본 설정 바이트·행 순서·해시 변경, 지원하지 않는 난독화 버전 |
| 관리자 검증값 | [정해진 입력·Salt·반복](#admin-verifier)으로 32바이트를 계산하고 표준 Base64로 비교. 새/변경 상태 및 대상 JAR 확인 | 기존 저장 검증값을 비밀번호로 입력, 엔트리·이력 하나 삭제, 중복 필드와 범위 위반 |
| 토큰·OTP·요청 인증 | [서명 입력](#authentication)을 수신측에서 바이트로 재생성. ES256 고정 폭, OTP 앞 0, 같은 시각의 요청 MAC 확인 | 다른 키/alg/Claim, TLS·리다이렉트, 열린 시간창 밖, 원본 요청 변조 |

이 표는 교차 구현 시험을 설계하는 데 필요한 입력과 판정이다. 현행 릴리스의 실제 실행 증거는 QA 보고서를 기준으로 확인한다.
