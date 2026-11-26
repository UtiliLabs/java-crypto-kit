# Java API 레퍼런스

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md) · [타입별 메서드·옵션 찾기](#api-members)

<a name="topic-security-api"></a>

<a name="topic-security-api--범용-java-api-공통-규칙"></a>
<a name="topic-security-api--13-범용-보안-java-api"></a>
## 13. 범용 보안 Java API

테스트용 입력을 명령줄에서 비교할 때는 [독립 API CLI](../guide/cli.md#api-cli)를 사용할 수 있습니다. 애플리케이션 코드는 아래 Java API를 직접 호출합니다.

처음 기능을 선택할 때는 [업무별 API 선택표](api-selection.md#topic-api-selection--15-업무별-java-api-선택-가이드)를 사용하세요. 이 문서의 [타입별 호출 형식](#api-members)은 관리형 암복호화 공개 API, Tomcat JNDI Factory, `security`·`jwt`·`oauth`의 공개 타입과 중첩 타입을 다룹니다.

업무 가이드에서 `// 예제:`로 시작하는 메서드는 [SecurityApiExample.java](../../src/test/java/example/SecurityApiExample.java)와 [TokenApiExample.java](../../src/test/java/example/TokenApiExample.java)의 시험 대상 메서드와 일치합니다.

<a name="topic-security-api--131-공통-규칙"></a>
## 13.1 공통 규칙

- **패키지:** `io.javacryptokit.security`(암호화·서명·해시·키·OTP 등), `io.javacryptokit.jwt`(JWT), `io.javacryptokit.oauth`(OAuth). 배포 JAR 하나에 들어 있고 외부 라이브러리가 필요 없습니다(Java 8 표준 기능만).
- **관리형 키와 독립:** JAR 내장 키·키 목록·설정 파일·JVM 속성·변경 이력·CLI 관리자 비밀번호를 읽거나 바꾸지 않습니다. 키·정책은 호출자가 주며, 같은 JVM의 관리형 객체나 다른 객체 상태를 바꾸지 않습니다.
- **알고리즘은 열거형으로만 고릅니다:** `AesKeySize`·`Pbkdf2Algorithm`·`HmacAlgorithm`·`DigestAlgorithm`·`SignatureAlgorithm`·`RsaOaepAlgorithm`·`OtpAlgorithm`·`KeyStoreType`·`JwtAlgorithm`. 임의 알고리즘 문자열·MD5·SHA-1 해시/서명·DES·ECB·인증 없는 CBC·JWT `none`은 없습니다(SHA-1은 HOTP/TOTP 표준 연동에만).
- **입출력:** 바이트는 `byte[]`, 문자열은 UTF-8(짝 없는 서로게이트는 거부), 비밀번호·Passphrase는 `char[]`, 파일은 `Path`(스트리밍). 바이트 결과를 문자열로 받을 때는 `Encoding`(`HEX`·`BASE64`·`BASE64_URL`·`BASE32`)을 명시합니다. 형식을 추측해 다른 형식으로 다시 시도하지 않습니다.
- **예외:** 입력 오류(null·길이·형식)는 `IllegalArgumentException`, 실행 중인 Java에 알고리즘이 없으면 `IllegalStateException`, 파일 I/O는 `IOException`, 복호화 실패는 기존 `CredentialCryptoException`(`INTEGRITY`·`INVALID_TOKEN`, Reason 목록은 그대로), JWT는 `JwtException`, OAuth HTTPS 호출은 `IntrospectionException`·`TokenRequestException`, 키 저장소는 `KeyStoreException`. MAC·서명 불일치는 `false`, OTP 불일치는 빈 값입니다.

  오류 문구는 한국어 고정이며 키·평문·토큰·비밀번호·경로를 넣지 않습니다. 요약: [13.21절](#topic-security-api--1321-예외와-실패-처리-요약).
- **스레드·메모리:** 만든 객체(`AesGcm`·`Hmac`·`JwtVerifier`·`TokenIntrospector`·`ClientCredentials` 등)는 불변이라 한 번 만들어 여러 스레드에서 재사용합니다. JCA 객체는 호출마다 새로 만듭니다. 넘긴 키·비밀번호 배열은 바꾸지 않으므로 다 쓰면 호출자가 지웁니다(JVM 메모리에서 완전히 지운다는 보장은 없음).
- **예제 읽는 법:** `// 예제:`는 시험 소스의 메서드 이름입니다. 아래 공통 import와 함께 사용합니다. 실제로 보관하거나 전달하는 비밀값은 호출자가 준비하며 예제 값을 운영에 사용하지 않습니다.

**범용 API의 공통 호출 구조**

| 단계 | 개발자가 할 일 |
|---|---|
| 1. 기능 선택 | [1.5절](api-selection.md#topic-api-selection--15-업무별-java-api-선택-가이드)에서 업무 목적에 맞는 API 선택 |
| 2. 키와 입력 준비 | 키·비밀번호·원본 데이터·신뢰할 공개키 등 기능별 입력 준비. JAR 내장 키를 자동 사용하지 않음 |
| 3. 객체 또는 정적 메서드 | 객체형 API는 설정 후 재사용, 정적 메서드는 필요한 값을 전달하여 호출. Builder는 여러 스레드에서 공유하지 않음 |
| 4. 결과 처리 | 형식과 반환값을 확인하고 암호문·해시·토큰 등 필요한 결과만 저장. 실패 결과를 승인으로 처리하지 않음 |

예제의 패키지 import는 다음과 같습니다. 각 메서드가 사용하는 항목만 가져오면 됩니다.

```java
import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.security.*;
import io.javacryptokit.jwt.*;
import io.javacryptokit.oauth.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.security.cert.CertPathValidatorException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.net.URI;
import java.util.*;
import java.io.IOException;
```

예제는 업무 코드에 붙일 메서드 단위입니다. 호출자가 준비하는 키·입력·서버 주소는 실제 업무 값으로 바꾸고, 예제의 호출 코드를 해당 메서드 또는 실행 클래스 안에 배치합니다.

실행 가능한 전체 예제 클래스는 저장소의 [SecurityApiExample.java](../../src/test/java/example/SecurityApiExample.java), [TokenApiExample.java](../../src/test/java/example/TokenApiExample.java), [ApiUsageExample.java](../../src/test/java/example/ApiUsageExample.java)를 참고합니다.

CLI나 별도 관리자 설정을 추가할 필요는 없습니다.

<a name="topic-security-api--java-예제-실행"></a>
## Java 예제 실행

기능 문서의 독립 실행 예제를 해당 클래스 이름으로 저장합니다. JAR와 Java 파일을 같은 폴더에 둡니다. 예: `AesExample.java`.

**Windows PowerShell**

```powershell
javac -cp .\java-crypto-kit-0.2.0.jar .\AesExample.java
java -cp '.;java-crypto-kit-0.2.0.jar' AesExample
```

**Linux / macOS**

```bash
javac -cp ./java-crypto-kit-0.2.0.jar AesExample.java
java -cp '.:java-crypto-kit-0.2.0.jar' AesExample
```

다른 예제는 파일명과 클래스명을 바꾸면 됩니다. 실제 배포 JAR의 파일명을 사용하세요. `// 예제:`로 시작하는 메서드 예제는 본인의 클래스 안에 넣고, 입력값을 전달하여 호출합니다.

단독 실행 클래스는 JDK 8의 `javac`와 JAR만으로 컴파일할 수 있습니다. 인증서 파일이나 외부 서비스가 필요한 메서드 예제는 해당 업무 가이드에서 준비 조건을 먼저 확인하세요.

<a name="topic-security-api--1321-예외와-실패-처리-요약"></a>
## 13.21 예외와 실패 처리 요약

| API | 입력 오류 | 정상적인 불일치 | 실패(검증·통신) |
|---|---|---|---|
| `AesGcm`·`RsaOaep`·`HybridEncryption` 복호화 | `IllegalArgumentException` | — | `CredentialCryptoException`: `INTEGRITY`(키·AAD·변조, 원인 구분 없음)·`INVALID_TOKEN`(형식)·`INVALID_INPUT`(`decryptText` 결과가 UTF-8이 아님) |
| `Hmac`·`Signatures`·`Digests.verifyFile` | `IllegalArgumentException`(키·형식) | `false` | 파일은 `IOException` |
| `Passwords.verify` | 저장값 형식 오류 `IllegalArgumentException` | `false` | — |
| `Hotp`·`Totp` | `IllegalArgumentException`(비밀키·허용창) | 빈 `OptionalLong` | — |
| `RequestAuth.verify` | — | `BAD_MAC`·`TIMESTAMP_OUT_OF_RANGE` | `MALFORMED` |
| `Certificates.validateChain` | `IllegalArgumentException` | — | `CertPathValidatorException` |
| `KeyStoreReader` | `IllegalArgumentException`(null 비밀번호 등) | — | `KeyStoreException`, 파일 `IOException` |
| `JwtVerifier`·`AccessTokenVerifier` | 설정 오류 `IllegalArgumentException` | — | `JwtException`(`getReason()`) |
| `TokenIntrospector` | `IllegalArgumentException` | `active() == false` | `IntrospectionException` |
| `ClientCredentials` | `IllegalArgumentException` | — | `TokenRequestException`(`OAUTH_ERROR`+표준 코드 등) |

`OAuthClientException`은 `IntrospectionException`·`TokenRequestException`의 공통 상위 예외입니다(`getReason`·`getStatusCode`·`getOAuthError`). 모든 오류 문구에는 키·평문·토큰·비밀번호·경로가 들어가지 않습니다.

### 알고리즘 선택 열거형과 상태 조회

| 열거형 | 조회 메서드와 활용 |
|---|---|
| `AesKeySize` | `keyBytes()` — AES_128은 16, AES_256은 32. 키 입력 길이를 맞출 때 사용 |
| `RsaOaepAlgorithm` | `hashLength()` — SHA256은 32, SHA512는 64. 실제 허용 평문 길이는 `RsaOaep.maxPlaintextBytes`로 조회 |
| `SignatureAlgorithm` | `keyAlgorithm()` — RSA 또는 EC. 서명용 키 유형 확인 |
| `Pbkdf2Algorithm` | `id()` — 저장 형식 이름, `jcaName()` — JCA 알고리즘 이름, `recommendedIterations()` — 권장 반복 횟수 |
| `OtpAlgorithm` | `secretBytes()` — 새 비밀키 길이: SHA1 20, SHA256 32, SHA512 64바이트. HOTP는 SHA1만 사용 |
| `HmacAlgorithm` | `length()` — MAC 출력 바이트 수. SHA256 32, SHA512 64 |

### 관리형 암복호화 오류 판단

`CredentialCryptoException.getReason()`으로 `CONFIGURATION`, `KEY_SOURCE`, `INVALID_INPUT`, `INVALID_TOKEN`, `KEY_ID_MISMATCH`, `INTEGRITY`, `CRYPTO_PROVIDER`를 구분합니다. `getCauseType()`은 원인 예외의 클래스 이름만 제공합니다(없으면 null). `Reason.description()`은 현재 메시지 언어의 고정 설명이며, 자동 분기는 번역되지 않는 열거형으로 처리합니다. `Reason.isTokenProblem()`은 형식·키 ID·무결성 오류인지 판별합니다. 관리형 `verify`는 이 세 사유에서는 false를 반환하고 그 밖의 구성·키 공급원 오류 등은 예외로 전달합니다. 호출 코드는 보통 예외를 받아 처리합니다. 직접 생성할 때는 공개 생성자의 상세 문구에 비밀값이나 경로를 넣지 마세요.

<a name="api-members"></a>
## 타입별 호출 형식

업무 가이드에서 사용할 기능을 고른 뒤, 아래에서 클래스 이름을 펼쳐 인수 순서와 반환 타입을 확인하세요. 같은 이름의 메서드도 인수에 따라 키 선택, 암호화 형식, 반환값이 달라집니다. 검증기와 HTTPS 클라이언트는 Builder에서 정책을 설정한 뒤 `build()`로 만들어 재사용합니다. 토큰 발급용 Builder는 `sign(key)`로 토큰 한 건을 생성합니다.

[관리형 키·Tomcat](#api-managed) · [AES·RSA·Hybrid 암호화](#api-encryption) · [체크섬·요청 인증·서명](#api-integrity) · [난수·비밀번호·키 파생](#api-utilities) · [인증서·키 저장소](#api-certs) · [일회용 코드](#api-otp) · [JWT 서명과 검증](#api-jwt) · [OAuth 검증과 토큰 요청](#api-oauth)

<a name="api-managed"></a>
### 관리형 키·Tomcat

[업무 예제와 선택 기준](../guide/java-encryption.md#topic-java-api)

<details>
<summary>CredentialCrypto</summary>

`io.javacryptokit.CredentialCrypto`

- `fromDefaultConfiguration()`  
  `CredentialCrypto` · 설정이 적용된 객체
- `fromConfigFile(Path configFile)`  
  `CredentialCrypto` · 설정이 적용된 객체 · `configFile` 외부 설정 파일 경로
- `fromRawKey(String keyId, byte[] key)`  
  `CredentialCrypto` · 그 키 하나만 쓰는 객체(유형 KeyType.KEY, 공급 방식 direct) · `keyId` Key ID(영문·숫자·-·_ 1~64자, 암호문에 기록된다) · `key` 32바이트 AES 키(바꾸지 않고 복사한다)
- `fromPassphrase(String keyId, char[] passphrase, byte[] salt, int iterations)`  
  `CredentialCrypto` · 그 키 하나만 쓰는 객체(유형 KeyType.PASS, 공급 방식 direct) · `keyId` Key ID(영문·숫자·-·_ 1~64자) · `passphrase` Passphrase(비어 있거나 공백만·제어문자 불가, UTF-8 1KiB 이하. 바꾸지 않는다) · `salt` Salt 16바이트(바꾸지 않는다) · `iterations` PBKDF2 반복 횟수(100,000~5,000,000, 권장 600,000)
- `fromPassphrase(String keyId, char[] passphrase, byte[] salt, int iterations, Pbkdf2Algorithm algorithm)`  
  `CredentialCrypto` · 그 키 하나만 쓰는 객체(유형 KeyType.PASS, 공급 방식 direct) · `keyId` Key ID(영문·숫자·-·_ 1~64자) · `passphrase` Passphrase(비어 있거나 공백만·제어문자 불가, UTF-8 1KiB 이하. 바꾸지 않는다) · `salt` Salt 16바이트(바꾸지 않는다) · `iterations` PBKDF2 반복 횟수(100,000~5,000,000, 권장 SHA256 600,000·SHA512 210,000) · `algorithm` PBKDF2 알고리즘
- `withKeyId(String keyId)`  
  `CredentialCrypto` · 그 키로 암호화하는 객체 · `keyId` 등록된 Key ID
- `encryptText(String plainText)`  
  `String` · 설정한 출력 형식의 토큰(ENC[v1:...] 또는 B64[...]) · `plainText` 암호화할 텍스트(비어 있으면 안 됨)
- `encryptText(String plainText, KeyType type)`  
  `String` · 설정한 출력 형식의 토큰 · `plainText` 암호화할 텍스트(비어 있으면 안 됨) · `type` KeyType.PASS 또는 KeyType.KEY
- `encryptText(String plainText, KeyType type, String keyId)`  
  `String` · 설정한 출력 형식의 토큰 · `plainText` 암호화할 텍스트(비어 있으면 안 됨) · `type` 기대하는 유형 · `keyId` 등록된 Key ID(withKeyId(String) 객체에서도 이 값이 우선한다)
- `encryptText(char[] plainText)`  
  `String` · 설정한 출력 형식의 토큰 · `plainText` 암호화할 문자 배열(비어 있으면 안 됨)
- `encryptText(char[] plainText, KeyType type)`  
  `String` · 설정한 출력 형식의 토큰 · `plainText` 암호화할 문자 배열(비어 있으면 안 됨) · `type` KeyType.PASS 또는 KeyType.KEY
- `encryptText(char[] plainText, KeyType type, String keyId)`  
  `String` · 설정한 출력 형식의 토큰 · `plainText` 암호화할 문자 배열(비어 있으면 안 됨) · `type` 기대하는 유형 · `keyId` 등록된 Key ID
- `decryptText(String token)`  
  `String` · 복호화한 텍스트(결과가 올바른 UTF-8이 아니면 실패) · `token` 암호문 토큰
- `encryptBytes(byte[] data)`  
  `String` · 설정한 출력 형식의 토큰 · `data` 암호화할 바이트(비어 있으면 안 됨). 이 메서드는 배열을 바꾸지 않는다.
- `encryptBytes(byte[] data, KeyType type)`  
  `String` · 설정한 출력 형식의 토큰 · `data` 암호화할 바이트(비어 있으면 안 됨) · `type` KeyType.PASS 또는 KeyType.KEY
- `encryptBytes(byte[] data, KeyType type, String keyId)`  
  `String` · 설정한 출력 형식의 토큰 · `data` 암호화할 바이트(비어 있으면 안 됨) · `type` 기대하는 유형 · `keyId` 등록된 Key ID
- `decryptBytes(String token)`  
  `byte[]` · 원본 바이트 · `token` 암호문 토큰(ENC[v1:...] 또는 B64[...])
- `verify(String token)`  
  `boolean` · 토큰이 올바르고 등록된 키로 복호화되면 true, 토큰 자체의 문제(형식·Key ID·무결성)면 false · `token` 확인할 토큰
- `isToken(String value)`  
  `boolean` · 토큰 접두어로 시작하면 true · `value` 검사할 값(null 허용)
- `keyId()`  
  `String` · 유형·Key ID를 정하지 않은 새 암호화(encryptText(value))가 실제로 쓰는 키의 Key ID(비밀값 아님)
- `keyType()`  
  `KeyType` · encryptText(value)가 실제로 쓰는 키의 유형
- `keySource()`  
  `String` · encryptText(value)가 실제로 쓰는 키의 공급 방식: embedded, file, env, vault, aws-kms, direct(직접 준 키)
- `keys()`  
  `List<KeyInfo>` · 키 정보 목록(변경 불가)
- `encryptFile(Path in, Path out)`  
  `void` · `in` 입력 파일(일반 파일) · `out` 출력 파일(없어야 하며 상위 폴더는 있어야 한다)
- `encryptFile(Path in, Path out, KeyType type)`  
  `void` · `in` 입력 파일 · `out` 출력 파일(없어야 한다) · `type` KeyType.PASS 또는 KeyType.KEY
- `encryptFile(Path in, Path out, KeyType type, String keyId)`  
  `void` · `in` 입력 파일 · `out` 출력 파일(없어야 한다) · `type` 기대하는 유형 · `keyId` 등록된 Key ID
- `decryptFile(Path in, Path out)`  
  `void` · `in` 암호화 파일 · `out` 출력 파일(없어야 한다). POSIX에서는 소유자만 읽을 수 있는 권한(600)으로 만들어진다.

</details>

<details>
<summary>KeyType</summary>

`io.javacryptokit.KeyType`

- `PASS`  
  Passphrase에서 파생한 AES-256 키(기본).
- `KEY`  
  32바이트 AES-256 키.
- `code()`  
  `String` · 설정(crypto.key.type)과 CLI(--type)에서 쓰는 이름: pass 또는 key
- `fromCode(String code)`  
  `KeyType` · 해당 유형, 허용 이름이 아니면 null · `code` pass 또는 key

</details>

<details>
<summary>KeyInfo</summary>

`io.javacryptokit.KeyInfo`

- `keyId()`  
  `String` · Key ID(암호문·파일 헤더에 기록되는 식별자)
- `type()`  
  `KeyType` · 유형(KeyType.PASS 또는 KeyType.KEY)
- `source()`  
  `String` · 공급원 이름: embedded, file, env, vault, aws-kms
- `isTypeDefault()`  
  `boolean` · 이 유형의 기본 키이면 true(그 유형을 지정한 새 암호화가 쓰는 키)
- `isEncryptionDefault()`  
  `boolean` · 유형·Key ID를 정하지 않은 새 암호화(encryptText(value))가 쓰는 키이면 true
- `isPublicDefault()`  
  `boolean` · 공개 기본 키(공개 예제 키)이면 true. 키를 읽지 못했으면 false
- `isAvailable()`  
  `boolean` · 키를 실제로 읽을 수 있었으면 true
- `failureReason()`  
  `CredentialCryptoException.Reason` · 키를 읽지 못한 사유 코드(읽었으면 null)
- `failureMessage()`  
  `String` · 키를 읽지 못한 원인과 조치(Throwable.getMessage()와 같은 정제된 문구, 읽었으면 null). 키·경로·설정값은 들어 있지 않다.
- `fingerprint()`  
  `String` · 짧은 키 지문(앞 12자 + ... + 뒤 8자). 키를 읽지 못했으면 null
- `toString()`  
  `String` · 비밀값 없는 한 줄 요약(로그에 남겨도 된다)

</details>

<details>
<summary>CredentialCryptoException</summary>

`io.javacryptokit.CredentialCryptoException`

- `CredentialCryptoException(CredentialCryptoException.Reason reason)`  
  `reason` 실패 사유
- `CredentialCryptoException(CredentialCryptoException.Reason reason, String safeDetail)`  
  `reason` 실패 사유 · `safeDetail` 비밀값·입력값·경로가 들어 있지 않은 고정 문구(없으면 null)
- `CredentialCryptoException(CredentialCryptoException.Reason reason, String safeDetail, Throwable cause)`  
  `reason` 실패 사유 · `safeDetail` 비밀값·입력값·경로가 들어 있지 않은 고정 문구(없으면 null) · `cause` 원인 예외. 클래스 이름만 기록한다(없으면 null).
- `getReason()`  
  `CredentialCryptoException.Reason` · 실패 사유
- `getCauseType()`  
  `String` · 원인 예외의 클래스 단순 이름(예: NoSuchFileException). 없으면 null. 비밀값이 아니다.

</details>

<details>
<summary>CredentialCryptoException.Reason</summary>

`io.javacryptokit.CredentialCryptoException.Reason`

- `CONFIGURATION`  
  외부 설정 파일이 없거나 읽을 수 없음, UTF-8 아님, 허용되지 않은 설정값, 설정 경로 문제, 모호한 키 설정.
- `KEY_SOURCE`  
  키 파일·환경변수·Vault·AWS KMS에서 키를 읽을 수 없거나 키 형식(Base64)·길이(32바이트)가 올바르지 않음.
- `INVALID_INPUT`  
  빈 값, 너무 긴 값, UTF-8로 표현할 수 없는 문자, 텍스트로 해석할 수 없는 복호화 결과, 파일 입출력 문제.
- `INVALID_TOKEN`  
  ENC[v1:...]·B64[...] 또는 암호화 파일(JCKF v1/v2) 형식이 아니거나 손상됨.
- `KEY_ID_MISMATCH`  
  암호문(또는 암호화 파일)에 기록된 키 식별자와 현재 설정의 키 식별자가 다름.
- `INTEGRITY`  
  AES-GCM 인증 태그 검증 실패: 다른 키로 만들었거나 암호문이 변조·손상·잘림.
- `CRYPTO_PROVIDER`  
  실행 중인 Java가 AES-256-GCM을 제공하지 않는 등 암호화 기능 자체를 쓸 수 없음.
- `description()`  
  `String` · 사람이 읽을 수 있는 고정 설명(현재 메시지 언어, 비밀값 없음)
- `isTokenProblem()`  
  `boolean` · 암호문 자체의 문제(형식·키ID·무결성)이면 true. verify가 false로 응답하는 사유들이다.

</details>

<details>
<summary>EncryptedDataSourceFactory</summary>

`io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory`

XML Resource에서 `cryptoPool`로 Pool을 선택하는 절차는 [Tomcat Pool 선택표](../guide/tomcat-jdbc.md#topic-tomcat--32-dbcp2와-tomcat-jdbc-pool-선택)를 참고하세요.

- `EncryptedDataSourceFactory()`  
  Tomcat이 Resource의 factory 속성으로 인스턴스를 만듭니다. 애플리케이션은 JNDI로 DataSource를 조회합니다.
- `getObjectInstance(Object object, Name name, Context nameContext, Hashtable<?,?> environment)`  
  `Object` · Tomcat 공식 Pool Factory가 만든 DataSource · `object` Tomcat이 넘겨주는 Resource 정의(javax.sql.DataSource 타입의 Reference) · `name` JNDI 이름(위임 대상 Factory에 그대로 전달) · `nameContext` JNDI 컨텍스트(위임 대상 Factory에 그대로 전달) · `environment` JNDI 환경 정보(위임 대상 Factory에 그대로 전달)

</details>

<a name="api-encryption"></a>
### AES·RSA·Hybrid 암호화

[업무 예제와 선택 기준](../guide/java-encryption.md#topic-aes)

<details>
<summary>AesGcm</summary>

`io.javacryptokit.security.AesGcm`

- `IV_BYTES`  
  IV 길이(바이트).
- `TAG_BYTES`  
  인증 태그 길이(바이트).
- `generateKey(AesKeySize keySize)`  
  `byte[]` · 새 AES 키(보안 난수) · `keySize` 키 길이
- `of(AesKeySize keySize, byte[] key)`  
  `AesGcm` · 객체 · `keySize` 키 길이 · `key` 키(정확히 16 또는 32바이트, 복사해 보관한다. 호출자 배열은 호출자가 지운다)
- `fromPassphrase(AesKeySize keySize, Pbkdf2Algorithm algorithm, char[] passphrase, byte[] salt, int iterations)`  
  `AesGcm` · 객체 · `keySize` 키 길이 · `algorithm` PBKDF2 알고리즘 · `passphrase` Passphrase(바꾸지 않는다) · `salt` Salt(16~64바이트, 처음 한 번 Pbkdf2.newSalt()로 만들어 보관) · `iterations` 반복 횟수(100,000~5,000,000)
- `keySize()`  
  `AesKeySize` · 키 길이
- `encrypt(byte[] plaintext)`  
  `byte[]` · IV ‖ 암호문 ‖ 태그 · `plaintext` 평문(바꾸지 않는다)
- `encrypt(byte[] plaintext, byte[] aad)`  
  `byte[]` · IV ‖ 암호문 ‖ 태그 · `plaintext` 평문(바꾸지 않는다) · `aad` 함께 인증할 업무 값(없으면 null)
- `decrypt(byte[] sealed)`  
  `byte[]` · 평문 · `sealed` IV ‖ 암호문 ‖ 태그
- `decrypt(byte[] sealed, byte[] aad)`  
  `byte[]` · 평문 · `sealed` IV ‖ 암호문 ‖ 태그 · `aad` 암호화할 때 준 업무 값(없었으면 null)
- `encryptText(String text, Encoding encoding)`  
  `String` · 인코딩한 IV ‖ 암호문 ‖ 태그 · `text` 평문 문자열(UTF-8) · `encoding` 결과 형식(예: Encoding.BASE64_URL)
- `encryptText(String text, String aad, Encoding encoding)`  
  `String` · 인코딩한 IV ‖ 암호문 ‖ 태그 · `text` 평문 문자열(UTF-8) · `aad` 함께 인증할 업무 값(UTF-8, 없으면 null) · `encoding` 결과 형식
- `decryptText(String sealedText, Encoding encoding)`  
  `String` · 평문 문자열 · `sealedText` encryptText(java.lang.String, io.javacryptokit.security.Encoding)의 결과 · `encoding` 그 형식
- `decryptText(String sealedText, String aad, Encoding encoding)`  
  `String` · 평문 문자열 · `sealedText` encryptText(java.lang.String, io.javacryptokit.security.Encoding)의 결과 · `aad` 암호화할 때 준 업무 값(없었으면 null) · `encoding` 그 형식
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>AesKeySize</summary>

`io.javacryptokit.security.AesKeySize`

- `AES_128`  
  AES-128(키 16바이트). 외부 시스템 연동 등 꼭 필요할 때 명시적으로 선택한다.
- `AES_256`  
  AES-256(키 32바이트). 기본 권장.
- `keyBytes()`  
  `int` · 키 길이(바이트)

</details>

<details>
<summary>RsaOaep</summary>

`io.javacryptokit.security.RsaOaep`

- `maxPlaintextBytes(Key key, RsaOaepAlgorithm algorithm)`  
  `int` · 이 키·매개변수로 암호화할 수 있는 최대 평문 바이트 수 · `key` RSA 공개키 또는 개인키 · `algorithm` OAEP 매개변수
- `encrypt(PublicKey key, byte[] data)`  
  `byte[]` · 암호문(모듈러스와 같은 길이) · `key` 상대방 RSA 공개키 · `data` 평문(최대 maxPlaintextBytes(java.security.Key, io.javacryptokit.security.RsaOaepAlgorithm), 바꾸지 않는다)
- `encrypt(PublicKey key, byte[] data, RsaOaepAlgorithm algorithm)`  
  `byte[]` · 암호문 · `key` 상대방 RSA 공개키 · `data` 평문(최대 maxPlaintextBytes(java.security.Key, io.javacryptokit.security.RsaOaepAlgorithm)) · `algorithm` OAEP 매개변수
- `encryptText(PublicKey key, String text, Encoding encoding)`  
  `String` · 인코딩한 암호문 · `key` 상대방 RSA 공개키 · `text` 평문(UTF-8 바이트 수가 최대 길이 이하) · `encoding` 결과 형식
- `encryptText(PublicKey key, String text, RsaOaepAlgorithm algorithm, Encoding encoding)`  
  `String` · 인코딩한 암호문 · `key` 상대방 RSA 공개키 · `text` 평문(UTF-8) · `algorithm` OAEP 매개변수 · `encoding` 결과 형식
- `decrypt(PrivateKey key, byte[] ciphertext)`  
  `byte[]` · 평문 · `key` RSA 개인키 · `ciphertext` 암호문
- `decrypt(PrivateKey key, byte[] ciphertext, RsaOaepAlgorithm algorithm)`  
  `byte[]` · 평문 · `key` RSA 개인키 · `ciphertext` 암호문 · `algorithm` 암호화할 때 쓴 OAEP 매개변수
- `decryptText(PrivateKey key, String ciphertext, Encoding encoding)`  
  `String` · 평문 문자열 · `key` RSA 개인키 · `ciphertext` encryptText(java.security.PublicKey, java.lang.String, io.javacryptokit.security.Encoding) 결과 · `encoding` 그 형식
- `decryptText(PrivateKey key, String ciphertext, RsaOaepAlgorithm algorithm, Encoding encoding)`  
  `String` · 평문 문자열 · `key` RSA 개인키 · `ciphertext` encryptText(java.security.PublicKey, java.lang.String, io.javacryptokit.security.Encoding) 결과 · `algorithm` 암호화할 때 쓴 OAEP 매개변수 · `encoding` 그 형식

</details>

<details>
<summary>RsaOaepAlgorithm</summary>

`io.javacryptokit.security.RsaOaepAlgorithm`

- `SHA256`  
  RSAES-OAEP, SHA-256 + MGF1-SHA256(기본). 최대 평문 = 모듈러스 바이트 - 66(RSA 2048: 190, 3072: 318바이트).
- `SHA512`  
  RSAES-OAEP, SHA-512 + MGF1-SHA512. 최대 평문 = 모듈러스 바이트 - 130(RSA 2048: 126, 3072: 254바이트).
- `hashLength()`  
  `int` · 해시 출력 길이(바이트, 최대 평문 계산의 hLen)

</details>

<details>
<summary>HybridEncryption</summary>

`io.javacryptokit.security.HybridEncryption`

- `MAX_PLAINTEXT_BYTES`  
  평문 최대 크기(64MiB).
- `MAX_AAD_BYTES`  
  업무 AAD 최대 크기(64KiB).
- `encrypt(PublicKey recipient, byte[] plaintext)`  
  `byte[]` · JCKH 봉투 · `recipient` 수신자 RSA 공개키(2048비트 이상) · `plaintext` 평문(최대 64MiB, 바꾸지 않는다)
- `encrypt(PublicKey recipient, byte[] plaintext, byte[] aad)`  
  `byte[]` · JCKH 봉투 · `recipient` 수신자 RSA 공개키(2048비트 이상) · `plaintext` 평문(최대 64MiB) · `aad` 함께 인증할 업무 값(없으면 null, 최대 64KiB)
- `decrypt(PrivateKey recipientKey, byte[] envelope)`  
  `byte[]` · 평문 · `recipientKey` 수신자 RSA 개인키 · `envelope` JCKH 봉투
- `decrypt(PrivateKey recipientKey, byte[] envelope, byte[] aad)`  
  `byte[]` · 평문 · `recipientKey` 수신자 RSA 개인키 · `envelope` JCKH 봉투 · `aad` 암호화할 때 준 업무 값(없었으면 null)
- `encryptText(PublicKey recipient, String text, Encoding encoding)`  
  `String` · 인코딩한 JCKH 봉투 · `recipient` 수신자 RSA 공개키 · `text` 평문 · `encoding` 결과 형식(예: Encoding.BASE64_URL)
- `encryptText(PublicKey recipient, String text, String aad, Encoding encoding)`  
  `String` · 인코딩한 JCKH 봉투 · `recipient` 수신자 RSA 공개키 · `text` 평문(UTF-8) · `aad` 함께 인증할 업무 값(UTF-8, 없으면 null) · `encoding` 결과 형식
- `decryptText(PrivateKey recipientKey, String envelope, Encoding encoding)`  
  `String` · 평문 문자열 · `recipientKey` 수신자 RSA 개인키 · `envelope` encryptText(java.security.PublicKey, java.lang.String, io.javacryptokit.security.Encoding) 결과 · `encoding` 그 형식
- `decryptText(PrivateKey recipientKey, String envelope, String aad, Encoding encoding)`  
  `String` · 평문 문자열 · `recipientKey` 수신자 RSA 개인키 · `envelope` encryptText(java.security.PublicKey, java.lang.String, io.javacryptokit.security.Encoding) 결과 · `aad` 암호화할 때 준 업무 값(없었으면 null) · `encoding` 그 형식

</details>

<a name="api-integrity"></a>
### 체크섬·요청 인증·서명

[업무 예제와 선택 기준](../guide/data-integrity.md#topic-hmac)

<details>
<summary>Digests</summary>

`io.javacryptokit.security.Digests`

- `sha256(byte[] data)`  
  `byte[]` · SHA-256(data)
- `sha256Hex(String text)`  
  `String` · SHA-256(UTF-8(text))의 소문자 16진수 64자
- `sha256Hex(byte[] data)`  
  `String` · SHA-256(data)의 소문자 16진수 64자
- `sha256File(Path file)`  
  `String` · 파일 SHA-256의 소문자 16진수 64자 · `file` 파일
- `hash(DigestAlgorithm algorithm, byte[] data)`  
  `byte[]` · 해시 · `algorithm` 알고리즘 · `data` 원본(바꾸지 않는다)
- `hash(DigestAlgorithm algorithm, String text)`  
  `byte[]` · 해시 · `algorithm` 알고리즘 · `text` 원본 문자열(UTF-8로 해시)
- `hash(DigestAlgorithm algorithm, byte[] data, Encoding encoding)`  
  `String` · 인코딩한 해시 · `algorithm` 알고리즘 · `data` 원본 · `encoding` 출력 형식
- `hash(DigestAlgorithm algorithm, String text, Encoding encoding)`  
  `String` · 인코딩한 해시 · `algorithm` 알고리즘 · `text` 원본 문자열(UTF-8로 해시) · `encoding` 출력 형식
- `hashFile(DigestAlgorithm algorithm, Path file)`  
  `byte[]` · 해시 · `algorithm` 알고리즘 · `file` 파일(바꾸지 않는다)
- `hashFile(DigestAlgorithm algorithm, Path file, Encoding encoding)`  
  `String` · 인코딩한 해시 · `algorithm` 알고리즘 · `file` 파일 · `encoding` 출력 형식
- `verifyFile(DigestAlgorithm algorithm, Path file, String expected, Encoding encoding)`  
  `boolean` · 같으면 true, 다르면 false · `algorithm` 알고리즘 · `file` 파일 · `expected` 신뢰할 수 있는 경로로 받은 기대 해시 · `encoding` 기대값의 형식

</details>

<details>
<summary>DigestAlgorithm</summary>

`io.javacryptokit.security.DigestAlgorithm`

- `SHA256`  
  SHA-256(결과 32바이트). 기본값.
- `SHA512`  
  SHA-512(결과 64바이트).
- `length()`  
  `int` · 결과 길이(바이트)

</details>

<details>
<summary>Hmac</summary>

`io.javacryptokit.security.Hmac`

- `MIN_KEY_BYTES`  
  일반 경로의 최소 키 길이(바이트, 256비트).
- `generateKey()`  
  `byte[]` · 새 HMAC-SHA256 키(32바이트 보안 난수)
- `generateKey(HmacAlgorithm algorithm)`  
  `byte[]` · 새 키(SHA256 32바이트, SHA512 64바이트 보안 난수) · `algorithm` 알고리즘
- `of(byte[] key)`  
  `Hmac` · 객체 · `key` 32바이트 이상 키(복사해 보관한다)
- `of(HmacAlgorithm algorithm, byte[] key)`  
  `Hmac` · 객체 · `algorithm` 알고리즘 · `key` 32바이트 이상 키(복사해 보관한다)
- `ofExternalKey(HmacAlgorithm algorithm, byte[] key)`  
  `Hmac` · 객체 · `algorithm` 알고리즘 · `key` 외부 시스템의 비밀(복사해 보관한다)
- `algorithm()`  
  `HmacAlgorithm` · 알고리즘
- `sign(byte[] data)`  
  `byte[]` · MAC · `data` 원본(바꾸지 않는다)
- `sign(String text)`  
  `byte[]` · MAC · `text` 원본 문자열(UTF-8)
- `sign(byte[] data, Encoding encoding)`  
  `String` · 인코딩한 MAC · `data` 원본 · `encoding` 출력 형식
- `sign(String text, Encoding encoding)`  
  `String` · 인코딩한 MAC · `text` 원본 문자열(UTF-8) · `encoding` 출력 형식
- `verify(byte[] data, byte[] mac)`  
  `boolean` · MAC이 맞으면 true(null·빈 값·길이가 다른 값은 false) · `data` 원본 · `mac` 받은 MAC
- `verify(byte[] data, String mac, Encoding encoding)`  
  `boolean` · MAC이 맞으면 true · `data` 원본 · `mac` 받은 MAC 문자열 · `encoding` MAC 문자열의 형식
- `verify(String text, String mac, Encoding encoding)`  
  `boolean` · MAC이 맞으면 true · `text` 원본 문자열(UTF-8) · `mac` 받은 MAC 문자열 · `encoding` MAC 문자열의 형식
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>HmacAlgorithm</summary>

`io.javacryptokit.security.HmacAlgorithm`

- `SHA256`  
  HMAC-SHA256(결과 32바이트, 새 키 32바이트). 기본값.
- `SHA512`  
  HMAC-SHA512(결과 64바이트, 새 키 64바이트).
- `length()`  
  `int` · MAC 결과 길이(바이트) = Hmac.generateKey(HmacAlgorithm)가 만드는 키 길이

</details>

<details>
<summary>RequestAuth</summary>

`io.javacryptokit.security.RequestAuth`

- `DEFAULT_MAX_SKEW`  
  기본 허용 시각 오차(5분).
- `MAX_ALLOWED_SKEW`  
  지정할 수 있는 최대 허용 오차(15분).
- `of(Hmac hmac)`  
  `RequestAuth` · 객체 · `hmac` 양쪽이 공유하는 키의 Hmac
- `of(Hmac hmac, Duration maxSkew, Clock clock)`  
  `RequestAuth` · 객체 · `hmac` 양쪽이 공유하는 키의 Hmac · `maxSkew` 허용 시각 오차(1초~15분) · `clock` 시계(시험·고정 시각용)
- `sign(byte[] request)`  
  `RequestAuth.Signed` · 시각·Nonce·MAC · `request` 서명할 요청 바이트(바꾸지 않는다)
- `verify(byte[] request, String timestamp, String nonce, String mac)`  
  `RequestAuth.Result` · 판정 · `request` 받은 요청 바이트(보낸 쪽과 같은 규칙으로 만든 값) · `timestamp` 받은 시각 문자열 · `nonce` 받은 Nonce · `mac` 받은 MAC(Base64URL)

</details>

<details>
<summary>RequestAuth.Result</summary>

`io.javacryptokit.security.RequestAuth.Result`

- `VALID`  
  MAC이 맞고 시각이 허용 범위 안.
- `MALFORMED`  
  시각·Nonce·MAC 형식 오류.
- `TIMESTAMP_OUT_OF_RANGE`  
  시각이 허용 오차를 벗어남(오래된 요청·시계 차이).
- `BAD_MAC`  
  MAC 불일치(다른 키·변조).
- `isValid()`  
  `boolean` · VALID이면 true

</details>

<details>
<summary>RequestAuth.Signed</summary>

`io.javacryptokit.security.RequestAuth.Signed`

- `timestamp()`  
  `String` · Unix 초(10진수)
- `nonce()`  
  `String` · Nonce(Base64URL 22자)
- `mac()`  
  `String` · MAC(Base64URL)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>Signatures</summary>

`io.javacryptokit.security.Signatures`

- `DEFAULT_RSA_BITS`  
  새 RSA 키 기본 길이(비트).
- `MIN_RSA_BITS`  
  RSA 최소 길이(비트).
- `generateKeyPair(SignatureAlgorithm algorithm)`  
  `KeyPair` · 키 쌍(저장·보관은 호출자 책임) · `algorithm` 알고리즘
- `generateRsaKeyPair(int bits)`  
  `KeyPair` · RSA 키 쌍 · `bits` 2048, 3072 또는 4096
- `sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] data)`  
  `byte[]` · 서명 · `algorithm` 알고리즘 · `key` 개인키 · `data` 원본(바꾸지 않는다)
- `sign(SignatureAlgorithm algorithm, PrivateKey key, String text)`  
  `byte[]` · 서명 · `algorithm` 알고리즘 · `key` 개인키 · `text` 원본 문자열(UTF-8)
- `sign(SignatureAlgorithm algorithm, PrivateKey key, byte[] data, Encoding encoding)`  
  `String` · 인코딩한 서명 · `algorithm` 알고리즘 · `key` 개인키 · `data` 원본 · `encoding` 서명 출력 형식
- `sign(SignatureAlgorithm algorithm, PrivateKey key, String text, Encoding encoding)`  
  `String` · 인코딩한 서명 · `algorithm` 알고리즘 · `key` 개인키 · `text` 원본 문자열(UTF-8) · `encoding` 서명 출력 형식
- `signFile(SignatureAlgorithm algorithm, PrivateKey key, Path file)`  
  `byte[]` · 서명 · `algorithm` 알고리즘 · `key` 개인키 · `file` 파일(바꾸지 않는다)
- `verify(SignatureAlgorithm algorithm, PublicKey key, byte[] data, byte[] signature)`  
  `boolean` · 서명이 맞으면 true(형식이 깨진 서명·null·빈 값은 false) · `algorithm` 알고리즘 · `key` 공개키 · `data` 원본 · `signature` 서명
- `verify(SignatureAlgorithm algorithm, PublicKey key, byte[] data, String signature, Encoding encoding)`  
  `boolean` · 서명이 맞으면 true · `algorithm` 알고리즘 · `key` 공개키 · `data` 원본 · `signature` 서명 문자열 · `encoding` 서명 문자열의 형식
- `verify(SignatureAlgorithm algorithm, PublicKey key, String text, String signature, Encoding encoding)`  
  `boolean` · 서명이 맞으면 true · `algorithm` 알고리즘 · `key` 공개키 · `text` 원본 문자열(UTF-8) · `signature` 서명 문자열 · `encoding` 서명 문자열의 형식
- `verifyFile(SignatureAlgorithm algorithm, PublicKey key, Path file, byte[] signature)`  
  `boolean` · 서명이 맞으면 true · `algorithm` 알고리즘 · `key` 공개키 · `file` 파일(바꾸지 않는다) · `signature` 서명
- `checkKey(SignatureAlgorithm algorithm, Key key)`  
  `void` · `algorithm` 알고리즘 · `key` 개인키 또는 공개키

</details>

<details>
<summary>SignatureAlgorithm</summary>

`io.javacryptokit.security.SignatureAlgorithm`

- `RSA_SHA256`  
  RSASSA-PKCS1-v1_5 + SHA-256(SHA256withRSA). RSA 2048비트 이상. JWT RS256과 같은 서명.
- `ECDSA_P256_SHA256`  
  ECDSA P-256 + SHA-256, 서명은 ASN.1 DER(JCA·OpenSSL 기본 형식, 길이 가변).
- `ECDSA_P256_SHA256_P1363`  
  ECDSA P-256 + SHA-256, 서명은 고정 64바이트 R‖S(IEEE P1363, WebCrypto·JWT ES256 형식).
- `keyAlgorithm()`  
  `String` · 키 알고리즘(RSA 또는 EC)

</details>

<details>
<summary>PemKeys</summary>

`io.javacryptokit.security.PemKeys`

- `readPrivateKey(String pem)`  
  `PrivateKey` · 개인키 · `pem` PKCS#8 PEM 문자열
- `readPrivateKey(byte[] der)`  
  `PrivateKey` · 개인키 · `der` PKCS#8 DER
- `readPrivateKeyFile(Path file)`  
  `PrivateKey` · 개인키 · `file` PKCS#8 PEM 또는 DER 파일
- `readPublicKey(String pem)`  
  `PublicKey` · 공개키 · `pem` SubjectPublicKeyInfo PEM 문자열
- `readPublicKey(byte[] der)`  
  `PublicKey` · 공개키 · `der` SubjectPublicKeyInfo DER
- `readPublicKeyFile(Path file)`  
  `PublicKey` · 공개키 · `file` SubjectPublicKeyInfo PEM 또는 DER 파일
- `toPem(PrivateKey key)`  
  `String` · PKCS#8 PEM(-----BEGIN PRIVATE KEY-----, 64자 줄바꿈). 비밀이므로 안전하게 보관한다 · `key` 개인키(RSA·EC)
- `toPem(PublicKey key)`  
  `String` · SubjectPublicKeyInfo PEM(-----BEGIN PUBLIC KEY-----) · `key` 공개키(RSA·EC)
- `toDer(Key key)`  
  `byte[]` · PKCS#8(개인키) 또는 SubjectPublicKeyInfo(공개키) DER · `key` 개인키 또는 공개키

</details>

<a name="api-utilities"></a>
### 난수·비밀번호·키 파생

[업무 예제와 선택 기준](../guide/security-utilities.md#topic-random)

<details>
<summary>SecureRandoms</summary>

`io.javacryptokit.security.SecureRandoms`

- `DEFAULT_TOKEN_BYTES`  
  token()의 기본 길이(바이트, 256비트).
- `DEFAULT_NONCE_BYTES`  
  nonce()의 기본 길이(바이트, 128비트).
- `MIN_TOKEN_BYTES`  
  토큰·Nonce 최소 길이(바이트, 128비트).
- `MAX_TOKEN_BYTES`  
  토큰·Nonce 최대 길이(바이트).
- `MAX_BYTES`  
  bytes(int) 최대 길이(바이트).
- `string(int length, SecureRandoms.Alphabet alphabet)`  
  `String` · 접두어 없는 고정 길이 난수 문자열 · `length` 생성할 문자 수(1~1,024) · `alphabet` 사용할 문자 집합
- `string(int length, SecureRandoms.Alphabet alphabet, String prefix)`  
  `String` · 접두어와 난수 문자. 첫 자리의 0도 유지한다 · `length` 접두어를 제외한 난수 문자 수(1~1,024) · `alphabet` 사용할 문자 집합 · `prefix` 결과 앞에 그대로 붙일 문자열(빈 문자열 허용, UTF-16 단위 최대 1,024)
- `bytes(int length)`  
  `byte[]` · 새 난수 바이트 · `length` 바이트 수(1~65,536)
- `token()`  
  `String` · 32바이트 난수의 Base64URL(패딩 없음, 43자)
- `token(int byteLength)`  
  `String` · Base64URL(패딩 없음) 토큰 · `byteLength` 난수 바이트 수(16~1,024). 문자 수가 아니다
- `token(int byteLength, Encoding encoding)`  
  `String` · 토큰 문자열 · `byteLength` 난수 바이트 수(16~1,024) · `encoding` 출력 형식(예: Encoding.HEX)
- `nonce()`  
  `String` · 16바이트 난수의 Base64URL(패딩 없음, 22자)
- `uuidV4()`  
  `UUID` · 새 UUID 버전 4(122비트 난수, version·variant 비트는 RFC 9562 규격)

</details>

<details>
<summary>SecureRandoms.Alphabet</summary>

`io.javacryptokit.security.SecureRandoms.Alphabet`

- `DIGITS`  
  0–9
- `UPPER`  
  A–Z
- `LOWER`  
  a–z
- `LETTERS`  
  A–Z, a–z
- `UPPER_DIGITS`  
  A–Z, 0–9
- `LOWER_DIGITS`  
  a–z, 0–9
- `ALPHANUMERIC`  
  A–Z, a–z, 0–9

</details>

<details>
<summary>Passwords</summary>

`io.javacryptokit.security.Passwords`

- `MIN_VERIFY_ITERATIONS`  
  검증할 때 받는 최소 반복 횟수(예전 값 검증용, 새 해시는 Pbkdf2.MIN_ITERATIONS 이상).
- `hash(char[] password)`  
  `String` · 저장 문자열 · `password` 비밀번호(바꾸지 않는다)
- `hash(char[] password, Pbkdf2Algorithm algorithm, int iterations)`  
  `String` · 저장 문자열 · `password` 비밀번호(바꾸지 않는다) · `algorithm` 알고리즘 · `iterations` 반복 횟수(100,000~5,000,000)
- `verify(char[] password, String stored)`  
  `boolean` · 맞으면 true. 다르거나, 입력이 해시할 수 없는 값(빈 값·공백만·제어문자 등)이면 false · `password` 입력 비밀번호(바꾸지 않는다) · `stored` hash(char[])가 만든 저장 문자열
- `needsRehash(String stored)`  
  `boolean` · 알고리즘이 다르거나 반복 횟수가 정책보다 적으면 true · `stored` 저장 문자열
- `needsRehash(String stored, Pbkdf2Algorithm algorithm, int iterations)`  
  `boolean` · 알고리즘이 다르거나 반복 횟수가 정책보다 적으면 true · `stored` 저장 문자열 · `algorithm` 현재 정책의 알고리즘 · `iterations` 현재 정책의 반복 횟수

</details>

<details>
<summary>Pbkdf2</summary>

`io.javacryptokit.security.Pbkdf2`

- `SALT_BYTES`  
  newSalt()가 만드는 Salt 길이(바이트).
- `MIN_SALT_BYTES`  
  Salt 최소 길이(바이트).
- `MAX_SALT_BYTES`  
  Salt 최대 길이(바이트).
- `MIN_ITERATIONS`  
  최소 반복 횟수.
- `MAX_ITERATIONS`  
  최대 반복 횟수(지나친 연산으로 인한 서비스 거부 방지).
- `MAX_PASSPHRASE_BYTES`  
  Passphrase 최대 길이(UTF-8 바이트).
- `newSalt()`  
  `byte[]` · 새 16바이트 보안 난수 Salt
- `deriveKey(Pbkdf2Algorithm algorithm, char[] passphrase, byte[] salt, int iterations, int keyBytes)`  
  `byte[]` · 파생 키(호출자가 다 쓰면 지운다) · `algorithm` 알고리즘 · `passphrase` Passphrase(바꾸지 않는다) · `salt` Salt(16~64바이트, 바꾸지 않는다) · `iterations` 반복 횟수(100,000~5,000,000) · `keyBytes` 키 길이(16~64바이트)

</details>

<details>
<summary>Pbkdf2Algorithm</summary>

`io.javacryptokit.security.Pbkdf2Algorithm`

- `SHA256`  
  PBKDF2-HMAC-SHA256(권장 반복 600,000회). 기본값이며 관리형 pass 키와 같은 방식이다.
- `SHA512`  
  PBKDF2-HMAC-SHA512(권장 반복 210,000회).
- `recommendedIterations()`  
  `int` · 권장 반복 횟수(SHA256 600,000, SHA512 210,000)
- `id()`  
  `String` · 저장 형식에 쓰는 이름(pbkdf2-sha256·pbkdf2-sha512)
- `jcaName()`  
  `String` · JCA 알고리즘 이름(PBKDF2WithHmacSHA256·PBKDF2WithHmacSHA512, 다른 시스템과 맞출 때 참고)

</details>

<details>
<summary>Hkdf</summary>

`io.javacryptokit.security.Hkdf`

- `derive(byte[] ikm, byte[] salt, byte[] info, int length)`  
  `byte[]` · 파생 키 · `ikm` 입력 키 재료(바꾸지 않는다) · `salt` Salt(없으면 null) · `info` 용도 구분 값(없으면 null) · `length` 출력 길이(바이트)
- `derive(HmacAlgorithm algorithm, byte[] ikm, byte[] salt, byte[] info, int length)`  
  `byte[]` · 파생 키 · `algorithm` 알고리즘 · `ikm` 입력 키 재료 · `salt` Salt(없으면 null) · `info` 용도 구분 값(없으면 null) · `length` 출력 길이(바이트)
- `derive(HmacAlgorithm algorithm, byte[] ikm, byte[] salt, String info, int length)`  
  `byte[]` · 파생 키 · `algorithm` 알고리즘 · `ikm` 입력 키 재료 · `salt` Salt(없으면 null) · `info` 용도 구분 문자열(UTF-8) · `length` 출력 길이(바이트)
- `extract(HmacAlgorithm algorithm, byte[] salt, byte[] ikm)`  
  `byte[]` · PRK(해시 길이) · `algorithm` 알고리즘 · `salt` Salt(없으면 null → 해시 길이의 0바이트) · `ikm` 입력 키 재료(비어 있으면 안 된다)
- `expand(HmacAlgorithm algorithm, byte[] prk, byte[] info, int length)`  
  `byte[]` · 파생 키 · `algorithm` 알고리즘 · `prk` PRK(해시 길이 이상) · `info` 용도 구분 값(없으면 null) · `length` 출력 길이(1 ~ 255 × 해시 길이)

</details>

<details>
<summary>Bytes</summary>

`io.javacryptokit.security.Bytes`

- `utf8(String text)`  
  `byte[]` · UTF-8 바이트 · `text` 문자열
- `utf8String(byte[] data)`  
  `String` · 문자열 · `data` UTF-8 바이트
- `equalsConstantTime(byte[] a, byte[] b)`  
  `boolean` · 둘 다 비어 있지 않고 내용이 같으면 true. 하나라도 null·빈 값이면 false · `a` 값(바꾸지 않는다) · `b` 값(바꾸지 않는다)
- `equalsConstantTime(String a, String b)`  
  `boolean` · 둘 다 비어 있지 않고 같으면 true. 하나라도 null·빈 문자열이거나 UTF-8로 나타낼 수 없으면 false · `a` 값 · `b` 값

</details>

<details>
<summary>Encoding</summary>

`io.javacryptokit.security.Encoding`

- `HEX`  
  16진수.
- `BASE64`  
  표준 Base64(패딩 포함).
- `BASE64_URL`  
  Base64URL(패딩 없음).
- `BASE32`  
  Base32(RFC 4648, 대문자·패딩 없음).
- `encode(byte[] data)`  
  `String` · 인코딩한 문자열 · `data` 원본(바꾸지 않는다)
- `decode(String text)`  
  `byte[]` · 원래 바이트 · `text` 인코딩한 문자열

</details>

<a name="api-certs"></a>
### 인증서·키 저장소

[업무 예제와 선택 기준](../guide/certificates-keystores.md#topic-certificates)

<details>
<summary>Certificates</summary>

`io.javacryptokit.security.Certificates`

- `read(String pem)`  
  `X509Certificate` · 인증서 · `pem` 인증서 하나의 PEM
- `read(byte[] derOrPem)`  
  `X509Certificate` · 인증서 · `derOrPem` 인증서 하나의 DER 또는 PEM 바이트
- `readFile(Path file)`  
  `X509Certificate` · 인증서 · `file` 인증서 하나의 PEM 또는 DER 파일
- `readChain(String pem)`  
  `List<X509Certificate>` · 인증서 목록(입력 순서) · `pem` 여러 인증서를 이어 붙인 PEM(보통 끝 인증서 → 중간 인증서 순서)
- `readChainFile(Path file)`  
  `List<X509Certificate>` · 인증서 목록(입력 순서) · `file` 여러 인증서 PEM 파일
- `info(X509Certificate certificate)`  
  `CertificateInfo` · 분석 결과(신뢰 검증 아님) · `certificate` 인증서
- `validateChain(List<X509Certificate> chain, Collection<X509Certificate> trustAnchors, Instant at)`  
  `void` · `chain` 끝(서버·서명자) 인증서부터 중간 인증서 순서. 끝에 신뢰 루트가 붙어 있으면 제외하고 검증한다 · `trustAnchors` 신뢰하는 루트(또는 중간) 인증서 · `at` 검증 기준 시각

</details>

<details>
<summary>CertificateInfo</summary>

`io.javacryptokit.security.CertificateInfo`

- `subject()`  
  `String` · 주체 DN(RFC 2253)
- `issuer()`  
  `String` · 발급자 DN(RFC 2253)
- `serialNumberHex()`  
  `String` · 일련번호(소문자 16진수)
- `notBefore()`  
  `Instant` · 유효 시작 시각
- `notAfter()`  
  `Instant` · 유효 종료 시각
- `publicKeyAlgorithm()`  
  `String` · 공개키 알고리즘(예: RSA, EC)
- `publicKeySize()`  
  `int` · 공개키 크기(RSA 모듈러스 비트, EC 곡선 필드 비트, 그 밖은 0)
- `signatureAlgorithm()`  
  `String` · 서명 알고리즘(예: SHA256withRSA)
- `sha256Fingerprint()`  
  `String` · DER 전체의 SHA-256 지문(대문자 16진수 콜론 구분, openssl x509 -fingerprint -sha256·keytool과 같은 표기)
- `subjectAlternativeNames()`  
  `List<String>` · 주체 대체 이름(DNS:·IP:·EMAIL:·URI: 접두어, 없으면 빈 목록)
- `isValidAt(Instant time)`  
  `boolean` · notBefore ≤ time ≤ notAfter이면 true · `time` 기준 시각
- `daysUntilExpiry(Instant now)`  
  `long` · 만료까지 남은 날(이미 지났으면 음수) · `now` 기준 시각
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>KeyStoreReader</summary>

`io.javacryptokit.security.KeyStoreReader`

- `MAX_BYTES`  
  읽을 수 있는 최대 크기(16MiB).
- `load(Path file, KeyStoreType type, char[] storePassword)`  
  `KeyStoreReader` · 읽은 저장소 · `file` 키 저장소 파일(읽기만 한다) · `type` 형식 · `storePassword` 저장소 비밀번호(바꾸지 않는다)
- `load(InputStream input, KeyStoreType type, char[] storePassword)`  
  `KeyStoreReader` · 읽은 저장소 · `input` 키 저장소 내용(닫지 않는다, 최대 16MiB) · `type` 형식 · `storePassword` 저장소 비밀번호
- `load(byte[] content, KeyStoreType type, char[] storePassword)`  
  `KeyStoreReader` · 읽은 저장소 · `content` 키 저장소 바이트(바꾸지 않는다) · `type` 형식 · `storePassword` 저장소 비밀번호
- `type()`  
  `KeyStoreType` · 형식
- `aliases()`  
  `List<String>` · 별칭 목록(정렬)
- `isPrivateKeyEntry(String alias)`  
  `boolean` · 개인키(+인증서) 엔트리이면 true · `alias` 별칭
- `isCertificateEntry(String alias)`  
  `boolean` · 신뢰 인증서(인증서만) 엔트리이면 true · `alias` 별칭
- `privateKey(String alias, char[] keyPassword)`  
  `PrivateKey` · 개인키 · `alias` 별칭 · `keyPassword` 엔트리 비밀번호(PKCS12는 보통 저장소 비밀번호와 같다, 바꾸지 않는다)
- `certificate(String alias)`  
  `X509Certificate` · X.509 인증서 · `alias` 별칭(개인키 엔트리면 그 인증서, 인증서 엔트리면 그 인증서)
- `publicKey(String alias)`  
  `PublicKey` · 그 인증서의 공개키 · `alias` 별칭
- `certificateChain(String alias)`  
  `List<X509Certificate>` · 인증서 체인(끝 인증서부터, 인증서 엔트리면 그 인증서 하나) · `alias` 개인키 엔트리의 별칭
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>KeyStoreType</summary>

`io.javacryptokit.security.KeyStoreType`

- `PKCS12`  
  PKCS#12(.p12·.pfx).
- `JKS`  
  Java KeyStore(.jks).

</details>

<a name="api-otp"></a>
### 일회용 코드

[업무 예제와 선택 기준](../guide/authentication.md#topic-otp)

<details>
<summary>Hotp</summary>

`io.javacryptokit.security.Hotp`

- `MIN_SECRET_BYTES`  
  비밀키 최소 길이(바이트, RFC 4226: 128비트 이상).
- `DEFAULT_DIGITS`  
  기본 자릿수.
- `MAX_LOOK_AHEAD`  
  최대 lookAhead.
- `generateSecret()`  
  `byte[]` · 새 비밀키(20바이트 보안 난수)
- `of(byte[] secret)`  
  `Hotp` · 6자리 HOTP · `secret` 비밀키(16바이트 이상, 복사해 보관)
- `of(byte[] secret, int digits)`  
  `Hotp` · HOTP · `secret` 비밀키(16바이트 이상) · `digits` 자릿수(6~8)
- `generate(long counter)`  
  `String` · 코드(앞자리 0 포함) · `counter` 카운터(0 이상)
- `verify(String code, long counter, int lookAhead)`  
  `OptionalLong` · 일치한 카운터(없거나 코드 형식이 아니면 빈 값) · `code` 입력 코드 · `counter` 확인을 시작할 카운터(0 이상) · `lookAhead` 앞으로 더 확인할 개수(0~100)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>Totp</summary>

`io.javacryptokit.security.Totp`

- `DEFAULT_PERIOD`  
  기본 주기.
- `MAX_WINDOW`  
  최대 허용창(앞뒤 구간 수).
- `generateSecret()`  
  `byte[]` · 새 SHA1용 비밀키(20바이트 보안 난수)
- `generateSecret(OtpAlgorithm algorithm)`  
  `byte[]` · 새 비밀키(SHA1 20, SHA256 32, SHA512 64바이트) · `algorithm` 알고리즘
- `of(byte[] secret)`  
  `Totp` · SHA1·6자리·30초 TOTP · `secret` 비밀키(16바이트 이상, 복사해 보관)
- `of(byte[] secret, OtpAlgorithm algorithm, int digits, Duration period)`  
  `Totp` · TOTP · `secret` 비밀키(16바이트 이상) · `algorithm` 알고리즘 · `digits` 자릿수(6~8) · `period` 주기(15~300초, 초 단위)
- `timeStep(Instant time)`  
  `long` · 그 시각의 시간 구간 번호 · `time` 시각(1970년 이후)
- `generate(Instant time)`  
  `String` · 그 시각의 코드(앞자리 0 포함) · `time` 시각
- `generate(Clock clock)`  
  `String` · 현재 코드 · `clock` 토큰 시각을 검증할 때 쓸 시계. 기본은 시스템 UTC이며, 고정 시각 시험에서는 `Clock.fixed`를 쓸 수 있습니다.
- `verify(String code, Instant time, int window)`  
  `OptionalLong` · 일치한 시간 구간 번호(없거나 형식이 아니면 빈 값) · `code` 입력 코드 · `time` 기준 시각 · `window` 앞뒤로 받을 구간 수(0~10)
- `verify(String code, Clock clock, int window)`  
  `OptionalLong` · 일치한 시간 구간 번호 · `code` 입력 코드 · `clock` 시계 · `window` 앞뒤로 받을 구간 수(0~10)
- `otpauthUri(String issuer, String accountName)`  
  `String` · otpauth URI · `issuer` 서비스 이름(1~100자, : 불가) · `accountName` 사용자 계정(1~100자, : 불가)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>OtpAlgorithm</summary>

`io.javacryptokit.security.OtpAlgorithm`

- `SHA1`  
  HMAC-SHA1(새 비밀키 20바이트). HOTP·TOTP 기본값.
- `SHA256`  
  HMAC-SHA256(새 비밀키 32바이트). TOTP 전용.
- `SHA512`  
  HMAC-SHA512(새 비밀키 64바이트). TOTP 전용.
- `secretBytes()`  
  `int` · 새 비밀키 길이(바이트)

</details>

<a name="api-jwt"></a>
### JWT 서명과 검증

[업무 예제와 선택 기준](../guide/authentication.md#topic-jwt)

<details>
<summary>Jwt</summary>

`io.javacryptokit.jwt.Jwt`

- `builder()`  
  `Jwt.Builder` · 시스템 UTC 시계를 쓰는 생성기
- `builder(Clock clock)`  
  `Jwt.Builder` · 생성기 · `clock` 발급 시각·만료 계산에 쓸 시계
- `parseUnverified(String token)`  
  `UnverifiedJwt` · 미검증 분석 결과 · `token` compact JWS

</details>

<details>
<summary>Jwt.Builder</summary>

`io.javacryptokit.jwt.Jwt.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `type(String type)`  
  `type` 헤더 typ(기본 JWT, 예: at+jwt). null이면 typ를 쓰지 않는다
- `issuer(String issuer)`  
  `issuer` 토큰 발급자를 나타낼 iss 문자열. 검증기의 기대 발급자와 일치해야 합니다.
- `subject(String subject)`  
  `subject` 토큰이 가리키는 사용자 또는 서비스의 식별자(sub).
- `audience(String... audience)`  
  `audience` aud(하나면 문자열, 둘 이상이면 배열)
- `expiresAt(Instant expiresAt)`  
  `expiresAt` 토큰을 더 이상 수락하지 않을 절대 시각(exp). 일반 검증기의 기본 정책에서 필수입니다.
- `expiresIn(Duration lifetime)`  
  `lifetime` 발급 시각부터 만료까지(1초 이상)
- `notBefore(Instant notBefore)`  
  `notBefore` 검증기가 토큰을 수락할 수 있는 가장 이른 시각(nbf).
- `issuedAt(Instant issuedAt)`  
  `issuedAt` iat(기본은 현재 시각). null이면 iat를 쓰지 않는다
- `jwtId(String jwtId)`  
  `jwtId` 토큰 한 건을 식별할 문자열(jti). 재사용 추적이 필요하면 애플리케이션에서 기록합니다.
- `randomJwtId()`  
  보안 난수로 jti를 생성합니다.
- `claim(String name, String value)`  
  `name` 업무 클레임 이름(표준 이름 불가) · `value` 문자열
- `claim(String name, long value)`  
  `name` 업무 클레임 이름 · `value` 정수
- `claim(String name, boolean value)`  
  `name` 업무 클레임 이름 · `value` 논리 값
- `claim(String name, List<String> values)`  
  `name` 업무 클레임 이름 · `values` 문자열 배열
- `claim(String name, Map<String,?> value)`  
  `name` 업무 클레임 이름 · `value` 중첩 객체(값은 문자열·정수·논리·null·목록·객체만)
- `sign(JwtKey key)`  
  `String` · header.payload.signature · `key` 서명 키(HS256 비밀키 또는 개인키)

</details>

<details>
<summary>JwtKey</summary>

`io.javacryptokit.jwt.JwtKey`

- `MIN_HS256_BYTES`  
  HS256 비밀키 최소 길이(바이트).
- `hs256(byte[] secret)`  
  `JwtKey` · HS256 키(서명·검증) · `secret` 공유 비밀키(32바이트 이상, 복사해 보관)
- `rs256(PrivateKey key)`  
  `JwtKey` · RS256 서명 키 · `key` RSA 개인키(2048비트 이상)
- `rs256(PublicKey key)`  
  `JwtKey` · RS256 검증 키 · `key` RSA 공개키(2048비트 이상)
- `es256(PrivateKey key)`  
  `JwtKey` · ES256 서명 키 · `key` EC P-256 개인키
- `es256(PublicKey key)`  
  `JwtKey` · ES256 검증 키 · `key` EC P-256 공개키
- `withKeyId(String keyId)`  
  `JwtKey` · kid를 붙인 새 키(원래 키는 그대로) · `keyId` kid(출력 가능한 ASCII 1~256자, 공백 불가)
- `withIssuer(String issuer)`  
  `JwtKey` · 발급자에 묶은 새 키 · `issuer` 이 키를 쓰는 발급자(iss 값 그대로)
- `algorithm()`  
  `JwtAlgorithm` · 알고리즘
- `keyId()`  
  `String` · kid(없으면 null)
- `issuer()`  
  `String` · 묶인 발급자(없으면 null)
- `canSign()`  
  `boolean` · 서명할 수 있으면 true(HS256·개인키)
- `canVerify()`  
  `boolean` · 검증할 수 있으면 true(HS256·공개키)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>JwtAlgorithm</summary>

`io.javacryptokit.jwt.JwtAlgorithm`

- `HS256`  
  HMAC-SHA256(공유 비밀키 32바이트 이상).
- `RS256`  
  RSASSA-PKCS1-v1_5 + SHA-256(RSA 2048비트 이상). RFC 9068 필수 지원 알고리즘.
- `ES256`  
  ECDSA P-256 + SHA-256(서명은 64바이트 R‖S).

</details>

<details>
<summary>Jwks</summary>

`io.javacryptokit.jwt.Jwks`

- `parse(String json, String issuer)`  
  `List<JwtKey>` · 검증용 키 목록 · `json` JWKS 문자열 · `issuer` 이 JWKS를 쓰는 발급자(iss 값)
- `parse(String json)`  
  `List<JwtKey>` · 검증용 키 목록 · `json` JWKS 문자열

</details>

<details>
<summary>JwtVerifier</summary>

`io.javacryptokit.jwt.JwtVerifier`

- `MAX_CLOCK_SKEW`  
  최대 허용 시각 오차.
- `builder()`  
  `JwtVerifier.Builder` · 검증기 생성기
- `verify(String token)`  
  `VerifiedJwt` · 검증된 JWT · `token` compact JWS

</details>

<details>
<summary>JwtVerifier.Builder</summary>

`io.javacryptokit.jwt.JwtVerifier.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `key(JwtKey key)`  
  `key` 검증 키(HS256 비밀키 또는 공개키)
- `keys(Collection<JwtKey> keys)`  
  `keys` 검증 키 목록(예: Jwks.parse(String, String) 결과)
- `issuer(String issuer)`  
  `issuer` 기대 발급자(iss 정확히 일치)
- `audience(String audience)`  
  `audience` 이 서비스의 식별자(토큰 aud에 포함되어야 함)
- `anyAudience()`  
  audience를 지정하지 않아도 aud가 있는 토큰을 허용합니다. 특정 API의 대상 검증에는 audience를 지정하세요.
- `types(String... allowed)`  
  `allowed` 값(예: JWT, at+jwt; 대소문자·application/ 무시)
- `requireClaims(String... names)`  
  `names` 있어야 하는 클레임
- `requireClaimValue(String name, String value)`  
  `name` 클레임 이름 · `value` 기대 문자열(정확히 일치, 형식 변환 없음)
- `requireExpiration(boolean required)`  
  `required` exp 필수 여부(기본 true)
- `requireIssuedAt(boolean required)`  
  `required` iat 필수 여부(기본 false)
- `rejectFutureIssuedAt(boolean reject)`  
  `reject` 허용 오차보다 미래의 iat 거부 여부(기본 true)
- `maxAge(Duration maxAge)`  
  `maxAge` iat 기준 최대 나이(지정하면 iat 필수)
- `clockSkew(Duration skew)`  
  `skew` 서버 간 시계 차 허용(0~300초, 기본 0)
- `allowFractionalTimes(boolean allow)`  
  `allow` 소수 초 NumericDate 허용(기본 false)
- `clock(Clock clock)`  
  `clock` 현재 시각 시계(기본 시스템 UTC)
- `build()`  
  `JwtVerifier` · 검증기

</details>

<details>
<summary>VerifiedJwt</summary>

`io.javacryptokit.jwt.VerifiedJwt`

- `algorithm()`  
  `JwtAlgorithm` · 검증에 쓴 알고리즘
- `keyId()`  
  `String` · 검증에 쓴 키의 kid(없으면 null)
- `header()`  
  `JwtClaims` · 헤더
- `claims()`  
  `JwtClaims` · 검증된 클레임
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>UnverifiedJwt</summary>

`io.javacryptokit.jwt.UnverifiedJwt`

- `algorithm()`  
  `String` · 헤더의 alg 문자열(검증 전이므로 지원하지 않는 값일 수 있다)
- `keyId()`  
  `String` · 헤더의 kid(없거나 문자열이 아니면 null)
- `type()`  
  `String` · 헤더의 typ(없거나 문자열이 아니면 null)
- `header()`  
  `JwtClaims` · 헤더 전체(검증되지 않음)
- `claims()`  
  `JwtClaims` · 클레임(검증되지 않음)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>JwtClaims</summary>

`io.javacryptokit.jwt.JwtClaims`

- `parse(String json)`  
  `JwtClaims` · 보기 객체 · `json` JSON 객체 문자열
- `issuer()`  
  `String` · iss
- `subject()`  
  `String` · sub
- `jwtId()`  
  `String` · jti
- `audience()`  
  `List<String>` · aud(문자열 하나 또는 문자열 배열을 목록으로, 없으면 빈 목록)
- `expiresAt()`  
  `Instant` · exp(없으면 null)
- `notBefore()`  
  `Instant` · nbf(없으면 null)
- `issuedAt()`  
  `Instant` · iat(없으면 null)
- `names()`  
  `Set<String>` · 클레임 이름(입력 순서)
- `has(String name)`  
  `boolean` · 있으면(값이 JSON null이어도) true · `name` 이름
- `getString(String name)`  
  `String` · 문자열 값(없거나 null이면 null) · `name` 이름
- `getLong(String name)`  
  `Long` · 정수 값(없으면 null) · `name` 이름
- `getBoolean(String name)`  
  `Boolean` · 논리 값(없으면 null) · `name` 이름
- `getStringList(String name)`  
  `List<String>` · 문자열 배열(없으면 빈 목록) · `name` 이름
- `getObject(String name)`  
  `JwtClaims` · 중첩 객체(없으면 null) · `name` 이름
- `getInstant(String name)`  
  `Instant` · NumericDate(정수 초)를 시각으로(없으면 null) · `name` 이름
- `toJson()`  
  `String` · 이 객체의 압축 JSON(민감한 클레임이 있을 수 있으니 로그에 남기지 않는다)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>JwtException</summary>

`io.javacryptokit.jwt.JwtException`

- `JwtException(JwtException.Reason reason, String message, String claim)`  
  `reason` 사유 · `message` 고정 문구 · `claim` 관련 클레임·헤더 이름(없으면 null)
- `getReason()`  
  `JwtException.Reason` · 실패 사유
- `getClaim()`  
  `String` · 관련 클레임·헤더 이름(예: exp), 없으면 null. 값이 아니라 이름이다

</details>

<details>
<summary>JwtException.Reason</summary>

`io.javacryptokit.jwt.JwtException.Reason`

- `MALFORMED`  
  형식 오류: 세 구간이 아님, Base64URL·UTF-8·JSON 오류, 중복 헤더·클레임, 크기 상한 초과.
- `UNSUPPORTED`  
  지원하지 않는 표현: none·모르는 알고리즘, crit·b64, JWE·중첩 JWT.
- `KEY_NOT_FOUND`  
  검증 키 없음: 그 알고리즘·kid의 키가 등록되지 않았거나 kid가 없어 키를 하나로 정할 수 없음.
- `SIGNATURE`  
  서명 불일치(다른 키·변조·잘못된 서명 길이).
- `EXPIRED`  
  만료(exp).
- `NOT_YET_VALID`  
  아직 사용 시작 전(nbf).
- `ISSUED_IN_FUTURE`  
  발급 시각(iat)이 허용 오차보다 미래.
- `TOO_OLD`  
  발급 시각(iat)이 허용한 최대 나이보다 오래됨.
- `ISSUER`  
  발급자(iss) 불일치.
- `AUDIENCE`  
  대상(aud) 불일치 또는 대상 정책 없음.
- `TYPE`  
  토큰 종류(typ 헤더) 불일치.
- `MISSING_CLAIM`  
  필수 클레임 없음.
- `INVALID_CLAIM`  
  클레임 형식·값이 정책과 다름(금지 클레임 포함).
- `SCOPE`  
  필요한 권한(scope·roles) 없음.

</details>

<a name="api-oauth"></a>
### OAuth 검증과 토큰 요청

[업무 예제와 선택 기준](../guide/authentication.md#topic-oauth)

<details>
<summary>AccessTokens</summary>

`io.javacryptokit.oauth.AccessTokens`

- `builder()`  
  `AccessTokens.Builder` · 시스템 UTC 시계 생성기
- `builder(Clock clock)`  
  `AccessTokens.Builder` · 생성기 · `clock` 발급 시각 시계

</details>

<details>
<summary>AccessTokens.Builder</summary>

`io.javacryptokit.oauth.AccessTokens.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `issuer(String value)`  
  `value` 발급자
- `subject(String value)`  
  `value` 주체(사용자 ID, 클라이언트 자격 흐름이면 클라이언트 ID)
- `audience(String... values)`  
  `values` 대상 API 식별자
- `clientId(String value)`  
  `value` 요청한 클라이언트 ID
- `scopes(String... scopes)`  
  `scopes` 허용 권한(공백으로 이어 scope 클레임에 넣는다; 이름에 공백 불가)
- `roles(List<String> values)`  
  `values` 역할(roles 문자열 배열)
- `expiresIn(Duration value)`  
  `value` 유효 기간(1초 이상, 짧게 권장)
- `jwtId(String value)`  
  `value` 토큰 ID(지정하지 않으면 256비트 보안 난수)
- `claim(String name, String value)`  
  `name` 업무 클레임 · `value` 문자열
- `claim(String name, long value)`  
  `name` 업무 클레임 · `value` 정수
- `claim(String name, boolean value)`  
  `name` 업무 클레임 · `value` 논리 값
- `sign(JwtKey key)`  
  `String` · typ: at+jwt compact JWS · `key` 발급자의 서명 키

</details>

<details>
<summary>AccessTokenVerifier</summary>

`io.javacryptokit.oauth.AccessTokenVerifier`

- `rfc9068()`  
  `AccessTokenVerifier.Builder` · RFC 9068 표준 프로파일 생성기
- `profile()`  
  `AccessTokenVerifier.Builder` · 설정형(공급자별) 프로파일 생성기
- `verify(String token)`  
  `AccessToken` · 검증된 Access Token · `token` Bearer 토큰(compact JWS)

</details>

<details>
<summary>AccessTokenVerifier.Builder</summary>

`io.javacryptokit.oauth.AccessTokenVerifier.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `issuer(String issuer)`  
  `issuer` 신뢰하는 발급자(정확히 일치, 필수)
- `audience(String audience)`  
  `audience` 이 API의 식별자(토큰 aud에 포함, 필수)
- `key(JwtKey key)`  
  `key` 발급자의 검증 키
- `keys(Collection<JwtKey> keys)`  
  `keys` 발급자의 검증 키 목록(예: Jwks.parse)
- `types(String... allowed)`  
  `allowed` 설정형 검증에서 허용할 JWT 헤더 typ 목록. 마지막 호출이 이전 목록을 대체합니다. RFC 9068에서는 `at+jwt`로 고정됩니다.
- `requireClaims(String... names)`  
  `names` 있어야 하는 클레임(등록 클레임이 아닌 이름이면 토큰 종류 구분 조건, 누적)
- `requireClaimValue(String name, String value)`  
  `name` 클레임 · `value` 기대 문자열(예: Keycloak typ=Bearer, Entra ver=2.0)
- `forbidClaims(String... names)`  
  `names` 있으면 거부할 클레임(예: ID Token 표지 nonce·at_hash, 누적)
- `clientIdClaim(String name)`  
  `name` 클라이언트 ID 클레임(설정형만, 예: azp·appid; 지정하면 필수)
- `scopeClaim(String name)`  
  `name` 공백 구분 위임 권한 클레임(기본 scope, Entra scp)
- `rolesClaim(String name)`  
  `name` 문자열 배열 역할 클레임(기본 roles)
- `requirePermissionClaim(boolean required)`  
  `required` true면 scope와 roles가 모두 비어 있는 토큰을 거부합니다. 기본 false이며 마지막 값이 적용됩니다.
- `requireScopes(String... scopes)`  
  `scopes` 모두 있어야 하는 위임 권한(누적)
- `requireRoles(String... roles)`  
  `roles` 모두 있어야 하는 역할(누적)
- `clockSkew(Duration skew)`  
  `skew` 발급 서버와 검증 서버의 시계 차를 허용하는 시간. 기본 0초, 최대 300초
- `maxAge(Duration maxAge)`  
  `maxAge` 발급 시각(iat)부터 허용할 최대 경과 시간. 생략하면 추가 수명 제한이 없고, 지정하면 토큰에 iat가 필요합니다.
- `requireIssuedAt(boolean required)`  
  `required` 설정형 프로파일에서 발급 시각(iat)을 요구할지 선택합니다. 기본 false. RFC 9068은 항상 필수입니다.
- `rejectFutureIssuedAt(boolean reject)`  
  `reject` 미래 iat 거부(기본 true)
- `allowFractionalTimes(boolean allow)`  
  `allow` 소수 초 시간 허용(기본 false)
- `clock(Clock clock)`  
  `clock` 토큰 시각을 검증할 때 쓸 시계. 기본은 시스템 UTC이며, 고정 시각 시험에서는 `Clock.fixed`를 쓸 수 있습니다.
- `build()`  
  `AccessTokenVerifier` · 검증기

</details>

<details>
<summary>AccessToken</summary>

`io.javacryptokit.oauth.AccessToken`

- `issuer()`  
  `String` · 발급자(iss)
- `subject()`  
  `String` · 주체(sub, 사용자 또는 클라이언트)
- `clientId()`  
  `String` · 클라이언트 ID(프로파일에서 정한 클레임, RFC 9068은 client_id; 정하지 않았으면 null)
- `audience()`  
  `List<String>` · 대상(aud)
- `scopes()`  
  `Set<String>` · 위임 권한(scope 클레임을 공백으로 나눈 값, 없으면 빈 집합)
- `roles()`  
  `List<String>` · 역할(roles 클레임, 없으면 빈 목록)
- `hasScope(String scope)`  
  `boolean` · 있으면 true · `scope` 권한 이름(정확히 일치, 부분 문자열 아님)
- `hasRole(String role)`  
  `boolean` · 있으면 true · `role` 역할 이름(정확히 일치)
- `expiresAt()`  
  `Instant` · 만료 시각
- `jwtId()`  
  `String` · 토큰 ID(jti, 없으면 null)
- `claims()`  
  `JwtClaims` · 검증된 전체 클레임
- `jwt()`  
  `VerifiedJwt` · 검증된 JWT(알고리즘·kid·헤더)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>TokenIntrospector</summary>

`io.javacryptokit.oauth.TokenIntrospector`

- `MAX_RESPONSE_LIMIT`  
  응답 최대 크기 상한.
- `builder(URI endpoint)`  
  `TokenIntrospector.Builder` · 생성기 · `endpoint` 신뢰하는 HTTPS Introspection 엔드포인트(설정에서만 받는다. 토큰·클레임의 URL을 쓰지 않는다)
- `introspect(String token)`  
  `IntrospectionResult` · 결과(활성/비활성) · `token` 조회할 토큰
- `introspect(String token, String tokenTypeHint)`  
  `IntrospectionResult` · 결과(활성/비활성) · `token` 조회할 토큰 · `tokenTypeHint` 토큰 종류 힌트(예: access_token, 없으면 null)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>TokenIntrospector.Builder</summary>

`io.javacryptokit.oauth.TokenIntrospector.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `clientSecretBasic(String clientId, char[] clientSecret)`  
  `clientId` 이 리소스 서버의 클라이언트 ID · `clientSecret` 클라이언트 비밀(Authorization 헤더 값으로만 보관, 호출자 배열은 호출자가 지운다)
- `connectTimeout(Duration timeout)`  
  `timeout` HTTPS 연결 대기 시간. 기본 5초, 허용 1밀리초~60초
- `readTimeout(Duration timeout)`  
  `timeout` HTTPS 응답을 읽을 때의 대기 시간. 기본 10초, 허용 1밀리초~120초
- `maxResponseBytes(int bytes)`  
  `bytes` 읽을 응답 본문의 최대 바이트 수. 기본 64KiB, 허용 1KiB~1MiB
- `sslContext(SSLContext context)`  
  `context` 사설 CA 등 HTTPS 서버의 신뢰 설정. 생략하면 JVM 기본 신뢰 설정을 사용하고 호스트 이름도 검증합니다.
- `build()`  
  `TokenIntrospector` · 구성한 HTTPS 조회 클라이언트. `clientSecretBasic` 없이 만들면 입력 오류입니다.

</details>

<details>
<summary>IntrospectionResult</summary>

`io.javacryptokit.oauth.IntrospectionResult`

- `active()`  
  `boolean` · 인증 서버가 활성이라고 답했으면 true
- `scopes()`  
  `Set<String>` · 권한(scope를 공백으로 나눈 값, 비활성이거나 없으면 빈 집합)
- `clientId()`  
  `String` · client_id(비활성·없으면 null)
- `username()`  
  `String` · username(비활성·없으면 null)
- `tokenType()`  
  `String` · token_type(비활성·없으면 null)
- `subject()`  
  `String` · sub(비활성·없으면 null)
- `issuer()`  
  `String` · iss(비활성·없으면 null)
- `audience()`  
  `List<String>` · aud(비활성·없으면 빈 목록)
- `jwtId()`  
  `String` · jti(비활성·없으면 null)
- `expiresAt()`  
  `Instant` · exp(비활성·없으면 null)
- `issuedAt()`  
  `Instant` · iat(비활성·없으면 null)
- `notBefore()`  
  `Instant` · nbf(비활성·없으면 null)
- `claims()`  
  `JwtClaims` · 응답의 최상위 멤버 전체(비활성이면 active만)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>ClientCredentials</summary>

`io.javacryptokit.oauth.ClientCredentials`

- `builder(URI tokenEndpoint)`  
  `ClientCredentials.Builder` · 생성기 · `tokenEndpoint` 신뢰하는 HTTPS token endpoint(설정에서만 받는다. 응답·토큰 안의 URL을 따라가지 않는다)
- `requestToken()`  
  `TokenResponse` · 발급받은 토큰
- `requestToken(String... scopes)`  
  `TokenResponse` · 발급받은 토큰 · `scopes` 요청할 scope(각각 공백·"·\ 없는 출력 가능 ASCII)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>ClientCredentials.Builder</summary>

`io.javacryptokit.oauth.ClientCredentials.Builder`

설정 메서드는 현재 Builder를 반환합니다.

- `clientSecretBasic(String clientId, char[] clientSecret)`  
  `clientId` 클라이언트 ID · `clientSecret` 클라이언트 비밀(헤더 값으로만 보관, 호출자 배열은 호출자가 지운다)
- `clientSecretPost(String clientId, char[] clientSecret)`  
  `clientId` 클라이언트 ID · `clientSecret` 클라이언트 비밀
- `connectTimeout(Duration timeout)`  
  `timeout` HTTPS 연결 대기 시간. 기본 5초, 허용 1밀리초~60초
- `readTimeout(Duration timeout)`  
  `timeout` HTTPS 응답을 읽을 때의 대기 시간. 기본 10초, 허용 1밀리초~120초
- `maxResponseBytes(int bytes)`  
  `bytes` 읽을 응답 본문의 최대 바이트 수. 기본 64KiB, 허용 1KiB~1MiB
- `sslContext(SSLContext context)`  
  `context` 사설 CA 등 신뢰 설정(호스트명 검증은 JDK 기본 유지)
- `clock(Clock clock)`  
  `clock` 응답 수신 시각·만료 계산 시계(기본 시스템 UTC)
- `build()`  
  `ClientCredentials` · 토큰 요청 클라이언트. `clientSecretBasic` 또는 `clientSecretPost` 중 하나가 필요합니다.

</details>

<details>
<summary>TokenResponse</summary>

`io.javacryptokit.oauth.TokenResponse`

- `accessToken()`  
  `String` · access_token 원문(로그에 남기지 않는다)
- `tokenType()`  
  `String` · token_type: 지원하는 Bearer만 받으며 대소문자 구분 없이 받아 Bearer로 돌려준다
- `authorizationHeader()`  
  `String` · HTTP Authorization 헤더 값(Bearer &lt;토큰&gt;)
- `expiresIn()`  
  `OptionalLong` · expires_in(초). 인증 서버가 주지 않았으면 빈 값(만료 시각을 지어내지 않음)
- `expiresAt()`  
  `Instant` · 응답을 받은 시각 + expires_in, 서버가 주지 않았으면 null
- `receivedAt()`  
  `Instant` · 응답을 받은 시각(주입한 시계 기준)
- `requestedScopes()`  
  `Set<String>` · 요청한 scope(공백으로 나눈 값, 요청하지 않았으면 빈 집합)
- `grantedScopes()`  
  `Set<String>` · 응답의 scope(공백으로 나눈 값). 응답에 없으면 빈 집합(scopeInResponse()로 구분)
- `scopeInResponse()`  
  `boolean` · 응답에 scope가 있었으면 true(없으면 RFC 6749상 요청과 같다는 뜻이지만 이 객체는 추측하지 않는다)
- `toString()`  
  `String` · 진단용 문자열 표현

</details>

<details>
<summary>OAuthClientException</summary>

`io.javacryptokit.oauth.OAuthClientException`

- `getReason()`  
  `OAuthClientException.Reason` · 실패 사유
- `getStatusCode()`  
  `int` · HTTP 상태 코드(응답을 받지 못했으면 -1)
- `getOAuthError()`  
  `String` · 인증 서버의 표준 오류 코드(invalid_client·invalid_scope·unauthorized_client· invalid_request·invalid_grant·unsupported_grant_type), 없거나 표준이 아니면 null

</details>

<details>
<summary>OAuthClientException.Reason</summary>

`io.javacryptokit.oauth.OAuthClientException.Reason`

- `OAUTH_ERROR`  
  인증 서버가 OAuth 오류 응답을 돌려줌(RFC 6749 5.2, OAuthClientException.getOAuthError()의 표준 오류 코드).
- `HTTP_STATUS`  
  인증 서버가 200이 아닌 상태를 돌려줌(4xx·5xx).
- `CLIENT_AUTH`  
  클라이언트 인증 실패(401·403).
- `REDIRECT`  
  리다이렉트 응답(따라가지 않음).
- `TIMEOUT`  
  연결·읽기 시간 초과.
- `TLS`  
  TLS 실패(인증서 신뢰·호스트명 불일치 등).
- `NETWORK`  
  그 밖의 네트워크 오류.
- `INVALID_RESPONSE`  
  응답이 JSON 객체가 아니거나 필수 값·형식이 맞지 않음.
- `RESPONSE_TOO_LARGE`  
  응답이 크기 상한을 넘음.

</details>

<details>
<summary>IntrospectionException</summary>

`io.javacryptokit.oauth.IntrospectionException`


</details>

<details>
<summary>TokenRequestException</summary>

`io.javacryptokit.oauth.TokenRequestException`


</details>

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
