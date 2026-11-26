# 보안 유틸리티 API

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md) · [CLI 명령·예제](#api-cli-guide)

비밀번호의 단방향 저장, 난수·토큰·UUID 생성, 키 파생, 바이너리 인코딩과 안전 비교를 제공합니다. 각 기능은 독립 Java API로 사용하며 관리형 키 설정이나 CLI 관리자 인증에 의존하지 않습니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[목적별 선택](#guide-section-1) · [기능을 함께 활용하는 예](#guide-section-2) · [비밀번호 해시 및 검증](#topic-password) · [보안 난수·난수 문자열·UUID](#topic-random) · [HKDF·PBKDF2 키 파생](#topic-key-derivation) · [인코딩 및 안전 비교](#topic-encoding)

---

<a name="guide-section-1"></a>
## 목적별 선택

| 필요 기능 | Java API | 사용 상황 |
|---|---|---|
| 회원 비밀번호 저장·검증 | [`Passwords`](#topic-password) | 원문 복원이 필요 없는 인증 |
| 토큰·Nonce·문자열·UUID | [`SecureRandoms`](#topic-random) | 비밀번호 재설정 토큰, 랜덤 식별자, 추적 ID |
| 키를 파생하거나 용도별로 분리 | [`Hkdf`, `Pbkdf2`](#topic-key-derivation) | 기존 키 재료·Passphrase 사용 |
| 데이터 표현 변환·비교 | [`Encoding`, `Bytes`](#topic-encoding) | Hex, Base64URL, UTF-8 및 안전 비교 |

모두 Java API로 사용합니다. CLI 관리자 비밀번호 기능이나 관리형 암호화 키 설정과 독립적입니다. 인코딩은 암호화가 아니며 UUID와 짧은 난수 문자열은 절대 유일성을 보장하지 않습니다. 예제 실행은 [Java API 공통 규칙](../reference/java-api-reference.md)을 확인합니다.

<a name="guide-section-2"></a>
## 기능을 함께 활용하는 예

| 업무 요구 | 적합한 기능 | 피해야 할 선택 |
|---|---|---|
| 로그인 비밀번호 저장 | `Passwords.hash` → 전체 저장 문자열 저장 → `verify` → 성공 후 필요시 `needsRehash` | AES로 회원 비밀번호 복호화 가능하게 저장 |
| 사용자 입력용 숫자 코드 | `SecureRandoms.string`의 `DIGITS` | 첫 0이 사라지는 정수 변환, 짧은 코드만으로 인증(시도 제한·만료 정책 필요) |
| 비밀 토큰 | `SecureRandoms.token()` 기본 32바이트 난수 | 짧은 업무 식별값 또는 UUID를 비밀 토큰으로 사용 |
| 업무 표시용 랜덤 문자열 | `string(length, Alphabet, prefix)` | 절대 유일성이나 순번 보장으로 간주 |
| AES 키·Salt·Nonce 준비 | 각 API의 생성 기능 또는 용도에 맞는 `SecureRandoms.bytes`·`nonce` | 같은 실제 키의 GCM IV를 직접 재사용 |
| 하나의 난수 키에서 용도별 키 생성 | HKDF의 용도별 info 구분 | 사람이 정한 비밀번호에 HKDF만 사용 |
| Passphrase에서 키 생성 | PBKDF2와 Salt·반복 횟수·알고리즘 보관 | SHA 해시 한번만으로 키 파생 |
| 데이터 전송 표현 | Base64URL·Hex·Base32 등 합의한 형식 | 인코딩을 암호화로 오해 |

Java API와 독립 CLI는 암호 처리 구현을 공유합니다. [CLI 명령·옵션·예제](#api-cli-guide)에서 실행 방법을 확인할 수 있습니다. 관리형 `pass`는 내부에서 PBKDF2를 사용하지만 이 문서의 `Pbkdf2`는 호출자가 키 파생 조건을 직접 지정하는 독립 기능입니다. CLI 관리자 비밀번호와 사용자 로그인 비밀번호도 서로 다른 저장·검증 체계입니다.

<a name="topic-password"></a>

## 비밀번호 해시 및 검증

<a name="topic-password--비밀번호-해시"></a>
<a name="topic-password--137-비밀번호-해시--passwords"></a>
### 비밀번호 해시 — Passwords (13.7)

**사용 상황:** 회원 가입 시 해시를 DB에 저장하고 로그인 때 입력 비밀번호와 비교하는 경우입니다. 비밀번호를 다시 읽어야 하는 DB 접속정보 같은 비밀은 [AES 암복호화](java-encryption.md#topic-aes--132-aes-gcm과-업무-aad--aesgcm)를 사용합니다.

```java
// 예제: SecurityApiExample.register
public static String register(char[] password) {
    return Passwords.hash(password);                                  // $pbkdf2-sha256$v=1$i=600000$...$...
}
```

```java
// 예제: SecurityApiExample.login
public static String[] login(char[] password, String stored) {
    if (!Passwords.verify(password, stored)) return new String[] {"false", null};
    String upgraded = Passwords.needsRehash(stored) ? Passwords.hash(password) : null; // 정책이 강해졌으면 교체
    return new String[] {"true", upgraded};
}
```

- **저장 형식(버전 1):** `$pbkdf2-sha256$v=1$i=600000$<Salt>$<해시>`(PHC 문법, Salt·해시는 패딩 없는 표준 Base64). 해시마다 16바이트 보안 난수 Salt를 새로 씁니다. 기본 PBKDF2-HMAC-SHA256 600,000회, `hash(비밀번호, Pbkdf2Algorithm.SHA512, 210_000)`처럼 고를 수 있습니다(새 해시 100,000~5,000,000회).
- **검증:** 저장값에 적힌 알고리즘·반복 횟수로 다시 계산해 안전 비교합니다. 반복 5,000,000회 초과·모르는 형식은 계산하지 않고 거부합니다(과도한 연산 방지). 빈 값·공백만·제어문자 입력은 `false`입니다. 입력은 NFC 정규화 후 UTF-8, 최대 1,024바이트.
- **재해시:** `needsRehash`가 `true`면(예전 정책의 약한 값) 로그인에 성공한 그 비밀번호로 다시 해시해 저장합니다. 저장값을 스스로 바꾸지 않습니다.
- **애플리케이션 몫:** 비밀번호 규칙·시도 제한·계정 잠금. CLI 관리자 비밀번호 규칙(10~128자)을 적용하지 않으며 관리자 검증값과 저장소를 공유하지 않습니다.

| 호출 | 기본값 / 허용 범위 |
|---|---|
| `hash(password)` | SHA256·600,000회, 16바이트 새 Salt |
| `hash(password, algorithm, iterations)` | SHA256/SHA512, 100,000~5,000,000회 |
| `verify(password, stored)` | 저장값의 알고리즘·Salt·반복 횟수로 검증. 과거 해시 검증만 1,000회 이상 허용 |
| `needsRehash(stored[, algorithm, iterations])` | 현재 목표 정책과 저장 해시 비교. 로그인 성공 후에만 다시 해시하여 교체 |

DB에 저장하는 값은 `hash`가 반환하는 문자열 전체입니다. Salt만 따로 잘라 저장할 필요가 없습니다. `verify`가 `false`이면 로그인 실패, 저장 형식 자체가 손상되면 예외로 처리합니다.


<a name="topic-password--실행-예제--시험-비밀번호의-해시와-검증"></a>
### 실행 예제 — 시험 비밀번호의 해시와 검증

`PasswordExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.Passwords;
import java.util.Arrays;

public class PasswordExample {
    public static void main(String[] args) throws Exception {
        char[] password = "example-only".toCharArray();
        try {
            String stored = Passwords.hash(password);
            System.out.println(Passwords.verify(password, stored));
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
```

**예상 결과**

```text
true
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-random"></a>

## 보안 난수·난수 문자열·UUID

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-utilities)

<a name="topic-random--보안-난수-및-uuid"></a>
<a name="topic-random--135-보안-난수uuid--securerandoms"></a>
### 보안 난수·UUID — SecureRandoms (13.5)

**사용 상황:** 비밀번호 재설정 링크에 넣을 비밀 토큰, 서버 간 요청 Nonce, 키·Salt 등 예측하기 어려운 값을 만들 때 사용합니다. 거래번호의 중복을 보장하는 기능이나 인증번호 사용 이력 관리가 아닙니다.

```java
// 예제: SecurityApiExample.randomValues
public static String[] randomValues() {
    String resetToken = SecureRandoms.token();                        // 32바이트 → Base64URL 43자
    String apiKey = SecureRandoms.token(32, Encoding.HEX);            // 32바이트 → 16진수 64자
    String traceId = SecureRandoms.uuidV4().toString();               // 추적용(비밀·절대 유일성 아님)
    String code = SecureRandoms.string(6, SecureRandoms.Alphabet.DIGITS, "R-");
    return new String[] {resetToken, apiKey, traceId, code};
}
```

- `token()`은 32바이트(256비트)를 Base64URL 43자로, `nonce()`는 16바이트를 22자로 만듭니다. 토큰 길이는 16~1,024바이트(`token(바이트 수, 형식)`), 원시 바이트는 `bytes(1~65,536)`. `uuidV4()`는 RFC 9562 UUID 버전 4입니다.
- JDK `SecureRandom`만 씁니다(시간·서버 번호·고정 Seed 없음). 숫자 6자리는 접두어가 고정이면 100만 가지여서 반복 발급 중 중복될 수 있습니다. 만료·시도 횟수·사용 이력은 애플리케이션이 관리합니다. UUID는 추적용이며 비밀 토큰이 아닙니다.
- 실행 중인 VM·컨테이너를 스냅샷으로 복제한 직후에는 난수 생성기 상태가 같을 수 있으므로 JVM을 다시 시작합니다(특히 Windows Java 8 기본 `SHA1PRNG`는 스스로 재시드하지 않음).

| 호출 | 입력 단위 | 반환 형식 및 기본값 |
|---|---|---|
| `bytes(length)` | 1~65,536바이트 | `byte[]`, 키·Salt 등의 난수 재료 |
| `token()` / `token(byteLength)` | 기본 32바이트, 허용 16~1,024바이트 | Base64URL, 패딩 없음(32B→43자, 16B→22자) |
| `token(byteLength, encoding)` | 같은 바이트 범위 | `Encoding`으로 지정(HEX 32B→64자) |
| `nonce()` | 고정 16바이트 | Base64URL 22자 |
| `uuidV4()` | 인자 없음 | `UUID`, 문자열이 필요하면 `toString()` |

#### 고정 길이 난수 문자열 생성

`SecureRandoms.string(length, alphabet)` 또는 `SecureRandoms.string(length, alphabet, prefix)`를 사용합니다. `length`는 접두어를 제외한 난수 문자 수(1~1,024)입니다. `prefix`는 빈 문자열도 가능하며 UTF-16 길이 최대 1,024입니다. null이나 범위를 벗어난 길이는 `IllegalArgumentException`입니다.

| `SecureRandoms.Alphabet` | 문자 집합 | 사용 예 |
|---|---|---|
| `DIGITS` | 0–9 | 숫자 문자열 (첫 자리 0 유지) |
| `UPPER` | A–Z | 대문자 코드 |
| `LOWER` | a–z | 소문자 코드 |
| `LETTERS` | A–Z, a–z | 영문 문자열 |
| `UPPER_DIGITS` | A–Z, 0–9 | 대문자·숫자 코드 |
| `LOWER_DIGITS` | a–z, 0–9 | 소문자·숫자 코드 |
| `ALPHANUMERIC` | A–Z, a–z, 0–9 | 영문·숫자 문자열 |

```java
import io.javacryptokit.security.SecureRandoms;

public class RandomStringExample {
    public static void main(String[] args) {
        String digits = SecureRandoms.string(6, SecureRandoms.Alphabet.DIGITS);
        String code = SecureRandoms.string(12, SecureRandoms.Alphabet.UPPER_DIGITS, "REF-");
        System.out.println(digits.length()); // 6
        System.out.println(code.length());   // 16
    }
}
```

각 자리는 지정 문자 집합에서 독립적으로 선택합니다. 혼합 문자 집합의 각 종류가 반드시 하나 이상 포함된다는 뜻은 아닙니다. 숫자 문자열은 정수로 변환하지 않아야 앞의 0이 보존됩니다. 짧은 코드는 추측·충돌 위험이 있으므로 시도 제한·만료·일회 사용·중복 제어는 업무 정책으로 구현합니다. 충분한 엔트로피가 필요한 비밀 토큰에는 `token()`을 우선 사용합니다.

문자 수와 난수 바이트 수는 다릅니다. 짧은 인증번호의 발급·사용·폐기는 별개의 업무 정책입니다.


<a name="topic-random--실행-예제--난수-및-토큰-길이-확인"></a>
### 실행 예제 — 난수 및 토큰 길이 확인

`RandomExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.SecureRandoms;

public class RandomExample {
    public static void main(String[] args) throws Exception {
        System.out.println(SecureRandoms.bytes(32).length);
        System.out.println(SecureRandoms.token().length());
        System.out.println(SecureRandoms.uuidV4().toString().length());
    }
}
```

**예상 결과**

```text
32
43
36
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-key-derivation"></a>

## HKDF·PBKDF2 키 파생

<a name="topic-key-derivation--키-파생-hkdfpbkdf2"></a>
<a name="topic-key-derivation--138-키-파생-hkdfpbkdf2--hkdf-pbkdf2"></a>
### 키 파생 HKDF·PBKDF2 — Hkdf, Pbkdf2 (13.8)

**사용 상황:** 하나의 안전한 원본 키에서 암호화·MAC 용도의 별도 키가 필요하면 HKDF, 사람이 입력한 Passphrase에서 암호 키를 만들어야 하면 PBKDF2를 선택합니다.

```java
// 예제: SecurityApiExample.splitKeys
public static byte[][] splitKeys(byte[] masterKey, byte[] salt) {
    byte[] encryptionKey = Hkdf.derive(HmacAlgorithm.SHA256, masterKey, salt, "orders/enc/v1", 32);
    byte[] macKey = Hkdf.derive(HmacAlgorithm.SHA256, masterKey, salt, "orders/mac/v1", 32);
    return new byte[][] {encryptionKey, macKey};
}
```

- **HKDF(RFC 5869):** 이미 충분히 무작위인 키 재료에서 용도(`info`)별 키를 나눕니다. SHA256·SHA512, 출력 1~255×해시 길이, Salt가 없으면 해시 길이만큼의 0바이트(RFC 규칙). 사람이 입력한 비밀번호에 HKDF만 쓰지 않습니다.
- **PBKDF2:** `Pbkdf2.deriveKey(알고리즘, Passphrase, Salt, 반복 횟수, 키 길이)`는 다른 시스템과 같은 키를 직접 맞출 때 씁니다(보통은 `AesGcm.fromPassphrase`가 파생까지 함). Salt 16~64바이트(`Pbkdf2.newSalt()`), 반복 100,000~5,000,000, 키 16~64바이트.

| 호출 | 선택 기준 |
|---|---|
| `Hkdf.derive(ikm, salt, info, length)` | SHA256 기본. `info`는 바이트 |
| `Hkdf.derive(algorithm, ikm, salt, info, length)` | SHA256/SHA512 선택, `info`는 바이트 또는 UTF-8 문자열 |
| `Hkdf.extract(algorithm, salt, ikm)` / `expand(algorithm, prk, info, length)` | RFC 5869의 두 단계 직접 제어가 필요할 때 |
| `Pbkdf2.newSalt()` / `deriveKey(algorithm, passphrase, salt, iterations, keyBytes)` | 새 Salt 16바이트 / 키 파생 |

`Pbkdf2Algorithm.SHA256` 권장 600,000회, `SHA512` 권장 210,000회입니다. 키를 복원하려면 처음 파생할 때와 동일한 매개변수가 필요합니다.


<a name="topic-key-derivation--실행-예제--용도별-키-생성"></a>
### 실행 예제 — 용도별 키 생성

`KdfExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.util.Arrays;

public class KdfExample {
    public static void main(String[] args) throws Exception {
        byte[] original = SecureRandoms.bytes(32);
        byte[] salt = SecureRandoms.bytes(16);
        byte[] enc = Hkdf.derive(HmacAlgorithm.SHA256, original, salt, "example/enc", 32);
        byte[] mac = Hkdf.derive(HmacAlgorithm.SHA256, original, salt, "example/mac", 32);
        System.out.println(!Arrays.equals(enc, mac));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-encoding"></a>

## 인코딩 및 안전 비교

<a name="topic-encoding--인코딩-및-안전-비교"></a>
<a name="topic-encoding--139-인코딩안전-비교--encoding-bytes"></a>
### 인코딩·안전 비교 — Encoding, Bytes (13.9)

**사용 상황:** API JSON에 바이트 배열을 문자열로 담거나 URL용 토큰을 만들고, 검증값을 비교하는 경우입니다. 인코딩은 암호화가 아니며 비밀을 숨기지 않습니다.

```java
// 예제: SecurityApiExample.encodingAndCompare
public static boolean encodingAndCompare(String storedToken, String presentedToken) {
    byte[] raw = Encoding.BASE64_URL.decode(SecureRandoms.token());   // 형식이 틀리면 IllegalArgumentException
    String hex = Encoding.HEX.encode(raw);                            // 인코딩은 암호화가 아니다
    return hex.length() == 64 && Bytes.equalsConstantTime(storedToken, presentedToken); // null·빈 값은 false
}
```

| 형식 | 출력 | 입력(디코딩) |
|---|---|---|
| `HEX` | 소문자 16진수 | 대소문자 모두, 짝수 길이 |
| `BASE64` | 표준 Base64, 패딩 포함 | 정확한 패딩 필수 |
| `BASE64_URL` | URL·파일 이름에 안전한 Base64URL, 패딩 없음 | 패딩 있어도 됨(있으면 정확해야 함) |
| `BASE32` | RFC 4648 대문자, 패딩 없음(OTP 비밀키) | 대소문자·패딩 모두 허용 |

- 공백·줄바꿈·형식 밖 문자·정규형이 아닌 값(남는 비트)은 거부하며 값을 고치지 않습니다. 인코딩은 암호화가 아닙니다.
- `Bytes.utf8`·`utf8String`은 엄격한 UTF-8 변환입니다. `Bytes.equalsConstantTime`은 JDK `MessageDigest.isEqual`로 비교하되 **null·빈 값이 하나라도 있으면 `false`**(JDK 그대로는 null끼리 `true`)이고, 길이가 다르면 바로 `false`입니다. 시간차 공격을 완전히 없앤다고 보장하지 않으며 값의 진위·유효기간은 판단하지 않습니다.

| 호출 | 역할 |
|---|---|
| `Encoding.HEX/BASE64/BASE64_URL/BASE32.encode(byte[])` | 바이트 → 문자열 |
| 같은 `Encoding`의 `decode(String)` | 문자열 → 바이트. 형식 불일치는 오류 |
| `Bytes.utf8(String)` / `Bytes.utf8String(byte[])` | 엄격한 UTF-8 변환 |
| `Bytes.equalsConstantTime(...)` | 이미 확보한 바이트나 문자열 비교. null·빈 값은 유효한 일치로 보지 않음 |

Base64URL은 인코딩 시 패딩을 붙이지 않으며, 디코딩 시 올바른 패딩은 허용합니다. JWT compact JWS는 별도의 패딩 없는 형식 규칙을 따릅니다.


<a name="topic-encoding--실행-예제--utf-8-바이트와-base64-변환"></a>
### 실행 예제 — UTF-8 바이트와 Base64 변환

`EncodingExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.nio.charset.StandardCharsets;

public class EncodingExample {
    public static void main(String[] args) throws Exception {
        byte[] raw = "sample".getBytes(StandardCharsets.UTF_8);
        String encoded = Encoding.BASE64.encode(raw);
        String restored = new String(Encoding.BASE64.decode(encoded), StandardCharsets.UTF_8);
        System.out.println(encoded);
        System.out.println("sample".equals(restored));
    }
}
```

**예상 결과**

```text
c2FtcGxl
true
```

<a name="api-cli-guide"></a>
## 독립 보안 API의 CLI 사용

[인증·비밀 입출력 규칙](cli.md#api-cli)과 아래 업무별 옵션을 확인하세요.

<a name="api-encode"></a>
### 인코딩

인코딩은 데이터를 표시하는 형식입니다. `encode`는 UTF-8 한 줄이나 최대 1 MiB의 원본 파일을 변환하며 BOM·줄바꿈을 포함한 파일 바이트를 그대로 보존합니다. `decode`는 최대 2 MiB + 5바이트의 인코딩 파일에서 UTF-8 BOM 하나와 끝 LF 또는 CRLF 하나를 제거한 뒤 해석합니다. 원본이 바이너리이면 `--out`을 지정하세요.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api encode` | 초기 설정 후 사용 | `--encoding`, `--in`, `--out` |

<details>
<summary>옵션과 기본값</summary>

- `encode` — 기본 Base64. 입력 파일의 BOM과 줄바꿈도 그대로 변환합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
java -jar java-crypto-kit-0.2.0-cfg.jar api encode --enc base64 --in sample.bin --out sample.b64
```

<a name="api-decode"></a>
### 디코딩

입력 형식을 추측하지 않습니다. 파일로 저장한 인코딩 결과는 끝 줄바꿈 한 개를 제거한 뒤 해석합니다. 디코딩 결과의 바이트를 보존하려면 `--out`을 지정합니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api decode` | 초기 설정 후 사용 | `--encoding`, `--in`, `--out` |

<details>
<summary>옵션과 기본값</summary>

- `decode` — 기본 Base64. UTF-8이 아닌 바이너리는 --out으로 저장합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
java -jar java-crypto-kit-0.2.0-cfg.jar api decode --enc base64 --in sample.b64 --out restored.bin
```

<a name="api-random"></a>
### 난수와 UUID

바이트·토큰·문자열 결과는 보호 출력입니다. Nonce와 UUID는 공개 결과입니다. 접두어는 난수 길이에 포함되지 않으며 고유성을 보증하지 않습니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api random bytes` | 매 실행 | `--length`, `--encoding`, `--out`, `--show` |
| `api random token` | 매 실행 | `--length`, `--encoding`, `--out`, `--show` |
| `api random string` | 매 실행 | `--length`, `--alphabet`, `--prefix`, `--out`, `--show` |
| `api random nonce` | 초기 설정 후 사용 | `--out` |
| `api random uuid` | 초기 설정 후 사용 | `--out` |

<details>
<summary>옵션과 기본값</summary>

- `random bytes` — 기본 32바이트, 범위 1~65536. 기본 표현 Base64.
- `random token` — 기본 32바이트(16~1024), 표현 Base64URL.
- `random string` — 기본 영문·숫자 32자. 접두어 제외 1~1024자.
- `random nonce` — Base64URL 결과. 재사용 여부는 호출자가 관리합니다.
- `random uuid` — 표준 UUID 문자열을 반환합니다.
- `--alphabet` — digits, upper, lower, letters, upper-digits, lower-digits, alphanumeric.
- `--encoding` — hex, base64, base64url, base32.
- `--length` — 난수 또는 파생키 길이. 명령별 단위·범위를 확인합니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--prefix` — 접두어. 기본값은 빈 문자열.
- `--show` — 실제 터미널에서 SHOW 확인 뒤 화면에만 표시합니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
java -jar java-crypto-kit-0.2.0-cfg.jar api rand bytes --len 16 --enc hex --out salt.hex
java -jar java-crypto-kit-0.2.0-cfg.jar api rand token --len 32 --out random.txt
java -jar java-crypto-kit-0.2.0-cfg.jar api rand string --len 12 --alphabet digits --prefix TEST- --out random.txt
java -jar java-crypto-kit-0.2.0-cfg.jar api rand nonce --out nonce.txt
java -jar java-crypto-kit-0.2.0-cfg.jar api rand uuid
```

<a name="api-password"></a>
### 앱 비밀번호 해시

`verify`는 저장 해시가 기록한 알고리즘과 횟수를 쓰며 `needs-rehash`는 선택한 정책과 비교합니다. 후자의 true/false는 모두 정상 종료입니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api password hash` | 매 실행 | `--algorithm`, `--iterations`, `--password-file`, `--out`, `--show` |
| `api password verify` | 매 실행 | `--password-file`, `--in` |
| `api password needs-rehash` | 매 실행 | `--algorithm`, `--iterations`, `--in` |

<details>
<summary>옵션과 기본값</summary>

- `password hash` — 기본 PBKDF2 SHA-256 600000회. SHA-512는 210000회.
- `password verify` — 저장 해시에 알고리즘과 반복 횟수가 포함됩니다.
- `password needs-rehash` — true/false를 출력합니다. 파일은 그대로입니다.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--iterations` — PBKDF2 반복 횟수. 알고리즘별 기본값 적용.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--password-file` — 앱 비밀번호 UTF-8 보호 파일.
- `--show` — 실제 터미널에서 SHOW 확인 뒤 화면에만 표시합니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
java -jar java-crypto-kit-0.2.0-cfg.jar api password hash --password-file app.pw --out app.hash
java -jar java-crypto-kit-0.2.0-cfg.jar api password verify --password-file app.pw --in app.hash
java -jar java-crypto-kit-0.2.0-cfg.jar api password needs-rehash --in app.hash
```

<a name="api-kdf"></a>
### 키 파생

PBKDF2에 쓸 Salt는 Hex로 지정합니다. HKDF의 `--key-file`에는 지정된 표현의 IKM이 들어갑니다. HKDF의 출력 길이 한도는 해시 길이의 255배입니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api kdf pbkdf2` | 매 실행 | `--algorithm`, `--iterations`, `--salt`, `--salt-file`, `--length`, `--encoding`, `--pass-file`, `--out`, `--show` |
| `api kdf hkdf` | 매 실행 | `--algorithm`, `--salt`, `--salt-file`, `--info`, `--info-file`, `--length`, `--encoding`, `--key-encoding`, `--key-file`, `--out`, `--show` |

<details>
<summary>옵션과 기본값</summary>

- `kdf pbkdf2` — Salt 16~64바이트, 반복 100000~5000000회, 결과 16~64바이트.
- `kdf hkdf` — 기본 SHA-256과 32바이트. Salt·Info 생략 가능.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--info` — 선택형 공개 HKDF Info(UTF-8).
- `--info-file` — HKDF Info 바이트 파일. --info와 배타적.
- `--iterations` — PBKDF2 반복 횟수. 알고리즘별 기본값 적용.
- `--key-encoding` — 공유키 표현. 기본 base64.
- `--key-file` — 인코딩한 비밀키 한 줄이 든 보호 파일.
- `--length` — 난수 또는 파생키 길이. 명령별 단위·범위를 확인합니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--pass-file` — UTF-8 Passphrase 보호 파일.
- `--salt` — Hex Salt. --salt-file과 함께 쓸 수 없습니다.
- `--salt-file` — Hex Salt 한 줄을 담은 파일.
- `--show` — 실제 터미널에서 SHOW 확인 뒤 화면에만 표시합니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
java -jar java-crypto-kit-0.2.0-cfg.jar api kdf pbkdf2 --pass-file sample.pass --salt-file salt.hex --out pbkdf2.key
java -jar java-crypto-kit-0.2.0-cfg.jar api kdf hkdf --key-file hmac.key --info trial --out hkdf.key
```

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
