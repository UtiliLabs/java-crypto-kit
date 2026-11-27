# 데이터 무결성 및 서버 간 요청 인증

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md) · [CLI 명령·예제](#api-cli-guide)

Java API와 독립 CLI로 위변조 확인, 메시지 인증, 공개키 기반 서명 검증을 수행합니다. [명령·옵션·예제](#api-cli-guide) 공유 키를 가진 양측에는 HMAC, 공개키 검증에는 전자서명, 신뢰하는 체크섬 비교에는 SHA 해시를 선택합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[목적별 선택](#guide-section-1) · [실제 업무에 적용할 때의 기준](#guide-section-2) · [HMAC 메시지 인증](#topic-hmac) · [서버 간 API 요청 인증](#topic-request-auth) · [SHA 해시와 파일 체크섬](#topic-hash) · [전자서명 및 PEM 키](#topic-signature)

---

<a name="guide-section-1"></a>
## 목적별 선택

| 목적 | Java API | 무엇을 확인하나요? |
|---|---|---|
| 공유 키 기반 메시지 위변조 검증 | [`Hmac`](#topic-hmac) | 원본 메시지와 인증값 일치 |
| 서버 간 요청 서명·시간 검증 | [`RequestAuth`](#topic-request-auth) | 서명 및 허용 시간 (재전송 이력은 별도 관리) |
| 공지된 체크섬과 비교 | [`Digests`](#topic-hash) | 원본 데이터 해시 일치 |
| 공개키로 서명 검증 | [`Signatures`, `PemKeys`](#topic-signature) | 서명한 쪽의 개인키에 대응하는 공개키 |

관리형 `verify`는 JCK 암호문을 점검합니다. 원본 파일·메시지의 검증은 [`api hmac verify`](#api-hmac), [`api hash verify`](#api-hash), [`api sig verify`](#api-signature), [`api req-auth verify`](#api-request-auth) 또는 해당 Java API를 사용합니다.

<a name="guide-section-2"></a>
## 실제 업무에 적용할 때의 기준

| 업무 | 처리 순서 | 판정 후 할 일 |
|---|---|---|
| 제휴사 메시지 검증 | 공유 비밀키와 동일한 원본 바이트 규칙 합의 → HMAC 생성·전송 → 수신측 검증 | 불일치면 업무 요청 거부. 메시지는 암호화되지 않음 |
| 서버 간 API 인증 | 요청의 검증 대상 데이터를 양측에서 동일하게 구성 → RequestAuth 서명 → 수신 측에서 시각·MAC 확인 → 앱에서 nonce 재사용 확인 | 허용 시간과 서명을 통과해도 재사용 여부는 외부 저장소에서 별도 확인 |
| 배포 파일 검사 | 신뢰 경로로 얻은 기준 SHA-256/512 값과 다운로드 파일의 해시 비교 | 불일치 시 사용 중단. 해시만으로 발급자 신원을 증명하지 못함 |
| 파일 또는 전문 서명 | 개인키로 서명 → 원문과 서명값 전달 → 신뢰한 공개키로 검증 | 실패 시 처리 중단. PEM·키 저장소에서 준비한 키를 사용 가능 |

이 API의 키는 관리형 암호화 `pass/key` 등록과 별개입니다. HMAC 공유 키와 데이터 암호화 키를 별도로 관리하고, 공개키 서명에서는 수신자에게 개인키를 전달하지 않습니다. 해시 출력의 Hex·Base64 표현이 다르더라도 같은 바이트인지를 확인합니다. 전송 규약은 알고리즘과 인코딩까지 일치해야 합니다.

<a name="topic-hmac"></a>

## HMAC 메시지 인증

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-integrity)

<a name="topic-hmac--hmac-메시지-인증"></a>
<a name="topic-hmac--133-hmac--hmac"></a>
### HMAC — Hmac (13.3)

**기능:** 공유 비밀키로 메시지 인증 코드(HMAC-SHA256·SHA512)를 만들고 확인합니다.

**사용 상황:** 서버 간 API 요청 서명, 웹훅 검증, 전문 위변조 확인.

**선택 기준:** 내용 보호는 암호화, 개인키로 서명하고 공개키로 검증하려면 [전자서명](#topic-signature--1310-전자서명과-키-파일--signatures-pemkeys)을 사용합니다.

```java
// 예제: SecurityApiExample.macRoundTrip
public static boolean macRoundTrip(String message) {
    byte[] key = Hmac.generateKey();                                  // 32바이트 보안 난수(양쪽이 안전하게 나눠 보관)
    Hmac hmac = Hmac.of(key);
    String mac = hmac.sign(message, Encoding.BASE64_URL);
    return hmac.verify(message, mac, Encoding.BASE64_URL);
}
```

```java
// 예제: SecurityApiExample.verifyWebhook
public static boolean verifyWebhook(byte[] partnerSecret, byte[] body, String signatureHeader) {
    Hmac hmac = Hmac.ofExternalKey(HmacAlgorithm.SHA256, partnerSecret); // 상대가 정한 기존 비밀(짧을 수 있음)
    String hex = signatureHeader.startsWith("sha256=") ? signatureHeader.substring(7) : signatureHeader;
    return hmac.verify(body, hex, Encoding.HEX);                      // 값이 다르면 false, 형식이 틀리면 예외
}
```

- **키:** 새 키는 `Hmac.generateKey()`(SHA256 32바이트, SHA512 64바이트). `Hmac.of`는 32바이트 이상만 받습니다. 외부 시스템이 이미 정한 짧은 비밀(웹훅 문자열 등)과 맞출 때만 `Hmac.ofExternalKey`(1바이트 이상)를 씁니다. 키를 늘이거나 자르지 않습니다.
- **원본:** 문자열은 UTF-8 바이트로 계산하며 JSON 정렬·공백 정리 같은 정규화를 하지 않습니다(양쪽이 같은 바이트를 써야 함).
- **결과:** `sign`은 `byte[]` 또는 지정한 인코딩, `verify`는 안전 비교로 맞으면 `true`(값이 다르면 `false`, MAC 문자열이 그 인코딩이 아니면 예외). 재전송 방지는 하지 않습니다.

<a name="topic-hmac--hmac-호출-선택표"></a>
#### Hmac 호출 선택표

| 호출 | 사용법 |
|---|---|
| `generateKey()` / `generateKey(HmacAlgorithm)` | 신규 공유 비밀키 생성, 기본 SHA256 |
| `of(byte[])` / `of(HmacAlgorithm, byte[])` | 기본 SHA256 또는 SHA512로 생성, 키 32바이트 이상 |
| `ofExternalKey(HmacAlgorithm, byte[])` | 상대가 이미 정한 비밀과 호환해야 할 때만 사용 |
| `sign(byte[])` / `sign(String)` | MAC 원시 바이트 반환 |
| `sign(byte[], Encoding)` / `sign(String, Encoding)` | MAC을 지정한 인코딩의 문자열로 반환 |
| `verify(byte[], byte[])` | 원시 바이트 MAC 검증 |
| `verify(byte[], String, Encoding)` / `verify(String, String, Encoding)` | 전달받은 문자열 MAC 검증 |
| `algorithm()` | 객체의 알고리즘 확인 |

**웹훅 검증:** HTTP 본문을 파싱한 뒤 JSON으로 다시 만들지 말고, 연계 규격이 요구하는 원본 바이트와 서명을 비교합니다. 형식 오류와 `false` 모두 인증 실패로 처리합니다.


<a name="topic-hmac--실행-예제--메시지-인증값-생성과-검증"></a>
### 실행 예제 — 메시지 인증값 생성과 검증

`HmacExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;

public class HmacExample {
    public static void main(String[] args) throws Exception {
        Hmac hmac = Hmac.of(Hmac.generateKey());
        String mac = hmac.sign("sample", Encoding.HEX);
        System.out.println(hmac.verify("sample", mac, Encoding.HEX));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-request-auth"></a>

## 서버 간 API 요청 인증

<a name="topic-request-auth--api-요청-인증"></a>
<a name="topic-request-auth--134-api-요청-인증--requestauth"></a>
### API 요청 인증 — RequestAuth (13.4)

**기능:** HMAC에 시각(Unix 초)·Nonce를 묶어 서버 간 요청을 서명하고, 받는 쪽에서 MAC·허용 시간(기본 ±5분, 최대 15분)을 확인합니다. MAC 계산·비교는 `Hmac`, Nonce는 `SecureRandoms`를 그대로 씁니다.

```java
// 예제: SecurityApiExample.requestAuth
public static RequestAuth.Result requestAuth(byte[] sharedKey, String method, String pathAndQuery, byte[] body) {
    byte[] request = (method + "\n" + pathAndQuery + "\n" + Digests.sha256Hex(body)).getBytes(StandardCharsets.UTF_8);
    RequestAuth auth = RequestAuth.of(Hmac.of(sharedKey));            // 허용 오차 5분, 시스템 UTC 시계
    RequestAuth.Signed signed = auth.sign(request);                   // 헤더: X-Timestamp·X-Nonce·X-Signature 등
    RequestAuth.Result result = auth.verify(request, signed.timestamp(), signed.nonce(), signed.mac());
    return result;
}
```

- **서명 원본(버전 1):** `"JCK-REQ-AUTH-v1\n" + 시각 + "\n" + Nonce + "\n"` 뒤에 호출자가 정한 요청 바이트. 메서드·경로·본문 중 무엇을 넣을지는 두 시스템이 정합니다. 다른 언어로 구현하는 상대도 이 바이트를 그대로 만들면 됩니다.
- **결과:** `VALID`·`BAD_MAC`·`TIMESTAMP_OUT_OF_RANGE`·`MALFORMED`(네트워크 입력 형식 오류도 예외 없이 결과로).
- **한계:** VALID는 "키를 가진 쪽이 허용 시간 안에 만든 요청"이라는 뜻일 뿐 재전송을 막지 않습니다. Nonce를 한 번만 받아야 하면 애플리케이션이 판단합니다. 서버 간 시계는 NTP 등으로 맞춥니다.

<a name="topic-request-auth--요청-인증에서-교환하는-값"></a>
#### 요청 인증에서 교환하는 값

| 항목 | 형식·기본값 |
|---|---|
| `RequestAuth.of(hmac)` | 시스템 UTC, 허용 오차 5분 |
| `RequestAuth.of(hmac, maxSkew, clock)` | `Duration` 1초~15분, 검증용 `Clock` 지정 가능(초 단위 적용) |
| `sign(request)` | `Signed` 반환: `timestamp()`(0~999,999,999,999 범위의 Unix 초 문자열), `nonce()`(Base64URL 22자), `mac()`(Base64URL) |
| `verify(request, timestamp, nonce, mac)` | `Result` 반환. `isValid()`로 성공 여부 확인 |
| 수신 형식 | 시각 숫자 1~12자, Nonce URL 안전 문자 16~128자, MAC URL 안전 문자(알고리즘의 MAC 길이 검증) |

발신자가 반환받은 세 값을 합의한 HTTP 헤더에 넣고, 수신자는 같은 규칙으로 만든 요청 바이트와 헤더값을 `verify`에 전달합니다. 헤더 이름 자체는 JCK가 강제하지 않습니다. 유효한 요청이 같은 허용 시간 내 다시 도착하면 `VALID`가 반환될 수 있습니다.


<a name="topic-request-auth--실행-예제--요청-서명-생성과-검증"></a>
### 실행 예제 — 요청 서명 생성과 검증

`RequestExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.nio.charset.StandardCharsets;

public class RequestExample {
    public static void main(String[] args) throws Exception {
        byte[] body = "sample".getBytes(StandardCharsets.UTF_8);
        RequestAuth auth = RequestAuth.of(Hmac.of(Hmac.generateKey()));
        RequestAuth.Signed signed = auth.sign(body);
        System.out.println(auth.verify(body, signed.timestamp(), signed.nonce(), signed.mac()).isValid());
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-hash"></a>

## SHA 해시와 파일 체크섬

<a name="topic-hash--sha-해시-및-파일-지문"></a>
<a name="topic-hash--136-해시파일-지문--digests"></a>
### 해시·파일 지문 — Digests (13.6)

**사용 상황:** 배포 파일의 SHA-256을 배포자가 공개한 값과 비교하거나 파일 전송 전후 내용이 같은지 확인할 때 사용합니다. 해시로 사용자 비밀번호를 저장하거나 요청자의 신원을 검증하지 않습니다.

```java
// 예제: SecurityApiExample.fileMatches
public static boolean fileMatches(Path file, String publishedSha256) throws IOException {
    return Digests.verifyFile(DigestAlgorithm.SHA256, file, publishedSha256, Encoding.HEX); // 스트리밍
}
```

- SHA-256·SHA-512(`DigestAlgorithm`), 입력은 `byte[]`·UTF-8 문자열·파일. 파일은 64KiB씩 읽어 스트리밍으로 계산하고 바꾸지 않습니다. 편의 메서드 `sha256`·`sha256Hex`·`sha256File`.
- 결과 구분: 파일 없음·읽기 실패는 `IOException`, 기대값과 다르면 `false`, 기대값이 그 형식이 아니면 `IllegalArgumentException`.
- 해시는 키가 없어 누구나 만들 수 있습니다. 기준 해시를 믿을 수 있는 경로로 받아야 하며, 비밀번호 저장·보낸 쪽 인증에 쓰지 않습니다.

| 호출 | 결과 |
|---|---|
| `sha256(byte[])` | 32바이트 해시 |
| `sha256Hex(String/byte[])` / `sha256File(Path)` | 64자 소문자 HEX |
| `hash(algorithm, data[, encoding])` | 바이트 또는 문자열 해시, `data`는 UTF-8 문자열 또는 바이트 |
| `hashFile(algorithm, path[, encoding])` | 파일을 스트리밍 해시 |
| `verifyFile(algorithm, path, expected, encoding)` | 기대 해시와 일치하면 `true` |

`DigestAlgorithm.SHA256`은 32바이트, `SHA512`는 64바이트 결과입니다. HEX로 표기하면 각각 64자, 128자입니다.


<a name="topic-hash--실행-예제--문자열-해시-길이-확인"></a>
### 실행 예제 — 문자열 해시 길이 확인

`HashExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.Digests;

public class HashExample {
    public static void main(String[] args) throws Exception {
        String sha256 = Digests.sha256Hex("sample");
        System.out.println(sha256.length());
    }
}
```

**예상 결과**

```text
64
```

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-signature"></a>

## 전자서명 및 PEM 키

<a name="topic-signature--전자서명-및-pem-키"></a>
<a name="topic-signature--1310-전자서명과-키-파일--signatures-pemkeys"></a>
### 전자서명과 키 파일 — Signatures, PemKeys (13.10)

**사용 상황:** 외부 기관에 파일이나 전문을 보내고 상대는 공개키만으로 발신자를 검증해야 할 때 사용합니다. 공유 키 기반 HMAC과 달리 검증 상대에게 개인키를 줄 필요가 없습니다.

```java
// 예제: SecurityApiExample.signFile
public static boolean signFile(Path file) throws IOException {
    KeyPair pair = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
    String privatePem = PemKeys.toPem(pair.getPrivate());             // 서명 서버만 보관(비밀)
    String publicPem = PemKeys.toPem(pair.getPublic());               // 검증하는 쪽에 배포
    PrivateKey signingKey = PemKeys.readPrivateKey(privatePem);
    byte[] signature = Signatures.signFile(SignatureAlgorithm.ECDSA_P256_SHA256, signingKey, file);
    PublicKey verifyKey = PemKeys.readPublicKey(publicPem);
    return Signatures.verifyFile(SignatureAlgorithm.ECDSA_P256_SHA256, verifyKey, file, signature);
}
```

- **알고리즘:** `RSA_SHA256`(RSA 2048비트 이상, 새 키 기본 3072), `ECDSA_P256_SHA256`(DER 서명), `ECDSA_P256_SHA256_P1363`(64바이트 R‖S, WebCrypto·JWT ES256 형식). ECDSA는 서명할 때마다 값이 달라지는 것이 정상입니다. 검증 전에 r·s 범위와 DER 정규형을 확인합니다.
- **결과:** 서명이 맞으면 `true`, 형식이 깨진 서명도 `false`. 키 종류·길이·곡선이 알고리즘과 맞지 않으면 예외. 파일은 스트리밍(`signFile`·`verifyFile`).
- **키 파일:** 개인키 PKCS#8(`-----BEGIN PRIVATE KEY-----`), 공개키 X.509 SubjectPublicKeyInfo(`-----BEGIN PUBLIC KEY-----`)의 PEM·DER 읽기·쓰기. PKCS#1(`RSA PRIVATE KEY`)·SEC1(`EC PRIVATE KEY`)·암호화 PEM은 변환 명령(`openssl pkcs8 -topk8 -nocrypt -in old.pem -out key.pem`)을 알려 주며 거부합니다.

  인증서는 [13.11절](certificates-keystores.md#topic-certificates--1311-x509-인증서--certificates).
- 서명은 내용을 숨기지 않으며, 공개키가 정말 서명자의 것인지는 따로 확보합니다. RSA 서명(PKCS#1 v1.5)은 RSA 암호화([13.13절](java-encryption.md#topic-rsa--1313-rsa-oaep--rsaoaep))와 다른 기능입니다.

| 호출 | 입력·출력 |
|---|---|
| `Signatures.checkKey(algorithm, key)` | 키 종류·크기·곡선이 알고리즘과 맞는지 미리 점검. 부적합 시 `IllegalArgumentException` |
| `Signatures.generateKeyPair(algorithm)` | RSA 또는 P-256 키 쌍 |
| `generateRsaKeyPair(bits)` | 2048/3072/4096비트 RSA 키 쌍 |
| `sign(algorithm, privateKey, data[, encoding])` | 문자열/바이트 → 서명 바이트 또는 인코딩 문자열 |
| `verify(algorithm, publicKey, byte[], byte[])` 또는 `verify(algorithm, publicKey, String/byte[], String, encoding)` | 원본과 서명 확인 → boolean |
| `signFile(algorithm, privateKey, path)` / `verifyFile(algorithm, publicKey, path, signature)` | 파일 스트리밍 서명 및 검증 |
| `PemKeys.readPrivateKey` / `readPublicKey` | PEM 문자열 또는 DER 바이트 → 키 객체 |
| `readPrivateKeyFile` / `readPublicKeyFile` | PEM/DER 파일 → 키 객체 |
| `toPem(key)` / `toDer(key)` | 키 객체 → 문자열/바이트. 개인키 출력은 비밀자료 |

`SignatureAlgorithm.RSA_SHA256`은 RSA PKCS#1 v1.5 서명(SHA-256), `ECDSA_P256_SHA256`은 DER, `ECDSA_P256_SHA256_P1363`은 고정 64바이트 R‖S입니다. 서명 방식을 RSA 암호화 방식과 혼동하지 않습니다.


<a name="topic-signature--실행-예제--문자열-서명과-공개키-검증"></a>
### 실행 예제 — 문자열 서명과 공개키 검증

`SignatureExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.security.KeyPair;

public class SignatureExample {
    public static void main(String[] args) throws Exception {
        SignatureAlgorithm algorithm = SignatureAlgorithm.RSA_SHA256;
        KeyPair pair = Signatures.generateKeyPair(algorithm);
        String signature = Signatures.sign(algorithm, pair.getPrivate(), "sample", Encoding.BASE64);
        System.out.println(Signatures.verify(algorithm, pair.getPublic(), "sample", signature, Encoding.BASE64));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

<a name="api-cli-guide"></a>
## 독립 보안 API의 CLI 사용

[인증·비밀 입출력 규칙](cli.md#api-cli)과 아래 업무별 옵션을 확인하세요.

<a name="api-hmac"></a>
### HMAC

기본 키 표현은 Base64입니다. 외부 시스템의 짧은 키를 비교할 때만 `--external-key`를 명시합니다. 실제 요청 원본이 파일이면 바이트 단위로 읽습니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api hmac sign` | 매 실행 | `--algorithm`, `--key-file`, `--key-encoding`, `--in`, `--encoding`, `--out`, `--external-key` |
| `api hmac verify` | 매 실행 | `--algorithm`, `--key-file`, `--key-encoding`, `--in`, `--encoding`, `--expected-file`, `--external-key` |

<details>
<summary>옵션과 기본값</summary>

- `hmac sign` — 기본 SHA-256과 Hex. 최대 1 MiB의 입력 바이트를 그대로 씁니다.
- `hmac verify` — 동일한 키·전문·표현을 사용합니다. 불일치는 FAIL(1)입니다.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--expected-file` — 예상값 한 줄의 파일. 생략하면 입력합니다.
- `--external-key` — 외부 HMAC 키 호환 모드를 명시합니다.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--key-encoding` — 공유키 표현. 기본 base64.
- `--key-file` — 인코딩한 비밀키 한 줄이 든 보호 파일.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# HMAC 키 생성
java -jar java-crypto-kit-0.2.1.jar api keygen --type hmac --out hmac.key --reason 'HMAC interop'

# 공유 키로 메시지 인증값 생성
java -jar java-crypto-kit-0.2.1.jar api hmac sign --key-file hmac.key --in request.json --out request.mac

# 메시지의 HMAC 인증값 검증
java -jar java-crypto-kit-0.2.1.jar api hmac verify --key-file hmac.key --in request.json --expected-file request.mac
```

<a name="api-hash"></a>
### 해시 생성과 비교

같은 입력을 다른 구현에서 비교할 때는 알고리즘과 표현을 맞춥니다. 해시 일치는 발신자의 신원을 보증하지 않습니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api hash generate` | 초기 설정 후 사용 | `--algorithm`, `--in`, `--encoding`, `--out` |
| `api hash verify` | 초기 설정 후 사용 | `--algorithm`, `--in`, `--encoding`, `--expected-file` |

<details>
<summary>옵션과 기본값</summary>

- `hash generate` — 기본 SHA-256과 Hex. 파일을 스트리밍으로 읽습니다.
- `hash verify` — 같은 해시 알고리즘과 예상값 표현을 사용합니다.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--expected-file` — 예상값 한 줄의 파일. 생략하면 입력합니다.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# 입력 파일의 해시 계산
java -jar java-crypto-kit-0.2.1.jar api hash gen --in application.jar --out application.sha

# 저장한 해시와 현재 파일 대조
java -jar java-crypto-kit-0.2.1.jar api hash verify --in application.jar --expected-file application.sha
```

<a name="api-signature"></a>
### 전자서명

RSA 서명의 기본 표현은 Base64입니다. ECDSA의 일반 서명은 DER로, JWT의 ES256 표현과 구분합니다. 서명 불일치는 FAIL과 종료 코드 1로 확인합니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api signature sign` | 매 실행 | `--algorithm`, `--private-key`, `--encoding`, `--in`, `--out` |
| `api signature verify` | 초기 설정 후 사용 | `--algorithm`, `--public-key`, `--encoding`, `--in`, `--signature-file` |

<details>
<summary>옵션과 기본값</summary>

- `signature sign` — 기본 RSA-SHA256과 Base64. 파일은 스트리밍합니다.
- `signature verify` — ECDSA-P256 서명은 DER 형식이며 ecdsa-sha256을 지정합니다.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--encoding` — hex, base64, base64url, base32.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--private-key` — PKCS#8 개인키 PEM/DER 보호 파일.
- `--public-key` — 신뢰한 SPKI 공개키 PEM/DER 파일.
- `--signature-file` — 분리 서명 파일.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# EC 키 생성
java -jar java-crypto-kit-0.2.1.jar api keygen --type ec --out ec --reason 'signature test'

# 개인 키로 데이터 서명
java -jar java-crypto-kit-0.2.1.jar api sig sign --alg ecdsa-sha256 --priv-key ec-private.pem --in sample.txt --out sample.sig

# 공개 키로 데이터 서명 검증
java -jar java-crypto-kit-0.2.1.jar api sig verify --alg ecdsa-sha256 --pub-key ec-public.pem --in sample.txt --sig-file sample.sig
```

<a name="api-request-auth"></a>
### RequestAuth

서명 결과의 JSON은 timestamp(Unix 초 문자열), nonce(Base64URL), mac(Base64URL)입니다. 그대로 `--auth-file`로 전달하거나 세 필드를 각각 지정합니다. `--at`은 시계를 고정하고 Nonce는 API가 생성합니다. 결과 파일과 리다이렉션에서는 JSON 한 줄, 실제 터미널에서는 필드별로 정렬한 JSON을 출력합니다. Java API도 같은 시각 범위를 적용합니다. 범위 밖의 값을 반환하는 `Clock`으로 서명하면 `IllegalArgumentException`이 발생합니다. 별도 요청 정규화와 재사용 상태 저장은 호출자가 관리합니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api request-auth sign` | 매 실행 | `--algorithm`, `--key-file`, `--key-encoding`, `--in`, `--at`, `--out` |
| `api request-auth verify` | 매 실행 | `--algorithm`, `--key-file`, `--key-encoding`, `--in`, `--at`, `--clock-skew`, `--auth-file`, `--timestamp`, `--nonce`, `--mac` |

<details>
<summary>옵션과 기본값</summary>

- `request-auth sign` — API가 Nonce를 생성합니다. 결과는 시각·Nonce·MAC을 담습니다.
- `request-auth verify` — 기본 허용 오차 300초, 최대 900초. 재사용 검사는 호출자 몫입니다.
- `--algorithm` — 이 명령의 알고리즘. 위 허용값을 확인합니다.
- `--at` — 시계를 고정할 0~999999999999 범위의 Unix 초 정수. 생략하면 현재 시각을 사용합니다.
- `--clock-skew` — 허용 오차(초). 명령별 범위를 확인합니다.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--key-encoding` — 공유키 표현. 기본 base64.
- `--key-file` — 인코딩한 비밀키 한 줄이 든 보호 파일.
- `--mac` — sign 결과 Base64URL MAC.
- `--nonce` — sign 결과 Base64URL Nonce.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--auth-file` — 서명 결과의 JSON 파일입니다. 세 문자열 `timestamp`, `nonce`, `mac`만 허용하며 개별 필드 옵션과 함께 지정할 수 없습니다.
- `--timestamp` — RequestAuth sign이 반환한 Unix 초.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# HMAC 키 생성
java -jar java-crypto-kit-0.2.1.jar api keygen --type hmac --out hmac.key --reason 'request test'

# HTTP 요청 인증값 생성
java -jar java-crypto-kit-0.2.1.jar api req-auth sign --key-file hmac.key --in request.json --out request.sig.json

# HTTP 요청 인증값 검증
java -jar java-crypto-kit-0.2.1.jar api req-auth verify --key-file hmac.key --in request.json --auth-file request.sig.json
```

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
