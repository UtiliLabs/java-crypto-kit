# OTP·JWT·OAuth 인증 및 토큰 처리

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

사용자 일회용 코드와 서비스 토큰을 생성·검증하거나 외부 인증 서버와 연계할 때 사용하는 Java API입니다. 토큰 검증과 애플리케이션의 권한·세션 관리는 구분합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[인증 방식 선택](#guide-section-1) · [사용자 인증과 API 인증의 적용 단계](#guide-section-2) · [HOTP·TOTP 일회용 코드](#topic-otp) · [JWT 발급·검증 및 JWKS](#topic-jwt) · [OAuth JWT 접근 토큰 검증](#topic-oauth) · [OAuth Token Introspection](#topic-oauth-introspection) · [OAuth Client Credentials](#topic-oauth-client-credentials)

---

<a name="guide-section-1"></a>
## 인증 방식 선택

| 필요 기능 | Java API | 적용 상황 |
|---|---|---|
| 인증 앱과 일회용 코드 | [`Hotp`, `Totp`](#topic-otp) | 가입·로그인 추가 인증 |
| 자체 서비스 JWT 발급 및 검증 | [`Jwt`, `JwtVerifier`, `Jwks`](#topic-jwt) | 서비스 토큰의 서명과 클레임 검증 |
| 외부 인증 서버의 JWT 접근 토큰 검증 | [`AccessTokenVerifier`](#topic-oauth) | API 리소스 서버의 발급자·대상·토큰 유형·권한 확인 |
| Opaque Token 활성 상태 확인 | [`TokenIntrospector`](#topic-oauth-introspection) | 인증 서버 HTTPS Introspection |
| 서버 간 API 접근 토큰 요청 | [`ClientCredentials`](#topic-oauth-client-credentials) | 배치·서버의 토큰 발급 요청 |

### 서버 간 OAuth 연동 순서

호출 서비스는 `ClientCredentials`로 토큰을 받고, 대상 API는 토큰 종류에 맞춰 `AccessTokenVerifier` 또는 `TokenIntrospector`로 검증합니다. 검증된 scope·role로 최종 업무 권한을 판단합니다. 토큰 보관·캐시·재발급 정책, OTP 재사용 방지, 세션 관리, 인증 서버 구현은 애플리케이션 책임입니다.

이 기능은 Java API 전용이며 CLI 관리자 인증과는 별개입니다. 예제 실행은 [Java API 공통 규칙](../reference/java-api-reference.md)을 참조합니다.

<a name="guide-section-2"></a>
## 사용자 인증과 API 인증의 적용 단계

| 단계 | 선택 및 연계 |
|---|---|
| 회원 가입·비밀번호 확인 | [Passwords](security-utilities.md#topic-password)로 원문을 저장하지 않고 해시 검증 |
| 추가 인증 | TOTP는 인증 앱과 시간 동기화, HOTP는 카운터 기반. 등록된 비밀키와 검증 정책 필요 |
| 자체 토큰 발급 | Jwt로 서명된 토큰 생성, 검증 서버는 신뢰 키·발급자·대상·만료 조건으로 확인 |
| 외부 OAuth 서버 연계 | ClientCredentials로 서버용 토큰을 발급받고 응답 만료·권한 정보를 읽음 |
| API 서버 검증 | JWT 접근 토큰이면 AccessTokenVerifier, opaque 토큰이면 TokenIntrospector. 토큰 종류와 발급자 정책에 맞게 선택 |
| 업무 승인 | 검증된 주체와 scope·role 및 애플리케이션 권한을 함께 확인 |

JWT의 HS256은 공유 비밀키를 가진 쪽이 모두 발급할 수 있고, RS256/ES256은 개인키를 가진 발급자만 서명하고 공개키로 검증합니다. 검증 서버가 여러 개라면 비대칭 방식이 키 배포에 유리합니다. JWKS는 신뢰하는 발급자의 공개키 목록을 읽는 기능이며 자동 HTTP 다운로드나 캐시는 아닙니다. 일반 JWT, OAuth 접근 토큰, ID Token을 같은 것으로 취급하지 않습니다.

<a name="topic-otp"></a>

## HOTP·TOTP 일회용 코드

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-otp)

<a name="topic-otp--hotptotp"></a>
<a name="topic-otp--1312-hotptotp--hotp-totp"></a>
### HOTP·TOTP — Hotp, Totp (13.12)

**사용 상황:** 등록한 비밀키와 시간(TOTP) 또는 카운터(HOTP)를 바탕으로 인증 앱과 같은 일회용 코드를 생성·검증할 때 사용합니다. SMS용 임의 숫자 코드 생성이나 사용자 계정 관리와는 다른 기능입니다.

```java
// 예제: SecurityApiExample.totp
public static OptionalLong totp(byte[] secret, String code) {
    Totp totp = Totp.of(secret);                                      // SHA1·6자리·30초(인증 앱 호환)
    String uri = totp.otpauthUri("예제 서비스", "user@example.com");   // QR로만 보여 주고 로그에 남기지 않는다
    OptionalLong step = totp.verify(code, Instant.now(), 1);          // 앞뒤 1구간(±30초)
    return uri.startsWith("otpauth://totp/") ? step : OptionalLong.empty();
}
```

- **TOTP(RFC 6238):** 기본 SHA1·6자리·30초(인증 앱 호환이 가장 넓음), `Totp.of(비밀키, OtpAlgorithm.SHA256, 8, Duration.ofSeconds(30))`처럼 고를 수 있음. 허용창 0~10(보통 1 = ±30초), 일치한 시간 구간 번호를 돌려줍니다. 일부 인증 앱은 SHA1·6자리·30초가 아닌 설정을 무시할 수 있으므로 앱으로 확인합니다.
- **HOTP(RFC 4226):** HMAC-SHA1, `verify(코드, 시작 카운터, 0~100)`이 일치한 카운터를 돌려줍니다.
- **비밀키:** 16바이트 이상(새 키는 `generateSecret`), 사람에게 보여 줄 때는 `Encoding.BASE32`. `otpauthUri`는 인증 앱 등록용 URI이며 **비밀키가 들어 있으므로** QR 화면 외에 로그·URL 기록에 남기지 않습니다.
- 6~8자리 코드는 우연히 겹칠 수 있습니다. 코드 재사용 방지·시도 제한·비밀키 보관은 애플리케이션 몫입니다.

| 설정 | TOTP | HOTP |
|---|---|---|
| 생성기 | `Totp.of(secret[, algorithm, digits, period])` | `Hotp.of(secret[, digits])` |
| 기본 알고리즘 | SHA1 | SHA1 고정 |
| 자리 수 | 6~8(기본 6) | 6~8(기본 6) |
| 주기/카운터 | 15~300초(정수, 기본 30초) | 호출자 제공 0 이상의 long |
| 생성 | `generate(Instant/Clock)` | `generate(counter)` |
| 검증 | `verify(code, time, window)` (앞뒤 0~10구간) | `verify(code, counter, lookAhead)` (앞으로 0~100) |
| 비밀 생성 | `generateSecret([algorithm])` | `generateSecret()` |

검증 결과 `OptionalLong`은 일치한 시간 구간/카운터입니다. 성공한 값의 재사용을 막거나 HOTP 다음 카운터를 저장하는 기능은 없습니다.

<a name="topic-otp--인증-앱-등록과-검증-순서"></a>
#### 인증 앱 등록과 검증 순서

1. 신규 사용자 등록 때 `Totp.generateSecret()`으로 비밀키를 한 번 만들고 사용자와 연결해 보호된 저장소에 보관합니다.
2. `Totp.of(secret).otpauthUri(issuer, accountName)`으로 등록 URI를 만들어 인증 앱에 전달합니다. URI와 QR에는 비밀키가 포함됩니다. JCK는 QR 이미지 생성이나 계정 등록 서버를 제공하지 않습니다.
3. 로그인 시 같은 비밀키로 `Totp.of(secret)`을 만들고 입력 코드와 현재 시각을 `verify`에 전달합니다. `OptionalLong.isPresent()`가 참이면 시간 구간이 일치한 것입니다. 이미 사용한 구간인지의 판단은 호출자 책임입니다.
4. HOTP는 시간 대신 호출자가 보관하는 카운터를 사용합니다. 검증 결과의 카운터는 다음 요청에서 같은 값이 재사용되지 않도록 서비스가 갱신합니다.

TOTP의 `generateSecret(OtpAlgorithm)`은 SHA1 20바이트, SHA256 32바이트, SHA512 64바이트의 비밀키를 생성합니다. `timeStep(Instant)`으로 시각의 구간 번호를 구할 수 있습니다. HOTP는 SHA1 고정이며 새 비밀키는 20바이트입니다.


<a name="topic-otp--실행-예제--동일-시간과-키로-totp-검증"></a>
### 실행 예제 — 동일 시간과 키로 TOTP 검증

`OtpExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.time.Instant;

public class OtpExample {
    public static void main(String[] args) throws Exception {
        Totp totp = Totp.of(Totp.generateSecret());
        Instant now = Instant.now();
        String code = totp.generate(now);
        System.out.println(totp.verify(code, now, 0).isPresent());
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-jwt"></a>

## JWT 발급·검증 및 JWKS

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-jwt)

<a name="topic-jwt--jwtjwks"></a>
<a name="topic-jwt--1316-jwt--jwt-jwtkey-jwtverifier-jwks"></a>
### JWT — Jwt, JwtKey, JwtVerifier, Jwks (13.16)

**기능:** 서명된 JWT(compact JWS, HS256·RS256·ES256)를 만들고, 서명 없이 내용만 보고(미검증 분석), 키·정책으로 검증합니다.

**선택 기준:** OAuth 인증 서버의 접근 토큰은 [13.17절](#topic-oauth--1317-oauth-access-token--accesstokenverifier-accesstokens). JWT Payload는 암호화되지 않으므로 비밀을 넣지 않습니다.

```java
// 예제: TokenApiExample.issue
public static String issue(PrivateKey signingKey) {
    JwtKey key = JwtKey.rs256(signingKey).withKeyId("2026-11");       // 각 서버가 키를 새로 만들지 않는다
    return Jwt.builder()
            .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
            .expiresIn(Duration.ofMinutes(10)).randomJwtId()
            .claim("role", "manager")
            .sign(key);                                               // header.payload.signature
}
```

```java
// 예제: TokenApiExample.verify
public static String verify(PublicKey current, PublicKey previous, String token) throws JwtException {
    JwtVerifier verifier = JwtVerifier.builder()
            .key(JwtKey.rs256(current).withKeyId("2026-11"))
            .key(JwtKey.rs256(previous).withKeyId("2026-05"))
            .issuer("https://auth.example.com").audience("orders-api")
            .clockSkew(Duration.ofSeconds(30))                        // 서버 간 시계 차(기본 0초, 최대 300초)
            .build();                                                 // 한 번 만들어 재사용(스레드 안전)
    VerifiedJwt jwt = verifier.verify(token);                         // 실패하면 JwtException(getReason)
    return jwt.claims().getString("role");
}
```

```java
// 예제: TokenApiExample.peekIssuer
public static String peekIssuer(String token) throws JwtException {
    UnverifiedJwt peek = Jwt.parseUnverified(token);                  // 서명을 확인하지 않음
    return peek.claims().issuer();                                    // 이 값으로 인증하지 말고 검증기 선택에만 쓴다
}
```

- **키:** `JwtKey.hs256(32바이트 이상 보안 난수 비밀)`, `rs256(개인키·공개키, RSA 2048 이상)`, `es256(P-256)`. 알고리즘은 키가 정하며 토큰의 `alg`로 바뀌지 않습니다(RSA 공개키를 HMAC 비밀로 쓰는 혼동 불가). 키 교체 기간에는 kid가 다른 이전·새 키를 함께 등록합니다. `withIssuer`로 키를 발급자에 묶으면 그 발급자의 토큰만 검증합니다.
- **JWKS:** 애플리케이션이 신뢰 경로(설정, 인증 서버 `jwks_uri`를 직접 HTTPS로 받은 값)로 얻은 JSON을 `Jwks.parse(json, 발급자)`로 읽습니다(네트워크 조회·캐시 없음). 서명 검증용 RSA(2048 이상, RS256)·EC P-256(ES256)만 받고, `use: enc`·`key_ops`에 verify 없는 키·지원하지 않는 키는 건너뛰며, 개인키 성분·대칭 키·알고리즘 불일치·중복 kid·다른 발급자, 쓸 수 있는 키가 하나도 없는 JWKS는 거부합니다.
- **검증 순서와 기본 정책:** 64KiB 이하·세 구간·엄격한 Base64URL·UTF-8·JSON(중복 멤버 거부) → 헤더(`alg`는 HS256·RS256·ES256만, `none`·`crit`·`b64`·JWE·중첩 JWT 거부, `jku`·`x5u`·`jwk`·`x5c`는 무시하고 쓰지 않음, `typ`는 기본으로 없거나 `JWT`이며 `types`로 지정) → kid·알고리즘으로 등록 키 하나 선택(여러 키를 차례로 시도하지 않음) → 서명 → 클레임. `exp` 필수(끌 수 있음), 허용 오차 기본 0초(최대 300초), 미래 `iat` 거부(끌 수 있음), `maxAge`, 시간 값은 0 이상 정수 초(소수 초 허용 옵션), `iss` 정확히 일치, `aud`에 기대 대상 포함 — 대상을 정하지 않았는데 토큰에 `aud`가 있으면 거부(`anyAudience()`로 명시).
- **생략과 명시적 null의 구분:** 검증기가 처리하는 등록 헤더·클레임 및 JWKS 키 속성은 선택 항목이라도 값으로 `null`을 전달하는 것과 항목을 생략하는 것이 다릅니다. 선택 항목이 필요 없다면 생략하고, 존재하면 해당 타입과 형식에 맞는 값을 제공합니다. 명시적 `null`을 정상 값으로 처리하지 않습니다.
- **결과 읽기:** `VerifiedJwt`의 `algorithm()`·`keyId()`·`header()`·`claims()`. `JwtClaims`는 표준 클레임(`issuer()`·`subject()`·`audience()`·`expiresAt()` 등)과 `getString`·`getLong`·`getBoolean`·`getStringList`·`getObject`로 값을 읽으며, 없으면 null(`getStringList`는 빈 목록), 형식이 다르면 변환하지 않고 `IllegalArgumentException`입니다.
- **미검증 분석:** `Jwt.parseUnverified`는 `UnverifiedJwt`를 돌려주며 서명을 확인하지 않습니다. 어떤 검증기를 쓸지 고를 때만 쓰고 인증에 쓰지 않습니다(검증 결과 `VerifiedJwt`로 바꿀 수 없음).
- **실패:** `JwtException.getReason()` — `MALFORMED`·`UNSUPPORTED`·`KEY_NOT_FOUND`·`SIGNATURE`·`EXPIRED`·`NOT_YET_VALID`·`ISSUED_IN_FUTURE`·`TOO_OLD`·`ISSUER`·`AUDIENCE`·`TYPE`·`MISSING_CLAIM`·`INVALID_CLAIM`·`SCOPE`. 실패한 토큰의 클레임은 돌려주지 않습니다.
- **여러 서버:** 발급 서버만 개인키(또는 HS256 공유 키)를 갖고 검증 서버에는 공개키를 배포합니다(비대칭 권장). 서버 간 시계는 NTP로 맞추고 차이가 있으면 `clockSkew`(예: 30~60초)를 씁니다. 서명·만료 검증은 토큰 폐기·재사용을 확인하지 않습니다.

**키 객체 확인:** `JwtKey.algorithm()`·`keyId()`·`issuer()`로 알고리즘 및 설정한 식별자를 확인합니다. `canSign()`·`canVerify()`는 키의 서명·검증 가능 여부입니다.

비대칭 개인키는 서명용, 공개키는 검증용이고 HS256 공유키는 두 용도로 사용합니다.

**JWT 발급 설정 (`Jwt.builder()` / `builder(Clock)`)**

| 옵션 | 용도·기본값 |
|---|---|
| `type(String)` | 기본 `JWT`, null은 헤더 생략(일반 JWT 발급용) |
| `issuer` / `subject` / `audience(String...)` | 발급자·주체·대상. 대상 하나는 문자열, 여러 개는 배열 |
| `expiresAt(Instant)` / `expiresIn(Duration)` | 절대 만료 시각 또는 발급 후 만료 기간(최소 1초). 검증의 기본 정책에 맞게 명시 |
| `notBefore(Instant)` / `issuedAt(Instant)` | 사용 시작/발급 시각, iat 기본 현재 시각, null로 iat 생략 가능 |
| `jwtId(String)` / `randomJwtId()` | 직접 지정 또는 256비트 난수 식별값 |
| `claim(name, value)` | 업무 클레임: String, long, boolean, List<String>, Map<String, ?>. 표준 클레임은 전용 옵션으로 |
| `sign(JwtKey)` | 서명 후 compact JWS 문자열 반환 |

**JWT 검증 설정 (`JwtVerifier.builder()`)**

| 옵션 | 의미·선택 기준 |
|---|---|
| `key` / `keys` | 신뢰 검증 키. 여러 키는 kid로 선택 |
| `issuer` / `audience` | 기대 발급자·대상. 실제 서비스에서는 둘 다 지정 |
| `anyAudience()` | 기대 audience를 지정하지 않아도 aud가 있는 토큰을 받도록 명시. 기본은 이런 토큰을 거부합니다. audience를 지정하면 그 값은 계속 확인합니다 |
| `types(String...)` | 허용 헤더 typ. 지정하지 않으면 JWT 또는 헤더 없음 |
| `requireClaims` / `requireClaimValue` | 필수 클레임 또는 정확한 문자열 값 |
| `requireExpiration(boolean)` | 기본 true |
| `requireIssuedAt(boolean)` | 기본 false; maxAge 지정 시 iat 필요 |
| `rejectFutureIssuedAt(boolean)` | 기본 true |
| `maxAge(Duration)` | iat 기준 최대 수명(양수) |
| `clockSkew(Duration)` | 기본 0초, 정수 초로 0~300초 |
| `allowFractionalTimes(boolean)` | 기본 false(정수 Unix 초만) |
| `clock(Clock)` | 기본 UTC 시스템 시계, 고정 시험 시각 지정 가능 |
| `build().verify(token)` | 검증된 `VerifiedJwt` 반환. 실패 시 `JwtException` |

검증 성공 후 `VerifiedJwt.algorithm()`은 실제 서명에 사용한 `JwtAlgorithm`을 반환합니다. `HS256`은 양측이 같은 비밀키를 쓰고, `RS256`(RSA)과 `ES256`(P-256)은 발급자가 개인키로 서명하고 수신자가 공개키로 검증합니다. 검증기는 미리 등록한 키와 알고리즘이 일치해야 토큰을 수락합니다.

클레임 값을 출력하기 전에 검증된 토큰인지 구분합니다. 토큰 문자열·Payload 전체를 운영 로그에 남기지 않습니다.


### JWT 헤더 및 클레임 읽기

| 호출 | 결과와 활용 |
|---|---|
| `JwtClaims.parse(json)` | JSON 객체를 엄격하게 분석. 서명 검증 아님 |
| `issuer()` / `subject()` / `jwtId()` | 발급자·주체·토큰 ID |
| `audience()` | 단일 문자열 또는 배열 형태의 대상을 목록으로 반환 |
| `expiresAt()` / `issuedAt()` / `notBefore()` | 표준 시간 클레임을 `Instant`로 반환 |
| `getString` / `getLong` / `getBoolean` | 이름을 지정해 해당 타입의 값을 읽음. 타입을 강제 변환하지 않음 |
| `getStringList` / `getObject` | 문자열 배열 또는 중첩 JSON 객체 |
| `getInstant(name)` | 업무 시간 클레임(NumericDate)을 `Instant`로 변환 |
| `names()` / `has(name)` | 클레임 이름 목록 / 항목 존재 여부. `has`는 명시적 JSON null도 존재로 판단 |
| `toJson()` | 압축 JSON 전체. 민감 정보가 들어 있을 수 있으므로 로그에 남기지 않음 |
| `JwtException.getClaim()` | 실패한 관련 헤더·클레임의 이름(없으면 null). 값 자체는 반환하지 않음 |

검증된 `VerifiedJwt` 또는 검증된 접근 토큰에서 얻은 값을 업무 권한 판단에 사용합니다. 단순 `parse`·미검증 분석은 인증 결과가 아닙니다.

<a name="topic-jwt--실행-예제--jwt-발급과-검증"></a>
### 실행 예제 — JWT 발급과 검증

`JwtExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.jwt.*;
import io.javacryptokit.security.*;
import java.time.Duration;

public class JwtExample {
    public static void main(String[] args) throws Exception {
        JwtKey key = JwtKey.hs256(SecureRandoms.bytes(32));
        String token = Jwt.builder().issuer("example").audience("demo")
                .subject("sample").expiresIn(Duration.ofMinutes(5)).sign(key);
        JwtVerifier verifier = JwtVerifier.builder().key(key).issuer("example").audience("demo").build();
        System.out.println("sample".equals(verifier.verify(token).claims().subject()));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-oauth"></a>

## OAuth JWT 접근 토큰 검증

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-oauth)

<a name="topic-oauth--oauth-access-token-검증"></a>
<a name="topic-oauth--1317-oauth-access-token--accesstokenverifier-accesstokens"></a>
### OAuth Access Token — AccessTokenVerifier, AccessTokens (13.17)

**기능:** 리소스 서버(API)가 OAuth 인증 서버의 JWT 접근 토큰을 "이 API를 호출해도 되는 토큰인가" 기준으로 검증합니다. 일반 JWT·ID Token·다른 서비스용 토큰을 접근 토큰과 구분하는 정책을 적용합니다.

RFC 9068은 전용 typ를 검사하고, 설정형 프로파일은 인증 서버의 실제 토큰 규칙에 따라 호출자가 조건을 지정해야 합니다.

<a name="topic-oauth--예제-입력-준비"></a>
#### 예제 입력 준비

| 입력 | 준비할 값 |
|---|---|
| 발급자·대상 | 인증 서버의 issuer 및 API audience |
| 검증 키 | 신뢰 경로로 받은 공개키 또는 JWKS |
| 접근 토큰 | 해당 인증 서버에서 발급한 토큰 |
| 프로파일 | 실제 접근 토큰과 ID Token을 구분하는 정책 |

예제의 URL·키 ID·권한 이름은 실제 서비스 값으로 바꿉니다.

<a name="topic-oauth--java-예제"></a>
#### Java 예제

```java
// 예제: TokenApiExample.issueAccessToken
public static String issueAccessToken(PrivateKey signingKey) {
    return AccessTokens.builder()
            .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
            .clientId("web-portal").scopes("orders.read", "orders.write")
            .expiresIn(Duration.ofMinutes(5))
            .sign(JwtKey.rs256(signingKey).withKeyId("2026-11"));     // typ: at+jwt, jti·iat 자동
}
```

```java
// 예제: TokenApiExample.canReadOrders
public static boolean canReadOrders(PublicKey issuerKey, String bearer) {
    AccessTokenVerifier verifier = AccessTokenVerifier.rfc9068()
            .issuer("https://auth.example.com").audience("orders-api")
            .key(JwtKey.rs256(issuerKey).withKeyId("2026-11"))
            .requireScopes("orders.read")                             // 정확한 이름(부분 문자열 아님)
            .build();
    try {
        AccessToken token = verifier.verify(bearer);
        return token.hasScope("orders.read");                         // 업무 권한·폐기 여부는 앱이 추가로 판단
    } catch (JwtException e) {
        return false;                                                 // e.getReason(): TYPE·AUDIENCE·EXPIRED·SCOPE ...
    }
}
```

```java
// 예제: TokenApiExample.keycloakStyle
public static AccessTokenVerifier keycloakStyle(String issuer, String jwksJson) {
    List<JwtKey> keys = Jwks.parse(jwksJson, issuer);                 // 네트워크 조회 없음, 발급자에 키를 묶음
    return AccessTokenVerifier.profile()
            .issuer(issuer).audience("orders-api").keys(keys)
            .requireClaimValue("typ", "Bearer")                       // Access Token(Bearer)과 ID Token(ID) 구분
            .clientIdClaim("azp")
            .clockSkew(Duration.ofSeconds(60))
            .build();
}
```

| 프로파일 | 토큰 종류 조건 | 필수 클레임 | 쓰는 곳 |
|---|---|---|---|
| `rfc9068()` | 헤더 `typ`가 `at+jwt` 또는 `application/at+jwt`(대소문자 무시)만 | iss·exp·aud·sub·client_id·iat·jti | RFC 9068을 따르는 인증 서버 |
| `profile()` | 실제 발급자에서 Access Token과 ID Token을 구분하는 비어 있지 않은 조건을 지정 | 발급자(iss)·대상(aud)·만료(exp)와 공급자별 구분 조건. 나머지는 설정에 따라 검사 | 헤더 `typ`가 `JWT`인 인증 서버(Microsoft Entra ID·Keycloak 기본 설정 등) |

- **공통:** 발급자·대상은 필수, 서명·시간 규칙은 [13.16절](#topic-jwt--1316-jwt--jwt-jwtkey-jwtverifier-jwks)과 같습니다. 권한은 정확한 이름으로 비교합니다(`orders.read`가 `orders.readonly`로 승인되지 않음). 실패는 `JwtException`(권한 부족은 `SCOPE`).
- **공급자별 차이(설정형 예):** Microsoft Entra ID v2는 `typ: JWT`, 위임 권한 `scp`(공백 구분)·앱 권한 `roles`(배열), 클라이언트 `azp`, `ver: 2.0` → `.types("JWT").scopeClaim("scp").rolesClaim("roles").clientIdClaim("azp").requireClaimValue("ver", "2.0").requirePermissionClaim(true)`. Keycloak은 접근 토큰 클레임 `typ: Bearer`, ID Token `typ: ID` → `.requireClaimValue("typ", "Bearer").clientIdClaim("azp")`. 위 설정은 공급자별 구성의 예시이며, `ver`·`roles` 등의 존재만으로 ID Token이 반드시 거부되는 것은 아닙니다.

  해당 인증 서버에서 실제 발급한 Access Token과 ID Token을 비교하여 구분 정책을 검증한 뒤 적용합니다. Entra 실서버 연동은 시험하지 않았습니다(Keycloak은 Docker 하니스로 실연동).
- **설정형 프로파일의 빌더 검증:** `build()`는 최종 설정을 검사합니다. `JWT`를 허용하는 헤더 유형만 지정하거나, 일반 등록 클레임만 요구하거나, 빈 조건을 추가하거나, 이전에 지정했던 구분 조건을 해제하면 충분한 구분 조건이 아닙니다. 실제 공급자 규칙에 맞는 전용 헤더 유형, 업무 클레임의 존재·값·금지 조건 또는 비어 있지 않은 권한 조건을 지정해야 합니다. 이 검사 자체가 공급자별 토큰 정책의 정확성을 보장하지는 않으므로 실제 발급 토큰으로 별도 확인합니다.
- **ID Token 오인 방지:** 대상(aud) 일치만으로 판단하지 않고 토큰 종류 조건을 함께 둡니다(같은 앱 등록을 쓰면 ID Token의 aud가 API와 같을 수 있음).
- **발급(`AccessTokens`):** 자체 인증 서버·시험·서버 간 발급용으로 `typ: at+jwt`와 필수 클레임(jti는 256비트 난수, iat는 현재)을 넣습니다. 토큰 엔드포인트·Refresh Token·폐기 기능은 없습니다.
- 검증 성공은 최종 업무 승인·폐기·세션 상태 확인이 아닙니다.

| 옵션 | 의미 |
|---|---|
| `issuer` / `audience` / `key` 또는 `keys` | 신뢰하는 발급자·대상·검증 키(필수) |
| `types` | 설정형 프로파일의 허용 헤더 유형. `JWT`만으로는 ID Token과 구분할 수 없음 |
| `requireClaims` / `requireClaimValue` / `forbidClaims` | 필요한 클레임·기대 문자열·있으면 거부할 클레임 |
| `clientIdClaim` | 설정형 클라이언트 ID 필드. 지정하면 필수. RFC 9068은 client_id 고정 |
| `scopeClaim` / `rolesClaim` | 기본 scope(공백 구분 문자열) / roles(문자열 배열) |
| `requirePermissionClaim` / `requireScopes` / `requireRoles` | 권한이 비어 있지 않아야 하는지, 특정 권한·역할이 모두 있어야 하는지 |
| `clockSkew` / `maxAge` / `requireIssuedAt` / `rejectFutureIssuedAt` / `allowFractionalTimes` / `clock` | 일반 JWT 시간 정책. RFC 9068의 iat 필수 조건은 변경 불가 |

`AccessTokens.builder()`는 발급자·주체·대상·클라이언트 ID·만료 기간을 지정하고 `scopes`·`roles`·`jwtId`·업무 `claim`을 선택하여 `sign`합니다. 결과는 Access Token용 compact JWS이며 인증 서버 전체 기능이 아닙니다.

`AccessToken`의 `issuer()`·`subject()`·`clientId()`·`audience()`·`scopes()`·`roles()`·`hasScope()`·`hasRole()`·`expiresAt()`·`jwtId()`·`claims()`·`jwt()`를 활용합니다.

API의 최종 업무 권한은 검증 후에도 별도로 판단합니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-oauth-introspection"></a>

## OAuth Token Introspection

<a name="topic-oauth-introspection--oauth-token-introspection"></a>
<a name="topic-oauth-introspection--1318-token-introspection--tokenintrospector"></a>
### Token Introspection — TokenIntrospector (13.18)

**기능:** 접근 토큰(Opaque 또는 인증 서버가 Introspection을 지원하는 JWT)의 활성 상태를 호출자가 정한 인증 서버 엔드포인트에 RFC 7662로 묻습니다.

<a name="topic-oauth-introspection--예제-입력-준비"></a>
#### 예제 입력 준비

| 입력 | 준비할 값 |
|---|---|
| `endpoint` | 인증 서버의 HTTPS Introspection 주소 |
| `clientSecret` | 인증 서버에서 발급한 클라이언트 비밀 |
| `opaqueToken` | 확인할 접근 토큰 |

예제의 `orders-api`와 `orders.read`는 실제 클라이언트 ID와 권한으로 바꿉니다.

<a name="topic-oauth-introspection--java-예제"></a>
#### Java 예제

```java
// 예제: TokenApiExample.introspect
public static boolean introspect(URI endpoint, char[] clientSecret, String opaqueToken) {
    TokenIntrospector introspector = TokenIntrospector.builder(endpoint)   // https만, 리다이렉트 안 따라감
            .clientSecretBasic("orders-api", clientSecret)
            .build();                                                  // 한 번 만들어 재사용
    try {
        IntrospectionResult result = introspector.introspect(opaqueToken, "access_token");
        return result.active() && result.scopes().contains("orders.read");
    } catch (IntrospectionException e) {
        // 인증 서버 통신·응답 문제(e.getReason()): 토큰을 유효하다고 보지 않고 일시 오류(예: 503)로 처리한다.
        return false;
    }
}
```

- **요청:** HTTPS `POST`, form 본문 `token`(+`token_type_hint`), 클라이언트 인증 `client_secret_basic`(ID·비밀을 각각 form-urlencoding 후 Basic). 토큰·비밀을 URL에 넣지 않습니다.
- **TLS·제한:** JVM 기본 신뢰 저장소 또는 `sslContext`로 주입한 신뢰 설정을 쓰며 호스트명 검증은 항상 JDK 기본입니다(끄는 기능 없음). `http://`·사용자 정보가 든 주소는 거부, 리다이렉트는 따라가지 않습니다. 연결 5초·읽기 10초·응답 64KiB 기본(최대 60초·120초·1MiB).
- **결과 구분:** 비활성은 `active() == false`(다른 값은 비움), 통신·응답 문제는 `IntrospectionException`(`CLIENT_AUTH`·`HTTP_STATUS`·`REDIRECT`·`TIMEOUT`·`TLS`·`NETWORK`·`INVALID_RESPONSE`·`RESPONSE_TOO_LARGE`). 통신 실패를 활성으로 보거나 JWT 검증으로 대신하지 않습니다.

  위의 boolean 예제는 성공 여부만 반환하므로 통신 오류도 false입니다. HTTP 상태를 구분해야 하는 실제 API에서는 `IntrospectionException`을 상위 계층까지 전달하거나 별도로 처리하여 비활성 토큰과 서버 장애를 구별합니다.

  발급 요청과 상태 조회의 장애를 한 곳에서 처리할 때는 두 예외의 상위 타입 `OAuthClientException`을 사용합니다. `getReason()`은 실패 종류, `getStatusCode()`는 받은 HTTP 상태(응답이 없으면 -1), `getOAuthError()`는 서버가 보낸 표준 OAuth 오류 코드(없으면 null)를 반환합니다.

  대상·권한 확인은 결과의 `audience()`·`scopes()`로 호출자가 합니다. 토큰 캐시·공유 DB·로그는 없습니다.

| 설정 | 기본·허용값 |
|---|---|
| `builder(URI)` | 호출자가 신뢰하는 HTTPS introspection endpoint |
| `clientSecretBasic(clientId, char[])` | 클라이언트 인증(필수) |
| `connectTimeout(Duration)` | 5초, 1ms~60초 허용(1ms 미만·60초 초과 거부) |
| `readTimeout(Duration)` | 10초, 1ms~120초 허용(1ms 미만·120초 초과 거부) |
| `maxResponseBytes(int)` | 65,536바이트, 1,024~1,048,576바이트 |
| `sslContext(SSLContext)` | 미지정 시 JVM 기본 TLS 신뢰 설정 |
| `build().introspect(token[, tokenTypeHint])` | `IntrospectionResult` 반환 |

`IntrospectionResult`에서 `active`, `scopes`, `clientId`, `username`, `tokenType`, `subject`, `issuer`, `audience`, `jwtId`, `expiresAt`, `issuedAt`, `notBefore`, `claims`를 조회할 수 있습니다.

서버가 반환하지 않은 선택 항목을 추측하지 않습니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-oauth-client-credentials"></a>

## OAuth Client Credentials

<a name="topic-oauth-client-credentials--oauth-client-credentials"></a>
<a name="topic-oauth-client-credentials--1319-client-credentials-토큰-발급-요청--clientcredentials"></a>
### Client Credentials 토큰 발급 요청 — ClientCredentials (13.19)

**기능:** 다른 API를 호출하기 전에 기존 인증 서버의 token endpoint에서 서비스 계정(기밀 클라이언트)용 접근 토큰을 받습니다(RFC 6749 4.4). 인증 서버·로그인·Authorization Code·Refresh Token 관리 기능이 아닙니다.

<a name="topic-oauth-client-credentials--예제-입력-준비"></a>
#### 예제 입력 준비

| 입력 | 준비할 값 |
|---|---|
| 토큰 엔드포인트 | 인증 서버의 HTTPS token 주소 |
| 클라이언트 ID·비밀 | 서비스 계정의 인증 정보 |
| scope | 대상 API에 부여된 권한 |

인증 서버의 등록 정보와 발급 정책에 맞춰 입력값을 변경합니다.

<a name="topic-oauth-client-credentials--java-예제"></a>
#### Java 예제

```java
// 예제: TokenApiExample.partnerAuthorization
public static String partnerAuthorization(URI tokenEndpoint, char[] clientSecret) throws TokenRequestException {
    ClientCredentials client = ClientCredentials.builder(tokenEndpoint)
            .clientSecretBasic("orders-batch", clientSecret)          // 또는 clientSecretPost(인증 서버가 요구할 때)
            .build();                                                  // 한 번 만들어 재사용
    TokenResponse token = client.requestToken("orders.read");         // 실패: TokenRequestException(getReason·getOAuthError)
    // 토큰 재사용·만료 전 재발급 시점은 애플리케이션이 정한다(token.expiresAt()이 null이면 서버가 만료를 알려 주지 않은 것).
    return token.authorizationHeader();                               // "Bearer ..." → 호출할 API의 Authorization 헤더
}
```

- **요청:** HTTPS `POST`, UTF-8 form `grant_type=client_credentials`와 선택 `scope`(공백 구분). 클라이언트 인증은 정확히 하나: `clientSecretBasic`(기본) 또는 `clientSecretPost`(인증 서버가 요구할 때). 두 방식을 함께 쓰거나 실패 때 다른 방식으로 바꿔 시도하지 않습니다. HTTPS 처리·제한은 [13.18절](#topic-oauth-introspection--1318-token-introspection--tokenintrospector)과 같습니다.
- **응답(`TokenResponse`):** `accessToken()`(JWT라고 가정하지 않음), `tokenType()`(`Bearer`만, 대소문자 무시), `expiresIn()`(인증 서버가 주지 않으면 빈 값)·`expiresAt()`(그때 null, 만료를 지어내지 않음), `requestedScopes()`·`grantedScopes()`(차이를 숨기지 않음), `authorizationHeader()`. 응답의 Refresh Token은 읽지 않습니다.
- **실패(`TokenRequestException`):** 인증 서버의 OAuth 오류(400 등)는 `OAUTH_ERROR`와 표준 코드(`getOAuthError()`: `invalid_client`·`invalid_scope`·`unauthorized_client` 등, `error_description`은 전달하지 않음). 401·403은 `CLIENT_AUTH`(요청을 고정 길이 스트리밍으로 보내 JVM 전역 `Authenticator`가 다른 자격 증명을 자동으로 보내지 않게 하며, 이때 JDK가 401 본문을 주지 않으므로 오류 코드를 추측하지 않음). 그 밖에 `HTTP_STATUS`·`REDIRECT`·`TIMEOUT`·`TLS`·`NETWORK`·`INVALID_RESPONSE`·`RESPONSE_TOO_LARGE`.
- **애플리케이션 몫:** 토큰 재사용·만료 전 재발급·호출 빈도·인증 서버 장애 처리·서버 간 토큰 공유. 자동 재시도·캐시·스케줄러는 없습니다. 발급 성공은 리소스 접근 승인과 다르며, 받은 토큰을 다른 서버에서 쓸 수 있는지는 인증 서버의 대상·권한 정책에 달려 있습니다.

| 설정 / 결과 | 의미 |
|---|---|
| `builder(URI)` | 호출자가 신뢰하는 HTTPS token endpoint |
| `clientSecretBasic` / `clientSecretPost` | 인증 서버가 요구하는 클라이언트 인증 방식 한 개 선택 |
| `connectTimeout` / `readTimeout` / `maxResponseBytes` / `sslContext` | [13.18절](#topic-oauth-introspection--1318-token-introspection--tokenintrospector)의 공통 HTTPS 설정과 동일 |
| `clock(Clock)` | 응답 수신 시각 및 만료 계산에 사용하는 시계 |
| `requestToken()` / `requestToken(scopes...)` | scope 미지정 또는 요청 scope 지정. `TokenResponse` 반환 |
| `receivedAt()` / `scopeInResponse()` | 응답 수신 시각 / 서버가 scope를 명시했는지 확인 |

**응답으로 다음 호출을 결정하기**

- 호출에 필요한 권한과 발급 응답의 권한을 비교하려면 `scopeInResponse()`부터 확인합니다. `requestedScopes()`는 요청값이고 `grantedScopes()`는 서버가 명시한 값입니다. 응답에 scope가 없으면 후자는 빈 집합입니다.
- `expiresIn()`은 초 단위 `OptionalLong`입니다. 서버가 수명을 주지 않으면 비어 있고 `expiresAt()`도 `null`입니다. 만료 전에 다시 요청하는 시점과 캐시는 호출 서비스에서 관리합니다.
- `clientSecretBasic`은 HTTP 인증 헤더, `clientSecretPost`는 폼 본문을 사용합니다. 인증 서버가 지원하는 한 가지를 한 번만 지정하세요. 같은 Builder에서 인증 방식을 두 번 지정하면 입력 오류입니다.

실제 HTTP 요청에 넣는 값은 `token.authorizationHeader()`입니다. 응답을 화면에 출력하거나 로그에 남기지 않습니다. 만료값이 없다면 수명을 임의로 만들지 말고 인증 서버 정책을 확인합니다.

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
