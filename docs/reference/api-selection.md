# 업무별 Java API 선택표

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

<a name="topic-api-selection"></a>

<a name="topic-api-selection--업무별-api-선택"></a>
<a name="topic-api-selection--15-업무별-java-api-선택-가이드"></a>
## 1.5 업무별 Java API 선택 가이드

외부 시스템과 키·형식·알고리즘을 교차 검증할 때는 [독립 보안 API CLI](../guide/cli.md#api-cli)를 사용할 수 있습니다. PKIX 체인·키 저장소 조회와 안전 비교는 Java에서 호출합니다.

업무 목적에 맞는 API를 선택하세요. 관리형 키 기능은 2~12장, 범용 보안 API는 [13장](java-api-reference.md#topic-security-api--13-범용-보안-java-api)에 자세히 있습니다.

범용 API는 관리형 키·설정·History·CLI 인증과 독립적입니다. 키와 정책은 호출자가 지정합니다.

<a name="topic-api-selection--암복호화와-데이터-보호"></a>
옵션의 인수 순서나 결과 객체의 메서드를 찾을 때는 [타입별 호출 형식](java-api-reference.md#api-members)에서 클래스 이름을 펼치세요.

### 암복호화와 데이터 보호

| 목적 | 적용 예 | API | 제약·주의 |
|---|---|---|---|
| JAR·설정으로 관리하는 키로 값·파일을 암복호화 | WAS DB 접속 비밀번호, 기존 업무 암호문 | `CredentialCrypto.fromDefaultConfiguration` ([6장](../guide/java-encryption.md#topic-java-api--6-java-api)), Tomcat Factory([3장](../guide/tomcat-jdbc.md#topic-tomcat--3-tomcat-jndi-연동)) | 키 정책은 관리형 키 규칙을 따름. 아래 직접 키 방식과 구분 |
| 애플리케이션이 가진 32바이트 키로 원문 복구가 필요한 데이터를 보호 | 회원 개인정보·계좌 관련 컬럼, 업무 파일 | `CredentialCrypto.fromRawKey` ([6.7절](../guide/java-encryption.md#topic-direct-key--67-개발자가-직접-키를-주는-api)), AES-128·업무 AAD가 필요하면 `AesGcm` ([13.2절](../guide/java-encryption.md#topic-aes--132-aes-gcm과-업무-aad--aesgcm)) | 복호화에 같은 키(와 키 ID)가 필요. 키 보관·교체는 애플리케이션 몫 |
| 직접 관리하는 비밀 문자열(Passphrase)에서 키를 만들어 암호화 | 업무별 비밀 문자열로 설정값·파일 보호 | `CredentialCrypto.fromPassphrase` ([6.7절](../guide/java-encryption.md#topic-direct-key--67-개발자가-직접-키를-주는-api)), `AesGcm.fromPassphrase` ([13.2절](../guide/java-encryption.md#topic-aes--132-aes-gcm과-업무-aad--aesgcm)) | 같은 원문만으로는 안 풀림: Salt·KDF·반복 횟수·알고리즘을 함께 보관 |
| 암호문을 다른 레코드로 옮겨 붙이는 것을 탐지 | 고객 ID·거래 ID에 묶인 암호문 | `AesGcm` 업무 AAD ([13.2절](../guide/java-encryption.md#topic-aes--132-aes-gcm과-업무-aad--aesgcm)) | 복호화할 때 같은 AAD가 필요. AAD 자체는 암호화되지 않음 |
| 수신자 공개키로 짧은 비밀값(데이터 키 등)을 전달 | 상대 서버에 임시 키·비밀 전달 | `RsaOaep` ([13.13절](../guide/java-encryption.md#topic-rsa--1313-rsa-oaep--rsaoaep)) | 평문 크기 제한(RSA 2048·OAEP SHA256은 190바이트). 서명이 아님 |
| 수신자 공개키로 큰 업무 메시지를 보호해 전달 | 제휴사 전송 데이터, 공개키만 받은 상대에게 보내는 메시지 | `HybridEncryption` ([13.14절](../guide/java-encryption.md#topic-hybrid--1314-hybrid-암호화--hybridencryption)) | 공개키가 정말 상대 것인지 확인 필요. JWE 아님. 메모리 64MiB까지, 파일 스트리밍 없음 |

<a name="topic-api-selection--데이터-인증전자서명인증서"></a>
### 데이터 인증·전자서명·인증서

| 목적 | 적용 예 | API | 제약·주의 |
|---|---|---|---|
| 두 시스템이 공유 비밀키로 메시지 위변조·보낸 쪽 확인 | 서버 간 API 요청 서명, 웹훅·전문 검증 | `Hmac` ([13.3절](../guide/data-integrity.md#topic-hmac--133-hmac--hmac)), 요청 형식까지 정해 쓰려면 `RequestAuth` ([13.4절](../guide/data-integrity.md#topic-request-auth--134-api-요청-인증--requestauth)) | 암호화가 아님(내용은 보임). 재전송 방지는 별도 |
| 서명한 쪽만 개인키를 갖고 여러 상대가 공개키로 검증 | 외부 기관 전문 검증, 파일 전자서명 | `Signatures`, 키 파일은 `PemKeys` ([13.10절](../guide/data-integrity.md#topic-signature--1310-전자서명과-키-파일--signatures-pemkeys)) | 서명은 내용을 숨기지 않음. 공개키의 신뢰 확보 필요 |
| 이미 가진 `.p12`·`.pfx`·`.jks`의 키·인증서 사용 | 기관 발급 서명 키, 기존 TLS 키 저장소 | `KeyStoreReader` ([13.15절](../guide/certificates-keystores.md#topic-keystore--1315-pkcs12jks-키-저장소--keystorereader)) | 읽기 전용. 별칭·엔트리 비밀번호 명시. 저장소에 있다고 신뢰하는 것은 아님 |
| 인증서의 만료일·발급자·지문 확인, 신뢰 체인 검증 | HTTPS·mTLS 인증서 만료 점검 | `Certificates` ([13.11절](../guide/certificates-keystores.md#topic-certificates--1311-x509-인증서--certificates)) | 분석·기간 확인 ≠ 신뢰 체인 검증 ≠ 호스트명·폐기 확인(미지원) |

<a name="topic-api-selection--비밀번호난수해시키-파생인코딩"></a>
### 비밀번호·난수·해시·키 파생·인코딩

| 목적 | 적용 예 | API | 제약·주의 |
|---|---|---|---|
| 사용자 로그인 비밀번호를 원문 없이 저장·확인 | 회원 가입·로그인·재해시 | `Passwords` ([13.7절](../guide/security-utilities.md#topic-password--137-비밀번호-해시--passwords)) | 복호화 용도 아님. 시도 제한·계정 잠금은 애플리케이션 몫 |
| 파일·데이터가 이전에 확보한 값과 같은지 확인 | 배포 파일 체크섬, 데이터 변경 확인 | `Digests` ([13.6절](../guide/data-integrity.md#topic-hash--136-해시파일-지문--digests)) | 기준 해시를 믿을 수 있어야 함. 비밀번호 저장·보낸 쪽 인증 용도 아님 |
| 예측하기 어려운 임시값·비밀값 | 비밀번호 재설정 토큰, 요청 Nonce, 키·Salt | `SecureRandoms` (`string` 포함) ([13.5절](../guide/security-utilities.md#topic-random--135-보안-난수uuid--securerandoms)) | 용도에 맞는 길이와 문자 집합 선택. 중복 방지·사용 처리는 애플리케이션에서 관리 |
| 시스템 간 추적용 식별자 | 요청 추적 ID, 작업 ID | `SecureRandoms.uuidV4` ([13.5절](../guide/security-utilities.md#topic-random--135-보안-난수uuid--securerandoms)) | 비밀값·절대 중복 금지 용도와 구분 |
| 충분히 무작위인 원본 키에서 용도별 키 분리 | 한 원본 키에서 암호화용·MAC용 키 | `Hkdf` ([13.8절](../guide/security-utilities.md#topic-key-derivation--138-키-파생-hkdfpbkdf2--hkdf-pbkdf2)) | 사람이 입력한 비밀번호에는 `Pbkdf2`(느린 KDF) |
| 바이너리 값을 문자로 전달·저장, 검증값 비교 | API JSON의 바이너리, URL용 토큰, 해시의 Hex, OTP 키 | `Encoding`, `Bytes` ([13.9절](../guide/security-utilities.md#topic-encoding--139-인코딩안전-비교--encoding-bytes)) | 인코딩은 암호화가 아님. 비교는 진위·유효기간을 판단하지 않음 |

<a name="topic-api-selection--otpjwtoauth"></a>
### OTP·JWT·OAuth

| 목적 | 적용 예 | API | 제약·주의 |
|---|---|---|---|
| 카운터·시간 기반 일회용 비밀번호 | 인증 앱 2단계 인증 | `Totp`, `Hotp` ([13.12절](../guide/authentication.md#topic-otp--1312-hotptotp--hotp-totp)) | 코드 재사용 방지·시도 제한·비밀키 보관은 애플리케이션 몫 |
| 서명된 클레임 토큰으로 여러 서비스가 발급자·대상·만료 확인 | 서비스 간 접근 토큰, 로그인 후 JWT | `Jwt`, `JwtVerifier`, `Jwks` ([13.16절](../guide/authentication.md#topic-jwt--1316-jwt--jwt-jwtkey-jwtverifier-jwks)) | 미검증 분석으로 인증하지 않음. 서명·클레임·권한 정책이 따로 필요 |
| OAuth 인증 서버가 발급한 JWT 접근 토큰을 API가 확인 | 사내·외부 OAuth 서버 연동, audience·scope 확인 | `AccessTokenVerifier` ([13.17절](../guide/authentication.md#topic-oauth--1317-oauth-access-token--accesstokenverifier-accesstokens)) | 일반 JWT·ID Token과 구분하는 프로파일. RFC 9068 서버가 아니면 설정형 프로파일 |
| 내용을 볼 수 없는(Opaque) 접근 토큰의 상태 조회 | 외부 OAuth 서버의 Introspection | `TokenIntrospector` ([13.18절](../guide/authentication.md#topic-oauth-introspection--1318-token-introspection--tokenintrospector)) | 비활성과 통신 실패를 구분. 자체 OAuth 서버 기능 아님 |
| 다른 API를 부르기 전에 서비스 계정 토큰 발급받기 | 배치·서버 간 호출 | `ClientCredentials` ([13.19절](../guide/authentication.md#topic-oauth-client-credentials--1319-client-credentials-토큰-발급-요청--clientcredentials)) | 기존 인증 서버가 필요. 로그인·자체 토큰 서버 아님. 토큰 캐시·재발급은 애플리케이션 몫 |

**헷갈리기 쉬운 선택**

- **AES 암호화 vs 비밀번호 해시:** 나중에 원문이 필요하면 암호화(`CredentialCrypto`·`AesGcm`), 맞는지만 확인하면 해시(`Passwords`). 로그인 비밀번호를 암호화해 저장하지 않습니다.
- **SHA 해시 vs HMAC vs 전자서명:** 해시는 키가 없어 누구나 다시 만들 수 있습니다(변경 확인만). HMAC은 같은 비밀키를 가진 두 쪽 사이의 위변조·보낸 쪽 확인, 전자서명은 개인키를 가진 한 쪽만 만들고 누구나 공개키로 확인할 때 씁니다.
- **RSA-OAEP vs Hybrid:** 상대 공개키로 짧은 값(예: RSA 2048·OAEP SHA256은 190바이트 이하)만 보내면 RSA-OAEP, 그보다 크면 Hybrid. RSA를 여러 조각으로 나눠 쓰지 않습니다.
- **Base64 vs 암호화:** 인코딩은 누구나 되돌릴 수 있는 표기 방식일 뿐입니다.
- **일반 JWT vs OAuth JWT Access Token vs Opaque Token:** 직접 발급·검증하는 서비스 토큰은 `JwtVerifier`, OAuth 인증 서버의 JWT 접근 토큰은 `AccessTokenVerifier`(토큰 종류·대상·권한 확인), 해석할 수 없는 토큰은 `TokenIntrospector`.
- **보안 난수·UUID vs 절대 중복 금지 값:** 무작위 문자열의 충돌 가능성은 길이, 문자 집합, 발급량에 따라 달라집니다. 6자리 숫자는 가능한 값이 100만 개입니다. 절대 중복을 막아야 하는 값은 애플리케이션 저장소(DB UNIQUE 제약 등)가 보장합니다.
- **인증서 분석 vs 신뢰 검증:** 읽고 기간을 보는 것과, 믿는 루트까지 서명이 이어지는지(`validateChain`), 접속 호스트와 맞는지(HTTPS 클라이언트), 폐기됐는지(CRL·OCSP, 미지원)는 서로 다른 확인입니다.

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
