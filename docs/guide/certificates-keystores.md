# 인증서 및 키 저장소

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md) · [CLI 명령·예제](#api-cli-guide)

기존 X.509 인증서나 PKCS12·JKS 키 저장소를 Java 코드에서 읽고, 인증서 정보를 확인하거나 신뢰 체인을 검증하는 기능입니다. 전자서명과 공개키 암복호화에서 필요한 키를 준비할 때도 사용합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[업무별 적용](#guide-section-1) · [인증서와 키 저장소를 같이 사용하는 방법](#guide-section-2) · [X.509 인증서 및 PKIX 검증](#topic-certificates) · [PKCS12·JKS 키 저장소 읽기](#topic-keystore)

---

<a name="guide-section-1"></a>
## 업무별 적용

| 필요한 작업 | Java API |
|---|---|
| 인증서의 주체·발급자·만료일·지문 확인 | `Certificates` |
| 신뢰하는 CA까지 인증서 체인 검증 | `Certificates`의 PKIX 검증 |
| 기존 `.p12`·`.pfx`·`.jks`의 키와 인증서 읽기 | `KeyStoreReader` |
| 읽어 온 키로 서명·검증 또는 공개키 암복호화 | [전자서명](data-integrity.md#topic-signature) / [Java 암복호화](java-encryption.md#topic-rsa) |

[`api cert info`](#api-certificate)는 X.509 정보를 보여 주고 [`api keyconv`](#api-keyconvert)는 RSA·EC 키를 변환합니다. PKIX 체인 검증과 PKCS12/JKS 읽기는 Java API에서 제공합니다. 인증서 정보 조회와 TLS 호스트명 검증은 별개의 작업입니다.

<a name="guide-section-2"></a>
## 인증서와 키 저장소를 같이 사용하는 방법

| 확보한 자료 | 처리 단계 | 후속 기능 |
|---|---|---|
| 상대의 X.509 인증서 | 인증서를 읽고 기간·주체·발급자 확인, 신뢰 앵커를 지정해 체인 검증 | 신뢰한 공개키로 서명 검증 또는 RSA/Hybrid 암호화 |
| 본인의 PKCS12/JKS | 저장소 유형·비밀번호와 엔트리 별칭 확인 → 필요한 개인키·인증서 읽기 | 개인키로 서명 또는 공개키 암호문 복호화 |
| 공개 인증서만 있는 경우 | 인증서에서 공개키 추출 | 검증·암호화만 가능, 개인키가 필요한 작업 불가 |
| PEM/DER 키만 있는 경우 | [PemKeys](data-integrity.md#topic-signature)로 키 읽기 | 키 자체의 신뢰는 별도로 확인 |

인증서의 날짜가 유효하다고 신뢰 가능한 것은 아닙니다. 신뢰할 CA는 애플리케이션에서 정하고, TLS 호스트명·폐기 상태 검증은 JCK의 인증서 정보 조회와 별개입니다. 키 저장소 읽기 API는 인증서 발급·저장소 생성·갱신 도구가 아닙니다.

<a name="topic-certificates"></a>

## X.509 인증서 및 PKIX 검증

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-certs)

<a name="topic-certificates--x509-인증서"></a>
<a name="topic-certificates--1311-x509-인증서--certificates"></a>
### X.509 인증서 — Certificates (13.11)

<a name="topic-certificates--예제-입력-준비"></a>
#### 예제 입력 준비

| 입력 | 준비할 값 |
|---|---|
| `serverPem` | 확인할 X.509 인증서 파일 |
| `rootPem` | 호출자가 신뢰하는 루트 인증서 파일 |
| 검증 시점 | 현재 시각 또는 업무에서 지정한 시각 |

예제는 남은 일수를 반환합니다. 체인 검증이 실패하면 예외를 처리하세요.

<a name="topic-certificates--java-예제"></a>
#### Java 예제

```java
// 예제: SecurityApiExample.daysLeft
public static long daysLeft(Path serverPem, Path rootPem) throws Exception {
    X509Certificate server = Certificates.readFile(serverPem);
    CertificateInfo info = Certificates.info(server);                 // 분석만(신뢰·호스트명·폐기 확인 아님)
    X509Certificate root = Certificates.readFile(rootPem);
    Certificates.validateChain(Collections.singletonList(server), Collections.singletonList(root),
            Instant.now());                                           // 실패하면 CertPathValidatorException
    return info.daysUntilExpiry(Instant.now());
}
```

| 확인 | 지원 |
|---|---|
| 분석(주체·발급자·일련번호·기간·공개키·서명 알고리즘·SHA-256 지문·SAN) | `Certificates.info` → `CertificateInfo` |
| 유효기간(날짜) | `CertificateInfo.isValidAt`·`daysUntilExpiry` |
| 신뢰 체인(PKIX) | `Certificates.validateChain`(호출자가 준 신뢰 루트로만, JVM 기본 저장소 아님) |
| 호스트명 일치 | 미지원(HTTPS 클라이언트가 확인) |
| 폐기(CRL·OCSP) | 미지원(네트워크·기반 시설 필요) |

분석·날짜 확인의 성공을 신뢰로 보지 않습니다. 입력은 PEM·DER(1MiB까지), 체인 PEM은 `readChain`. 인증서 발급·갱신 기능은 없습니다.

| 호출 | 확인하는 것 |
|---|---|
| `Certificates.read(String/byte[])` / `readFile(Path)` | PEM·DER 인증서 |
| `readChain(String)` / `readChainFile(Path)` | 여러 PEM 인증서 → 체인 목록 |
| `info(certificate)` | 주체·발급자·기간·지문 등 `CertificateInfo` |
| `validateChain(chain, trustAnchors, at)` | 호출자가 정한 신뢰 루트와 시각으로 PKIX 검증. 성공 시 정상 반환, 실패는 예외 |

발급자 이름이 같다는 것만으로 인증서를 신뢰하지 않습니다. 시스템 간 통신의 TLS 호스트명 확인은 실제 HTTPS 클라이언트의 책임입니다.

### 인증서 분석 결과 (`CertificateInfo`) 활용

| 메서드 | 반환값 및 활용 |
|---|---|
| `subject()` / `issuer()` | 주체·발급자 DN(RFC 2253). 인증서 식별 및 발급자 조회 |
| `serialNumberHex()` | 소문자 16진수 일련번호. 발급자와 함께 인증서 관리에 활용 |
| `notBefore()` / `notAfter()` | 유효 시작·종료 `Instant` |
| `isValidAt(time)` | 지정 시각이 시작~종료 범위 안인지 확인. 신뢰 검증과 별개 |
| `daysUntilExpiry(now)` | 만료까지 남은 일수(정수 일 단위). 임박 알림에 활용하고 정확한 만료 여부는 `isValidAt`으로 확인 |
| `publicKeyAlgorithm()` / `publicKeySize()` | RSA·EC 등 키 종류와 키 크기(비트, 그 밖의 유형은 0) |
| `signatureAlgorithm()` | 인증서의 서명 알고리즘 이름 |
| `sha256Fingerprint()` | 인증서 DER 전체 SHA-256, 대문자 콜론 구분 Hex. 별도 신뢰 경로의 지문과 비교 |
| `subjectAlternativeNames()` | DNS·IP·EMAIL·URI 접두어 목록. 없으면 빈 목록. 호스트명 검증 자체는 수행하지 않음 |

이 결과 객체로 인증서 만료 목록을 만들 수 있습니다. 만료가 임박한 인증서를 실제로 갱신하는 것은 호출자의 작업이며, 체인 신뢰 검증은 `Certificates.validateChain`을 사용합니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-keystore"></a>

## PKCS12·JKS 키 저장소 읽기

<a name="topic-keystore--pkcs12jks-키-저장소"></a>
<a name="topic-keystore--1315-pkcs12jks-키-저장소--keystorereader"></a>
### PKCS12·JKS 키 저장소 — KeyStoreReader (13.15)

**기능:** 이미 가진 `.p12`·`.pfx`·`.jks`를 **읽기 전용**으로 열어 개인키·인증서·공개키·인증서 체인을 꺼내고, 그대로 서명·RSA-OAEP·Hybrid·JWT에 씁니다.

<a name="topic-keystore--예제-입력-준비"></a>
#### 예제 입력 준비

| 입력 | 준비할 값 |
|---|---|
| `p12` | 기존 PKCS12 파일 경로 |
| `storePassword` | 저장소 비밀번호 |
| `keyPassword` | 개인키 엔트리 비밀번호 |
| `document` | 서명할 데이터 바이트 |

예제의 `signer`는 실제 별칭으로 바꿉니다. 서명 검증 결과가 `true`이면 성공입니다.

<a name="topic-keystore--java-예제"></a>
#### Java 예제

```java
// 예제: SecurityApiExample.signWithKeyStore
public static boolean signWithKeyStore(Path p12, char[] storePassword, char[] keyPassword, byte[] document) throws Exception {
    KeyStoreReader store = KeyStoreReader.load(p12, KeyStoreType.PKCS12, storePassword); // 읽기 전용, 파일 불변
    PrivateKey signingKey = store.privateKey("signer", keyPassword);  // 별칭·엔트리 비밀번호를 명시
    byte[] signature = Signatures.sign(SignatureAlgorithm.RSA_SHA256, signingKey, document);
    return Signatures.verify(SignatureAlgorithm.RSA_SHA256, store.publicKey("signer"), document, signature);
}
```

- **형식:** `KeyStoreType.PKCS12`·`JKS`를 호출자가 지정합니다(확장자로 추측하지 않고, 파일 앞 표식으로 형식을 확인해 다른 형식은 거부). 저장소 비밀번호는 필수입니다(null이면 JKS가 무결성 확인을 건너뛰므로 거부). 개인키는 별칭과 엔트리 비밀번호를 명시했을 때만 꺼냅니다(PKCS12는 보통 저장소 비밀번호와 같음).
- **불변:** 파일을 바꾸지 않습니다(생성·수정·변환·삭제·비밀번호 변경 기능 없음). `load(InputStream, …)`은 스트림을 닫지 않습니다. 최대 16MiB.
- **오류(`KeyStoreException`):** 저장소 비밀번호 틀림, 키 엔트리 비밀번호 틀림, 없는 별칭, 개인키 엔트리가 아님, 형식이 다르거나 손상, 이 Java가 지원하지 않는 보호 알고리즘. 문구에 경로·비밀번호를 넣지 않습니다. 파일을 읽을 수 없으면 `IOException`.
- **Java 버전 차이:** 최신 JDK가 기본으로 만드는 PKCS12(PBES2·HmacPBESHA256)를 오래된 Java 8 업데이트는 읽지 못할 수 있습니다(시험: JDK 8u202는 JDK 21 `keytool`·OpenSSL 3이 기본값으로 만든 PKCS12를 읽지 못하고, JDK 21·25는 JDK 8u202가 만든 PKCS12·JKS와 OpenSSL 3 기본 PKCS12를 읽음). 이때 "지원하지 않는 보호 알고리즘"으로 알리며 약한 알고리즘으로 바꾸지 않습니다.

  오래된 Java에서도 읽어야 하면 만들 때 이전 호환 알고리즘을 씁니다(예: `keytool -J-Dkeystore.pkcs12.legacy ...`, OpenSSL은 `-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1`). 이전 호환 알고리즘은 보호 강도가 낮으므로 가능하면 Java 8 업데이트를 올리는 쪽을 먼저 검토합니다.

  JKS는 두 버전 모두 읽습니다. PKCS12 SecretKey 엔트리는 지원 범위가 아닙니다.
- 저장소에 있는 인증서라는 사실은 신뢰를 뜻하지 않습니다(신뢰 체인은 [13.11절](#topic-certificates--1311-x509-인증서--certificates)).

| 호출 | 결과 |
|---|---|
| `KeyStoreReader.load(Path/InputStream/byte[], type, storePassword)` | 읽기 전용 객체 |
| `type()` / `aliases()` | 지정한 형식 / 별칭 목록 |
| `isPrivateKeyEntry(alias)` / `isCertificateEntry(alias)` | 별칭의 엔트리 유형 확인 |
| `privateKey(alias, keyPassword)` | 개인키. 엔트리 비밀번호를 명시 |
| `certificate(alias)` / `publicKey(alias)` / `certificateChain(alias)` | 인증서·공개키·체인 |

어떤 별칭을 써야 할지 모르면 `aliases()`와 엔트리 유형을 먼저 확인합니다. 키 저장소 비밀번호와 엔트리 비밀번호를 같은 값으로 추정하지 않습니다.

<a name="api-cli-guide"></a>
## 독립 보안 API의 CLI 사용

[인증·비밀 입출력 규칙](cli.md#api-cli)과 아래 업무별 옵션을 확인하세요.

<a name="api-certificate"></a>
### 인증서 정보

날짜의 유효 여부는 `--at` 또는 현재 시각 기준입니다. X.509 파싱과 날짜 검사는 PKIX 신뢰 체인·호스트 이름 검증과 구분합니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api certificate info` | 초기 설정 후 사용 | `--in`, `--at`, `--out` |

<details>
<summary>옵션과 기본값</summary>

- `certificate info` — PEM/DER 입력. 현재 UTC 또는 --at으로 날짜 유효성을 확인합니다.
- `--at` — ISO-8601 UTC 시각. 기본 현재 시각.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# 인증서 발급자와 유효 기간 확인
java -jar java-crypto-kit-0.2.1.jar api cert info --in server.crt
```

<a name="api-keyconvert"></a>
### PEM·DER 변환

공개키는 SPKI, 개인키는 PKCS#8입니다. 입력은 PemKeys가 인식하는 PEM 또는 DER이고 출력 형식은 `--format`으로 지정합니다. 개인키 파일은 읽기 전에 권한을 확인합니다.

| 명령 | 관리자 인증 | 명령별 옵션 |
|---|---|---|
| `api keyconvert` | 매 실행 | `--type`, `--format`, `--in`, `--out` |

<details>
<summary>옵션과 기본값</summary>

- `keyconvert` — 유형·출력 형식·입력·출력 필수. 입력은 PEM 또는 DER입니다.
- `--format` — 출력 키 형식 pem 또는 der.
- `--in` — 입력 경로. 지원하는 경우 생략하면 한 줄 입력을 받습니다.
- `--out` — 새 출력 경로. 비밀 결과에는 보호 폴더를 씁니다.
- `--type` — 작업 방식 또는 키 유형.

</details>

입력 파일은 실제 테스트 파일로 바꾸고 결과 경로에는 새 파일명을 사용합니다. 비대화형 민감 명령에는 `--admin-pass-file`을 추가합니다.

```sh
# 키 파일 인코딩 변환
java -jar java-crypto-kit-0.2.1.jar api keyconv --type public --fmt der --in rsa-public.pem --out rsa.der
```

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
