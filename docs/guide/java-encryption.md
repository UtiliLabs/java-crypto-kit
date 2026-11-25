# Java 데이터 암복호화

[프로젝트 소개](../../README.md) · [전체 가이드](../user-guide.md)

애플리케이션에서 데이터 원문을 나중에 복원해야 할 때 사용합니다. 관리형 키 기반 API와 호출자 직접 키 주입 API, 독립 AES·RSA·Hybrid API를 하나의 흐름으로 비교하고 선택합니다.

<a name="guide-contents"></a>
**이 문서에서 찾을 수 있는 내용**

[어떤 암복호화 API를 선택할까요?](#guide-section-1) · [키 방식과 암호문 형식을 먼저 결정하세요](#guide-section-2) · [관리형 키 기반 암복호화](#topic-java-api) · [직접 키 주입 암복호화](#topic-direct-key) · [AES-GCM 및 업무 AAD](#topic-aes) · [RSA-OAEP 공개키 암복호화](#topic-rsa) · [Hybrid 공개키 암복호화](#topic-hybrid)

---

<a name="guide-section-1"></a>
## 어떤 암복호화 API를 선택할까요?

| 업무 | API | 키 관리 |
|---|---|---|
| Tomcat·CLI와 동일한 암호문과 등록 키 사용 | [`CredentialCrypto.fromDefaultConfiguration`](#topic-java-api) | JAR·외부 설정으로 관리 |
| 호출자가 보유한 키로 기존 ENC/JCKF 형식 사용 | [`CredentialCrypto.fromRawKey` / `fromPassphrase`](#topic-direct-key) | 호출자가 책임 |
| AES-128/256 및 업무 AAD 적용 | [`AesGcm`](#topic-aes) | 호출자가 키·AAD 관리 |
| 수신자 공개키로 짧은 비밀값 보호 | [`RsaOaep`](#topic-rsa) | 수신자의 신뢰할 공개키 |
| 수신자 공개키로 긴 메시지 보호 | [`HybridEncryption`](#topic-hybrid) | 공개키 및 개인키 관리 |

DB 비밀번호를 한 번 암호화해 설정 파일에 넣는 작업은 [CLI](cli.md)로 충분합니다. 실행 중 고객 데이터를 처리하거나 서비스 코드에서 암복호화해야 하면 이 가이드의 Java API를 사용합니다. 파일 스트리밍은 [파일 암복호화](file-encryption.md), 비밀번호의 단방향 저장은 [보안 유틸리티](security-utilities.md#topic-password)를 참조합니다.

**실행 준비:** JAR를 클래스패스에 넣고 JDK로 예제를 컴파일합니다. 공통 import, 입력 형식, 예외와 실행 방법은 [Java API 공통 사용 규칙](../reference/java-api-reference.md)에서 확인합니다.

<a name="guide-section-2"></a>
## 키 방식과 암호문 형식을 먼저 결정하세요

| 선택 | 키 재료 및 설정 | 결과 및 호환성 |
|---|---|---|
| 관리형 `pass` | JCK가 등록된 Passphrase에서 파생한 AES-256 키를 사용 | ENC/B64 또는 JCKF. 같은 등록 키를 쓰는 CLI·Tomcat과 호환 |
| 관리형 `key` | JCK가 등록된 32바이트 AES 키 사용 | 같은 형식. `KeyType.KEY` 또는 `withKeyId`로 선택 |
| 직접 `fromPassphrase` | 호출자가 Passphrase·Salt·반복 횟수·알고리즘과 키 ID를 전달 | AES-256, 동일한 재료와 ID가 있을 때 기존 형식 사용 가능 |
| 직접 `fromRawKey` | 호출자가 키 ID와 32바이트 AES 키를 전달 | AES-256, 독립 인메모리 객체 |
| 독립 `AesGcm` | 16/32바이트 키 또는 Passphrase 기반 키 파생, 업무 AAD 선택 | IV + 암호문 + 태그. ENC/JCKF와 호환되지 않음 |
| RSA / Hybrid | 수신자의 신뢰할 공개키로 암호화, 개인키로 복호화 | RSA-OAEP 또는 JCK Hybrid 자체 형식. 관리형 pass/key와 별개 |

관리형 기본 유형은 `pass`입니다. 명시하지 않으면 유형별 기본 키를 사용하고, `withKeyId`는 ID로 선택합니다. 복호화는 ENC/B64/JCKF의 키 ID를 사용합니다. 독립 AES 결과에는 키 ID·Salt·KDF·AAD가 들어 있지 않으므로 복원에 필요한 정보를 호출자가 관리합니다. 암호화를 할 필요 없는 회원 비밀번호 저장에는 `Passwords`, 위변조 검증에는 HMAC·전자서명을 선택합니다.

### 관리형 키를 사용하는 코드에서의 선택

- 설정 기본 키를 쓰려면 `encryptText(value)`.
- 유형별 기본 키를 쓰려면 `encryptText(value, KeyType.PASS)` 또는 `encryptText(value, KeyType.KEY)`.
- 업무 키를 고정하려면 `encryptText(value, KeyType.KEY, "app-aes")`(등록된 key 유형 예) 또는 `withKeyId("app-aes")`.
- 복호화에는 유형을 지정하지 않습니다. 기존 키를 제거하거나 다른 키로 덮으면 복원할 수 없습니다.

공개 JAR 기본 키는 시험용입니다. 운영 키 준비부터 배포까지는 [키 관리 가이드](key-management.md#choose-key-material)를 참조하세요.

<a name="topic-java-api"></a>

## 관리형 키 기반 암복호화

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-managed)

<a name="topic-java-api--관리형-java-암복호화"></a>
<a name="topic-java-api--6-java-api"></a>
### Java API (6)

관리형 키(JAR·설정의 키)를 쓰는 공개 진입점은 **`io.javacryptokit.CredentialCrypto`**입니다(유형 열거형 `io.javacryptokit.KeyType`, 키 정보 `io.javacryptokit.KeyInfo`, 예외 `CredentialCryptoException`). 애플리케이션이 키를 직접 주는 방식은 [6.7절](#topic-direct-key--67-개발자가-직접-키를-주는-api), 범용 보안 API(`io.javacryptokit.security`·`jwt`·`oauth` 패키지)는 [13장](../reference/java-api-reference.md#topic-security-api--13-범용-보안-java-api)에 있습니다.

그 밖의 하위 패키지(`core`·`config`·`key`·`file`·`cli`·`json` 등)는 내부 구현이므로 직접 쓰지 않습니다. 배포 JAR를 클래스패스에 추가하면 CLI·Tomcat과 같은 엔진·설정 규칙으로 문자열·바이트·파일을 처리합니다.

저장소에서 테스트로 관리하는 예제는 `src/test/java/example/ApiUsageExample.java`입니다.

Java API는 CLI 관리자 비밀번호를 요구하지 않으며 JAR의 관리자 비밀번호 설정·손상 여부와 관계없이 같게 동작합니다(키 자체의 설정 오류는 그대로 오류). 따라서 같은 JVM에서 이 API를 부를 수 있는 코드는 관리자 비밀번호 없이 복호화할 수 있습니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)).

**어떤 방식으로 시작할까요?**

| 요구 | 읽을 곳 |
|---|---|
| Tomcat·CLI와 같은 키 설정을 이용해 문자열을 암복호화 | [6.1](#topic-java-api--61-api-목록) · [6.2](#topic-java-api--62-문자열-암복호화와-직접-실행) |
| 애플리케이션이 직접 보유한 키·Passphrase를 주입 | [6.7 직접 키 API](#topic-direct-key--67-개발자가-직접-키를-주는-api) |
| `byte[]`나 큰 파일을 처리 | [6.3 바이트](#topic-java-api--63-byte-입력과-출력) · [7장 파일](file-encryption.md#topic-file-encryption--7-파일-암복호화) |
| AES-128·업무 AAD·HMAC·JWT·OAuth 등 별도 보안 API | [13장 기능별 상세](../reference/java-api-reference.md#topic-security-api--13-범용-보안-java-api) |

<a name="topic-java-api--61-api-목록"></a>
### API 목록 (6.1)

| 구분 | 메서드 | 입력 → 반환 | 참고 |
|---|---|---|---|
| 생성 | `fromDefaultConfiguration()` / `fromConfigFile(Path)` | 설정 → `CredentialCrypto` | WAS와 같은 설정 탐색 규칙 / 지정한 외부 설정 |
| 직접 키 생성 | `fromRawKey(keyId, byte[])` / `fromPassphrase(keyId, char[], salt, iterations[, Pbkdf2Algorithm])` | 키·Passphrase → `CredentialCrypto` | 설정·JAR 키를 읽지 않고 호출자가 준 키 하나만 씀([6.7절](#topic-direct-key--67-개발자가-직접-키를-주는-api)) |
| 문자열 암호화 | `encryptText(String)` / `encryptText(char[])` | 평문 → `String` 암호문 | 기본 유형의 기본 키. 출력 형식은 설정 `crypto.output.encoding`(기본 ENC) |
| 유형·키 지정 | `encryptText(값, KeyType)` / `encryptText(값, KeyType, keyId)` | 평문 → `String` 암호문 | 그 유형의 기본 키 / 그 키 ID(유형이 다르면 `CONFIGURATION`). `char[]`·`encryptBytes`·`encryptFile`도 같은 형태 |
| 설정 문자열을 키 유형으로 변환 | `KeyType.fromCode(code)` / `type.code()` | 문자열 ↔ `KeyType` | 정확한 소문자 `pass`·`key`만 변환. 알 수 없는 입력은 `null`이므로 호출자가 거부해야 합니다. |
| 키 ID만 지정 | `withKeyId(keyId)` | 키 ID → `CredentialCrypto` | 새 암호화가 그 키를 쓰는 객체(유형 자동). 미등록이면 `CONFIGURATION` |
| 문자열 복호화 | `decryptText(String)` | `ENC[...]`·`B64[...]` → `String` | 두 형식을 자동 인식. 잘못된 UTF-8은 오류 |
| 바이트 암호화 | `encryptBytes(byte[])` | 바이트 → **`String` 암호문** | 이름은 입력 타입을 뜻함 |
| 바이트 복호화 | `decryptBytes(String)` | 암호문 → **`byte[]`** | 원래 바이트를 그대로 복원 |
| 검증·판별 | `verify(String)` / `isToken(String)` | 암호문 → `boolean` | `isToken`은 접두어만 검사하며 복호화 가능·무결성 확인이 아님 |
| 상태 | `keyId()` / `keyType()` / `keySource()` | 없음 → `String`·`KeyType` | `encryptText(값)`이 **실제로 쓰는 키**의 키 ID·유형·공급원. 키 원문은 반환하지 않음 |
| 키 목록 | `keys()` | 없음 → `List<KeyInfo>` | 등록된 키마다 키 ID·유형·공급원·유형 기본 여부·암호화 기본 여부·공개 기본 키 여부·사용 가능 여부(실패 사유)·짧은 지문. 공개 키 자동 경고를 내지 않음 |
| 파일 | `encryptFile(Path, Path)` / `decryptFile(Path, Path)` | 입력·출력 경로 → 없음 | 원본 보존, 출력 덮어쓰기 금지, 대용량 스트리밍 |

`B64[...]`가 필요하면 설정 `crypto.output.encoding=base64`를 씁니다.

`CredentialCrypto`는 원시 AES 결과(`byte[]`)를 주고받지 않습니다(표준 AES-GCM 바이트 배치가 필요하면 [13.2절](#topic-aes--132-aes-gcm과-업무-aad--aesgcm)의 `AesGcm`). 복호화 메서드에는 유형 인자가 없습니다(암호문의 키 ID로 선택). `null` 유형·빈 키 ID는 다른 키로 바꾸지 않고 `INVALID_INPUT`입니다.

### 등록된 키의 상태 활용 (`KeyInfo`)

`crypto.keys()`의 각 항목은 키 자체가 아니라 상태 정보입니다. 서버 시작 전 필요한 키가 등록되어 있는지, 기본 키가 공개 키인지 확인할 때 활용합니다.

| 메서드 | 반환값 및 활용 |
|---|---|
| `keyId()` / `type()` / `source()` | 키 ID / `KeyType` / 공급원 문자열 |
| `isTypeDefault()` / `isEncryptionDefault()` | 해당 유형의 기본 키인지 / 새 암호화의 기본 키인지 |
| `isPublicDefault()` | 공개 기본 키인지. 운영 키 검토에 사용 |
| `isAvailable()` | 현재 키 로딩 성공 여부 |
| `failureReason()` / `failureMessage()` | 사용 불가 원인. 정상 키에서는 실패 정보가 없음 |
| `fingerprint()` | 키 비교용 지문(원문 아님) |

필요한 업무 키를 `isAvailable()`로 확인하되, 실제 데이터의 암복호화 결과와 외부 시스템 연결도 별도로 확인합니다.

**프로젝트에 JAR를 연결하는 방법**

배포 JAR를 프로젝트의 `libs/`에 둡니다. 관리형 키를 쓰는 경우 어떤 JAR 또는 외부 설정을 배포할지도 결정합니다. 직접 키 API만 쓰는 경우 공개 배포 JAR 그대로면 됩니다.

| 개발 환경 | 적용 방법 |
|---|---|
| Gradle | `dependencies { implementation files('libs/java-crypto-kit-0.1.0.jar') }` |
| Eclipse / IntelliJ IDEA / VS Code | 프로젝트의 Java Build Path 또는 Gradle 의존성에 JAR를 등록 |
| javac / java | Windows는 클래스패스 구분자 `;`, Linux/macOS는 `:`. [6.2절](#topic-java-api--62-문자열-암복호화와-직접-실행) 참조 |
| Tomcat JNDI Factory | Tomcat `lib`에 JAR 설치. 웹앱 자체 라이브러리와는 별개의 배치 정책([3.7절](tomcat-jdbc.md#topic-tomcat--37-jar를-lib과-웹앱에-함께-둘-때)) |
| AWS KMS | 기본 JAR 외에 선택 SDK ZIP을 풀어 클래스패스에 추가([8.2절](external-key-providers.md#topic-aws-kms--82-aws-kms)) |

직접 다운로드한 JAR를 쓰는 방법입니다. Maven Central에 게시된 좌표가 있다고 가정하지 않습니다.

<a name="topic-java-api--62-문자열-암복호화와-직접-실행"></a>
### 문자열 암복호화와 직접 실행 (6.2)

```java
import io.javacryptokit.CredentialCrypto;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
        String token = crypto.encryptText("example-only-secret");   // ENC[v1:...] (설정이 base64면 B64[...])
        String plain = crypto.decryptText(token);                    // ENC·B64 모두 복호화
        boolean ok = crypto.verify(token);                           // 평문 없이 검증
        if (!ok || !"example-only-secret".equals(plain)) throw new IllegalStateException("Mismatch");
    }
}
```

**Java 8로 직접 실행:** 위 코드를 `CryptoExample.java`로 저장하고 배포 JAR와 같은 폴더에서 실행합니다(Gradle·Tomcat 불필요).

```powershell
# Windows PowerShell(클래스패스 구분자 ;)
javac -cp .\java-crypto-kit-0.1.0-configured-2.jar .\CryptoExample.java
java -cp '.;java-crypto-kit-0.1.0-configured-2.jar' CryptoExample
```

```bash
# Linux(클래스패스 구분자 :)
javac -cp ./java-crypto-kit-0.1.0-configured-2.jar CryptoExample.java
java -cp '.:java-crypto-kit-0.1.0-configured-2.jar' CryptoExample
```

이 코드는 예시 값의 일치 여부만 확인하며 평문이나 키를 출력하지 않습니다.

공개 JAR로 실행하면 JDK 로그(java.util.logging)에 `[java-crypto-kit] 공개 기본 키 사용 중 (별도 키 설정 권장)` WARNING이 JVM당 한 번 나오는 것이 정상입니다([12.1절](../reference/security.md#121-공개-기본-키-경고)). 실제 서비스에서는 사용자 지정 키를 내장한 JAR나 외부 키 설정을 쓰고, 암호화하는 쪽과 복호화하는 쪽이 같은 키·키ID를 써야 합니다.

<a name="topic-java-api--63-byte-입력과-출력"></a>
### `byte[]` 입력과 출력 (6.3)

아래 조각은 6.2절의 `crypto` 객체를 그대로 씁니다. 따로 쓸 때는 `CredentialCrypto.fromDefaultConfiguration()`으로 먼저 만듭니다.

```java
byte[] input = new byte[] {0, 1, (byte) 255};
String token = crypto.encryptBytes(input);       // 입력은 byte[], 결과는 String 암호문
byte[] restored = crypto.decryptBytes(token);    // 결과가 byte[]
try {
    if (!java.util.Arrays.equals(input, restored)) throw new IllegalStateException("Mismatch");
} finally {
    java.util.Arrays.fill(restored, (byte) 0);
}
```

`encryptBytes(byte[])`는 **입력이 바이트 배열**이고 반환값은 `String` 암호문입니다. `decryptBytes(String)`의 결과가 `byte[]`입니다. 문자열 암호문에는 길이 제한이 있으므로 큰 데이터는 파일 API를 씁니다.

<a name="topic-java-api--64-민감정보와-오류-처리"></a>
### 민감정보와 오류 처리 (6.4)

```java
char[] password = "example-only".toCharArray();
try {
    String token = crypto.encryptText(password);
    if (!crypto.verify(token)) throw new IllegalStateException("Bad token");
} finally {
    java.util.Arrays.fill(password, '\0');
}
```

`String`은 JVM 메모리에서 확실히 지울 수 없으므로 민감한 입력에는 `char[]`를 고려합니다.

`encryptText(char[])`는 **입력 배열을 지우지 않으므로 호출자가 지웁니다.** `decryptText()` 결과(`String`)는 오래 보관하거나 로그에 남기지 않습니다.

오류는 `CredentialCryptoException#getReason()`으로 `KEY_SOURCE`·`KEY_ID_MISMATCH`·`INTEGRITY`·`INVALID_TOKEN` 등을 구분하며, 예외 메시지에는 평문·키·암호문이 들어가지 않습니다.

<a name="topic-java-api--65-유형과-키-id-선택"></a>
### 유형과 키 ID 선택 (6.5)

```java
import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.KeyInfo;
import io.javacryptokit.KeyType;

CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
String pass = crypto.encryptText("example-only-secret");                 // 기본 유형(pass)의 기본 키
String aes = crypto.encryptText("example-only-secret", KeyType.KEY);     // key 유형의 기본 키
String biz = crypto.withKeyId("biz-01").encryptText("example-only");     // 키 ID로 선택(유형 자동)
String checked = crypto.encryptText("example-only", KeyType.KEY, "key01"); // 유형 확인 후 그 키
String plain = crypto.decryptText(biz);                                  // 유형 없이 키 ID로 자동 복호화
for (KeyInfo key : crypto.keys()) {
    System.out.println(key);   // 예: KeyInfo[key01, key, embedded, type-default, ab12cd34ef56...7890abcd]
}
```

`keyId()`·`keyType()`·`keySource()`는 그 객체의 `encryptText(값)`이 실제로 쓰는 키를 돌려줍니다(`withKeyId`가 돌려준 객체는 그 키). `keys()`는 각 키를 실제로 읽어 확인하며(원격 키는 이때 처음 조회될 수 있음), 읽지 못한 키도 목록에 넣고 `isAvailable()`·`failureReason()`·`failureMessage()`로 알립니다.

`KeyInfo`에는 키 원문·Passphrase·내장 값이 없습니다.

<a name="topic-java-api--66-외부-설정과-설정을-읽는-시점"></a>
### 외부 설정과 설정을 읽는 시점 (6.6)

```java
CredentialCrypto crypto = CredentialCrypto.fromConfigFile(
        java.nio.file.Paths.get("/etc/java-crypto-kit/app.properties"));
```

설정은 객체를 만들 때 읽습니다. 내장·파일·환경변수 키는 호출할 때마다 읽고(Passphrase 파생 결과는 JVM 안에서 키마다 한 번만 계산), Vault·KMS 원격 키는 객체마다 키별로 처음 한 번 조회한 뒤 재사용합니다.

설정이나 키를 바꾸면 새 객체를 만듭니다(운영 WAS는 해당 Resource 재생성 또는 재시작). 객체는 여러 스레드에서 함께 써도 됩니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-direct-key"></a>

## 직접 키 주입 암복호화

<a name="topic-direct-key--직접-키-주입-java-api"></a>
<a name="topic-direct-key--2-java-api"></a>
<a name="topic-direct-key--첫-실행-예제"></a>
### 첫 실행 예제

Gradle 프로젝트의 `libs/`에 JAR를 넣습니다.

```groovy
dependencies {
    implementation files('libs/java-crypto-kit-0.1.0.jar')
}
```

아래 예제는 직접 키 방식입니다. `JckExample.java`로 저장하면 실행할 수 있습니다.

```java
import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.SecureRandoms;
import io.javacryptokit.security.Encoding;

public class JckExample {
    public static void main(String[] args) throws Exception {
        byte[] key = SecureRandoms.bytes(32);
        CredentialCrypto crypto = CredentialCrypto.fromRawKey("demo", key);
        String encrypted = crypto.encryptText("sample-data");
        String decrypted = crypto.decryptText(encrypted);

        Hmac hmac = Hmac.of(Hmac.generateKey());
        String mac = hmac.sign("sample-data", Encoding.HEX);
        boolean verified = hmac.verify("sample-data", mac, Encoding.HEX);
        if (!"sample-data".equals(decrypted) || !verified) {
            throw new IllegalStateException("Verification failed");
        }
        System.out.println("PASS");
    }
}
```

```powershell
# Windows PowerShell
javac -cp .\java-crypto-kit-0.1.0.jar .\JckExample.java
java -cp '.;java-crypto-kit-0.1.0.jar' JckExample
```

```bash
# Linux / macOS
javac -cp ./java-crypto-kit-0.1.0.jar JckExample.java
java -cp '.:java-crypto-kit-0.1.0.jar' JckExample
```

결과: `PASS`. 예제 키는 메모리에서 생성합니다. 실제 암복호화에는 동일한 키를 안전하게 보관·공유해야 합니다.

[관리형 Java API](#topic-java-api) · [범용 보안 API](../reference/java-api-reference.md#topic-security-api)


<a name="topic-direct-key--67-개발자가-직접-키를-주는-api"></a>
### 개발자가 직접 키를 주는 API (6.7)

**기능:** 애플리케이션이 이미 가진 32바이트 AES 키나 Passphrase로 `CredentialCrypto` 객체를 만들어, 관리형 키와 같은 `ENC[v1:...]`·JCKF v1 형식으로 암복호화합니다.

JAR 내장 키·키 목록·외부 설정 파일·JVM 속성을 읽거나 바꾸지 않고, 변경 이력·CLI 관리자 비밀번호·`--reason`·`CHANGE`와 무관합니다.

**사용 상황:** 키를 애플리케이션의 비밀 저장소(자체 Vault 클라이언트, 클라우드 비밀 관리, HSM 래핑 키 등)에서 받아 쓰는 서비스, 서비스마다 다른 키가 필요한데 JAR·설정을 나누기 어려운 경우. **선택 기준:** 조직이 JAR·설정으로 키를 관리하고 Tomcat·CLI와 같은 키를 공유해야 하면 관리형 키(`fromDefaultConfiguration`, [6.1절](#topic-java-api--61-api-목록)). AES-128이나 업무 AAD가 필요하면 [13.2절](#topic-aes--132-aes-gcm과-업무-aad--aesgcm)의 `AesGcm`(다른 결과 형식).

| 구분 | 관리형 키(`fromDefaultConfiguration`) | 직접 키(`fromRawKey`·`fromPassphrase`) |
|---|---|---|
| 키 출처 | JAR 내장·파일·환경변수·Vault·KMS(설정) | 호출자가 준 키·Passphrase(이 객체만 복사본 보관) |
| 키 선택 | 암호문의 Key ID로 키 목록에서 선택 | 이 객체의 Key ID 하나만(다르면 `KEY_ID_MISMATCH`) |
| 형식 | `ENC[v1:...]`·`B64[...]`(설정)·JCKF v1 | 늘 `ENC[v1:...]`·JCKF v1(AES-256) |
| 변경 이력·관리자 인증·경고 | 관리형 규칙 | 없음(공개 기본 키 경고도 없음) |
| 오류 문구 언어 | 설정 `crypto.lang` | 한국어 고정(사유 코드는 같음) |

```java
CredentialCrypto crypto = CredentialCrypto.fromRawKey("app-key-01", key);          // key: 32바이트
String token = crypto.encryptText("dummy-secret");                                  // ENC[v1:app-key-01:...]

byte[] salt = Pbkdf2.newSalt();                                                     // 처음 한 번 만들어 보관(비밀 아님)
CredentialCrypto pass = CredentialCrypto.fromPassphrase("app-pass-01", passphrase, salt, 600_000);
CredentialCrypto pass512 = CredentialCrypto.fromPassphrase("app-pass-02", passphrase, salt,
        Pbkdf2Algorithm.SHA512.recommendedIterations(), Pbkdf2Algorithm.SHA512);    // KDF 선택(결과 키는 AES-256)
```

전체 예제(재시작 뒤 복호화, 여러 객체 함께 쓰기, 실패 처리, 호출자 배열 정리)는 `src/test/java/example/DirectKeyExample.java`이며 JDK 8·21·25에서 컴파일·실행 시험한 예제입니다.

- **복호화에 필요한 값은 호출자가 보관:** 암호문에는 Key ID만 들어 있습니다. Passphrase 방식은 같은 Key ID·Passphrase·Salt(16바이트)·반복 횟수(100,000~5,000,000, 권장 SHA256 600,000·SHA512 210,000)·PBKDF2 알고리즘을 모두 다시 줘야 같은 키가 되며, 하나라도 다르면 `INTEGRITY`입니다. Passphrase는 NFC 정규화 후 UTF-8로 계산합니다(관리형 pass 키와 같은 규칙).
- **재시작·여러 서버:** 같은 값으로 객체를 다시 만들면 이전 암호문을 복호화합니다. 객체는 스레드 안전하며 Passphrase 파생은 생성할 때 한 번만 합니다(호출마다 다시 파생하지 않음, 관리형 파생 캐시와 공유하지 않음).
- **Key ID 규칙:** 영문·숫자·`-`·`_` 1~64자. 직접 키 객체끼리, 또는 관리형 키와 같은 Key ID를 써도 저장소는 섞이지 않습니다. 다만 Key ID와 실제 키가 모두 같으면 같은 암호문 규칙이라 서로 복호화되는 것이 정상이며, Key ID는 같은데 키가 다르면 `INTEGRITY`입니다.
- **메모리:** 넘긴 키·Passphrase 배열은 바꾸지 않으므로 다 쓰면 호출자가 지웁니다(객체는 복사본을 씀). JVM 메모리에서 완전히 지운다는 보장은 없습니다.
- **오류:** `INVALID_INPUT`(Key ID·키 길이·Salt·반복 횟수·Passphrase 규칙), `KEY_ID_MISMATCH`(다른 Key ID의 암호문), `INTEGRITY`(키·Passphrase·Salt·반복 횟수·알고리즘이 다르거나 변조). 오류 문구에 키·평문이 들어가지 않습니다.
- **관리자 인증과의 관계:** CLI 관리자 비밀번호는 CLI 사용 통제일 뿐이며 이 API는 그것을 읽지도 거치지도 않습니다([12.8절](../reference/security.md#128-cli-관리자-인증의-범위와-한계)). 키 보관·교체·접근 통제는 애플리케이션 책임입니다.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-aes"></a>

## AES-GCM 및 업무 AAD

[전체 호출 형식과 반환값](../reference/java-api-reference.md#api-encryption)

<a name="topic-aes--aes-gcm-암복호화"></a>
<a name="topic-aes--132-aes-gcm과-업무-aad--aesgcm"></a>
### AES-GCM과 업무 AAD — AesGcm (13.2)

**기능:** 애플리케이션의 키(AES-128 16바이트·AES-256 32바이트)나 Passphrase로 데이터를 암호화하고, 결과를 표준 AES-GCM 바이트 배치 `IV(12) ‖ 암호문 ‖ 태그(16)`로 돌려줍니다. 업무 값(AAD)을 함께 인증할 수 있습니다.

**사용 상황:** 레코드 단위 개인정보 암호화에서 고객 ID·거래 ID를 AAD로 묶어 다른 레코드로 옮겨 붙인 암호문을 탐지할 때, 외부 시스템과 AES-128로 맞춰야 할 때. **선택 기준:** Key ID를 포함하는 암호문이나 대용량 파일 암복호화가 필요하면 `CredentialCrypto`([6.7절](#topic-direct-key--67-개발자가-직접-키를-주는-api), AES-256·ENC/JCKF). 비밀번호 저장은 [13.7절](security-utilities.md#topic-password--137-비밀번호-해시--passwords).

```java
// 예제: SecurityApiExample.aesGcmWithAad
public static String aesGcmWithAad(byte[] key, String customerId, String cardNumber) throws CredentialCryptoException {
    AesGcm gcm = AesGcm.of(AesKeySize.AES_256, key);                 // key: 애플리케이션이 확보한 32바이트
    String sealed = gcm.encryptText(cardNumber, "customer:" + customerId, Encoding.BASE64_URL);
    // DB에는 sealed만 저장(IV·태그 포함). AAD(customer:ID)는 저장하지 않고 복호화할 때 다시 만든다.
    return gcm.decryptText(sealed, "customer:" + customerId, Encoding.BASE64_URL); // AAD가 다르면 INTEGRITY
}
```

```java
// 예제: SecurityApiExample.aesGcmFromPassphrase
public static byte[] aesGcmFromPassphrase(char[] passphrase, byte[] salt, byte[] data) throws CredentialCryptoException {
    AesGcm gcm = AesGcm.fromPassphrase(AesKeySize.AES_128, Pbkdf2Algorithm.SHA512, passphrase, salt,
            Pbkdf2Algorithm.SHA512.recommendedIterations());          // 파생은 여기서 한 번(객체 재사용)
    byte[] sealed = gcm.encrypt(data);                                // IV(12) ‖ 암호문 ‖ 태그(16)
    return gcm.decrypt(sealed);
}
```

- **결과 형식:** 헤더·버전·Key ID·Salt가 없는 표준 배치(Go `Seal(nonce, nonce, …)`·Python `nonce + AESGCM.encrypt` 결과와 같은 순서). `ENC[...]`·JCKF와 서로 바꿔 풀 수 없습니다. 키 길이를 추측하지 않으며(선택한 크기와 정확히 같아야 함), IV를 직접 지정하는 기능은 없습니다.
- **보관:** 키, Passphrase 방식이면 Salt·PBKDF2 알고리즘·반복 횟수를 암호문과 별도로 보관합니다(Salt는 키마다 한 번, 암호화마다가 아님). AAD는 암호문에 들어 있지 않으므로 복호화할 때 같은 값을 다시 만듭니다.
- **실패:** 다른 키·Passphrase·Salt·AAD 또는 인증 실패는 `INTEGRITY`, 28바이트 미만·인코딩 오류는 `INVALID_TOKEN`. 문자열 복호화 결과가 UTF-8이 아니면 `INVALID_INPUT`. 실패하면 평문을 일부라도 돌려주지 않습니다. 메모리의 바이트만 처리하며 파일 스트리밍은 지원하지 않습니다.
- **키 사용량:** 암호화마다 새 난수 IV를 씁니다. 같은 실제 키의 사용 한도는 [13.20절](#topic-aes--1320-다중-서버-운영과-aes-gcm-키-사용량).

<a name="topic-aes--aesgcm-호출-선택표"></a>
#### AesGcm 호출 선택표

| 호출 | 사용법 |
|---|---|
| `generateKey(AesKeySize)` | 새 보안 난수 키 생성(16 또는 32바이트). 암호화와 복호화에 같은 키를 사용하도록 안전하게 보관 |
| `of(AesKeySize, byte[])` | 선택한 키 크기에 정확히 맞는 원시 키로 객체 생성 |
| `fromPassphrase(AesKeySize, Pbkdf2Algorithm, char[], byte[], int)` | Passphrase·Salt·반복 횟수로 키 파생 후 객체 생성 |
| `encrypt(byte[])` / `decrypt(byte[])` | 업무 AAD가 없을 때. 결과는 IV와 태그가 포함된 바이트 배열 |
| `encrypt(byte[], byte[])` / `decrypt(byte[], byte[])` | 두 번째 인자로 업무 AAD 전달. 미사용 시 null |
| `encryptText(String, Encoding)` / `decryptText(String, Encoding)` | UTF-8 문자열·선택한 인코딩 사용 |
| `encryptText(String, String, Encoding)` / `decryptText(String, String, Encoding)` | 두 번째 문자열이 업무 AAD |
| `keySize()` | 객체의 AES 키 크기 확인 |

**AAD가 필요 없는 간단한 문자열 암복호화:** 다음은 같은 키로 암복호화하는 예입니다. 운영에서는 생성된 키를 안전하게 보관하고 재사용합니다.

```java
byte[] key = AesGcm.generateKey(AesKeySize.AES_256);
AesGcm crypto = AesGcm.of(AesKeySize.AES_256, key);
String encrypted = crypto.encryptText("sample", Encoding.BASE64_URL);
String plain = crypto.decryptText(encrypted, Encoding.BASE64_URL);
```

**저장 설계:** 암호화 결과는 암호문 필드에, 키 식별정보는 별도로 저장합니다. 복호화 시 어떤 키와 AAD를 사용할지 결정해야 합니다. AES-128 키가 32바이트로 자동 변환되거나, `ENC`와 상호 변환되는 API는 아닙니다.

<a name="topic-aes--1320-다중-서버-운영과-aes-gcm-키-사용량"></a>
### 다중 서버 운영과 AES-GCM 키 사용량 (13.20)

- **난수:** 각 JVM의 `SecureRandom`으로 예측하기 어려운 토큰·IV를 만듭니다. 동일 키를 여러 서버에서 쓸 때는 전체 생성 횟수가 커질수록 IV 충돌 위험도 커집니다. 절대 유일성은 보장하지 않습니다.
- **JWT·OAuth:** 서버 A가 발급하고 서버 B·C가 검증하는 구성은 독립 JVM 시험으로 확인했습니다(공개키 배포, kid로 이전·새 키 공존, 다른 대상·토큰 종류 거부). 시계는 NTP로 맞추고 `clockSkew`를 정합니다.
- **AES-GCM 키 사용량:** 이 라이브러리의 AES-GCM(`ENC`·JCKF·`AesGcm`·Hybrid)은 호출마다 12바이트 난수 IV를 씁니다. NIST SP 800-38D 기준으로 같은 **실제 키**는 모든 서버·프로세스를 합쳐 2^32회(약 43억 회) 이하의 암호화에만 씁니다.

  문자열·바이트 암호화는 한 번에 1회, JCKF 파일은 64KiB 청크마다 1회(1GiB 파일 = 16,384회)로 셉니다. 이 라이브러리는 사용량을 전역으로 세지 않으므로 한도를 자동으로 보장하지 않습니다.

  한도에 다가가기 훨씬 전에(예: 운영 정책상 그보다 충분히 적은 횟수) **새 무작위 키**를 만들어 새 Key ID로 교체합니다.

  같은 키에 Key ID만 바꾸는 것은 교체가 아닙니다(키가 같으면 같은 한도를 나눠 씀). Hybrid는 메시지마다 새 데이터 키를 만들므로 하나의 AES 데이터 키를 반복 사용하는 경우와 구분됩니다. 난수 생성기와 키 관리의 안전성은 여전히 필요합니다.
- **스냅샷 복제:** 실행 중인 JVM을 VM·컨테이너 스냅샷으로 복제하면 난수 생성기 상태가 같아질 수 있으므로 복제 뒤 JVM을 다시 시작합니다.
- **WAS:** `CATALINA_BASE/lib`의 JAR A와 웹앱 `WEB-INF/lib`의 JAR B를 함께 둘 때 범용 보안 API는 각 웹앱이 보는 JAR의 클래스를 쓰며 다른 JAR의 키·설정·이력을 바꾸지 않습니다(Docker 하니스 D01~D05·W01에서 확인). ClassLoader 분리는 기능 격리일 뿐 악의적 코드에 대한 보안 경계가 아닙니다.


<a name="topic-aes--실행-예제--aes-gcm-문자열-왕복"></a>
### 실행 예제 — AES-GCM 문자열 왕복

`AesExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;

public class AesExample {
    public static void main(String[] args) throws Exception {
        byte[] key = AesGcm.generateKey(AesKeySize.AES_256);
        AesGcm crypto = AesGcm.of(AesKeySize.AES_256, key);
        String encrypted = crypto.encryptText("sample", Encoding.BASE64_URL);
        String plain = crypto.decryptText(encrypted, Encoding.BASE64_URL);
        System.out.println("sample".equals(plain));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-rsa"></a>

## RSA-OAEP 공개키 암복호화

<a name="topic-rsa--rsa-oaep-암복호화"></a>
<a name="topic-rsa--1313-rsa-oaep--rsaoaep"></a>
### RSA-OAEP — RsaOaep (13.13)

**기능:** 상대방 **공개키**로 짧은 비밀값을 암호화하고, 개인키를 가진 쪽만 복호화합니다.

**사용 상황:** 데이터 키·임시 비밀을 상대 서버에 전달할 때. **선택 기준:** 큰 데이터는 [13.14절](#topic-hybrid--1314-hybrid-암호화--hybridencryption), 보낸 쪽 인증은 [13.10절](data-integrity.md#topic-signature--1310-전자서명과-키-파일--signatures-pemkeys).

```java
// 예제: SecurityApiExample.protectDataKey
public static byte[] protectDataKey(PublicKey recipient, PrivateKey recipientKey, byte[] dataKey) throws CredentialCryptoException {
    byte[] wrapped = RsaOaep.encrypt(recipient, dataKey);             // SHA-256 + MGF1-SHA256, RSA 2048이면 최대 190바이트
    return RsaOaep.decrypt(recipientKey, wrapped);                    // 실패는 원인 구분 없이 INTEGRITY
}
```

- **매개변수:** `RsaOaepAlgorithm.SHA256`(기본: OAEP SHA-256 + MGF1-SHA256, 빈 label) 또는 `SHA512`(SHA-512 + MGF1-SHA512). 해시와 MGF1 해시를 둘 다 명시합니다. SHA-1 OAEP·PKCS#1 v1.5 암호화는 없습니다.
- **최대 평문:** 모듈러스 바이트 − 2 × 해시 바이트 − 2. RSA 2048: SHA256 190·SHA512 126바이트, RSA 3072: 318·254바이트(`RsaOaep.maxPlaintextBytes`). 문자열은 UTF-8 바이트 수로 셉니다.
- **실패:** 다른 키·변조·매개변수 불일치는 원인을 나누지 않고 모두 `INTEGRITY`(공격자가 실패 원인을 구별하지 못하게), 암호문 길이가 키와 다르면 `INVALID_TOKEN`. 같은 평문도 매번 다른 암호문이 됩니다.

| 호출 | 용도 |
|---|---|
| `RsaOaep.encrypt(publicKey, data[, algorithm])` / `decrypt(privateKey, ciphertext[, algorithm])` | 바이트 입력·출력 |
| `encryptText(publicKey, text[, algorithm], encoding)` / `decryptText(privateKey, ciphertext[, algorithm], encoding)` | UTF-8·인코딩 문자열 |
| `maxPlaintextBytes(key, algorithm)` | 해당 RSA 키에서 허용되는 최대 평문 바이트 수 |

암호화·복호화 양쪽에 같은 OAEP 알고리즘을 사용해야 합니다. 다른 해시나 Padding을 자동으로 시도하지 않습니다.


<a name="topic-rsa--실행-예제--공개키-암호화와-개인키-복호화"></a>
### 실행 예제 — 공개키 암호화와 개인키 복호화

`RsaExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.security.KeyPair;

public class RsaExample {
    public static void main(String[] args) throws Exception {
        KeyPair pair = Signatures.generateRsaKeyPair(2048);
        String encrypted = RsaOaep.encryptText(pair.getPublic(), "sample", Encoding.BASE64);
        String plain = RsaOaep.decryptText(pair.getPrivate(), encrypted, Encoding.BASE64);
        System.out.println("sample".equals(plain));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

[이 문서의 목차로 ↑](#guide-contents)

<a name="topic-hybrid"></a>

## Hybrid 공개키 암복호화

<a name="topic-hybrid--hybrid-encryption"></a>
<a name="topic-hybrid--1314-hybrid-암호화--hybridencryption"></a>
### Hybrid 암호화 — HybridEncryption (13.14)

**기능:** 수신자 RSA 공개키로 큰 업무 메시지를 암호화합니다. 메시지마다 새 32바이트 데이터 키(DEK)를 만들어 RSA-OAEP(SHA-256)로 보호하고, 데이터는 AES-256-GCM으로 암호화합니다. **사용 상황:** 공개키만 가진 상대에게 RSA 한도를 넘는 데이터를 보낼 때.

```java
// 예제: SecurityApiExample.sendToPartner
public static String sendToPartner(PublicKey partnerKey, PrivateKey partnerPrivateKey, String orderJson) throws CredentialCryptoException {
    String envelope = HybridEncryption.encryptText(partnerKey, orderJson, "batch:2026-11-24", Encoding.BASE64);
    // 받는 쪽(개인키 보유): 같은 업무 AAD가 있어야 풀린다(봉투에는 AAD가 들어 있지 않음)
    return HybridEncryption.decryptText(partnerPrivateKey, envelope, "batch:2026-11-24", Encoding.BASE64);
}
```

**결과 형식(JCKH 봉투 버전 1, 이 라이브러리의 독립 형식):** 정수는 big-endian입니다.

| 위치 | 길이 | 내용 |
|---|---|---|
| 0 | 4 | `JCKH`(0x4A 0x43 0x4B 0x48) |
| 4 | 1 | 버전 1 |
| 5 | 1 | suite 1 = RSA-OAEP-SHA256/MGF1-SHA256 + AES-256-GCM |
| 6 | 2 | N = 보호된 DEK 길이(수신자 RSA 모듈러스 바이트, 256~1024) |
| 8 | N | 보호된 DEK |
| 8+N | 12 | IV |
| 20+N | L(≥16) | AES-GCM 암호문 ‖ 태그(16) |

GCM AAD = 봉투의 0 ~ 20+N 바이트(헤더 전체) ‖ 업무 AAD 길이(4바이트) ‖ 업무 AAD. 그래서 버전·suite·길이·DEK·IV가 한 바이트라도 바뀌거나 잘리거나 덧붙으면 실패하고, 업무 AAD도 같은 값을 줘야 합니다(빈 값 = 없음, 봉투에는 들어 있지 않음).

- **범위:** 메모리의 바이트·문자열, 평문 최대 64MiB, 업무 AAD 64KiB. 파일 스트리밍 API는 없습니다(큰 파일은 관리형·직접 키 `encryptFile`의 JCKF를 씀).
- **실패:** 다른 개인키·변조·AAD 불일치는 모두 `INTEGRITY`(DEK 복원 실패도 같은 경로로 처리), 표식·버전·suite·길이·크기 오류는 `INVALID_TOKEN`. 태그 확인 전에는 평문을 돌려주지 않습니다.
- **한계:** 수신자만 읽게 하는 기밀성 기능이며 보낸 쪽을 인증하지 않습니다(필요하면 서명을 함께). 수신자 공개키가 정말 수신자 것인지 확인해야 합니다. JWE가 아니며 JOSE 상호운용을 약속하지 않습니다. `ENC`·JCKF·`AesGcm` 결과와 다른 형식입니다.

| 호출 | 입력·출력 |
|---|---|
| `HybridEncryption.encrypt(publicKey, data[, aad])` | 바이트 → JCKH 봉투 |
| `decrypt(privateKey, envelope[, aad])` | JCKH → 원본 바이트 |
| `encryptText(publicKey, text[, aad], encoding)` | UTF-8 → 인코딩 문자열 |
| `decryptText(privateKey, envelope[, aad], encoding)` | 인코딩 문자열 → UTF-8 |

여러 수신자에게 보낼 때는 각 수신자 공개키로 독립 봉투를 만듭니다. 파일 암호화(스트리밍)와 메모리 봉투의 64MiB 제한을 구분합니다.


<a name="topic-hybrid--실행-예제--공개키를-이용한-메시지-왕복"></a>
### 실행 예제 — 공개키를 이용한 메시지 왕복

`HybridExample.java`로 저장하세요. 공개 배포 JAR만 있으면 실행할 수 있습니다. [컴파일·실행 명령](../reference/java-api-reference.md#topic-security-api--java-예제-실행).

```java
import io.javacryptokit.security.*;
import java.security.KeyPair;

public class HybridExample {
    public static void main(String[] args) throws Exception {
        KeyPair pair = Signatures.generateRsaKeyPair(2048);
        String sealed = HybridEncryption.encryptText(pair.getPublic(), "sample-message", Encoding.BASE64);
        String plain = HybridEncryption.decryptText(pair.getPrivate(), sealed, Encoding.BASE64);
        System.out.println("sample-message".equals(plain));
    }
}
```

**예상 결과**

```text
true
```

예제는 실행할 때 시험용 키를 생성합니다. 실제 서비스에서는 업무 키를 별도로 준비하고 재사용하세요.

---

[전체 가이드](../user-guide.md) · [프로젝트 소개](../../README.md)
