# 사용자 가이드

[프로젝트 소개](../README.md) · [JAR 다운로드](https://github.com/UtiliLabs/java-crypto-kit/releases)

소스 버전 0.2.1 기준입니다. 처음 적용할 때는 아래에서 사용 방식을 고르세요. 이미 구현 중이라면 [CLI 옵션](guide/cli.md#topic-cli--22-명령-목록), [Java 메서드·Builder](reference/java-api-reference.md#api-members), [설정 기본값](reference/configuration.md), [오류 코드](reference/troubleshooting.md#93-오류-코드별-조치)로 바로 이동할 수 있습니다.

[독립 CLI 전체 명령·옵션·인증](guide/cli.md#api-cli) · [CLI 단축어](guide/cli.md#cli-aliases) · [버전별 변경 이력](../CHANGELOG.md)

## 먼저 사용할 방식 선택

| 방식 | 시작할 곳 | 특징 |
|---|---|---|
| Java API | [업무별 Java API 선택표](reference/api-selection.md) | 업무 코드에서 직접 호출, CLI 관리자 인증 불필요 |
| 관리형 CLI | [명령줄 사용 가이드](guide/cli.md) | 초기 관리자 설정, 문자열·파일 암복호화, 키·JAR 설정 관리 |
| 독립 CLI | [업무별 `api` 명령](guide/cli.md#api-cli) | 호출자가 공급한 키로 암복호화·서명·토큰 처리, 결과 파일을 자동화에 연결 |
| Tomcat JDBC | [DB 접속정보 암호화 연동](guide/tomcat-jdbc.md) | CLI로 암호문 준비, Factory로 JNDI 연동 |

[다운로드와 사용 준비](reference/getting-started.md) · [Java 예제 실행과 공통 규칙](reference/java-api-reference.md)

## 키를 선택하는 기준

관리형 암복호화는 `pass`(비밀 문자열에서 AES 키 파생)와 `key`(32바이트 AES 키 직접 사용)를 제공합니다. 둘 다 AES-256-GCM이며 공급원은 별도로 선택합니다. 최초 설정은 JAR별 비밀 키 두 개를 생성합니다. 독립 CLI와 Java API에 사용하는 키는 호출자가 관리합니다.

[키 유형·공급원 선택](guide/key-management.md#choose-key-material) · [Tomcat 연동 전 키 선택](guide/tomcat-jdbc.md#tomcat-key-choice)

## 업무별 Java API와 독립 CLI

| 업무 | Java 예제와 API | CLI 옵션과 연결 예제 |
|---|---|---|
| 직접 키·Passphrase 암복호화 | [AES·RSA·Hybrid](guide/java-encryption.md) | [`api aes`, `api rsa`, `api hybrid`](guide/java-encryption.md#api-cli-guide) |
| 데이터 무결성·서명 | [HMAC·SHA·서명·RequestAuth](guide/data-integrity.md) | [무결성 명령](guide/data-integrity.md#api-cli-guide) |
| 토큰 및 일회용 코드 | [JWT·OAuth·OTP](guide/authentication.md) | [JWT](guide/authentication.md#api-jwt) · [OAuth](guide/authentication.md#api-oauth) · [OTP](guide/authentication.md#api-otp) |
| 비밀번호·난수·KDF·인코딩 | [보안 유틸리티](guide/security-utilities.md) | [유틸리티 명령](guide/security-utilities.md#api-cli-guide) |
| 키와 인증서 | [PEM·X.509·키 저장소](guide/certificates-keystores.md) | [시험 키 생성](guide/key-management.md#api-keygen) · [변환·인증서 정보](guide/certificates-keystores.md#api-cli-guide) |

PKCS12/JKS 읽기·PKIX 체인 검증·안전 비교는 Java API에서 제공합니다.

## 업무별 상세 가이드

### [Tomcat JDBC 접속정보 암호화 연동](guide/tomcat-jdbc.md)

Tomcat의 JNDI DataSource에 설정된 DB 계정·비밀번호를 보호합니다. 기존 애플리케이션의 JNDI 조회 코드는 유지하고, CLI로 준비한 암호문을 Factory가 복호화하여 실제 Connection Pool에 넘깁니다.

<a name="3-tomcat-jndi-연동"></a><a name="31-적용-순서"></a><a name="32-dbcp2와-tomcat-jdbc-pool-선택"></a><a name="33-resource를-넣을-파일"></a><a name="34-resource-주요-속성"></a><a name="35-애플리케이션의-조회-코드"></a><a name="36-jvm-공통-범위와-재시작"></a><a name="37-jar를-lib과-웹앱에-함께-둘-때"></a><a name="4-connection-pool-설정"></a><a name="41-먼저-볼-기본-옵션"></a><a name="42-문제가-생겼을-때-볼-고급-옵션"></a>

**바로가기:** [적용 절차 및 Resource 설정](guide/tomcat-jdbc.md#topic-tomcat) · [Resource별 Pool 선택](guide/tomcat-jdbc.md#topic-tomcat--32-dbcp2와-tomcat-jdbc-pool-선택) · [Connection Pool 옵션](guide/tomcat-jdbc.md#topic-connection-pools)

### [CLI 사용 가이드](guide/cli.md)

Java 소스를 작성하지 않고 터미널에서 DB 접속정보·설정값·파일을 암복호화하거나 키와 JAR 설정을 관리하고 진단합니다. 자동화 가능한 명령과 실제 터미널 입력이 필요한 명령을 구분합니다.

<a name="2-cli-명령"></a><a name="21-공통-규칙"></a><a name="22-명령-목록"></a><a name="221-도움말-명령"></a><a name="결과-출력과-비밀정보-표시"></a><a name="실행-환경과-기본-옵션"></a><a name="키-선택과-변경"></a><a name="부록-a-실무-명령어집"></a><a name="23-encrypt--문자열-암호화"></a><a name="24-decrypt--문자열-복호화"></a><a name="25-verify--복호화-가능-여부-확인"></a><a name="a2-체험-공개-키로-암호화복호화검증"></a><a name="14-cli-관리자-비밀번호"></a><a name="222-admin-setup--관리자-비밀번호-최초-설정"></a><a name="223-admin-password-change--관리자-비밀번호-변경"></a><a name="a1-준비-관리자-비밀번호와-보호된-폴더"></a><a name="a16-관리자-비밀번호-변경인증-실패자동화"></a><a name="관리자-비밀번호를-묻는-명령"></a><a name="비밀번호-규칙"></a><a name="최초-설정"></a><a name="210-config-show--jar-내장값-조회"></a><a name="212-config-set--jar-기본-설정-변경"></a><a name="213-info--실행-시-적용-설정과-출처"></a><a name="214-doctor--설정과-키-진단"></a>

**바로가기:** [최초 준비와 관리자 인증](guide/cli.md#topic-admin) · [명령 찾기 및 공통 사용 규칙](guide/cli.md#topic-cli) · [문자열 암호화·복호화·검증](guide/cli.md#topic-cli-encryption) · [설정 변경 및 진단](guide/cli.md#topic-cli-settings)

### [Java 데이터 암복호화](guide/java-encryption.md)

애플리케이션에서 데이터 원문을 나중에 복원해야 할 때 사용합니다. 관리형 키 기반 API와 호출자 직접 키 주입 API, 독립 AES·RSA·Hybrid API를 하나의 흐름으로 비교하고 선택합니다.

<a name="6-java-api"></a><a name="61-api-목록"></a><a name="62-문자열-암복호화와-직접-실행"></a><a name="63-byte-입력과-출력"></a><a name="64-민감정보와-오류-처리"></a><a name="65-유형과-키-id-선택"></a><a name="66-외부-설정과-설정을-읽는-시점"></a><a name="67-개발자가-직접-키를-주는-api"></a><a name="132-aes-gcm과-업무-aad--aesgcm"></a><a name="1320-다중-서버-운영과-aes-gcm-키-사용량"></a><a name="aesgcm-호출-선택표"></a><a name="1313-rsa-oaep--rsaoaep"></a><a name="1314-hybrid-암호화--hybridencryption"></a>

**바로가기:** [관리형 키 기반 암복호화](guide/java-encryption.md#topic-java-api) · [직접 키 주입 암복호화](guide/java-encryption.md#topic-direct-key) · [AES-GCM 및 업무 AAD](guide/java-encryption.md#topic-aes) · [RSA-OAEP 공개키 암복호화](guide/java-encryption.md#topic-rsa) · [Hybrid 공개키 암복호화](guide/java-encryption.md#topic-hybrid)

### [파일 암복호화](guide/file-encryption.md)

CSV, PDF, JSON, 이미지 등 파일을 내용 형식에 관계없이 보호합니다. 일회성 작업 또는 배치에서는 CLI를, 애플리케이션 처리 흐름에서는 Java API를 선택합니다.

<a name="215-file-encrypt--파일-암호화"></a><a name="216-file-decrypt--파일-복호화"></a><a name="7-파일-암복호화"></a><a name="a13-파일-암복호화"></a>

**바로가기:** [파일 처리 절차·명령·Java API](guide/file-encryption.md#topic-file-encryption)

### [암호화 키 관리](guide/key-management.md)

관리형 암복호화, Tomcat 및 파일 처리에서 사용하는 키의 준비부터 등록·선택·백업·복구·교체까지 다룹니다. 같은 키 ID와 실제 키를 유지해야 기존 암호문을 복호화할 수 있습니다.

<a name="13-체험용-내장-키와-운영용-사용자-지정-키"></a><a name="a3-운영-passphrasepass-키를-jar에-넣고-기본-키로"></a><a name="a4-운영-aes-키key를-jar에-넣기"></a><a name="5-키-공급원과-설정-적용"></a><a name="51-키-공급원-선택"></a><a name="52-설정을-두는-곳과-우선순위"></a><a name="53-외부-properties-지정"></a><a name="54-지금-쓰는-키-확인"></a><a name="55-키-목록과-유형-선택"></a><a name="a12-지금-쓰는-키-확인"></a><a name="26-keygen--새-키-파일-만들기"></a><a name="27-config-embed-key--사용자-지정-키-내장"></a><a name="28-fingerprint--키가-같은지-비교"></a><a name="218-config-key-add--키-추가"></a><a name="a5-키-생성-화면에-한-번-보이는-생성값과---export"></a><a name="a6-서버의-passphrase-파일환경변수를-등록지문-고정"></a><a name="219-config-key-use--기본-키-변경"></a><a name="220-config-key-remove--키-제거"></a><a name="a7-기본-키기본-유형-바꾸기"></a><a name="224-config-key-show--키-관리정보원문-확인"></a><a name="a17-키-원문-확인내보내기와-복구"></a><a name="56-자동-생성한-passkey-보관재등록복구"></a><a name="a-keygen-키-파일로-다시-등록"></a><a name="a10-생성값으로-재등록예전-암호문-복구"></a><a name="a9-다른-jar에-같은-키-복사"></a><a name="b-화면의-base64를-파일로-저장해-다시-등록"></a><a name="c-passphrase를-한-줄-파일로-저장해-다시-등록새-키"></a><a name="d-예전-암호문-복구에-필요한-pass-복원-정보"></a><a name="e---export-백업으로-새-jar에-복원"></a><a name="f-원본-jar에서-그대로-옮기기--from-jar"></a><a name="g-같은-키인지-지문으로-확인"></a><a name="h-예전-암호문파일을-실제로-복호화"></a><a name="값과-파일의-형식"></a><a name="먼저-구분할-두-가지"></a><a name="보관-지침"></a><a name="이력이-있는-jar에-되살릴-때"></a><a name="29-rekey--기존-암호문을-새-키로-바꾸기"></a><a name="92-키-교체"></a><a name="a8-키-회전-새-키-추가--rekey--이전-키-제거"></a><a name="211-config-history--설정-변경-이력"></a><a name="a11-변경-이력-보기유형별"></a>

**바로가기:** [최초 생성 키와 업무용 키 준비](guide/key-management.md#topic-key-selection) · [키 공급원과 설정 적용](guide/key-management.md#topic-key-management) · [AES 키 생성 및 내장](guide/key-management.md#topic-key-generation) · [새 키 및 기존 키 등록](guide/key-management.md#topic-key-registration) · [기본 키 선택 및 제거](guide/key-management.md#topic-key-defaults) · [키 관리정보 조회 및 백업](guide/key-management.md#topic-key-export) · [키 복구 및 다른 JAR로 이전](guide/key-management.md#topic-key-recovery) · [키 교체 및 암호문 이전](guide/key-management.md#topic-key-rotation) · [설정 변경 이력](guide/key-management.md#topic-history)

### [외부 키 관리 서비스 연동](guide/external-key-providers.md)

이미 외부 키 관리 체계를 운용하고 있다면 관리형 암복호화에 Vault KV v2 또는 AWS KMS를 연결할 수 있습니다. 독립 Java 보안 API와 달리 관리형 키 공급원을 설정하는 기능입니다.

<a name="8-vault와-aws-kms-선택"></a><a name="81-vault-kv-v2"></a><a name="217-kms-datakey--aws-kms-데이터-키-파일-만들기"></a><a name="82-aws-kms"></a>

**바로가기:** [HashiCorp Vault KV v2](guide/external-key-providers.md#topic-vault) · [AWS KMS 데이터 키 및 연동](guide/external-key-providers.md#topic-aws-kms)

### [데이터 무결성 및 서버 간 요청 인증](guide/data-integrity.md)

Java API와 독립 CLI로 위변조 확인, 메시지 인증과 공개키 기반 서명 검증을 수행합니다. 공유 키를 가진 양측에는 HMAC, 공개키 검증에는 전자서명, 신뢰하는 체크섬 비교에는 SHA 해시를 선택합니다.

<a name="133-hmac--hmac"></a><a name="hmac-호출-선택표"></a><a name="134-api-요청-인증--requestauth"></a><a name="요청-인증에서-교환하는-값"></a><a name="136-해시파일-지문--digests"></a><a name="1310-전자서명과-키-파일--signatures-pemkeys"></a>

**바로가기:** [HMAC 메시지 인증](guide/data-integrity.md#topic-hmac) · [서버 간 API 요청 인증](guide/data-integrity.md#topic-request-auth) · [SHA 해시와 파일 체크섬](guide/data-integrity.md#topic-hash) · [전자서명 및 PEM 키](guide/data-integrity.md#topic-signature)

### [OTP·JWT·OAuth 인증 및 토큰 처리](guide/authentication.md)

Java API와 독립 CLI로 일회용 코드·서비스 토큰을 생성하고 검증하거나 외부 인증 서버와 연계합니다. 토큰 검증과 애플리케이션의 권한·세션 관리는 구분합니다.

<a name="1312-hotptotp--hotp-totp"></a><a name="인증-앱-등록과-검증-순서"></a><a name="1316-jwt--jwt-jwtkey-jwtverifier-jwks"></a><a name="1317-oauth-access-token--accesstokenverifier-accesstokens"></a><a name="1318-token-introspection--tokenintrospector"></a><a name="1319-client-credentials-토큰-발급-요청--clientcredentials"></a>

**바로가기:** [HOTP·TOTP 일회용 코드](guide/authentication.md#topic-otp) · [JWT 발급·검증 및 JWKS](guide/authentication.md#topic-jwt) · [OAuth JWT 접근 토큰 검증](guide/authentication.md#topic-oauth) · [OAuth Token Introspection](guide/authentication.md#topic-oauth-introspection) · [OAuth Client Credentials](guide/authentication.md#topic-oauth-client-credentials)

### [보안 유틸리티](guide/security-utilities.md)

비밀번호의 단방향 저장, 난수·토큰·UUID 생성, 키 파생, 바이너리 인코딩과 안전 비교를 제공합니다. 동일한 기능을 Java API 또는 해당 CLI 명령으로 실행할 수 있습니다. CLI의 인증 요건은 명령별로 적용됩니다.

<a name="137-비밀번호-해시--passwords"></a><a name="135-보안-난수uuid--securerandoms"></a><a name="138-키-파생-hkdfpbkdf2--hkdf-pbkdf2"></a><a name="139-인코딩안전-비교--encoding-bytes"></a>

**바로가기:** [비밀번호 해시 및 검증](guide/security-utilities.md#topic-password) · [보안 난수·난수 문자열·UUID](guide/security-utilities.md#topic-random) · [HKDF·PBKDF2 키 파생](guide/security-utilities.md#topic-key-derivation) · [인코딩 및 안전 비교](guide/security-utilities.md#topic-encoding)

### [인증서 및 키 저장소](guide/certificates-keystores.md)

기존 X.509 인증서나 PKCS12·JKS 키 저장소를 Java 코드에서 읽고, 인증서 정보를 확인하거나 신뢰 체인을 검증하는 기능입니다. 독립 CLI에서는 X.509 정보 조회와 RSA·EC 키 변환을 제공합니다.

<a name="1311-x509-인증서--certificates"></a><a name="1315-pkcs12jks-키-저장소--keystorereader"></a>

**바로가기:** [X.509 인증서 및 PKIX 검증](guide/certificates-keystores.md#topic-certificates) · [PKCS12·JKS 키 저장소 읽기](guide/certificates-keystores.md#topic-keystore)

## 공통 참조 문서

| 문서 | 확인할 내용 |
|---|---|
| [다운로드와 사용 준비](reference/getting-started.md) | JAR 종류, 준비물, 버전, 예제 표기, 빌드 |
| [업무별 Java API 선택표](reference/api-selection.md) | 업무에 맞는 API, 알고리즘 및 제약 |
| [Java API 공통 규칙](reference/java-api-reference.md) | import, 실행, 타입, 반환값, 예외 |
| [설정 사전](reference/configuration.md) | 설정명, 허용값, 기본값 |
| [지원 환경 및 배포 점검](reference/compatibility.md) | JDK·Tomcat·외부 서비스 호환성 |
| [오류 해결](reference/troubleshooting.md) | CLI·Java·Tomcat 오류와 조치 |
| [보안 및 운영 참고](reference/security.md) | 키 보관, 공개된 기본 키 차단, CLI 인증의 범위 |
| [기술 명세](reference/technical-specification.md) | 구현 계약, 데이터 호환 규격, 요구사항 추적 |

CLI 도움말의 기존 장·절 번호는 상세 가이드의 괄호 안 번호와 연결됩니다. 각 문서의 상세 목차에서도 바로 해당 절로 이동할 수 있습니다.

<a name="1-개요와-준비"></a><a name="10-설정-사전"></a><a name="101-키와-암호화"></a><a name="102-동작과-tomcat-정책"></a><a name="103-vault-kv-v2"></a><a name="104-aws-kms"></a><a name="105-키-목록-항목"></a><a name="11-지원-기능"></a><a name="11-지원-범위와-배포-점검"></a><a name="111-검증-상태"></a><a name="112-다른-was와-프레임워크"></a><a name="113-배포-전-점검표"></a><a name="12-운영보안-참고"></a><a name="12-준비물과-내려받기"></a><a name="121-공개-기본-키-경고"></a><a name="122-키-파일과-키-내장-jar-보관"></a><a name="123-평문을-다루는-명령"></a><a name="124-jar-설정-이력의-성격"></a><a name="125-원격-키-공급원-운영"></a><a name="126-passphrase-운영"></a><a name="127-jar-내장값의-경량-난독화obf1"></a><a name="128-cli-관리자-인증의-범위와-한계"></a><a name="13-범용-보안-java-api"></a><a name="131-공통-규칙"></a><a name="1321-예외와-실패-처리-요약"></a><a name="15-업무별-java-api-선택-가이드"></a><a name="9-운영-변경과-장애-대응"></a><a name="91-키는-그대로-db-비밀번호만-변경"></a><a name="93-오류-코드별-조치"></a><a name="94-이전-형식-설정jar에서-올리기"></a><a name="a14-이전-형식-외부-설정을-그대로-쓰기"></a><a name="a15-자주-보는-오류"></a><a name="cli-명령"></a><a name="java-crypto-kit-사용자-가이드"></a><a name="otpjwtoauth"></a><a name="데이터-검증-및-보안-유틸리티"></a><a name="데이터-인증전자서명인증서"></a><a name="목차"></a><a name="범용-보안-api"></a><a name="비밀번호난수해시키-파생인코딩"></a><a name="설정-및-문제-해결"></a><a name="설치설정개발"></a><a name="시작-및-사용-방식"></a><a name="실무-명령어집"></a><a name="암복호화"></a><a name="암복호화와-데이터-보호"></a><a name="운영레퍼런스"></a><a name="원하는-작업부터-찾아보기"></a><a name="인증서-및-인증"></a><a name="장별-목차"></a><a name="키-관리-및-외부-키"></a>
