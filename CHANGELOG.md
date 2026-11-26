# 변경 이력

## v0.2.0

### 추가

- 기존 Java 보안 API를 실행하는 `api` CLI 18개 기능군. 직접 키 암복호화, 해시·서명·요청 인증, 키와 인증서, JWT·OAuth·OTP를 포함합니다.
- 미설정 JAR에서 전체·기능별 Help와 Examples 및 버전 조회. 업무 명령에는 기존 초기 설정과 관리자 인증 정책이 적용됩니다.
- 업무별 CLI 옵션·기본값·제한·인증 및 연계 예제. [사용자 가이드](docs/user-guide.md)

### 보완

- 새 설정 JAR 기본 이름은 `-cfg.jar`입니다. 기존 `-configured.jar`와 번호가 붙은 기존 파일을 계속 인식하며, 이후 새 결과는 `-cfg-2.jar`처럼 이어집니다.
- `enc`·`dec`, `api sig`·`api rand` 및 `--alg`·`--ttl` 등 단축어를 추가했습니다. [전체 단축어](docs/guide/cli.md#cli-aliases)
- 대화형 필수 입력·숨김 표시·파일 저장 안내, 한·영 Help 정렬과 실무 Examples를 보완했습니다.

- OTP 키 생성 파일은 Base32로 고정되어 후속 OTP 명령에 사용할 수 있습니다.
- JWT·OAuth의 토큰 거부는 `FAIL`과 한·영 사유를 표시합니다. 명령·입출력·통신 오류와 구분합니다.
- 보호 파일 오류는 실제 옵션을 표시합니다. Introspection의 16 KiB(ASCII) 입력 한도와 로컬 JWT의 64 KiB 한도를 명시합니다.

- 신규 파일은 JCKF v2로 암호화합니다. 청크 인증에 파일별 난수 식별자를 포함해 다른 파일의 청크가 섞이는 경우를 거부합니다. [파일 암복호화 및 v1 호환성](docs/guide/file-encryption.md)

### 호환성

- 기존 JCKF v1과 새 v2 모두 복호화할 수 있습니다. 기존 관리형 CLI, 문자열 암호문, 공개 Java API, Tomcat Factory와 선택형 AWS KMS SDK 구성을 유지합니다.

## v0.1.0

공개 실행형 JAR과 선택형 AWS KMS 의존성 ZIP을 배포했습니다. [v0.1.0 릴리스](https://github.com/UtiliLabs/java-crypto-kit/releases/tag/v0.1.0)
