#!/usr/bin/env bash
# java-crypto-kit 실서버 통합 시험(Docker): Tomcat 8.5/9.0/10.1/11.0 × DBCP2/Tomcat JDBC Pool × MariaDB
#
# 무엇을 확인하나: 빌드한 JAR를 실제 Tomcat 컨테이너에 넣고 JNDI 조회 -> getConnection() -> SQL까지 확인한다.
#   0  준비: Docker 이미지, MariaDB JDBC 드라이버(SHA-256 확인), 외부와 끊긴 시험 전용 네트워크
#   1  키 JAR(CLI만 사용): 빌드 JAR(CLI 관리자 비밀번호 미설정)은 실행 거부 -> admin setup(비대화형 --admin-pass-file)
#      -> keygen -> config embed-key(AES 키 corp01) -> config key add(pass 키 corp-pass, 기본 키) -> config set(Pool).
#      최초 설정 키를 뺀 JAR·pass 파일 키 JAR·이중 배포용 JAR A/B(pass 키는 비대화형 생성 + --export), 관리자 검증값 손상 JAR,
#      민감 명령마다 관리자 인증(비밀번호 파일)·키 생성·변경마다 --reason, 유형별 history(기본 pass·--all·[관리자]),
#      JAR 안 내장 키·이력의 obf1 저장, 관리자 검증값(원문 없음), fingerprint·doctor
#   2  실제 CLI: 가상 터미널로 encrypt(pass·key)·decrypt(관리자 비밀번호 숨김 입력·파일·틀린 값)·rekey(같은 유형·유형 간,
#      미설정 --from-jar 거부), JDK 8 verify, 암호문 키ID, 위조 거부
#   3  MariaDB: 시험 전용 계정·테이블(tmpfs)
#   4  M-*      공통 설정 fallback 8개 조합(Tomcat 4개 버전 × 두 Pool): 한 JVM에서 pass·key 암호문 정상 연결과
#               오류 판정(평문·위조·변조·미등록 키ID·DB 로그인 거부), 실제 테이블 SELECT·INSERT(pass·key 각각)
#   5  E01~E23  설정·보안 시나리오: 우선순위(-D > 외부 Properties > JAR), file·env 키, 언어·경고 끄기,
#               빌드 JAR 그대로(관리자·PASS·KEY 미설정 = CONFIGURATION), 키 원문 -D 거부, 키 누락 Fail Closed,
#               -D·외부 Properties 오타 거부, 빈 설정 경로 거부, 웹앱의 같은 이름 가짜 Pool Factory 차단(E17),
#               GlobalNamingResources + ResourceLink(E18), embed-key 뒤 최초 설정 키 암호문(E19), 최초 설정 키를 뺀 JAR(E20),
#               pass 파일 키 JDK 8 파생(E21)·지문 고정 위반(E22), 관리자 검증값 손상 JAR도 Tomcat 정상(E23, CLI 전용 검증값)
#      L01      (--legacy-jar) 실제 이전 버전 JAR를 새 CLI로 편집(이전 형식 유지) → 이전 바이너리 CLI·Tomcat 9 JNDI·SQL
#   6  D01~D05  이중 배포: Tomcat lib의 JAR A(인프라 키) + 웹앱 WEB-INF/lib의 JAR B(업무 키, Pool 설정도 다름).
#               Global·Context·conf/context.xml Resource를 어느 JAR의 Factory가 만드는지(Pool 종류·키로 판정),
#               개발자 API 클래스로더(문자열·파일 암복호화, 상대 JAR 파일 거부), 키·지문·설정 독립, 교차 복호화 차단,
#               실제 SQL, 공개된 기본 키 경고 0건, JVM 공통 -D(D03)·CRYPTO_CONFIG_FILE(D04)이 두 JAR에 모두 적용되는 간섭과
#               JAR B의 crypto.jvm.override.enabled=false로 공통 -D를 피하는 방법(D05).
#               D01~D05 모두 두 웹앱에서 범용 보안 API(원시 AES-GCM·직접 키·HMAC·비밀번호 해시·해시·난수·서명·JWT·
#               Access Token·TOTP·RSA-OAEP·Hybrid)를 호출해 클래스 출처(JAR B/JAR A)를 확인하고, 호출 뒤 JAR A 파일·키 목록·지문 불변 확인
#      W01      웹앱 WEB-INF/lib에만 JAR(Tomcat lib 설치 없음): Context Resource JNDI·SQL, 관리형 API, 범용 보안 API
#   7  G01~G04  Vault KV v2(--with-vault): 실제 Vault 컨테이너의 키, 권한 부족 토큰, 환경변수 토큰, pass 키 프로필
#      K01      Keycloak 실연동(--with-keycloak, HTTPS): Client Credentials 실제 발급(basic·post·틀린 비밀·잘못된 scope), JWKS 읽기,
#               실제 Access Token 검증(설정형 프로파일), 실제 ID Token 거부, RFC 9068(at+jwt) 발급 설정 확인,
#               RFC 7662 Introspection(활성·비활성·클라이언트 인증 실패)
#   8  결과 확인: 실행별 DB 행 대조(누락·중복·예상 밖 행 0), 결과 폴더의 비밀값 0, Docker 정리
#
# 사용법(저장소 루트에서, 먼저 빌드: ./gradlew clean build 또는 gradlew.bat clean build)
#   bash src/test/integration/run-tomcat-integration.sh                기본 시험(보통 8분 안팎, 이미지를 처음 받으면 더 걸림)
#   bash src/test/integration/run-tomcat-integration.sh --with-vault   Vault KV v2 시험 추가(Vault 코드를 바꿨을 때)
#   bash src/test/integration/run-tomcat-integration.sh --with-keycloak  Keycloak 실연동 추가(JWT·OAuth 코드를 바꿨을 때·Release 전)
#   bash src/test/integration/run-tomcat-integration.sh --keep-images  이번에 내려받은 Docker 이미지를 지우지 않음(반복 실행용)
#   그 밖의 옵션: --jar <java-crypto-kit JAR>(기본: build/libs의 JAR 하나)
#                 --driver <mariadb-java-client-3.5.11.jar>(인터넷 없이 실행할 때)   --help
#                 --legacy-jar <실제 이전 형식 JAR>(정식 0.1.0 이전 개발 빌드, 키 유형·관리자 비밀번호·obf1 없는 JAR):
#                   새 CLI로 편집한 그 JAR를 이전 바이너리 자신의 CLI와 Tomcat 9(Java 8) JNDI로 확인(L01)
# 필요 환경: bash 4 이상(Linux, Windows Git Bash), Docker 엔진, curl(드라이버 내려받기). 호스트 Java는 필요 없다.
# 실행 시점: Tomcat Factory·키 공급·Pool·설정 해석 코드를 바꿨을 때와 Release 전(일반 PR마다 필수는 아님).
#   Gradle test(JUnit)에서 자동 실행되지 않는 독립 Bash/Docker 시험이다(Docker가 필요한 시험을 기본 빌드에 강제하지 않음).
#
# 결과 읽는 법
#   종료 코드: 0 = 모두 PASS, 1 = FAIL 있음, 2 = 실행 환경 문제(Docker 미기동·JAR 없음·다운로드 실패 등, 시험 전에 중단)
#   화면 끝: "조합·시나리오별 결과"(케이스별 PASS/FAIL), "RESULT:" 줄, FAIL이면 "실패: [케이스] 기대 / 실제" 목록
#   원인 표시: 이 라이브러리 오류는 [사유: 코드] 메시지, 그 밖의 예외는 유형과 원인 클래스 이름(cause=..., 메시지 제외)
#     예) cause=ClassNotFoundException(io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory) = Tomcat lib의 JAR 누락·손상
#   이중 배포(D*)는 웹앱별 JNDI 결과와 함께 시험 JSP가 본 클래스 위치·키 목록·짧은 지문·복호화 사유 코드를 run.log에 남긴다.
#   결과 폴더 build/qa-integration/<UTC 시각>/: run.log(전체 출력), matrix.txt(케이스 | Tomcat·Java 버전 | 결과),
#     tomcat-logs/<케이스>.txt(Tomcat 로그 중 [java-crypto-kit] 줄만). 비밀번호·키·토큰은 남기지 않으며(끝에서 자동 검사)
#     gradlew clean으로 지워진다.
#   실패 조사 순서: 실패 목록의 케이스 -> tomcat-logs/<케이스>.txt의 [사유: 코드] -> docs/user-guide.md 9.3절(오류 코드별 조치)
#
# 안전 규칙
#   - Docker 자원은 이 실행 전용 이름(jck-qa-<실행ID>-*)과 라벨(jck-qa=1, jck-qa.run=<실행ID>)로만 만들고,
#     끝나면(실패·중단 포함) 그것과 이번에 내려받은 이미지만 지운다. prune 같은 일괄 삭제는 쓰지 않는다.
#   - 네트워크는 --internal(외부와 통신 불가)이고 어떤 포트도 호스트에 공개하지 않는다.
#   - 시험용 웹앱(JSP)은 실행 중 임시 폴더에 만들어 컨테이너 안에만 복사하고, 컨테이너 안의 curl로만 호출한다.
#     저장소·배포 JAR에는 웹앱이 없다.
#   - 키·Passphrase·DB 비밀번호·토큰·CLI 관리자 비밀번호는 실행마다 새로 만드는 시험용 값이며 임시 폴더에만 두고 끝나면 지운다.
#     CLI 관리자 비밀번호 파일은 작업용 컨테이너에만 넣는다(Tomcat 컨테이너에는 넣지 않음, Tomcat은 읽지 않음).
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash: docker 인자의 /경로를 Windows 경로로 바꾸지 않게 한다
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "[환경 오류] bash 4 이상이 필요합니다." >&2; exit 2; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../../.." && pwd)   # src/test/integration → 저장소 루트
[ -f "$REPO/build.gradle" ] && [ -f "$REPO/gradlew" ] || { echo "[환경 오류] 저장소 루트를 찾지 못했습니다: $REPO" >&2; exit 2; }
WITH_VAULT=0; WITH_KEYCLOAK=0; KEEP_IMAGES=0; JAR=""; DRIVER_IN=""; LEGACY_JAR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-vault) WITH_VAULT=1 ;;
    --with-keycloak) WITH_KEYCLOAK=1 ;;
    --keep-images) KEEP_IMAGES=1 ;;
    --jar) JAR="${2:-}"; shift ;;
    --driver) DRIVER_IN="${2:-}"; shift ;;
    --legacy-jar) LEGACY_JAR="${2:-}"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "[환경 오류] 알 수 없는 옵션: $1 (--help 참조)" >&2; exit 2 ;;
  esac
  shift
done

T85=tomcat:8.5-jdk8-temurin; T90=tomcat:9.0-jdk8-temurin; T101=tomcat:10.1-jdk21-temurin; T110=tomcat:11.0-jdk21-temurin
DB_IMAGE=mariadb:12.3.2; VAULT_IMAGE=hashicorp/vault:1.21.4; KC_IMAGE=quay.io/keycloak/keycloak:26.0.5
DRIVER_VERSION=3.5.11
DRIVER_SHA256=42604178b9e57ec08ee0035079961516f086e455d0141f0b22c6eff29fb2fff4
NEWF=io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory
TJF=org.apache.tomcat.jdbc.pool.DataSourceFactory
DBCPF=org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory
POOL_D=org.apache.tomcat.dbcp.dbcp2.BasicDataSource
POOL_T=org.apache.tomcat.jdbc.pool.DataSource


die() { echo "[환경 오류] $*" >&2; exit 2; }
hostpath() { if command -v cygpath > /dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
sha256() { if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }
rand() { od -An -tx1 -N"${1:-8}" /dev/urandom | tr -d ' \n'; }

# ------------------------------------------------------------------ 사전 점검(문제면 종료 코드 2)
command -v docker > /dev/null 2>&1 || die "docker 명령이 없습니다."
docker info > /dev/null 2>&1 || die "Docker 엔진에 연결할 수 없습니다. Docker Desktop(또는 dockerd)을 시작한 뒤 다시 실행하세요."
if [ -z "$JAR" ]; then
  set -- "$REPO"/build/libs/java-crypto-kit-*.jar
  { [ $# -eq 1 ] && [ -f "$1" ]; } || die "build/libs에 java-crypto-kit JAR가 하나 있어야 합니다. 먼저 ./gradlew clean build(Windows: gradlew.bat clean build)를 실행하세요."
  JAR="$1"
fi
[ -f "$JAR" ] || die "JAR 파일이 없습니다: $JAR"
[ -z "$LEGACY_JAR" ] || [ -f "$LEGACY_JAR" ] || die "이전 버전 JAR 파일이 없습니다: $LEGACY_JAR"
[ -n "$DRIVER_IN" ] || command -v curl > /dev/null 2>&1 || die "curl이 없습니다(--driver로 MariaDB JDBC JAR를 지정할 수 있습니다)."

RID="$(date -u +%H%M%S)$(rand 2)"
P="jck-qa-$RID"
LABELS=(--label jck-qa=1 --label "jck-qa.run=$RID")
NET="$P-net"; DB="$P-db"; WB="$P-bench"; VAULT="$P-vault"; KC="$P-keycloak"
RES="$REPO/build/qa-integration/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RES/tomcat-logs" || die "결과 폴더를 만들 수 없습니다: $RES"
WORK=$(mktemp -d 2> /dev/null || mktemp -d -t jckqa) || die "임시 폴더를 만들 수 없습니다."
WORKH=$(hostpath "$WORK")
PULLED=()
exec > >(tee "$RES/run.log") 2>&1
TEE_PID=$!

# ------------------------------------------------------------------ 정리(이 실행의 자원만)
cleanup() {
  local ids n img
  ids=$(docker ps -aq --filter "label=jck-qa.run=$RID")
  [ -n "$ids" ] && docker rm -f -v $ids > /dev/null 2>&1
  for n in $(docker network ls -q --filter "label=jck-qa.run=$RID"); do docker network rm "$n" > /dev/null 2>&1; done
  if [ "$KEEP_IMAGES" = 0 ]; then
    for img in ${PULLED[@]+"${PULLED[@]}"}; do
      [ -z "$(docker ps -aq --filter "ancestor=$img")" ] && docker rmi "$img" > /dev/null 2>&1
    done
  fi
  rm -rf "$WORK"
  return 0
}
trap cleanup EXIT
trap 'echo "!! 중단됨: 이 실행의 자원만 정리하고 종료합니다."; exit 130' INT TERM

# ------------------------------------------------------------------ 판정 도우미
PASSES=0; FAILS=(); CASE="-"; CASE_BEFORE=0; INSERT_RUNS=()   # INSERT_RUNS: 실제 테이블 INSERT를 요청한 실행 ID(끝에서 DB와 대조)
pass() { PASSES=$((PASSES + 1)); echo "   PASS $*"; }
fail() { FAILS+=("[$CASE] $*"); echo "   FAIL $*"; }
check() { if [ "$1" = 0 ]; then pass "$2"; else fail "$2"; fi; }   # check <0이면 참> <설명>
section() { echo; echo "=========================================================== $*"; }
SECRETS="$WORK/secrets.lst"; : > "$SECRETS"
secret() { [ -n "${1:-}" ] && printf '%s\n' "$1" >> "$SECRETS"; return 0; }
wb() { docker exec -e DBPW -e WRONGPW -e QA_ENV_KEY -e QA_VAULT_TOKEN "$WB" "$@"; }   # 작업용 컨테이너(JDK 21)에서 실행
# quiet <명령...>: 성공하면 출력을 숨기고, 실패하면 원인을 보여 준다(CLI 출력에는 키·평문이 없다).
quiet() { local o rc; o=$("$@" 2>&1); rc=$?; [ $rc = 0 ] || printf '%s
' "$o" | sed 's/^/   | /'; return $rc; }
fpw() { wb java -jar "$@" 2> /dev/null | grep -oE '[0-9a-f]{64}' | head -1; }   # fpw <JAR> fingerprint ...: 64자 키 지문
short() { printf '%s...%s' "${1:0:12}" "${1:56:8}"; }   # info·config show·keys()의 짧은 지문 형식(앞 12자...뒤 8자)

echo "java-crypto-kit Docker 통합 시험 시작 $(date -u +%Y-%m-%dT%H:%M:%SZ) (실행ID $RID)"
echo "대상 JAR: $(basename "$JAR") sha256=$(sha256 "$JAR" | cut -c1-16)…  결과 폴더: $RES"

section "0. 준비(이미지·드라이버·격리 네트워크)"
CASE=prepare
images=("$T85" "$T90" "$T101" "$T110" "$DB_IMAGE"); [ "$WITH_VAULT" = 1 ] && images+=("$VAULT_IMAGE")
[ "$WITH_KEYCLOAK" = 1 ] && images+=("$KC_IMAGE")
for img in "${images[@]}"; do
  if ! docker image inspect "$img" > /dev/null 2>&1; then
    echo "   이미지 내려받기: $img"
    docker pull -q "$img" > /dev/null || die "이미지를 내려받지 못했습니다: $img"
    PULLED+=("$img")
  fi
done
mkdir -p "$WORK/lib" "$WORK/secure" "$WORK/jars" "$WORK/tokens" "$WORK/runs" "$WORK/admin"
DRIVER="$WORK/lib/mariadb-java-client-$DRIVER_VERSION.jar"
if [ -n "$DRIVER_IN" ]; then
  cp "$DRIVER_IN" "$DRIVER" || die "드라이버를 복사하지 못했습니다: $DRIVER_IN"
else
  # Windows Git Bash의 curl.exe는 Windows 프로그램이므로 Windows 형식 경로를 넘긴다(Linux에서는 같은 경로).
  curl -fsSL -o "$(hostpath "$DRIVER")" "https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/$DRIVER_VERSION/mariadb-java-client-$DRIVER_VERSION.jar" \
    || die "MariaDB JDBC 드라이버를 내려받지 못했습니다(--driver로 직접 지정할 수 있습니다)."
fi
[ "$(sha256 "$DRIVER")" = "$DRIVER_SHA256" ] || die "MariaDB JDBC 드라이버의 SHA-256이 예상($DRIVER_VERSION)과 다릅니다."
pass "MariaDB Connector/J $DRIVER_VERSION SHA-256 확인"
docker network create --internal "${LABELS[@]}" "$NET" > /dev/null || die "Docker 네트워크를 만들지 못했습니다."
pass "격리 네트워크(--internal, 호스트 포트 공개 없음)"

# 시험용 값(실행마다 새로 생성, 결과에 남기지 않음)
export DBPW="qa-db-$(rand 6)" WRONGPW="qa-wrong-$(rand 6)"
PLAINPW="qa-plain-$(rand 6)"; ROOTPW="qa-root-$(rand 8)"; RAWDUMMY=$(head -c 32 /dev/urandom | base64)
# Passphrase(pass 키 재료): corp-pass는 JAR에 파생 키만 내장, corp-pfile은 실행 중 파일에서 읽어 파생(한글·이모지 포함)
CORP_PASSPHRASE="qa-corp-$(rand 8)"; PFILE_PASSPHRASE="qa-파일-🔐-$(rand 6)"; OTHER_PASSPHRASE="qa-other-$(rand 6)"
# CLI 관리자 비밀번호(10~128자, 영문자·숫자·특수문자 각 1자 이상): 비대화형 인증 파일과 인증 실패 시험용 다른 값 파일
ADMINPW="Qa-$(rand 8)@1"; ADMINPW_WRONG="Qa-$(rand 8)@2"
printf '%s\n' "$ADMINPW" > "$WORK/admin/admin.pw"; printf '%s\n' "$ADMINPW_WRONG" > "$WORK/admin/wrong.pw"
for v in "$DBPW" "$WRONGPW" "$PLAINPW" "$ROOTPW" "$RAWDUMMY" "$CORP_PASSPHRASE" "$PFILE_PASSPHRASE" "$OTHER_PASSPHRASE" \
    "$ADMINPW" "$ADMINPW_WRONG"; do secret "$v"; done
printf '%s' "$CORP_PASSPHRASE" > "$WORK/secure/corp.pass"
printf '%s\n' "$PFILE_PASSPHRASE" > "$WORK/secure/corp-pfile.pass"   # 끝 줄바꿈 하나는 떼고 읽는다
printf '%s' "$OTHER_PASSPHRASE" > "$WORK/secure/other.pass"
printf 'crypto.key.source=file\ncrypto.key.id=ext01\ncrypto.key.file=/opt/java-crypto-kit/ext01.key\n' > "$WORK/secure/ext-file.properties"
printf 'crypto.pool.factory=%s\n' "$DBCPF" > "$WORK/secure/pool-dbcp2.properties"
printf 'crypto.pool.factory=%s\ncrypto.jvm.override.enabled=false\n' "$DBCPF" > "$WORK/secure/pool-dbcp2-locked.properties"
printf 'crypto.key.source=file\ncrypto.key.id=ext01\ncrypto.key.file=/opt/java-crypto-kit/no-such.key\n' > "$WORK/secure/missing-key.properties"
printf 'crypto.key.source=embedded\ncrypto.warnning.enabled=false\n' > "$WORK/secure/typo.properties"
# D04: JVM 전체에 걸리는 외부 설정(CRYPTO_CONFIG_FILE)이 레거시 AES 슬롯을 바꾸면 두 JAR 모두에 적용된다.
printf 'crypto.key.source=file\ncrypto.key.id=shared01\ncrypto.key.file=/opt/java-crypto-kit/shared01.key\n' > "$WORK/secure/shared-slot.properties"

section "1. 키 JAR(CLI만 사용, 소스 수정·재빌드·외부 Properties 없음)"
CASE=company-jar
docker run -d --name "$WB" "${LABELS[@]}" --network "$NET" --entrypoint sleep "$T110" infinity > /dev/null || die "작업용 컨테이너를 시작하지 못했습니다."
docker exec "$WB" mkdir -p /w/jars /w/tokens /w/out /w/admin
docker cp "$(hostpath "$JAR")" "$WB:/w/jars/public.jar" > /dev/null
docker cp "$WORKH/secure" "$WB:/opt/java-crypto-kit" > /dev/null
docker cp "$WORKH/admin/." "$WB:/w/admin/" > /dev/null
docker exec "$WB" chmod 600 /w/admin/admin.pw /w/admin/wrong.pw
# 민감 명령(키 생성·변경·삭제, 설정 변경·조회, 이력, decrypt, rekey)의 비대화형 관리자 인증. 비밀번호는 파일에만 있다.
ADM="--admin-pass-file /w/admin/admin.pw"
# 빌드 JAR은 CLI 관리자 비밀번호 미설정: 비대화형이면 admin setup 외 명령은 아무것도 만들거나 바꾸지 않고 ADMIN_SETUP.
un=$(wb sh -c 'cd /w && java -jar jars/public.jar keygen --out /w/out/unset.key --reason "integration test"; echo "rc=$?"
  java -jar jars/public.jar doctor; echo "rc=$?"; ls /w/out /w/jars' 2>&1)
[ "$(grep -c 'ADMIN_SETUP' <<< "$un")" = 2 ] && [ "$(grep -c '^rc=1$' <<< "$un")" = 2 ] && [[ "$un" != *"unset.key"* && "$un" != *"configured"* ]]
check $? "미설정 빌드 JAR: keygen·doctor 거부(ADMIN_SETUP, 종료 코드 1), 키 파일·새 JAR 생성 없음"
quiet wb sh -c "cd /w && cp jars/public.jar jars/initial.jar && java -jar jars/initial.jar admin setup --operator qa $ADM"
check $? "admin setup(비대화형, --admin-pass-file): 빌드 JAR → 새 JAR initial.jar"
ad=$(wb sh -c 'cd /w && sha256sum jars/public.jar | cut -c1-64
  echo "kdf=$(grep -aFc "kdf=PBKDF2WithHmacSHA256" jars/initial.jar)"
  echo "plain=$(grep -aFc "$(cat /w/admin/admin.pw)" jars/initial.jar)"' 2>&1)
[ "$(head -1 <<< "$ad")" = "$(sha256 "$JAR")" ] && grep -qE '^kdf=[1-9][0-9]*$' <<< "$ad" && grep -qx 'plain=0' <<< "$ad"
check $? "admin setup: 빌드 원본 그대로, 시험 JAR 예약 영역에는 PBKDF2 검증값만"
initial_keys=$(wb java -jar /w/jars/initial.jar config show --lang en $ADM)
INITIAL_PASS=$(sed -n 's/^Default keys *: pass=\(pass-[0-9a-f]*\)$/\1/p' <<< "$initial_keys")
INITIAL_AES=$(sed -n 's/^ *key=\(key-[0-9a-f]*\)$/\1/p' <<< "$initial_keys")
[[ "$INITIAL_PASS" =~ ^pass-[0-9a-f]{32}$ && "$INITIAL_AES" =~ ^key-[0-9a-f]{32}$ ]]
check $? "최초 등록에서 생성한 활성 pass 및 AES 식별자"
quiet wb sh -c "cd /w && java -jar jars/initial.jar keygen --out /opt/java-crypto-kit/company.key --reason 'integration test' $ADM"
check $? "keygen(사용자 지정 AES 키, 관리자 인증·사유 필수)"
quiet wb sh -c "cd /w && cp jars/initial.jar jars/company-aes.jar && java -jar jars/company-aes.jar config embed-key --from-file /opt/java-crypto-kit/company.key --key-id corp01 --operator qa --reason 'integration test' --yes $ADM"
check $? "config embed-key: 사용자 지정 AES 키 + 키ID corp01(이전 초기 키 default는 키 목록에 남음)"
quiet wb sh -c "cd /w && cp jars/company-aes.jar jars/company.jar && java -jar jars/company.jar config key add --key-id corp-pass --from-file /opt/java-crypto-kit/corp.pass --active --operator qa --reason 'integration test' --yes $ADM"
check $? "config key add: pass 키 corp-pass(Passphrase 파일, JAR에는 파생 키만) + pass 기본 키로 지정"
quiet wb sh -c "cd /w && cp jars/company.jar jars/company-tj.jar && java -jar jars/company-tj.jar config set crypto.pool.factory=$TJF --operator qa --yes $ADM"
check $? "config set crypto.pool.factory=Tomcat JDBC Pool(키 내장 JAR에서 새 JAR)"
quiet wb sh -c "cd /w && cp jars/company.jar jars/company-h1.jar && java -jar jars/company-h1.jar config key remove --key-id $INITIAL_AES --operator qa --reason 'integration test' --yes $ADM && cp jars/company-h1.jar jars/company-hardened.jar && java -jar jars/company-hardened.jar config key remove --key-id $INITIAL_PASS --operator qa --reason 'integration test' --yes $ADM"
check $? "config key remove: 최초 등록한 두 키를 뺀 JAR"
quiet wb sh -c "cd /w && cp jars/company.jar jars/company-pfile.jar && java -jar jars/company-pfile.jar config key add --key-id corp-pfile --source file --location /opt/java-crypto-kit/corp-pfile.pass --operator qa --reason 'integration test' --yes $ADM"
check $? "config key add --source file: pass 파일 키 corp-pfile(지금 한 번 읽어 지문 고정, JAR에는 위치·Salt·지문만)"
for k in ext01 env01 shared01 infra biz; do quiet wb java -jar /w/jars/initial.jar keygen --out "/opt/java-crypto-kit/$k.key" --reason "integration test" $ADM || fail "keygen($k)"; done
# 이중 배포용: JAR A(인프라, Tomcat lib)와 JAR B(업무, 웹앱 WEB-INF/lib). 키 ID·키·Pool 설정이 모두 다르다.
for side in infra biz; do
  quiet wb sh -c "cd /w && cp jars/initial.jar jars/$side-aes.jar && java -jar jars/$side-aes.jar config embed-key --from-file /opt/java-crypto-kit/$side.key --key-id $side-key --operator qa --reason 'dual deploy' --yes $ADM \
    && cp jars/$side-aes.jar jars/$side.jar && java -jar jars/$side.jar config key add --key-id $side-pass --generate --export /opt/java-crypto-kit/$side-pass.backup --active --operator qa --reason 'dual deploy' --yes $ADM \
    && cp jars/$side.jar jars/$side-tj.jar && java -jar jars/$side-tj.jar config set crypto.pool.factory=$TJF --operator qa --yes $ADM"
  check $? "이중 배포용 JAR($side): AES 키 $side-key + pass 키 $side-pass(비대화형 생성 → --export 복원 백업, 기본 키), DBCP2·Tomcat JDBC Pool"
  # 생성한 Passphrase는 복원 백업에만 있다. 결과·로그에 나오면 안 되므로 비밀값 검사 목록에 넣는다.
  gp=$(wb sed -n 's/^passphrase=//p' "/opt/java-crypto-kit/$side-pass.backup"); secret "$gp"
  [ "${#gp}" = 32 ]; check $? "이중 배포용 JAR($side): 비대화형 생성값은 화면이 아닌 복원 백업 파일에만(32자 Passphrase)"
done
# D05용 JAR B: JVM 공통 -D를 받지 않는 정책(crypto.jvm.override.enabled=false)을 JAR에 넣는다.
quiet wb sh -c "cd /w && cp jars/biz-tj.jar jars/biz-locked.jar && java -jar jars/biz-locked.jar config set crypto.jvm.override.enabled=false --operator qa --reason 'block common -D' --yes $ADM"
check $? "D05용 JAR B: crypto.jvm.override.enabled=false(공통 -D 무시)"
# 80열을 넘는 이력 항목은 '->' 앞에서 줄을 바꾸므로 이어 붙여 비교한다.
hist=$(wb java -jar /w/jars/company-tj.jar config history --all $ADM 2>&1 | sed -E ':a;N;$!ba;s/\n +-> / -> /g')
[[ "$hist" == *"crypto.key.id: $INITIAL_AES -> corp01"* && "$hist" == *"crypto.key.embedded: (비공개) -> (교체됨)"* \
   && "$hist" == *"crypto.keys.$INITIAL_AES.embedded: (없음) -> (비공개)"* && "$hist" == *"키 corp01: (없음) -> key, embedded, "* \
   && "$hist" == *"crypto.key.active.pass: $INITIAL_PASS -> corp-pass"* && "$hist" == *"키 corp-pass: (없음) -> pass, embedded, "* \
   && "$hist" == *"crypto.pool.factory: $DBCPF -> $TJF"* && "$hist" == *"admin setup  [관리자]"* \
   && "$hist" == *"관리자 비밀번호: (없음) -> (설정됨)"* && "$hist" != *"$CORP_PASSPHRASE"* && "$hist" != *"$ADMINPW"* ]]
check $? "config history --all(관리자 인증): 키ID default→corp01·키 교체·이전 초기 키 보존·pass 키 추가·기본 키 지정·Pool 변경·[관리자] 설정 기록(비밀값 없음)"
histp=$(wb java -jar /w/jars/company-tj.jar config history $ADM 2>&1)
[[ "$histp" == *"표시 범위 : pass 관련 "* && "$histp" == *"crypto.key.active.pass: $INITIAL_PASS -> corp-pass"* \
   && "$histp" != *"crypto.pool.factory"* && "$histp" != *"crypto.key.id: $INITIAL_AES -> corp01"* && "$histp" != *"[관리자]"* ]]
check $? "config history(기본 pass): pass 키 변경만, AES 키·Pool 변경·관리자 기록은 --type key·--all에서만"
hn=$(wb java -jar /w/jars/company-tj.jar config history --admin-pass-file /w/admin/wrong.pw 2>&1); rc=$?
[ $rc = 1 ] && [[ "$hn" == *"ADMIN_AUTH"* && "$hn" != *"crypto.key.active.pass"* ]]
check $? "config history(다른 관리자 비밀번호 파일): ADMIN_AUTH, 이력 미표시"
jx=$(wb sh -c 'cd /w
  echo "obf=$(grep -aFc "crypto.key.embedded=obf1:" jars/company-tj.jar)"
  echo "plain-key=$(grep -aFc "$(cat /opt/java-crypto-kit/company.key)" jars/company-tj.jar)"
  echo "plain-reason=$(grep -aFc "integration test" jars/company-tj.jar)"' 2>&1)
[[ "$jx" == *"obf=1"* && "$jx" == *"plain-key=0"* && "$jx" == *"plain-reason=0"* ]]
check $? "JAR 예약 영역의 키와 이력은 obf1로 저장"
fp_jar=$(fpw /w/jars/company.jar fingerprint --type key)
fp_key=$(fpw /w/jars/initial.jar fingerprint --key-file /opt/java-crypto-kit/company.key)
[ -n "$fp_jar" ] && [ "$fp_jar" = "$fp_key" ]; check $? "fingerprint --type key: 키 내장 JAR의 AES 키 = 키 파일(64자 지문)"
fp_pass=$(fpw /w/jars/company.jar fingerprint); fp_pass_id=$(fpw /w/jars/company.jar fingerprint --key-id corp-pass)
[ -n "$fp_pass" ] && [ "$fp_pass" = "$fp_pass_id" ] && [ "$fp_pass" != "$fp_jar" ]
check $? "fingerprint(유형 미지정) = 기본 pass 키 corp-pass(--key-id와 같음), AES 키와 다름"
FP_INFRA_KEY=$(fpw /w/jars/infra.jar fingerprint --type key); FP_INFRA_PASS=$(fpw /w/jars/infra.jar fingerprint)
FP_BIZ_KEY=$(fpw /w/jars/biz.jar fingerprint --type key); FP_BIZ_PASS=$(fpw /w/jars/biz.jar fingerprint)
INITIAL_PASS_FP=$(fpw /w/jars/initial.jar fingerprint)
FP_SHARED=$(fpw /w/jars/initial.jar fingerprint --key-file /opt/java-crypto-kit/shared01.key)
[ -n "$FP_INFRA_KEY" ] && [ -n "$FP_INFRA_PASS" ] && [ -n "$FP_BIZ_KEY" ] && [ -n "$FP_BIZ_PASS" ] && [ -n "$FP_SHARED" ] \
  && [ "$FP_INFRA_KEY" != "$FP_BIZ_KEY" ] && [ "$FP_INFRA_PASS" != "$FP_BIZ_PASS" ] \
  && [ "$(fpw /w/jars/infra-tj.jar fingerprint --type key)" = "$FP_INFRA_KEY" ] && [ "$(fpw /w/jars/biz-tj.jar fingerprint)" = "$FP_BIZ_PASS" ]
check $? "이중 배포용 JAR A·B: pass·key 키 지문이 서로 다름, Pool만 바꾼 JAR는 키가 같음"
doc=$(wb java -jar /w/jars/company.jar doctor 2>&1); rc=$?
[ $rc = 0 ] && [[ "$doc" == *"키 로딩 정상: corp01, 사용자 지정"* && "$doc" == *"키 로딩 정상: corp-pass, 사용자 지정"* \
   && "$doc" == *"키 로딩 정상: $INITIAL_AES, 사용자 지정"* && "$doc" == *"키 로딩 정상: $INITIAL_PASS, 사용자 지정"* \
   && "$doc" == *"결과: PASS"* && "$doc" != *"[WARN]"* ]]
check $? "doctor(키 내장 JAR): 종료 코드 0, 등록된 키 4개 확인(corp01·corp-pass·최초 설정 키 2개 모두 사용자 지정), WARN 없음"
doc=$(wb java -jar /w/jars/initial.jar doctor 2>&1); rc=$?
[ $rc = 0 ] && [[ "$doc" == *"키 로딩 정상: $INITIAL_AES, 사용자 지정"* && "$doc" == *"키 로딩 정상: $INITIAL_PASS, 사용자 지정"* && "$doc" != *"[WARN]"* ]]
check $? "doctor(초기 키만 있는 JAR, 관리자 인증 불필요): 초기 설정 키 두 개 사실 표시, 정책 WARN·자동 경고 없음, 종료 코드 0"
doc=$(wb java -jar /w/jars/company-pfile.jar doctor 2>&1); rc=$?
[ $rc = 0 ] && [[ "$doc" == *"키 로딩 정상: corp-pfile, 사용자 지정"* ]]
check $? "doctor(pass 파일 키 JAR): 파일의 Passphrase로 파생한 키 = 고정 지문"
doc=$(wb java -Dcrypto.keys.corp-pfile.file=/opt/java-crypto-kit/other.pass -jar /w/jars/company-pfile.jar doctor 2>&1); rc=$?
[ $rc = 1 ] && [[ "$doc" == *"지문 불일치"* && "$doc" == *"키 로딩 정상: corp01, 사용자 지정"* ]]
check $? "doctor(-D로 위치만 바꿔 다른 Passphrase 파일): 그 키만 FAIL(지문 불일치), 다른 키 정상, 종료 코드 1"
wb java -jar /w/jars/company.jar doctor --config /opt/java-crypto-kit/missing-key.properties > /dev/null 2>&1; rc=$?
[ $rc = 1 ]; check $? "doctor(키 파일 없음): FAIL, 종료 코드 1"
# 관리자 검증값 손상(모르는 형식 버전) JAR: CLI는 모든 명령을 INTEGRITY로 거부(Fail Closed), Tomcat·Java API는 읽지 않는다(E23).
dm=$(wb sh -c 'rm -rf /tmp/jd && mkdir -p /tmp/jd/META-INF/java-crypto-kit && cd /tmp/jd \
  && printf "format.version=9\n" > META-INF/java-crypto-kit/admin.properties \
  && cp /w/jars/company.jar /w/jars/company-admin-damaged.jar && jar uf /w/jars/company-admin-damaged.jar META-INF/java-crypto-kit/admin.properties \
  && cd /w && java -jar jars/company-admin-damaged.jar doctor; echo "rc=$?"
  java -jar jars/company-admin-damaged.jar decrypt --admin-pass-file /w/admin/admin.pw; echo "rc=$?"' 2>&1)
[ "$(grep -c 'INTEGRITY' <<< "$dm")" = 2 ] && [ "$(grep -c '^rc=1$' <<< "$dm")" = 2 ] && [[ "$dm" != *"결과: PASS"* ]]
check $? "관리자 검증값 손상 JAR: CLI doctor·decrypt 모두 INTEGRITY(종료 코드 1), 비밀번호 파일로도 진행 안 됨"
hd=$(wb sh -c 'rm -rf /tmp/jh /tmp/jh.mf && mkdir /tmp/jh && cd /tmp/jh && jar xf /w/jars/initial.jar \
  && mv META-INF/MANIFEST.MF /tmp/jh.mf && rm -f META-INF/java-crypto-kit/config-history.properties \
  && jar cfm /w/jars/public-history-deleted.jar /tmp/jh.mf . && cd /w && sha256sum jars/public-history-deleted.jar | cut -c1-64
  java -jar jars/public-history-deleted.jar config history --all --admin-pass-file /w/admin/admin.pw; echo "rc=$?"
  java -jar jars/public-history-deleted.jar config set crypto.lang=en --operator qa --admin-pass-file /w/admin/admin.pw; echo "rc=$?"
  java -jar jars/public-history-deleted.jar config key show --key-id default --export /w/out/hd.export --admin-pass-file /w/admin/admin.pw; echo "rc=$?"
  java -jar jars/company.jar config show --jar jars/public-history-deleted.jar --admin-pass-file /w/admin/admin.pw; echo "rc=$?"
  ls /w/out; sha256sum jars/public-history-deleted.jar | cut -c1-64' 2>&1)
[ "$(grep -c 'INTEGRITY' <<< "$hd")" = 4 ] && [ "$(grep -c '^rc=1$' <<< "$hd")" = 4 ] && [[ "$hd" != *"hd.jar"* && "$hd" != *"hd.export"* ]] \
  && [ "$(grep -cE '^[0-9a-f]{64}$' <<< "$hd")" = 2 ] && [ "$(grep -E '^[0-9a-f]{64}$' <<< "$hd" | sort -u | wc -l | tr -d ' ')" = 1 ]
check $? "예약 영역이 유실된 JAR: config history·set·key show --export와 다른 JAR(--jar)로 지정 모두 INTEGRITY, 새 JAR·내보내기 없음, 원본 그대로"

section "2. 실제 CLI encrypt·decrypt·rekey(가상 터미널) - 암호문은 임시 파일에만 저장"
CASE=cli
export QA_ENV_KEY; QA_ENV_KEY=$(docker exec "$WB" cat /opt/java-crypto-kit/env01.key | tr -d '\r\n')
cat > "$WORK/gen-tokens.sh" << 'GEN'
#!/bin/sh
# 안내 문구가 나온 뒤(입력 숨김 상태) 값을 입력한다. 평문·암호문은 화면에 출력하지 않는다.
# PUB: 초기 키만 있는 CLI JAR(빌드 JAR에 관리자 비밀번호만 설정한 initial.jar). ADM: 비대화형 관리자 인증
J=/w/jars; PUB=$J/initial.jar; COMP=$J/company.jar; ADM="--admin-pass-file /w/admin/admin.pw"
# enc <이름> <값> "<java 옵션 -jar JAR>" [encrypt 옵션...]
enc() {
  name="$1"; value="$2"; java_args="$3"; shift 3
  (sleep 3; printf '%s\n' "$value") | script -qec "java $java_args encrypt $*" /dev/null > "/tmp/$name.out" 2>&1
  tr -d '\r' < "/tmp/$name.out" | grep -oE '(ENC\[v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\]|B64\[[A-Za-z0-9+/=_-]+\])' | head -1 > "/w/tokens/$name"
  # warn: 표준 오류의 [WARN] 줄 수(공개된 기본 키는 로딩 단계에서 KEY_SOURCE로 거부되므로 항상 0)
  echo "$name echo=$(grep -cF -- "$value" "/tmp/$name.out") warn=$(grep -c '^\[WARN\] ' "/tmp/$name.out")"
  rm -f "/tmp/$name.out"
}
enc CORP_PW "$DBPW" "-jar $COMP" --type key
enc CORP_USER "qa_app" "-jar $COMP" --type key
enc CORP_WRONG "$WRONGPW" "-jar $COMP" --type key
enc CORP_B64 "$DBPW" "-Dcrypto.output.encoding=base64 -jar $COMP" --type key
enc CORP_PASS_PW "$DBPW" "-jar $COMP"
enc PUB_PW "$DBPW" "-jar $PUB"
enc PUB_KEY "$DBPW" "-jar $PUB" --type key
enc FORGED "$DBPW" "-Dcrypto.key.id=corp01 -jar $PUB" --type key
enc FOREIGN "$DBPW" "-Dcrypto.key.id=other01 -jar $PUB" --type key
enc EXT_PW "$DBPW" "-Dcrypto.config.file=/opt/java-crypto-kit/ext-file.properties -jar $COMP" --type key
enc ENV_PW "$DBPW" "-Dcrypto.key.source=env -Dcrypto.key.env=QA_ENV_KEY -Dcrypto.key.id=env01 -jar $COMP" --type key
enc PFILE_PW "$DBPW" "-jar $J/company-pfile.jar" --key-id corp-pfile
enc INFRA_PASS_PW "$DBPW" "-jar $J/infra.jar"
enc INFRA_KEY_PW "$DBPW" "-jar $J/infra.jar" --type key
enc BIZ_PASS_PW "$DBPW" "-jar $J/biz.jar"
enc BIZ_KEY_PW "$DBPW" "-jar $J/biz.jar" --type key
enc SHARED_PW "$DBPW" "-Dcrypto.config.file=/opt/java-crypto-kit/shared-slot.properties -jar $J/infra.jar" --type key
# dec <표시 이름> <암호문 이름> [비밀번호 파일]: 관리자 인증 뒤 암호문을 입력하고 평문 표시 여부·사유 코드·관리자 비밀번호
#   화면 표시 여부만 센다. 파일을 주지 않으면 가상 터미널의 관리자 비밀번호 프롬프트에 숨김 입력한다.
dec() {
  if [ -n "${3:-}" ]; then
    (sleep 3; cat "/w/tokens/$2") | script -qec "java -jar $COMP decrypt --admin-pass-file $3" /dev/null > /tmp/d.out 2>&1
  else
    (sleep 3; cat /w/admin/admin.pw; sleep 3; cat "/w/tokens/$2") | script -qec "java -jar $COMP decrypt" /dev/null > /tmp/d.out 2>&1
  fi
  echo "$1 plain=$(grep -cF -- "$DBPW" /tmp/d.out) result=$(grep -c '복호화 결과: ' /tmp/d.out) integrity=$(grep -c 'INTEGRITY' /tmp/d.out)" \
    "auth=$(grep -c 'ADMIN_AUTH' /tmp/d.out) prompt=$(grep -c '관리자 비밀번호(입력 숨김):' /tmp/d.out) admin-echo=$(grep -cF -- "$(cat /w/admin/admin.pw)" /tmp/d.out)"
  rm -f /tmp/d.out
}
dec decrypt-key CORP_PW; dec decrypt-pass CORP_PASS_PW /w/admin/admin.pw; dec decrypt-forged FORGED /w/admin/admin.pw
dec decrypt-wrong-admin CORP_PW /w/admin/wrong.pw
# rk <결과 이름> <원본 암호문 이름> [rekey 옵션...]: 표준 출력은 새 암호문 한 줄, 표준 오류 바이트 수를 센다
rk() {
  out="$1"; src="$2"; shift 2
  java -jar $COMP rekey "$@" --value "$(cat "/w/tokens/$src")" > "/w/tokens/$out" 2> /tmp/rk.err
  echo "$out rekey=$? err=$(wc -c < /tmp/rk.err | tr -d ' ') setup=$(grep -c 'ADMIN_SETUP' /tmp/rk.err) auth=$(grep -c 'ADMIN_AUTH' /tmp/rk.err)"
  rm -f /tmp/rk.err
}
rk REKEY_PW PUB_KEY --from-jar $PUB $ADM
rk REKEY_PASS PUB_PW --from-jar $PUB $ADM
rk REKEY_X PUB_PW --type key $ADM
# 관리자 비밀번호 미설정 JAR(빌드 JAR)에서 키를 꺼낼 수 없고, 다른 비밀번호 파일이면 인증 실패(둘 다 새 암호문 없음)
rk REKEY_UNSET PUB_KEY --from-jar $J/public.jar $ADM
rk REKEY_NOAUTH PUB_KEY --from-jar $PUB --admin-pass-file /w/admin/wrong.pw
GEN
docker cp "$WORKH/gen-tokens.sh" "$WB:/w/gen-tokens.sh" > /dev/null
gen=$(wb sh /w/gen-tokens.sh 2>&1)
docker cp "$WB:/w/tokens/." "$WORKH/tokens/" > /dev/null
TOKENS="CORP_PW CORP_USER CORP_WRONG CORP_B64 CORP_PASS_PW PUB_PW PUB_KEY FORGED FOREIGN EXT_PW ENV_PW PFILE_PW
  INFRA_PASS_PW INFRA_KEY_PW BIZ_PASS_PW BIZ_KEY_PW SHARED_PW REKEY_PW REKEY_PASS REKEY_X"
for t in $TOKENS; do
  v=$(tr -d '\r\n' < "$WORK/tokens/$t" 2> /dev/null); printf -v "$t" '%s' "$v"; secret "$v"
done
[ "$(grep -c ' echo=0 ' <<< "$gen")" = 17 ]; check $? "encrypt 17회: 입력한 평문이 화면에 보이지 않음"
bad_ids=""
for pair in CORP_PW=corp01 CORP_USER=corp01 CORP_WRONG=corp01 CORP_PASS_PW=corp-pass PUB_PW=$INITIAL_PASS PUB_KEY=$INITIAL_AES \
    FORGED=corp01 FOREIGN=other01 EXT_PW=ext01 ENV_PW=env01 PFILE_PW=corp-pfile INFRA_PASS_PW=infra-pass INFRA_KEY_PW=infra-key \
    BIZ_PASS_PW=biz-pass BIZ_KEY_PW=biz-key SHARED_PW=shared01 REKEY_PW=corp01 REKEY_PASS=corp-pass REKEY_X=corp01; do
  n="${pair%%=*}"; [[ "${!n}" == "ENC[v1:${pair#*=}:"* ]] || bad_ids="$bad_ids $n"
done
[[ "$CORP_B64" == "B64["* ]] || bad_ids="$bad_ids CORP_B64"
[ -z "$bad_ids" ]
check $? "암호문 키ID: 유형 미지정 = pass 기본 키, --type key = AES 키, 최초 설정 키 2종·위조·미등록·외부·이중 배포 A/B·rekey·B64 포장${bad_ids:+ (다름:$bad_ids)}"
[ "$(grep -cE '^(CORP_PW|CORP_USER|CORP_WRONG|CORP_B64|CORP_PASS_PW|EXT_PW|ENV_PW|PFILE_PW|INFRA_PASS_PW|INFRA_KEY_PW|BIZ_PASS_PW|BIZ_KEY_PW|SHARED_PW) echo=0 warn=0$' <<< "$gen")" = 13 ]
check $? "encrypt: 사용자 지정·외부 키(pass·key·파일·환경변수)는 [WARN] 0건"
[ "$(grep -cE '^(PUB_PW|PUB_KEY|FORGED|FOREIGN) echo=0 warn=0$' <<< "$gen")" = 4 ]
check $? "최초 설정 키·위조·미등록 키ID 암호화에도 [WARN] 없음"
grep -q '^decrypt-key plain=1 result=1 integrity=0 auth=0 prompt=1 admin-echo=0$' <<< "$gen"
check $? "decrypt(가상 터미널): 관리자 비밀번호 프롬프트 숨김 입력(화면에 비밀번호 없음) 뒤 key 암호문 평문 표시"
grep -q '^decrypt-pass plain=1 result=1 integrity=0 auth=0 prompt=0 admin-echo=0$' <<< "$gen"
check $? "decrypt(--admin-pass-file): 프롬프트 없이 인증, pass 암호문 평문 표시(키 ID로 자동 선택)"
grep -q '^decrypt-forged plain=0 result=0 integrity=1 auth=0 ' <<< "$gen"; check $? "decrypt: 위조 암호문은 평문 없이 INTEGRITY"
grep -q '^decrypt-wrong-admin plain=0 result=0 integrity=0 auth=1 prompt=0 admin-echo=0$' <<< "$gen"
check $? "decrypt(다른 관리자 비밀번호 파일): ADMIN_AUTH, 암호문 입력·복호화 전에 끝남(평문 없음)"
[ "$(grep -cE '^REKEY_(PW|PASS|X) rekey=0 err=0 setup=0 auth=0$' <<< "$gen")" = 3 ]
check $? "rekey(관리자 인증, --from-jar도 같은 비밀번호): 최초 설정 키 암호문 → 사용자 지정 키(같은 유형 2건·--type key 유형 간 1건), 표준 오류 없음"
grep -q '^REKEY_UNSET rekey=1 err=[1-9][0-9]* setup=1 auth=0$' <<< "$gen" && grep -q '^REKEY_NOAUTH rekey=1 err=[1-9][0-9]* setup=0 auth=1$' <<< "$gen" \
  && [ ! -s "$WORK/tokens/REKEY_UNSET" ] && [ ! -s "$WORK/tokens/REKEY_NOAUTH" ]
check $? "rekey: --from-jar 미설정 빌드 JAR은 ADMIN_SETUP, 다른 비밀번호 파일은 ADMIN_AUTH(둘 다 새 암호문 없음)"
pre="${CORP_PW%:*}"; idx=$(( ${#pre} + 2 )); c="${CORP_PW:$idx:1}"; n=A; [ "$c" = A ] && n=B
TAMPERED="${CORP_PW:0:$idx}$n${CORP_PW:$((idx + 1))}"; secret "$TAMPERED"
docker cp "$WB:/w/jars/." "$WORKH/jars/" > /dev/null
docker cp "$WB:/opt/java-crypto-kit/." "$WORKH/secure/" > /dev/null
for k in company ext01 env01 shared01 infra biz; do secret "$(tr -d '\r\n' < "$WORK/secure/$k.key")"; done
v8=$(T="$CORP_PW" S="$CORP_PASS_PW" P="$PUB_PW" K="$PUB_KEY" O="$FOREIGN" F="$FORGED" Q="$PFILE_PW" docker run --rm "${LABELS[@]}" --network none \
  -v "$WORKH/jars:/j:ro" -v "$WORKH/secure:/opt/java-crypto-kit:ro" -e T -e S -e P -e K -e O -e F -e Q --entrypoint sh "$T85" -c '
  java -jar /j/company.jar verify --value "$T" > /dev/null 2>&1; echo "key=$?"
  java -jar /j/company.jar verify --value "$S" > /dev/null 2>&1; echo "pass=$?"
  java -jar /j/company.jar verify --value "$P" > /dev/null 2>&1; echo "public-pass=$?"
  java -jar /j/company.jar verify --value "$K" > /dev/null 2>&1; echo "public-key=$?"
  java -jar /j/company-pfile.jar verify --value "$Q" > /dev/null 2>&1; echo "pfile=$?"
  java -jar /j/company-hardened.jar verify --value "$P" 2>&1 | grep -c "KEY_ID_MISMATCH" | sed "s/^/hardened-pass=/"
  java -jar /j/company-hardened.jar verify --value "$K" 2>&1 | grep -c "KEY_ID_MISMATCH" | sed "s/^/hardened-key=/"
  java -jar /j/company.jar verify --value "$O" 2>&1 | grep -c "KEY_ID_MISMATCH" | sed "s/^/foreign=/"
  java -jar /j/company.jar verify --value "$F" 2>&1 | grep -c "INTEGRITY" | sed "s/^/forged=/"' 2>&1)
grep -q '^key=0$' <<< "$v8" && grep -q '^pass=0$' <<< "$v8"; check $? "JDK 21에서 만든 pass·key 암호문을 JDK 8에서 verify"
grep -q '^pfile=0$' <<< "$v8"; check $? "JDK 8에서 pass 파일 키(한글·이모지 Passphrase) PBKDF2 파생 = JDK 21에서 고정한 지문"
grep -q '^public-pass=0$' <<< "$v8" && grep -q '^public-key=0$' <<< "$v8"
check $? "키 내장 JAR: embed-key·key add 뒤에도 최초 등록한 두 키 암호문 복호화(기존 암호문 호환)"
grep -q '^hardened-pass=1$' <<< "$v8" && grep -q '^hardened-key=1$' <<< "$v8"; check $? "최초 설정 키를 뺀 JAR: 그 키 암호문 KEY_ID_MISMATCH"
grep -q '^foreign=1$' <<< "$v8" && grep -q '^forged=1$' <<< "$v8"; check $? "미등록 키ID 암호문 KEY_ID_MISMATCH, 위조 암호문(최초 설정 AES 키 + 키 ID corp01) INTEGRITY"

section "3. MariaDB(tmpfs 데이터, 시험 전용 계정)"
CASE=mariadb
export MARIADB_ROOT_PASSWORD="$ROOTPW" MARIADB_PASSWORD="$DBPW" MYSQL_PWD="$DBPW"
docker run -d --name "$DB" "${LABELS[@]}" --network "$NET" --network-alias jck-qa-db --tmpfs /var/lib/mysql:rw,size=768m \
  -e MARIADB_ROOT_PASSWORD -e MARIADB_PASSWORD -e MARIADB_DATABASE=qadb -e MARIADB_USER=qa_app "$DB_IMAGE" > /dev/null \
  || die "MariaDB 컨테이너를 시작하지 못했습니다."
up=1; for i in $(seq 1 90); do docker exec "$DB" healthcheck.sh --connect --innodb_initialized > /dev/null 2>&1 && { up=0; break; }; sleep 2; done
check $up "MariaDB 기동"
docker exec -e MYSQL_PWD "$DB" mariadb -uqa_app qadb -e "CREATE TABLE qa_check (id INT PRIMARY KEY, marker VARCHAR(64) NOT NULL);
  INSERT INTO qa_check VALUES (1, 'java-crypto-kit-qa');
  CREATE TABLE qa_log (id INT AUTO_INCREMENT PRIMARY KEY, run VARCHAR(64) NOT NULL);" > /dev/null
check $? "시험 테이블 생성"
echo "   MariaDB $(docker exec -e MYSQL_PWD "$DB" mariadb -uqa_app -N -e 'SELECT VERSION()' 2>/dev/null)"

# ------------------------------------------------------------------ Tomcat 시험 도우미
DBURL='jdbc:mariadb://jck-qa-db:3306/qadb'
ATTR_D='initialSize="1" maxTotal="5" maxIdle="2" maxWaitMillis="5000"'
ATTR_T='initialSize="1" maxActive="5" maxIdle="2" maxWait="5000"'
ATTR_X='initialSize="1"'
res() { # <JNDI 이름> <password> <Pool 속성> [username] [factory(빈 값이면 factory 속성 없음)]
  local f=""; [ -n "${5-$NEWF}" ] && f="factory=\"${5-$NEWF}\""
  echo "  <Resource name=\"$1\" auth=\"Container\" type=\"javax.sql.DataSource\" $f driverClassName=\"org.mariadb.jdbc.Driver\" url=\"$DBURL\" username=\"${4:-qa_app}\" password=\"$2\" $3/>"
}
# 시험 전용 JSP: JNDI 조회 → getConnection() → SELECT 1(+ run이 있으면 실제 테이블 SELECT·INSERT). 비밀값은 출력하지 않는다.
write_jsp() {
  cat > "$1/jck-qa.jsp" << 'JSP'
<%@ page contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8" import="javax.naming.InitialContext,javax.naming.NamingException,javax.sql.DataSource,java.sql.Connection,java.sql.PreparedStatement,java.sql.ResultSet,java.sql.SQLException" %><%
    if (!"127.0.0.1".equals(request.getRemoteAddr())) { response.setStatus(403); out.print("FORBIDDEN"); return; }
    String name = request.getParameter("ds");
    if (name == null || !name.matches("[A-Za-z0-9_./-]{1,100}")) name = "jdbc/qa";
    String run = request.getParameter("run");
    if (run == null || !run.matches("[A-Za-z0-9_.-]{1,64}")) run = "";
    try {
        DataSource ds = (DataSource) new InitialContext().lookup("java:comp/env/" + name);
        try (Connection c = ds.getConnection()) {
            StringBuilder s = new StringBuilder("OK ds=" + name + " pool=" + ds.getClass().getName() + " db=" + c.getMetaData().getDatabaseProductName());
            try (PreparedStatement p = c.prepareStatement("SELECT 1"); ResultSet r = p.executeQuery()) { r.next(); s.append(" result=").append(r.getInt(1)); }
            if (!run.isEmpty()) {
                try (PreparedStatement p = c.prepareStatement("SELECT marker FROM qa_check WHERE id = 1"); ResultSet r = p.executeQuery()) { r.next(); s.append(" marker=").append(r.getString(1)); }
                try (PreparedStatement p = c.prepareStatement("SELECT CURRENT_USER()"); ResultSet r = p.executeQuery()) { r.next(); s.append(" user=").append(r.getString(1)); }
                try (PreparedStatement p = c.prepareStatement("INSERT INTO qa_log(run) VALUES (?)")) { p.setString(1, run); p.executeUpdate(); }
                try (PreparedStatement p = c.prepareStatement("SELECT COUNT(*) FROM qa_log WHERE run = ?")) { p.setString(1, run); try (ResultSet r = p.executeQuery()) { r.next(); s.append(" inserted=").append(r.getInt(1)); } }
            }
            out.print(s);
        }
    } catch (Exception e) {
        response.setStatus(500);
        StringBuilder m = new StringBuilder("FAIL ds=" + name + " type=" + e.getClass().getSimpleName());
        if (e instanceof SQLException && ((SQLException) e).getSQLState() != null) m.append(" SQLState=").append(((SQLException) e).getSQLState());
        if (e instanceof NamingException && String.valueOf(e.getMessage()).startsWith("[java-crypto-kit]")) m.append(" message=").append(e.getMessage());
        // 원인 진단용: 원인 예외는 클래스 이름만 적는다(메시지 제외). 클래스 로딩 실패면 없는 클래스 이름을 함께 적는다(JAR 누락·손상 확인).
        Throwable c = e.getCause();
        for (int i = 0; c != null && i < 5; i++, c = c.getCause()) {
            m.append(i == 0 ? " cause=" : "<-").append(c.getClass().getSimpleName());
            if (c instanceof ClassNotFoundException || c instanceof NoClassDefFoundError) m.append('(').append(c.getMessage()).append(')');
        }
        out.print(m);
    }
%>
JSP
}
# 이중 배포 시험 JSP: 웹앱 코드가 보는 java-crypto-kit(app = 스레드 컨텍스트 클래스로더)와 Tomcat lib의 것(lib = 그 부모)을
# 각각 리플렉션으로 불러 클래스 위치·키 목록·짧은 지문·복호화 결과(사유 코드)·새 암호문의 키 ID만 출력한다.
# 암호문은 컨테이너 안의 파일(/opt/java-crypto-kit/dual-tokens.properties)에서 읽고 평문·암호문·키는 출력하지 않는다.
write_dual_jsp() {
  cat > "$1/jck-dual.jsp" << 'JSP'
<%@ page contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8" import="java.io.FileInputStream,java.io.InputStream,java.lang.reflect.InvocationTargetException,java.lang.reflect.Method,java.util.List,java.util.Properties,java.util.TreeMap,java.util.TreeSet" %><%!
    static String where(Class<?> c) {
        try {
            String u = String.valueOf(c.getProtectionDomain().getCodeSource().getLocation());
            if (u.startsWith("jar:")) u = u.substring(4);
            int bang = u.indexOf("!/");
            if (bang >= 0) u = u.substring(0, bang);
            if (u.startsWith("file:")) u = u.substring(5);
            while (u.startsWith("//")) u = u.substring(1);
            return u;
        } catch (Exception e) {
            return "unknown";
        }
    }
    static String reason(Throwable t) {
        while (t instanceof InvocationTargetException && t.getCause() != null) t = t.getCause();
        try { return String.valueOf(t.getClass().getMethod("getReason").invoke(t)); } catch (Exception e) { return t.getClass().getSimpleName(); }
    }
    static String keyIdOf(Object token) {
        String s = String.valueOf(token);
        int end = s.indexOf(':', 7);
        return s.startsWith("ENC[v1:") && end > 7 ? s.substring(7, end) : "unexpected";
    }
    // 개발자 파일 API: 각 사본(app·lib)의 기본 키로 같은 원본 파일을 암호화·복호화(왕복)하고, 상대 사본이 만든 파일은 키 ID로
    // 거부되는지 본다(파일 내용·키는 출력하지 않고, 임시 폴더는 매번 새로 만든 뒤 지운다).
    static void fileProbe(StringBuilder s, ClassLoader app, ClassLoader lib) {
        java.io.File dir = null;
        try {
            dir = java.nio.file.Files.createTempDirectory("jck-dual").toFile();
            java.nio.file.Path plain = new java.io.File(dir, "plain.bin").toPath();
            byte[] data = new byte[100000];
            new java.util.Random(7).nextBytes(data);
            java.nio.file.Files.write(plain, data);
            ClassLoader[] loaders = {app, lib};
            String[] tags = {"app", "lib"};
            Object[] cryptos = new Object[2];
            for (int i = 0; i < 2; i++) {
                try {
                    Class<?> api = Class.forName("io.javacryptokit.CredentialCrypto", true, loaders[i]);
                    Object crypto = api.getMethod("fromDefaultConfiguration").invoke(null);
                    java.nio.file.Path enc = new java.io.File(dir, tags[i] + ".jck").toPath();
                    java.nio.file.Path back = new java.io.File(dir, tags[i] + ".out").toPath();
                    api.getMethod("encryptFile", java.nio.file.Path.class, java.nio.file.Path.class).invoke(crypto, plain, enc);
                    api.getMethod("decryptFile", java.nio.file.Path.class, java.nio.file.Path.class).invoke(crypto, enc, back);
                    s.append(tags[i]).append(".file=")
                            .append(java.util.Arrays.equals(data, java.nio.file.Files.readAllBytes(back)) ? "OK" : "DIFF").append('\n');
                    cryptos[i] = crypto;
                } catch (Throwable e) {
                    s.append(tags[i]).append(".file=").append(reason(e)).append('\n');
                }
            }
            for (int i = 0; i < 2; i++) {
                int other = 1 - i;
                if (cryptos[i] == null || cryptos[other] == null) continue;
                java.nio.file.Path enc = new java.io.File(dir, tags[other] + ".jck").toPath();
                java.nio.file.Path back = new java.io.File(dir, tags[i] + "-from-" + tags[other] + ".out").toPath();
                String r;
                try {
                    cryptos[i].getClass().getMethod("decryptFile", java.nio.file.Path.class, java.nio.file.Path.class).invoke(cryptos[i], enc, back);
                    r = "OK";
                } catch (Throwable e) {
                    r = reason(e);
                }
                s.append(tags[i]).append(".fileFrom.").append(tags[other]).append('=').append(r).append('\n');
            }
        } catch (Throwable e) {
            s.append("file.error=").append(reason(e)).append('\n');
        } finally {
            if (dir != null) {
                java.io.File[] files = dir.listFiles();
                if (files != null) for (java.io.File f : files) f.delete();
                dir.delete();
            }
        }
    }
    static void probe(StringBuilder s, String tag, ClassLoader loader, Properties tokens) {
        try {
            Class<?> api = Class.forName("io.javacryptokit.CredentialCrypto", true, loader);
            s.append(tag).append(".api=").append(where(api)).append('\n');
            Object crypto;
            try {
                crypto = api.getMethod("fromDefaultConfiguration").invoke(null);
            } catch (Exception e) {
                s.append(tag).append(".load=").append(reason(e)).append('\n');
                return;
            }
            s.append(tag).append(".load=OK\n");
            s.append(tag).append(".default=").append(api.getMethod("keyId").invoke(crypto)).append('\n');
            TreeMap<String, String> fps = new TreeMap<String, String>();
            for (Object k : (List<?>) api.getMethod("keys").invoke(crypto)) {
                fps.put(String.valueOf(k.getClass().getMethod("keyId").invoke(k)), String.valueOf(k.getClass().getMethod("fingerprint").invoke(k)));
            }
            s.append(tag).append(".keys=").append(String.join(",", fps.keySet())).append('\n');
            for (String id : fps.keySet()) s.append(tag).append(".fp.").append(id).append('=').append(fps.get(id)).append('\n');
            Method dec = api.getMethod("decryptText", String.class);
            for (String name : new TreeSet<String>(tokens.stringPropertyNames())) {
                String r;
                try { dec.invoke(crypto, tokens.getProperty(name)); r = "OK"; } catch (Exception e) { r = reason(e); }
                s.append(tag).append(".dec.").append(name).append('=').append(r).append('\n');
            }
            s.append(tag).append(".enc=").append(keyIdOf(api.getMethod("encryptText", String.class).invoke(crypto, "jck-dual-probe"))).append('\n');
            Class<?> type = Class.forName("io.javacryptokit.KeyType", true, loader);
            Object aes = type.getField("KEY").get(null);
            s.append(tag).append(".encKey=").append(keyIdOf(api.getMethod("encryptText", String.class, type).invoke(crypto, "jck-dual-probe", aes))).append('\n');
        } catch (Throwable e) {
            s.append(tag).append(".error=").append(reason(e)).append('\n');
        }
    }
%><%
    if (!"127.0.0.1".equals(request.getRemoteAddr())) { response.setStatus(403); out.print("FORBIDDEN"); return; }
    Properties tokens = new Properties();
    try (InputStream in = new FileInputStream("/opt/java-crypto-kit/dual-tokens.properties")) { tokens.load(in); }
    ClassLoader app = Thread.currentThread().getContextClassLoader();
    ClassLoader lib = app.getParent();
    String factory = "io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory";
    StringBuilder s = new StringBuilder();
    s.append("factory.app=").append(where(Class.forName(factory, false, app))).append('\n');
    // Tomcat lib에 JAR가 없는 배치(W01)도 있으므로 상위 클래스로더에서 못 찾으면 none으로 적는다.
    String libFactory;
    boolean same;
    try {
        libFactory = where(Class.forName(factory, false, lib));
        same = Class.forName("io.javacryptokit.CredentialCrypto", false, app) == Class.forName("io.javacryptokit.CredentialCrypto", false, lib);
    } catch (ClassNotFoundException e) {
        libFactory = "none";
        same = false;
    }
    s.append("factory.lib=").append(libFactory).append('\n');
    s.append("same.class=").append(same).append('\n');
    probe(s, "app", app, tokens);
    probe(s, "lib", lib, tokens);
    fileProbe(s, app, lib);
    out.print(s);
%>
JSP
}
# 범용 보안 API 시험 JSP: 웹앱이 보는 java-crypto-kit(웹앱 클래스로더가 고른 JAR)의 공개 API를 직접 호출한다(관리형 키·설정·
# History를 쓰지 않는 API들). 결과는 단계별 OK/DIFF/예외 이름과 클래스 출처만 출력하고 키·평문·토큰은 출력하지 않는다.
# Tomcat 8.5 Jasper 기본 소스 수준(1.7)에서도 컴파일되도록 람다를 쓰지 않는다.
write_newapi_jsp() {
  cat > "$1/jck-newapi.jsp" << 'JSP'
<%@ page contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8" import="io.javacryptokit.CredentialCrypto,io.javacryptokit.security.*,io.javacryptokit.jwt.*,io.javacryptokit.oauth.*,java.security.KeyPair,java.time.Duration,java.time.Instant,java.util.Arrays" %><%!
    static String where(Class<?> c) {
        try {
            String u = String.valueOf(c.getProtectionDomain().getCodeSource().getLocation());
            if (u.startsWith("jar:")) u = u.substring(4);
            int bang = u.indexOf("!/");
            if (bang >= 0) u = u.substring(0, bang);
            if (u.startsWith("file:")) u = u.substring(5);
            while (u.startsWith("//")) u = u.substring(1);
            return u;
        } catch (Exception e) {
            return "unknown";
        }
    }
    abstract static class Step {
        abstract boolean ok() throws Exception;
    }
    static void step(StringBuilder s, String name, Step step) {
        String r;
        try { r = step.ok() ? "OK" : "DIFF"; } catch (Throwable e) { r = e.getClass().getSimpleName(); }
        s.append("newapi.").append(name).append('=').append(r).append('\n');
    }
%><%
    if (!"127.0.0.1".equals(request.getRemoteAddr())) { response.setStatus(403); out.print("FORBIDDEN"); return; }
    StringBuilder s = new StringBuilder();
    s.append("newapi.where=").append(where(Hmac.class)).append('\n');
    step(s, "aesgcm", new Step() { boolean ok() throws Exception {
        AesGcm g = AesGcm.fromPassphrase(AesKeySize.AES_128, Pbkdf2Algorithm.SHA512, "dummy-newapi-pass".toCharArray(), Pbkdf2.newSalt(), 100000);
        String c = g.encryptText("dummy-newapi", "order:1", Encoding.BASE64_URL);
        return !c.startsWith("ENC[") && "dummy-newapi".equals(g.decryptText(c, "order:1", Encoding.BASE64_URL)); } });
    step(s, "direct", new Step() { boolean ok() throws Exception {
        CredentialCrypto d = CredentialCrypto.fromRawKey("newapi-direct", AesGcm.generateKey(AesKeySize.AES_256));
        String t = d.encryptText("dummy-newapi");
        return t.startsWith("ENC[v1:newapi-direct:") && "dummy-newapi".equals(d.decryptText(t)); } });
    step(s, "hmac", new Step() { boolean ok() {
        Hmac h = Hmac.of(Hmac.generateKey());
        String mac = h.sign("body", Encoding.HEX);
        return h.verify("body", mac, Encoding.HEX) && !h.verify("body2", mac, Encoding.HEX); } });
    step(s, "password", new Step() { boolean ok() {
        String stored = Passwords.hash("dummy-newapi-pw".toCharArray(), Pbkdf2Algorithm.SHA256, 100000);
        return Passwords.verify("dummy-newapi-pw".toCharArray(), stored) && !Passwords.verify("other".toCharArray(), stored); } });
    step(s, "digest", new Step() { boolean ok() {
        return "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".equals(Digests.sha256Hex("abc")); } });
    step(s, "random", new Step() { boolean ok() {
        return SecureRandoms.token().length() == 43 && SecureRandoms.uuidV4().version() == 4; } });
    step(s, "signature", new Step() { boolean ok() {
        KeyPair kp = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256_P1363);
        byte[] sig = Signatures.sign(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, kp.getPrivate(), "msg");
        return sig.length == 64 && Signatures.verify(SignatureAlgorithm.ECDSA_P256_SHA256_P1363, kp.getPublic(), "msg".getBytes(), sig); } });
    step(s, "jwt", new Step() { boolean ok() throws Exception {
        KeyPair kp = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        String token = Jwt.builder().issuer("iss-tomcat").audience("api").expiresIn(Duration.ofMinutes(1)).sign(JwtKey.es256(kp.getPrivate()));
        return "iss-tomcat".equals(JwtVerifier.builder().key(JwtKey.es256(kp.getPublic())).issuer("iss-tomcat").audience("api").build()
                .verify(token).claims().issuer()); } });
    step(s, "access", new Step() { boolean ok() throws Exception {
        KeyPair kp = Signatures.generateRsaKeyPair(2048);
        String at = AccessTokens.builder().issuer("iss-tomcat").subject("u").audience("api").clientId("web").scopes("read")
                .expiresIn(Duration.ofMinutes(1)).sign(JwtKey.rs256(kp.getPrivate()));
        return AccessTokenVerifier.rfc9068().issuer("iss-tomcat").audience("api").key(JwtKey.rs256(kp.getPublic())).requireScopes("read")
                .build().verify(at).hasScope("read"); } });
    step(s, "totp", new Step() { boolean ok() {
        Totp t = Totp.of(Totp.generateSecret());
        Instant now = Instant.now();
        return t.verify(t.generate(now), now, 1).isPresent(); } });
    step(s, "oaep", new Step() { boolean ok() throws Exception {
        KeyPair kp = Signatures.generateRsaKeyPair(2048);
        String c = RsaOaep.encryptText(kp.getPublic(), "dummy-oaep", Encoding.BASE64);
        return "dummy-oaep".equals(RsaOaep.decryptText(kp.getPrivate(), c, Encoding.BASE64)); } });
    step(s, "hybrid", new Step() { boolean ok() throws Exception {
        KeyPair kp = Signatures.generateRsaKeyPair(2048);
        String c = HybridEncryption.encryptText(kp.getPublic(), "dummy-hybrid", "doc:1", Encoding.BASE64_URL);
        return "dummy-hybrid".equals(HybridEncryption.decryptText(kp.getPrivate(), c, "doc:1", Encoding.BASE64_URL)); } });
    out.print(s);
%>
JSP
}
NEWAPI_STEPS="aesgcm direct hmac password digest random signature jwt access totp oaep hybrid"
# newapi_check <컨테이너> <웹앱 경로> <기대 클래스 출처(JAR 경로)>: 범용 보안 API 단계가 모두 OK이고 출처가 기대한 JAR인지
newapi_check() {
  local name="$1" app="$2" where="$3" out st bad=""
  out=$(docker exec "$name" curl -s "http://127.0.0.1:8080/$app/jck-newapi.jsp" < /dev/null)
  printf '%s\n' "$out" | sed "s/^/   $app | /"
  for st in $NEWAPI_STEPS; do grep -qxF "newapi.$st=OK" <<< "$out" || bad="$bad $st"; done
  [ -z "$bad" ]; check $? "[$app] 범용 보안 API(${NEWAPI_STEPS// /·}) 모두 OK${bad:+ (실패:$bad)}"
  grep -qxF "newapi.where=$where" <<< "$out"; check $? "[$app] 범용 보안 API 클래스 출처 = $where"
}
EXP_NAMES=(); EXP_VALUES=()
expect() { EXP_NAMES=(); EXP_VALUES=(); while [ $# -gt 1 ]; do EXP_NAMES+=("$1"); EXP_VALUES+=("$2"); shift 2; done; }
WPUB_RE='공개된 기본 키 사용 중|Published default key in use'
MATRIX="$RES/matrix.txt"; : > "$MATRIX"
# wait_tomcat <컨테이너> <웹앱 경로>: HTTP 응답을 기다린다(0이면 기동). TV에 Tomcat·Java 버전을 넣는다.
wait_tomcat() {
  local name="$1" app="$2" code="" i
  for i in $(seq 1 90); do
    code=$(docker exec "$name" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/$app/jck-qa.jsp?ds=probe" < /dev/null 2> /dev/null)
    case "$code" in 200|403|404|500) break ;; esac
    code=""; sleep 1
  done
  TV=$(docker exec "$name" sh -c 'echo "Tomcat $TOMCAT_VERSION / Java $(java -version 2>&1 | head -1 | cut -d\" -f2)"' < /dev/null 2> /dev/null)
  [ -n "$code" ]
}
# ds_check <컨테이너> <웹앱 경로> <JNDI 이름> <기대: "OK <Pool 클래스>" 또는 "FAIL <포함 문구>">
ds_check() {
  local name="$1" app="$2" ds="$3" exp="$4" out tag=""
  [ "$app" = jck-qa ] || tag="[$app] "
  out=$(docker exec "$name" curl -s "http://127.0.0.1:8080/$app/jck-qa.jsp?ds=$ds" < /dev/null)
  case "$exp" in
    OK\ *) if [[ "$out" == "OK ds=$ds pool=${exp#OK } db=MariaDB result=1" ]]; then pass "$tag$ds → $out"; else fail "$tag$ds: 기대 OK(${exp#OK }) / 실제 ${out:-응답 없음}"; fi ;;
    FAIL\ *) if [[ "$out" == FAIL* && "$out" == *"${exp#FAIL }"* ]]; then pass "$tag$ds → $out"; else fail "$tag$ds: 기대 FAIL(${exp#FAIL }) / 실제 ${out:-응답 없음}"; fi ;;
  esac
}
# insert_check <컨테이너> <웹앱 경로> <JNDI 이름> <실행 ID>: 실제 테이블 SELECT·INSERT(끝에서 MariaDB 행과 대조)
insert_check() {
  local name="$1" app="$2" ds="$3" rid="$4" out tag=""
  [ "$app" = jck-qa ] || tag="[$app] "
  INSERT_RUNS+=("$rid")
  out=$(docker exec "$name" curl -s "http://127.0.0.1:8080/$app/jck-qa.jsp?ds=$ds&run=$rid" < /dev/null)
  if [[ "$out" == "OK ds=$ds pool="*" db=MariaDB result=1 marker=java-crypto-kit-qa user=qa_app@% inserted=1" ]]; then
    pass "$tag$ds 실제 테이블 SELECT·INSERT → $out"
  else fail "$tag$ds 실제 테이블 SELECT·INSERT: 실제 ${out:-응답 없음}"; fi
}
# finish_case <id> <컨테이너> <기대 공개된 기본 키 경고 수 또는 -> <기동(0=기동)>: 로그 검사, 결과 표 기록, 컨테이너 삭제
#   이 라이브러리의 자동 경고는 공개된 기본 키 경고 한 가지뿐이고(그 키는 로딩 단계에서 거부되어 기대값은 0) 그 밖의
#   [java-crypto-kit] WARNING이 있으면 실패로 본다.
finish_case() {
  local id="$1" name="$2" warn="$3" up="$4" logs leaks cmdline wpub wother fakes result=PASS
  logs=$(docker logs "$name" 2>&1)
  leaks=$(printf '%s\n' "$logs" | grep -v 'Command line argument:' | grep -cFf "$SECRETS")
  cmdline=$(printf '%s\n' "$logs" | grep 'Command line argument:' | grep -cFf "$SECRETS")
  wpub=$(printf '%s\n' "$logs" | grep -cE "$WPUB_RE")
  # 공개된 기본 키 경고 외의 이 라이브러리 정책성 WARNING(JULI 형식 "WARNING ... [java-crypto-kit]") 줄 수.
  # 사유 코드가 붙은 줄은 실제 오류 보고이므로 세지 않는다.
  wother=$(printf '%s\n' "$logs" | grep -E 'WARNING.*\[java-crypto-kit\]' | grep -vE "$WPUB_RE" | grep -cvE '\[(사유|reason): ')
  fakes=$(printf '%s\n' "$logs" | grep -c FAKE_POOL_FACTORY_CALLED)
  [ "$leaks" = 0 ]; check $? "Tomcat 로그의 비밀값(평문·키·Passphrase·토큰·암호문) 노출 ${leaks}건"
  [ "$cmdline" != 0 ] && echo "   참고: Tomcat 자체 'Command line argument' 로그에 -D 값 ${cmdline}줄(키 원문 -D를 금지하는 이유)"
  if [ "$warn" != "-" ]; then
    [ "$wpub" = "$warn" ]; check $? "공개된 기본 키 경고 = ${wpub}건 (기대 $warn)"
    [ "$wother" = 0 ]; check $? "그 밖의 라이브러리 정책 WARNING ${wother}건"
  fi
  if [ -n "${EXTRA_CLASSES:-}" ]; then [ "$fakes" = 0 ]; check $? "웹앱의 같은 이름 가짜 Pool Factory 호출 ${fakes}건"; fi
  if [ "$leaks" = 0 ]; then printf '%s\n' "$logs" | grep -F '[java-crypto-kit]' > "$RES/tomcat-logs/$id.txt"
  else echo "비밀값 노출이 발견되어 로그를 저장하지 않음" > "$RES/tomcat-logs/$id.txt"; fi
  { [ "$up" = 0 ] && [ "${#FAILS[@]}" -le "$CASE_BEFORE" ]; } || result=FAIL
  echo "$id | $TV | $result" >> "$MATRIX"
  docker rm -f -v "$name" > /dev/null 2>&1
  unset EXTRA_CLASSES SERVER_XML SETENV RUN_DS
}
# run_case <id> <image> <jar> <context.xml Resource들> <기대 공개된 기본 키 경고 수(0) 또는 -> [docker create 옵션...]
#   선택 변수: EXTRA_CLASSES(웹앱 WEB-INF/classes에 넣을 폴더), SERVER_XML, SETENV,
#             RUN_DS(실제 테이블 SELECT·INSERT로 확인할 JNDI 이름, 여러 개면 공백으로 구분)
run_case() {
  local id="$1" image="$2" jar="$3" resources="$4" warn="$5"; shift 5
  CASE="$id"; CASE_BEFORE=${#FAILS[@]}
  local name="$P-tc-$id" app="$WORK/runs/$id" k rds n=0 up=0
  rm -rf "$app"; mkdir -p "$app/META-INF"
  write_jsp "$app"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<Context>\n%s\n</Context>\n' "$resources" > "$app/META-INF/context.xml"
  [ -n "${EXTRA_CLASSES:-}" ] && { mkdir -p "$app/WEB-INF/classes"; cp -r "$EXTRA_CLASSES"/. "$app/WEB-INF/classes/"; }
  docker create --name "$name" "${LABELS[@]}" --network "$NET" "$@" "$image" > /dev/null || { fail "컨테이너 생성 실패"; return; }
  docker cp "$(hostpath "$jar")" "$name:/usr/local/tomcat/lib/java-crypto-kit.jar" > /dev/null
  docker cp "$(hostpath "$DRIVER")" "$name:/usr/local/tomcat/lib/mariadb-java-client.jar" > /dev/null
  docker cp "$(hostpath "$app")" "$name:/usr/local/tomcat/webapps/jck-qa" > /dev/null
  docker cp "$WORKH/secure" "$name:/opt/java-crypto-kit" > /dev/null
  [ -n "${SERVER_XML:-}" ] && docker cp "$(hostpath "$SERVER_XML")" "$name:/usr/local/tomcat/conf/server.xml" > /dev/null
  [ -n "${SETENV:-}" ] && docker cp "$(hostpath "$SETENV")" "$name:/usr/local/tomcat/bin/setenv.sh" > /dev/null
  docker start "$name" > /dev/null
  wait_tomcat "$name" jck-qa || up=1
  echo "--- [$id] $TV, JAR=$(basename "$jar")"
  check $up "Tomcat 기동"
  for k in "${!EXP_NAMES[@]}"; do ds_check "$name" jck-qa "${EXP_NAMES[$k]}" "${EXP_VALUES[$k]}"; done
  for rds in ${RUN_DS:-}; do n=$((n + 1)); insert_check "$name" jck-qa "$rds" "$id.$n"; done
  finish_case "$id" "$name" "$warn" "$up"
}

section "4. Tomcat 8.5/9.0/10.1/11.0 × DBCP2/Tomcat JDBC Pool - 키 내장 JAR만(-D·외부 Properties 없음), 한 JVM의 pass·key"
matrix_resources() { # <Pool 속성>
  res jdbc/qa "$CORP_PW" "$1"; res jdbc/qaPass "$CORP_PASS_PW" "$1"; res jdbc/qaEncUser "$CORP_PW" "$1" "$CORP_USER"
  res jdbc/qaB64 "$CORP_B64" "$1"; res jdbc/qaRekeyed "$REKEY_PW" "$1"; res jdbc/qaRekeyedPass "$REKEY_PASS" "$1"
  res jdbc/qaForeign "$FOREIGN" "$1"; res jdbc/qaForged "$FORGED" "$1"; res jdbc/qaTampered "$TAMPERED" "$1"
  res jdbc/qaPlain "$PLAINPW" "$1"; res jdbc/qaWrongDbPw "$CORP_WRONG" "$1"; res jdbc/qaNoFactory "$CORP_PW" "$1" qa_app ""
}
matrix_expect() { # <Pool 클래스> <오류 메시지의 Pool 이름>
  expect jdbc/qa "OK $1" jdbc/qaPass "OK $1" jdbc/qaEncUser "OK $1" jdbc/qaB64 "OK $1" \
    jdbc/qaRekeyed "OK $1" jdbc/qaRekeyedPass "OK $1" jdbc/qaForeign "FAIL [사유: KEY_ID_MISMATCH]" \
    jdbc/qaForged "FAIL [사유: INTEGRITY]" jdbc/qaTampered "FAIL [사유: INTEGRITY]" jdbc/qaPlain "FAIL [사유: PLAINTEXT_PASSWORD]" \
    jdbc/qaWrongDbPw "FAIL [사유: POOL_FAILURE] Connection Pool($2) 생성에 실패했습니다" jdbc/qaNoFactory "FAIL ds=jdbc/qaNoFactory"
}
for image in "$T85" "$T90" "$T101" "$T110"; do
  v=$(echo "$image" | cut -d: -f2 | cut -d- -f1)
  matrix_expect "$POOL_D" DBCP2; RUN_DS="jdbc/qa jdbc/qaPass"
  run_case "M-$v-dbcp2" "$image" "$WORK/jars/company.jar" "$(matrix_resources "$ATTR_D")" 0
  matrix_expect "$POOL_T" "Tomcat JDBC Pool"; RUN_DS="jdbc/qa jdbc/qaPass"
  run_case "M-$v-tomcat-jdbc" "$image" "$WORK/jars/company-tj.jar" "$(matrix_resources "$ATTR_T")" 0
done

section "5. 설정 우선순위(JVM -D > 외부 Properties > JAR 내부) · 키 공급 · 오류·보안"
COMP="$WORK/jars/company.jar"; COMPTJ="$WORK/jars/company-tj.jar"; PUB="$WORK/jars/public.jar"
R_EXT="$(res jdbc/qaExt "$EXT_PW" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")"
R_QA="$(res jdbc/qa "$CORP_PW" "$ATTR_X")"
R_PUB="$(res jdbc/qaPublic "$PUB_PW" "$ATTR_X")
$(res jdbc/qaPublicKey "$PUB_KEY" "$ATTR_X")"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"
run_case E01-external-by-jvm-property "$T101" "$COMP" "$R_EXT" 0 -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/ext-file.properties"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"
run_case E02-external-by-env-var-tomcat8.5 "$T85" "$COMP" "$R_EXT" 0 -e "CRYPTO_CONFIG_FILE=/opt/java-crypto-kit/ext-file.properties"
expect jdbc/qa "OK $POOL_D"
run_case E03-external-over-jar "$T101" "$COMPTJ" "$R_QA" 0 -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2.properties"
expect jdbc/qa "OK $POOL_T"
run_case E04-jvm-over-external "$T101" "$COMPTJ" "$R_QA" 0 \
  -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2.properties -Dcrypto.pool.factory=$TJF"
expect jdbc/qa "OK $POOL_D"
run_case E05-jvm-override-disabled "$T101" "$COMPTJ" "$R_QA" 0 \
  -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2-locked.properties -Dcrypto.pool.factory=$TJF -Dcrypto.jvm.override.enabled=true"
printf '%s\n' 'CATALINA_OPTS="$CATALINA_OPTS -Dcrypto.key.source=file -Dcrypto.key.file=/opt/java-crypto-kit/ext01.key -Dcrypto.key.id=ext01"' 'export CATALINA_OPTS' > "$WORK/setenv.sh"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"; SETENV="$WORK/setenv.sh"
run_case E06-jvm-only-file-key-setenv-tomcat9 "$T90" "$COMP" "$R_EXT" 0
expect jdbc/qaEnv "OK $POOL_D"
run_case E07-env-key-tomcat11 "$T110" "$COMP" "$(res jdbc/qaEnv "$ENV_PW" "$ATTR_X")" 0 -e QA_ENV_KEY \
  -e "CATALINA_OPTS=-Dcrypto.key.source=env -Dcrypto.key.env=QA_ENV_KEY -Dcrypto.key.id=env01"
expect jdbc/qa "OK $POOL_D" jdbc/qaForeign "FAIL [reason: KEY_ID_MISMATCH]"
run_case E08-lang-en "$T101" "$COMP" "$(res jdbc/qa "$CORP_PW" "$ATTR_X")
$(res jdbc/qaForeign "$FOREIGN" "$ATTR_X")" 0 -e "CATALINA_OPTS=-Dcrypto.lang=en"
# 경고 끄기: 최초 등록한 두 키 암호문을 써도 경고 0건, 연결은 정상
expect jdbc/qaPublic "OK $POOL_D" jdbc/qaPublicKey "OK $POOL_D"
run_case E09-warning-off "$T101" "$WORK/jars/initial.jar" "$R_PUB" 0 -e "CATALINA_OPTS=-Dcrypto.warning.enabled=false"
# 빌드 JAR 그대로(관리자·PASS·KEY 미설정)를 Tomcat lib에 넣으면 키가 없어 모든 Resource가 CONFIGURATION(공개 키로 대체하지 않음)
expect jdbc/qaPublic "FAIL [사유: CONFIGURATION]" jdbc/qaPublicKey "FAIL [사유: CONFIGURATION]" jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E10-public-jar "$T101" "$PUB" "$R_PUB
$(res jdbc/qa "$CORP_PW" "$ATTR_X")" 0
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E11-raw-key-by-jvm-rejected "$T101" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.key.embedded=$RAWDUMMY"
expect jdbc/qaExt "FAIL [사유: KEY_SOURCE]" jdbc/qa "FAIL ds=jdbc/qa "
run_case E12-missing-key-fail-closed "$T101" "$COMP" "$R_EXT" - -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/missing-key.properties"
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E13-jvm-typo-fail-closed "$T110" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.key.soruce=file"
expect jdbc/qa "OK $POOL_D"
run_case E14-unrelated-crypto-policy "$T90" "$COMP" "$R_QA" 0 -e "CATALINA_OPTS=-Dcrypto.policy=unlimited"
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E15-external-typo-rejected "$T101" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/typo.properties"
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E16-blank-config-path "$T101" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.config.file="

# 웹앱(WEB-INF/classes)에 공식 Pool과 같은 이름의 가짜 Factory를 넣어도 이 라이브러리를 로딩한 클래스로더의 공식 Pool만 쓴다.
for spec in "org.apache.tomcat.dbcp.dbcp2 BasicDataSourceFactory" "org.apache.tomcat.jdbc.pool DataSourceFactory"; do
  set -- $spec
  mkdir -p "$WORK/fake-src/$(echo "$1" | tr . /)"
  cat > "$WORK/fake-src/$(echo "$1" | tr . /)/$2.java" << FAKE
package $1;
/** 시험용 가짜 Factory: 호출되면 표시만 남긴다(비밀번호 값은 출력하지 않음). */
public class $2 implements javax.naming.spi.ObjectFactory {
    @Override
    public Object getObjectInstance(Object obj, javax.naming.Name name, javax.naming.Context ctx, java.util.Hashtable<?, ?> env) {
        System.out.println("FAKE_POOL_FACTORY_CALLED $2");
        return null;
    }
}
FAKE
done
docker cp "$WORKH/fake-src" "$WB:/w/fake-src" > /dev/null
wb sh -c 'mkdir -p /w/fake-classes && javac --release 8 -nowarn -d /w/fake-classes $(find /w/fake-src -name "*.java")' > /dev/null 2>&1
docker cp "$WB:/w/fake-classes" "$WORKH/fake-classes" > /dev/null; CASE=fake-factory
[ -f "$WORK/fake-classes/org/apache/tomcat/jdbc/pool/DataSourceFactory.class" ]; check $? "시험용 가짜 Pool Factory 컴파일"
for image in "$T85" "$T110"; do
  v=$(echo "$image" | cut -d: -f2 | cut -d- -f1)
  expect jdbc/qa "OK $POOL_D"; EXTRA_CLASSES="$WORK/fake-classes"
  run_case "E17-trust-$v-dbcp2" "$image" "$COMP" "$(res jdbc/qa "$CORP_PW" "$ATTR_D")" 0
  expect jdbc/qa "OK $POOL_T"; EXTRA_CLASSES="$WORK/fake-classes"
  run_case "E17-trust-$v-tomcat-jdbc" "$image" "$COMPTJ" "$(res jdbc/qa "$CORP_PW" "$ATTR_T")" 0
done

# server.xml GlobalNamingResources + ResourceLink
for spec in "$T101|$COMP|$POOL_D|$ATTR_D" "$T85|$COMPTJ|$POOL_T|$ATTR_T"; do
  IFS='|' read -r image jar pool attr <<< "$spec"; v=$(echo "$image" | cut -d: -f2 | cut -d- -f1)
  sx="$WORK/server-$v.xml"
  docker run --rm "${LABELS[@]}" --network none --entrypoint cat "$image" /usr/local/tomcat/conf/server.xml > "$sx.orig"
  awk -v line="$(res jdbc/qaGlobal "$CORP_PW" "$attr")" '{print} /<GlobalNamingResources>/{print line}' "$sx.orig" > "$sx"
  expect jdbc/linked "OK $pool"; SERVER_XML="$sx"
  run_case "E18-global-resource-link-$v" "$image" "$jar" '  <ResourceLink name="jdbc/linked" global="jdbc/qaGlobal" type="javax.sql.DataSource"/>' 0
done

# embed-key·key add 뒤에도 최초 설정 키는 키 목록에 남아(자동 삭제 없음) 그 키 암호문이 계속 연결된다(경고 0건).
expect jdbc/qaPublic "OK $POOL_D" jdbc/qaPublicKey "OK $POOL_D" jdbc/qaRekeyedX "OK $POOL_D" jdbc/qa "OK $POOL_D"
run_case E19-company-jar-public-tokens-tomcat9 "$T90" "$COMP" "$R_PUB
$(res jdbc/qaRekeyedX "$REKEY_X" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")" 0
# config key remove로 최초 설정 키를 뺀 JAR: 그 키 암호문은 KEY_ID_MISMATCH, 사용자 지정 pass·key 키는 정상, 경고 0건
expect jdbc/qaPublic "FAIL [사유: KEY_ID_MISMATCH]" jdbc/qaPublicKey "FAIL [사유: KEY_ID_MISMATCH]" jdbc/qa "OK $POOL_D" jdbc/qaPass "OK $POOL_D"
run_case E20-public-keys-removed-tomcat11 "$T110" "$WORK/jars/company-hardened.jar" "$R_PUB
$(res jdbc/qa "$CORP_PW" "$ATTR_X")
$(res jdbc/qaPass "$CORP_PASS_PW" "$ATTR_X")" 0
# pass 파일 키(지문 고정): Java 8 Tomcat이 파일의 한글·이모지 Passphrase로 PBKDF2 파생한 키가 JDK 21에서 고정한 지문과 같아야 연결된다.
expect jdbc/qaPfile "OK $POOL_D" jdbc/qa "OK $POOL_D"
run_case E21-pass-file-key-jdk8-tomcat9 "$T90" "$WORK/jars/company-pfile.jar" "$(res jdbc/qaPfile "$PFILE_PW" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")" 0
# -D로 위치 항목만 바꿔 다른 Passphrase 파일을 가리키면 그 키만 KEY_SOURCE(같은 키 ID로 다른 키를 조용히 받지 않음), 다른 키는 정상
expect jdbc/qaPfile "FAIL [사유: KEY_SOURCE]" jdbc/qa "OK $POOL_D"
run_case E22-pass-file-pin-mismatch "$T101" "$WORK/jars/company-pfile.jar" "$(res jdbc/qaPfile "$PFILE_PW" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")" 0 -e "CATALINA_OPTS=-Dcrypto.keys.corp-pfile.file=/opt/java-crypto-kit/other.pass"
# CLI 관리자 검증값이 손상된 JAR(CLI는 INTEGRITY로 거부, 1장): Tomcat JNDI는 검증값을 읽지 않으므로 pass·key 모두 그대로 연결
expect jdbc/qa "OK $POOL_D" jdbc/qaPass "OK $POOL_D"
run_case E23-admin-damaged-jar-tomcat10.1 "$T101" "$WORK/jars/company-admin-damaged.jar" "$R_QA
$(res jdbc/qaPass "$CORP_PASS_PW" "$ATTR_X")" 0

if [ -n "$LEGACY_JAR" ]; then
  CASE=legacy
  docker cp "$(hostpath "$LEGACY_JAR")" "$WB:/w/jars/legacy.jar" > /dev/null
  lg=$(wb sh -c "sha256sum /w/jars/legacy.jar
    java -jar /w/jars/initial.jar config set crypto.lang=en --operator qa --jar /w/jars/legacy.jar $ADM
    echo rc=\$?
    sha256sum /w/jars/legacy.jar" 2>&1)
  grep -q '^rc=1$' <<< "$lg" &&
    [ "$(grep -E '^[0-9a-f]{64} ' <<< "$lg" | sort -u | wc -l | tr -d ' ')" = 1 ]
  check $? "예약 영역 없는 이전 바이너리를 그대로 보존하고 직접 갱신 거부"
fi

section "6. 이중 배포: Tomcat lib의 JAR A(인프라) + 웹앱 WEB-INF/lib의 JAR B(업무) - 키·Pool 설정이 다른 두 JAR"
# run_dual <id> <image> <JAR A(Tomcat lib)> <JAR B(dual 웹앱 WEB-INF/lib)> <dual Resource들> <plain Resource들>
#          <Global Resource(server.xml)> <conf/context.xml Resource(빈 값이면 없음)> [docker create 옵션...]
#   웹앱 dual(JAR B 포함)과 plain(JAR 없음, Tomcat lib의 JAR A만 보임)을 한 Tomcat에 함께 배포한다.
#   변수: DEXP("웹앱|JNDI 이름|기대" 줄), DAPI("웹앱|jck-dual.jsp 출력 줄", 그 줄이 그대로 있어야 함),
#         DRUN("웹앱|JNDI 이름" 줄, 실제 테이블 SELECT·INSERT), DWARN(공개된 기본 키 경고 기대 수, 기본 0)
run_dual() {
  local id="$1" image="$2" jara="$3" jarb="$4" rdual="$5" rplain="$6" rglobal="$7" rshared="$8"; shift 8
  CASE="$id"; CASE_BEFORE=${#FAILS[@]}
  local name="$P-tc-$id" base="$WORK/runs/$id" a app ds exp line got n=0 up=0 api_dual api_plain
  rm -rf "$base"; mkdir -p "$base/dual/META-INF" "$base/dual/WEB-INF/lib" "$base/plain/META-INF"
  for a in dual plain; do write_jsp "$base/$a"; write_dual_jsp "$base/$a"; write_newapi_jsp "$base/$a"; done
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<Context>\n%s\n</Context>\n' "$rdual" > "$base/dual/META-INF/context.xml"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<Context>\n%s\n</Context>\n' "$rplain" > "$base/plain/META-INF/context.xml"
  cp "$jarb" "$base/dual/WEB-INF/lib/java-crypto-kit.jar"
  docker run --rm "${LABELS[@]}" --network none --entrypoint cat "$image" /usr/local/tomcat/conf/server.xml > "$base/server.xml.orig"
  docker run --rm "${LABELS[@]}" --network none --entrypoint cat "$image" /usr/local/tomcat/conf/context.xml > "$base/context.xml.orig"
  awk -v line="$rglobal" '{print} /<GlobalNamingResources>/{print line}' "$base/server.xml.orig" > "$base/server.xml"
  awk -v line="$rshared" '{print} /^<Context>/{print line}' "$base/context.xml.orig" > "$base/context.xml"
  [ "$(grep -c "factory=\"$NEWF\"" "$base/server.xml")" = 1 ] \
    && [ "$(grep -c "factory=\"$NEWF\"" "$base/context.xml")" = "$([ -n "$rshared" ] && echo 1 || echo 0)" ]
  check $? "server.xml GlobalNamingResources·conf/context.xml에 시험 Resource 추가"
  docker create --name "$name" "${LABELS[@]}" --network "$NET" "$@" "$image" > /dev/null || { fail "컨테이너 생성 실패"; return; }
  docker cp "$(hostpath "$jara")" "$name:/usr/local/tomcat/lib/java-crypto-kit.jar" > /dev/null
  docker cp "$(hostpath "$DRIVER")" "$name:/usr/local/tomcat/lib/mariadb-java-client.jar" > /dev/null
  docker cp "$(hostpath "$base/dual")" "$name:/usr/local/tomcat/webapps/dual" > /dev/null
  docker cp "$(hostpath "$base/plain")" "$name:/usr/local/tomcat/webapps/plain" > /dev/null
  docker cp "$WORKH/secure" "$name:/opt/java-crypto-kit" > /dev/null
  docker cp "$(hostpath "$base/server.xml")" "$name:/usr/local/tomcat/conf/server.xml" > /dev/null
  docker cp "$(hostpath "$base/context.xml")" "$name:/usr/local/tomcat/conf/context.xml" > /dev/null
  docker start "$name" > /dev/null
  { wait_tomcat "$name" dual && wait_tomcat "$name" plain; } || up=1
  echo "--- [$id] $TV, JAR A(lib)=$(basename "$jara"), JAR B(dual/WEB-INF/lib)=$(basename "$jarb")"
  check $up "Tomcat 기동(웹앱 dual·plain)"
  while IFS='|' read -r app ds exp; do [ -n "$app" ] && ds_check "$name" "$app" "$ds" "$exp"; done <<< "${DEXP:-}"
  api_dual=$(docker exec "$name" curl -s "http://127.0.0.1:8080/dual/jck-dual.jsp" < /dev/null)
  api_plain=$(docker exec "$name" curl -s "http://127.0.0.1:8080/plain/jck-dual.jsp" < /dev/null)
  printf '%s\n' "$api_dual" | sed 's/^/   dual  | /'; printf '%s\n' "$api_plain" | sed 's/^/   plain | /'
  while IFS='|' read -r app line; do
    [ -n "$app" ] || continue
    got="$api_dual"; [ "$app" = plain ] && got="$api_plain"
    if grep -qxF -- "$line" <<< "$got"; then pass "[$app API] $line"
    else fail "[$app API] 기대 '$line' / 실제 '$(grep -F -- "${line%%=*}=" <<< "$got" | head -1)'"; fi
  done <<< "${DAPI:-}"
  # 범용 보안 API: dual은 WEB-INF/lib의 JAR B, plain은 Tomcat lib의 JAR A가 제공한다. 호출 뒤 JAR A 파일·키 목록·지문 불변.
  local lib_before lib_after api_after
  lib_before=$(docker exec "$name" sha256sum "$L_LIB" < /dev/null 2> /dev/null | cut -c1-64)
  newapi_check "$name" dual "$L_APP"
  newapi_check "$name" plain "$L_LIB"
  api_after=$(docker exec "$name" curl -s "http://127.0.0.1:8080/dual/jck-dual.jsp" < /dev/null)
  lib_after=$(docker exec "$name" sha256sum "$L_LIB" < /dev/null 2> /dev/null | cut -c1-64)
  [ -n "$lib_before" ] && [ "$lib_before" = "$lib_after" ] \
    && [ "$(grep -E '^lib\.(load|default|keys|fp\.)' <<< "$api_dual")" = "$(grep -E '^lib\.(load|default|keys|fp\.)' <<< "$api_after")" ]
  check $? "범용 보안 API 호출 뒤 JAR A(Tomcat lib) 파일 SHA-256·키 목록·지문 그대로"
  while IFS='|' read -r app ds; do
    [ -n "$app" ] || continue
    n=$((n + 1)); insert_check "$name" "$app" "$ds" "$id.$n"
  done <<< "${DRUN:-}"
  finish_case "$id" "$name" "${DWARN:-0}" "$up"
  unset DEXP DAPI DRUN DWARN
}
CASE=dual-prepare
INITIAL_PASS_SHORT=$(short "$INITIAL_PASS_FP")
printf 'INFRA_PASS=%s\nINFRA_KEY=%s\nBIZ_PASS=%s\nBIZ_KEY=%s\nSHARED=%s\n' \
  "$INFRA_PASS_PW" "$INFRA_KEY_PW" "$BIZ_PASS_PW" "$BIZ_KEY_PW" "$SHARED_PW" > "$WORK/secure/dual-tokens.properties"
SP_IK=$(short "$FP_INFRA_KEY"); SP_IP=$(short "$FP_INFRA_PASS"); SP_BK=$(short "$FP_BIZ_KEY"); SP_BP=$(short "$FP_BIZ_PASS"); SP_SH=$(short "$FP_SHARED")
L_APP=/usr/local/tomcat/webapps/dual/WEB-INF/lib/java-crypto-kit.jar; L_LIB=/usr/local/tomcat/lib/java-crypto-kit.jar
LINK='  <ResourceLink name="jdbc/linkInfra" global="jdbc/gInfra" type="javax.sql.DataSource"/>'
GLOBAL="$(res jdbc/gInfra "$INFRA_PASS_PW" "$ATTR_X")"
SHARED_RES="$(res jdbc/shared "$INFRA_KEY_PW" "$ATTR_X")"
R_DUAL="$(res jdbc/ctxBiz "$BIZ_PASS_PW" "$ATTR_X")
$(res jdbc/ctxBizKey "$BIZ_KEY_PW" "$ATTR_X")
$(res jdbc/ctxInfra "$INFRA_PASS_PW" "$ATTR_X")
$LINK"
R_PLAIN="$(res jdbc/ctxInfra "$INFRA_PASS_PW" "$ATTR_X")
$(res jdbc/ctxBiz "$BIZ_PASS_PW" "$ATTR_X")
$LINK"
# D01·D02 공통 기대 <JAR A의 Pool 클래스> <JAR B의 Pool 클래스>:
#   Global Resource는 Tomcat 기동 시 lib의 JAR A가, 웹앱 Context Resource와 conf/context.xml Resource는 그 웹앱의
#   클래스로더가 찾은 Factory(dual은 WEB-INF/lib의 JAR B, plain은 lib의 JAR A)가 만든다. Pool 종류와 키로 판정한다.
dual_expect() {
  DEXP="dual|jdbc/ctxBiz|OK $2
dual|jdbc/ctxBizKey|OK $2
dual|jdbc/ctxInfra|FAIL [사유: KEY_ID_MISMATCH]
dual|jdbc/linkInfra|OK $1
dual|jdbc/shared|FAIL [사유: KEY_ID_MISMATCH]
plain|jdbc/ctxInfra|OK $1
plain|jdbc/ctxBiz|FAIL [사유: KEY_ID_MISMATCH]
plain|jdbc/linkInfra|OK $1
plain|jdbc/shared|OK $1"
  DAPI="dual|factory.app=$L_APP
dual|factory.lib=$L_LIB
dual|same.class=false
dual|app.api=$L_APP
dual|lib.api=$L_LIB
dual|app.load=OK
dual|lib.load=OK
dual|app.default=biz-pass
dual|lib.default=infra-pass
dual|app.keys=$(printf '%s\n' biz-key biz-pass "$INITIAL_AES" "$INITIAL_PASS" | LC_ALL=C sort | paste -sd, -)
dual|lib.keys=$(printf '%s\n' infra-key infra-pass "$INITIAL_AES" "$INITIAL_PASS" | LC_ALL=C sort | paste -sd, -)
dual|app.fp.biz-key=$SP_BK
dual|app.fp.biz-pass=$SP_BP
dual|lib.fp.infra-key=$SP_IK
dual|lib.fp.infra-pass=$SP_IP
dual|app.fp.$INITIAL_PASS=$INITIAL_PASS_SHORT
dual|lib.fp.$INITIAL_PASS=$INITIAL_PASS_SHORT
dual|app.dec.BIZ_KEY=OK
dual|app.dec.BIZ_PASS=OK
dual|app.dec.INFRA_KEY=KEY_ID_MISMATCH
dual|app.dec.INFRA_PASS=KEY_ID_MISMATCH
dual|app.dec.SHARED=KEY_ID_MISMATCH
dual|lib.dec.BIZ_KEY=KEY_ID_MISMATCH
dual|lib.dec.BIZ_PASS=KEY_ID_MISMATCH
dual|lib.dec.INFRA_KEY=OK
dual|lib.dec.INFRA_PASS=OK
dual|lib.dec.SHARED=KEY_ID_MISMATCH
dual|app.enc=biz-pass
dual|app.encKey=biz-key
dual|lib.enc=infra-pass
dual|lib.encKey=infra-key
dual|app.file=OK
dual|lib.file=OK
dual|app.fileFrom.lib=KEY_ID_MISMATCH
dual|lib.fileFrom.app=KEY_ID_MISMATCH
plain|factory.app=$L_LIB
plain|same.class=true
plain|app.api=$L_LIB
plain|app.default=infra-pass
plain|app.dec.INFRA_PASS=OK
plain|app.dec.BIZ_PASS=KEY_ID_MISMATCH
plain|app.file=OK
plain|app.fileFrom.lib=OK"
  DRUN="dual|jdbc/ctxBiz
dual|jdbc/linkInfra
plain|jdbc/ctxInfra"
}
dual_expect "$POOL_D" "$POOL_T"
run_dual D01-dual-tomcat9-libDBCP2-appJDBCPool "$T90" "$WORK/jars/infra.jar" "$WORK/jars/biz-tj.jar" "$R_DUAL" "$R_PLAIN" "$GLOBAL" "$SHARED_RES"
# D02는 최초 설정 키 암호문 Resource를 두 웹앱에 하나씩 더 둔다: 두 라이브러리 사본(클래스로더) 모두 그 키 ID로 복호화하고 경고는 0건이다.
dual_expect "$POOL_T" "$POOL_D"
DEXP="$DEXP
dual|jdbc/ctxPublic|OK $POOL_D
plain|jdbc/ctxPublic|OK $POOL_T"
run_dual D02-dual-tomcat11-libJDBCPool-appDBCP2 "$T110" "$WORK/jars/infra-tj.jar" "$WORK/jars/biz.jar" "$R_DUAL
$(res jdbc/ctxPublic "$PUB_PW" "$ATTR_X")" "$R_PLAIN
$(res jdbc/ctxPublic "$PUB_PW" "$ATTR_X")" "$GLOBAL" "$SHARED_RES"
# D03: JVM 전체에 걸리는 -D는 두 JAR 모두에 적용된다. JAR A에만 맞는 값(-Dcrypto.key.active.pass=infra-pass)이면
#      JAR B는 설정 로딩부터 CONFIGURATION으로 실패한다(다른 키로 바꾸지 않음). JAR A는 정상.
DEXP="dual|jdbc/ctxBiz|FAIL [사유: CONFIGURATION]
dual|jdbc/linkInfra|OK $POOL_D
plain|jdbc/ctxInfra|OK $POOL_D"
DAPI="dual|app.load=CONFIGURATION
dual|lib.load=OK
dual|lib.default=infra-pass"
run_dual D03-dual-common-jvm-option "$T90" "$WORK/jars/infra.jar" "$WORK/jars/biz-tj.jar" "$R_DUAL" "$R_PLAIN" "$GLOBAL" "" \
  -e "CATALINA_OPTS=-Dcrypto.key.active.pass=infra-pass"
# D04: CRYPTO_CONFIG_FILE(JVM 전체 환경변수)의 외부 설정이 레거시 AES 슬롯(crypto.key.*)을 바꾸면 두 JAR 모두 같은 AES 키
#      shared01을 쓰게 된다(교차 복호화가 가능해짐). 각 JAR의 원래 AES 키는 빠지고, pass 키(키 목록)는 각자 그대로다.
R_DUAL4="$(res jdbc/ctxBiz "$BIZ_PASS_PW" "$ATTR_X")
$(res jdbc/ctxBizKey "$BIZ_KEY_PW" "$ATTR_X")
$(res jdbc/ctxShared "$SHARED_PW" "$ATTR_X")
$LINK"
R_PLAIN4="$(res jdbc/ctxShared "$SHARED_PW" "$ATTR_X")
$(res jdbc/ctxInfraKey "$INFRA_KEY_PW" "$ATTR_X")"
DEXP="dual|jdbc/ctxBiz|OK $POOL_D
dual|jdbc/ctxBizKey|FAIL [사유: KEY_ID_MISMATCH]
dual|jdbc/ctxShared|OK $POOL_D
dual|jdbc/linkInfra|OK $POOL_T
plain|jdbc/ctxShared|OK $POOL_T
plain|jdbc/ctxInfraKey|FAIL [사유: KEY_ID_MISMATCH]"
DAPI="dual|app.keys=$(printf '%s\n' biz-pass shared01 "$INITIAL_AES" "$INITIAL_PASS" | LC_ALL=C sort | paste -sd, -)
dual|lib.keys=$(printf '%s\n' infra-pass shared01 "$INITIAL_AES" "$INITIAL_PASS" | LC_ALL=C sort | paste -sd, -)
dual|app.fp.shared01=$SP_SH
dual|lib.fp.shared01=$SP_SH
dual|app.dec.SHARED=OK
dual|lib.dec.SHARED=OK
dual|app.encKey=shared01
dual|lib.encKey=shared01
dual|app.dec.BIZ_KEY=KEY_ID_MISMATCH
dual|lib.dec.INFRA_KEY=KEY_ID_MISMATCH
dual|app.dec.BIZ_PASS=OK
dual|lib.dec.BIZ_PASS=KEY_ID_MISMATCH"
run_dual D04-dual-common-config-env "$T110" "$WORK/jars/infra-tj.jar" "$WORK/jars/biz.jar" "$R_DUAL4" "$R_PLAIN4" "$GLOBAL" "" \
  -e CRYPTO_CONFIG_FILE=/opt/java-crypto-kit/shared-slot.properties
# D05: D03과 같은 JVM 공통 -D를 JAR B 쪽에서 피한다. JAR B에 crypto.jvm.override.enabled=false를 넣으면(JAR의 정책은 -D로
#      되돌릴 수 없음) JAR B는 그 -D를 무시하고 자기 기본 키(biz-pass)로 동작한다. JAR A는 -D를 그대로 따른다.
DEXP="dual|jdbc/ctxBiz|OK $POOL_T
dual|jdbc/ctxBizKey|OK $POOL_T
dual|jdbc/linkInfra|OK $POOL_D
plain|jdbc/ctxInfra|OK $POOL_D"
DAPI="dual|app.load=OK
dual|app.default=biz-pass
dual|lib.load=OK
dual|lib.default=infra-pass
dual|app.file=OK
dual|lib.file=OK
dual|lib.fileFrom.app=KEY_ID_MISMATCH"
DRUN="dual|jdbc/ctxBiz"
run_dual D05-dual-jvm-option-avoided "$T90" "$WORK/jars/infra.jar" "$WORK/jars/biz-locked.jar" "$R_DUAL" "$R_PLAIN" "$GLOBAL" "" \
  -e "CATALINA_OPTS=-Dcrypto.key.active.pass=infra-pass"

# W01: 웹앱 WEB-INF/lib에만 JAR B를 넣고 Tomcat lib에는 java-crypto-kit이 없다(WAS 공통 설치 요구 없음).
#      Context Resource는 웹앱 클래스로더의 Factory(JAR B)가 만들고, 관리형 API·범용 보안 API도 JAR B에서 온다.
run_webinf_only() { # <id> <image> <JAR B> <Context Resource들>
  local id="$1" image="$2" jarb="$3" rdual="$4"
  CASE="$id"; CASE_BEFORE=${#FAILS[@]}
  local name="$P-tc-$id" base="$WORK/runs/$id" up=0 api libcount
  rm -rf "$base"; mkdir -p "$base/dual/META-INF" "$base/dual/WEB-INF/lib"
  write_jsp "$base/dual"; write_dual_jsp "$base/dual"; write_newapi_jsp "$base/dual"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<Context>\n%s\n</Context>\n' "$rdual" > "$base/dual/META-INF/context.xml"
  cp "$jarb" "$base/dual/WEB-INF/lib/java-crypto-kit.jar"
  docker create --name "$name" "${LABELS[@]}" --network "$NET" "$image" > /dev/null || { fail "컨테이너 생성 실패"; return; }
  docker cp "$(hostpath "$DRIVER")" "$name:/usr/local/tomcat/lib/mariadb-java-client.jar" > /dev/null
  docker cp "$(hostpath "$base/dual")" "$name:/usr/local/tomcat/webapps/dual" > /dev/null
  docker cp "$WORKH/secure" "$name:/opt/java-crypto-kit" > /dev/null
  docker start "$name" > /dev/null
  wait_tomcat "$name" dual || up=1
  echo "--- [$id] $TV, JAR B(dual/WEB-INF/lib)=$(basename "$jarb"), Tomcat lib에는 JAR 없음"
  check $up "Tomcat 기동(웹앱 dual만)"
  libcount=$(docker exec "$name" sh -c 'ls /usr/local/tomcat/lib | grep -c java-crypto-kit' < /dev/null 2> /dev/null)
  [ "$libcount" = 0 ]; check $? "Tomcat lib에 java-crypto-kit JAR 없음(${libcount}개)"
  ds_check "$name" dual jdbc/ctxBiz "OK $POOL_D"
  ds_check "$name" dual jdbc/ctxBizKey "OK $POOL_D"
  ds_check "$name" dual jdbc/ctxInfra "FAIL [사유: KEY_ID_MISMATCH]"
  insert_check "$name" dual jdbc/ctxBiz "$id.1"
  api=$(docker exec "$name" curl -s "http://127.0.0.1:8080/dual/jck-dual.jsp" < /dev/null)
  printf '%s\n' "$api" | grep -E '^(factory\.(app|lib)|app\.(api|load|default|keys)|app\.dec\.BIZ)' | sed 's/^/   dual  | /'
  grep -qxF "factory.app=$L_APP" <<< "$api" && grep -qxF "factory.lib=none" <<< "$api" && grep -qxF "app.api=$L_APP" <<< "$api" \
    && grep -qxF "app.default=biz-pass" <<< "$api" \
    && grep -qxF "app.dec.BIZ_PASS=OK" <<< "$api" && grep -qxF "app.dec.INFRA_PASS=KEY_ID_MISMATCH" <<< "$api"
  check $? "관리형 API·JNDI Factory 모두 WEB-INF/lib의 JAR B(기본 키 biz-pass, 업무 암호문만 복호화)"
  newapi_check "$name" dual "$L_APP"
  finish_case "$id" "$name" 0 "$up"
}
run_webinf_only W01-webinf-only-tomcat10.1 "$T101" "$WORK/jars/biz.jar" "$(res jdbc/ctxBiz "$BIZ_PASS_PW" "$ATTR_X")
$(res jdbc/ctxBizKey "$BIZ_KEY_PW" "$ATTR_X")
$(res jdbc/ctxInfra "$INFRA_PASS_PW" "$ATTR_X")"

if [ "$WITH_VAULT" = 1 ]; then
  section "7. HashiCorp Vault 1.21.4 실서버(dev TLS, KV v2) - --with-vault"
  CASE=vault
  export VAULT_DEV_ROOT_TOKEN_ID="qa-root-$(rand 10)" VAULT_TOKEN; VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"; secret "$VAULT_DEV_ROOT_TOKEN_ID"
  docker run -d --name "$VAULT" "${LABELS[@]}" --network "$NET" --network-alias jck-qa-vault --tmpfs /vault/file --tmpfs /vault/logs \
    --tmpfs /vault/tls:rw,mode=1777 -e SKIP_SETCAP=true -e VAULT_DEV_ROOT_TOKEN_ID -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    "$VAULT_IMAGE" server -dev -dev-tls -dev-tls-san=jck-qa-vault -dev-tls-cert-dir=/vault/tls > /dev/null || die "Vault 컨테이너를 시작하지 못했습니다."
  vx() { docker exec -i -e VAULT_ADDR=https://jck-qa-vault:8200 -e VAULT_CACERT=/vault/tls/vault-ca.pem -e VAULT_TOKEN "$VAULT" vault "$@"; }
  up=1; for i in $(seq 1 60); do vx status > /dev/null 2>&1 && { up=0; break; }; sleep 1; done
  check $up "Vault 기동(TLS)"
  docker exec "$VAULT" cat /vault/tls/vault-ca.pem > "$WORK/secure/vault-ca.pem"
  for k in v1 v2; do wb java -jar /w/jars/initial.jar keygen --out "/w/out/vault-$k.key" --reason "vault test" $ADM > /dev/null; done
  docker cp "$WB:/w/out/." "$WORKH/secure/" > /dev/null
  for k in v1 v2; do secret "$(tr -d '\r\n' < "$WORK/secure/vault-$k.key")"; tr -d '\r\n' < "$WORK/secure/vault-$k.key" | vx kv put -mount=secret java-crypto-kit/qa key=- > /dev/null; done
  check $? "KV v2 버전 1·2 저장"
  # pass 키 프로필용 Passphrase(한글 포함)는 다른 Secret 경로·필드에 둔다(crypto.keys.<id>.vault.path·vault.field).
  VAULT_PASSPHRASE="qa-볼트-$(rand 6)"; secret "$VAULT_PASSPHRASE"
  printf '%s' "$VAULT_PASSPHRASE" | vx kv put -mount=secret java-crypto-kit/qa-pass passphrase=- > /dev/null
  check $? "KV v2에 Passphrase 저장(java-crypto-kit/qa-pass, 필드 passphrase)"
  printf 'path "secret/data/java-crypto-kit/qa" {\n  capabilities = ["read"]\n}\npath "secret/data/java-crypto-kit/qa-pass" {\n  capabilities = ["read"]\n}\n' \
    | vx policy write jck-qa-read - > /dev/null
  GOOD=$(vx token create -policy=jck-qa-read -ttl=1h -field=token); LIMITED=$(vx token create -policy=default -ttl=1h -field=token)
  BAD="hvs.qa$(rand 16)"
  for t in GOOD LIMITED BAD; do secret "${!t}"; printf '%s' "${!t}" > "$WORK/secure/vault-$(echo "$t" | tr 'A-Z' 'a-z').token"; done
  export QA_VAULT_TOKEN="$GOOD"
  vprops() { local f="$1" id="$2"; shift 2
    { echo "crypto.key.source=vault"; echo "crypto.key.id=$id"; echo "crypto.vault.mount=secret"; echo "crypto.vault.field=key"
      for l in "$@"; do echo "$l"; done; } > "$WORK/secure/$f"; }
  U="crypto.vault.url=https://jck-qa-vault:8200"; CA="crypto.vault.ca.file=/opt/java-crypto-kit/vault-ca.pem"; PQ="crypto.vault.path=java-crypto-kit/qa"
  vprops vault-good.properties vault02 "$U" "$PQ" "$CA" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token"
  vprops vault-v1.properties vault01 "$U" "$PQ" "$CA" "crypto.vault.ver=1" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token"
  vprops vault-envtoken.properties vault02 "$U" "$PQ" "$CA" "crypto.vault.token.env=QA_VAULT_TOKEN"
  vprops vault-limited.properties vault02 "$U" "$PQ" "$CA" "crypto.vault.token.file=/opt/java-crypto-kit/vault-limited.token"
  vprops vault-bad.properties vault02 "$U" "$PQ" "$CA" "crypto.vault.token.file=/opt/java-crypto-kit/vault-bad.token"
  vprops vault-noca.properties vault02 "$U" "$PQ" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token"
  vprops vault-wrongpath.properties vault02 "$U" "crypto.vault.path=java-crypto-kit/none" "$CA" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token"
  vprops vault-v9.properties vault09 "$U" "$PQ" "$CA" "crypto.vault.ver=9" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token"
  # 연결 설정만 둔 외부 설정: Vault의 pass 키 프로필이 이 연결 설정으로 읽는다. 레거시 슬롯(crypto.key.*)은 JAR의 내장 키를
  # 그대로 쓰므로 crypto.key.source=embedded를 함께 적는다(Vault 설정만 있고 공급원이 없으면 의도가 모호해 CONFIGURATION).
  printf '%s\n' "crypto.key.source=embedded" "$U" "$CA" "crypto.vault.mount=secret" "crypto.vault.token.file=/opt/java-crypto-kit/vault-good.token" \
    > "$WORK/secure/vault-conn.properties"
  docker exec "$WB" rm -rf /opt/java-crypto-kit; docker cp "$WORKH/secure" "$WB:/opt/java-crypto-kit" > /dev/null
  vdoc() { # <설정 이름> <기대 종료 코드> <기대 문구>
    local outv rc; outv=$(wb java -jar /w/jars/company.jar doctor --config "/opt/java-crypto-kit/vault-$1.properties" 2>&1); rc=$?
    [ "$rc" = "$2" ] && [[ "$outv" == *"$3"* ]]; check $? "doctor vault-$1: 종료 코드 $rc, '$3'"
    ! grep -qFf "$SECRETS" <<< "$outv" || fail "doctor vault-$1 출력에 비밀값"
  }
  vdoc good 0 "PASS"; vdoc v1 0 "PASS"; vdoc envtoken 0 "PASS"
  vdoc limited 1 "읽을 권한이 없습니다"; vdoc bad 1 "인증을 거부했습니다"; vdoc noca 1 "TLS 인증서를 신뢰할 수 없거나"
  vdoc wrongpath 1 "crypto.vault.path가 맞는지도 확인하세요"; vdoc v9 1 "찾지 못했습니다"
  fpv() { wb java -jar /w/jars/company.jar fingerprint "$@" 2> /dev/null | grep -oE '[0-9a-f]{64}'; }
  [ -n "$(fpv --type key --config /opt/java-crypto-kit/vault-good.properties)" ] \
    && [ "$(fpv --type key --config /opt/java-crypto-kit/vault-good.properties)" = "$(fpv --key-file /opt/java-crypto-kit/vault-v2.key)" ] \
    && [ "$(fpv --type key --config /opt/java-crypto-kit/vault-v1.properties)" = "$(fpv --key-file /opt/java-crypto-kit/vault-v1.key)" ]
  check $? "버전 미지정 = 최신(v2) 키, crypto.vault.ver=1 = v1 키(지문 비교)"
  wb sh -c '(sleep 3; printf "%s\n" "$DBPW") | script -qec "java -Dcrypto.config.file=/opt/java-crypto-kit/vault-good.properties -jar /w/jars/company.jar encrypt --type key" /dev/null 2>&1 | tr -d "\r" | grep -oE "ENC\[v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\]" | head -1 > /w/tokens/VAULT_PW'
  docker cp "$WB:/w/tokens/VAULT_PW" "$WORKH/tokens/VAULT_PW" > /dev/null
  VAULT_PW=$(tr -d '\r\n' < "$WORK/tokens/VAULT_PW"); secret "$VAULT_PW"
  [[ "$VAULT_PW" == "ENC[v1:vault02:"* ]]; check $? "Vault 키로 CLI encrypt"
  quiet wb cp /w/jars/company.jar /w/jars/company-vpass.jar && quiet wb java -Dcrypto.config.file=/opt/java-crypto-kit/vault-conn.properties -jar /w/jars/company-vpass.jar config key add --key-id vault-pass \
    --source vault --location 'java-crypto-kit/qa-pass#passphrase' --operator qa --reason "vault test" --yes $ADM
  check $? "config key add --source vault: pass 키 vault-pass(지금 한 번 읽어 지문 고정, JAR에는 경로·필드·Salt·지문만)"
  vprop=$(wb java -jar /w/jars/company-vpass.jar config show $ADM 2>&1)
  [[ "$vprop" == *"crypto.keys.vault-pass.vault.path = java-crypto-kit/qa-pass"* && "$vprop" == *"crypto.keys.vault-pass.fingerprint ="* \
     && "$vprop" != *"$VAULT_PASSPHRASE"* && "$vprop" != *"$GOOD"* ]]
  check $? "Vault pass 키 JAR 설정: 경로·고정 지문만, Passphrase·토큰 없음"
  wb sh -c '(sleep 3; printf "%s\n" "$DBPW") | script -qec "java -Dcrypto.config.file=/opt/java-crypto-kit/vault-conn.properties -jar /w/jars/company-vpass.jar encrypt --key-id vault-pass" /dev/null 2>&1 | tr -d "\r" | grep -oE "ENC\[v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\]" | head -1 > /w/tokens/VAULT_PASS_PW'
  docker cp "$WB:/w/tokens/VAULT_PASS_PW" "$WORKH/tokens/VAULT_PASS_PW" > /dev/null
  docker cp "$WB:/w/jars/company-vpass.jar" "$WORKH/jars/company-vpass.jar" > /dev/null
  VAULT_PASS_PW=$(tr -d '\r\n' < "$WORK/tokens/VAULT_PASS_PW"); secret "$VAULT_PASS_PW"
  [[ "$VAULT_PASS_PW" == "ENC[v1:vault-pass:"* ]]; check $? "Vault pass 키로 CLI encrypt(--key-id vault-pass)"
  expect jdbc/qaVault "OK $POOL_D"; RUN_DS=jdbc/qaVault
  run_case G01-vault-key-tomcat10.1 "$T101" "$COMP" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_D")" 0 \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-good.properties"
  expect jdbc/qaVault "FAIL 읽을 권한이 없습니다"
  run_case G02-vault-limited-token "$T101" "$COMP" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_D")" - \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-limited.properties"
  expect jdbc/qaVault "OK $POOL_T"; RUN_DS=jdbc/qaVault
  run_case G03-vault-env-token-tomcat8.5 "$T85" "$COMPTJ" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_T")" 0 -e QA_VAULT_TOKEN \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-envtoken.properties"
  expect jdbc/qaVaultPass "OK $POOL_D" jdbc/qa "OK $POOL_D"
  run_case G04-vault-pass-profile-tomcat11 "$T110" "$WORK/jars/company-vpass.jar" "$(res jdbc/qaVaultPass "$VAULT_PASS_PW" "$ATTR_D")
$(res jdbc/qa "$CORP_PW" "$ATTR_D")" 0 -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-conn.properties"
fi

if [ "$WITH_KEYCLOAK" = 1 ]; then
  section "7K. Keycloak 실연동(--with-keycloak, HTTPS): JWKS·Access Token·ID Token 거부·RFC 9068 설정·Introspection"
  CASE=keycloak
  KC_STORE_PW="qa-kc-store-$(rand 8)"; KC_ADMIN_PW="qa-kc-admin-$(rand 8)"; KC_WEB_SECRET="qa-web-$(rand 12)"
  KC_9068_SECRET="qa-9068-$(rand 12)"; KC_API_SECRET="qa-api-$(rand 12)"; KC_USER_PW="qa-user-$(rand 10)"
  for s in "$KC_STORE_PW" "$KC_ADMIN_PW" "$KC_WEB_SECRET" "$KC_9068_SECRET" "$KC_API_SECRET" "$KC_USER_PW"; do secret "$s"; done
  # 시험용 CA와 Keycloak 서버 인증서(SAN jck-qa-keycloak)를 작업용 컨테이너의 keytool로 만든다(저장소에 두지 않음).
  wb sh -c "rm -rf /w/kc && mkdir -p /w/kc && cd /w/kc \
    && keytool -genkeypair -alias ca -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -dname 'CN=JCK QA Keycloak CA' -ext bc:c -validity 3 -keystore ca.p12 -storetype PKCS12 -storepass $KC_STORE_PW -keypass $KC_STORE_PW \
    && keytool -exportcert -alias ca -rfc -file ca.pem -keystore ca.p12 -storetype PKCS12 -storepass $KC_STORE_PW \
    && keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -dname 'CN=jck-qa-keycloak' -validity 3 -keystore server.p12 -storetype PKCS12 -storepass $KC_STORE_PW -keypass $KC_STORE_PW \
    && keytool -certreq -alias server -file server.csr -keystore server.p12 -storetype PKCS12 -storepass $KC_STORE_PW \
    && keytool -gencert -alias ca -infile server.csr -outfile server.pem -rfc -sigalg SHA256withRSA -ext SAN=dns:jck-qa-keycloak -ext EKU=serverAuth -validity 3 -keystore ca.p12 -storetype PKCS12 -storepass $KC_STORE_PW \
    && keytool -importcert -alias ca -file ca.pem -noprompt -keystore server.p12 -storetype PKCS12 -storepass $KC_STORE_PW \
    && keytool -importcert -alias server -file server.pem -keystore server.p12 -storetype PKCS12 -storepass $KC_STORE_PW" > /dev/null 2>&1
  check $? "시험용 CA·Keycloak HTTPS 인증서(SAN jck-qa-keycloak) 생성"
  mkdir -p "$WORK/kc"; docker cp "$WB:/w/kc/server.p12" "$WORKH/kc/server.p12" > /dev/null
  # 영역(realm): web-client(클라이언트 자격·비밀번호 흐름, 대상 매퍼 orders-api), web-client-9068(at+jwt 헤더 설정),
  #             orders-api(Introspection 호출용 기밀 클라이언트), 시험 사용자 1명. 값은 이번 실행의 시험용 난수다.
  mkdir -p "$WORK/kc/import"
  cat > "$WORK/kc/import/realm.json" << KCREALM
{"realm":"jck","enabled":true,"accessTokenLifespan":300,
 "clients":[
  {"clientId":"orders-api","enabled":true,"publicClient":false,"secret":"$KC_API_SECRET","standardFlowEnabled":false,
   "directAccessGrantsEnabled":false,"serviceAccountsEnabled":false},
  {"clientId":"web-client","enabled":true,"publicClient":false,"secret":"$KC_WEB_SECRET","standardFlowEnabled":false,
   "directAccessGrantsEnabled":true,"serviceAccountsEnabled":true,
   "protocolMappers":[{"name":"orders-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
     "config":{"included.custom.audience":"orders-api","access.token.claim":"true","id.token.claim":"false"}}]},
  {"clientId":"web-client-9068","enabled":true,"publicClient":false,"secret":"$KC_9068_SECRET","standardFlowEnabled":false,
   "directAccessGrantsEnabled":false,"serviceAccountsEnabled":true,"attributes":{"access.token.header.type.rfc9068":"true"},
   "protocolMappers":[{"name":"orders-audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
     "config":{"included.custom.audience":"orders-api","access.token.claim":"true","id.token.claim":"false"}}]}],
 "users":[{"username":"qa-user","enabled":true,"email":"qa-user@example.invalid","emailVerified":true,"firstName":"QA","lastName":"User",
   "credentials":[{"type":"password","value":"$KC_USER_PW","temporary":false}]}]}
KCREALM
  docker create --name "$KC" "${LABELS[@]}" --network "$NET" --network-alias jck-qa-keycloak \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=qa-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
    -e KEYCLOAK_ADMIN=qa-admin -e KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PW" \
    "$KC_IMAGE" start-dev --import-realm --http-enabled=false --https-port=8443 \
    --https-key-store-file=/opt/keycloak/conf/server.p12 --https-key-store-password="$KC_STORE_PW" > /dev/null \
    || die "Keycloak 컨테이너를 만들지 못했습니다."
  docker cp "$WORKH/kc/server.p12" "$KC:/opt/keycloak/conf/server.p12" > /dev/null
  # 이미지에는 data/import 폴더가 없으므로 폴더째 복사한다(대상 폴더를 새로 만든다).
  docker cp "$WORKH/kc/import" "$KC:/opt/keycloak/data/import" > /dev/null
  check $? "Keycloak 영역 가져오기 파일 복사(data/import/realm.json)"
  docker start "$KC" > /dev/null
  KC_VERSION=$(docker exec "$KC" sh -c 'ls /opt/keycloak/lib/lib/main 2> /dev/null | grep -oE "keycloak-core-[0-9.]+" | head -1' < /dev/null 2> /dev/null)
  # 검사 프로그램: 빌드 JAR의 공개 API만 쓴다(애플리케이션이 신뢰 경로로 JWKS를 받아 Jwks.parse에 넘기는 흐름).
  cat > "$WORK/kc/KeycloakCheck.java" << 'KCJAVA'
import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.jwt.Jwks;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.oauth.AccessTokenVerifier;
import io.javacryptokit.oauth.ClientCredentials;
import io.javacryptokit.oauth.IntrospectionException;
import io.javacryptokit.oauth.IntrospectionResult;
import io.javacryptokit.oauth.TokenIntrospector;
import io.javacryptokit.oauth.TokenRequestException;
import io.javacryptokit.oauth.TokenResponse;
import io.javacryptokit.security.Certificates;
import io.javacryptokit.security.Encoding;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class KeycloakCheck {
    static SSLContext tls;

    public static void main(String[] args) throws Exception {
        String base = args[0];
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("ca", Certificates.readFile(Paths.get(args[1])));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        tls = SSLContext.getInstance("TLS");
        tls.init(null, tmf.getTrustManagers(), null);
        String discovery = null;
        for (int i = 0; i < 120 && discovery == null; i++) {
            try { discovery = get(base + "/.well-known/openid-configuration"); } catch (IOException e) { Thread.sleep(2000); }
        }
        out("ready", discovery == null ? "TIMEOUT" : "OK");
        if (discovery == null) return;
        JwtClaims d = JwtClaims.parse(discovery);
        String issuer = d.getString("issuer");
        out("issuer", base.equals(issuer) ? "OK" : "DIFF");
        List<JwtKey> keys = Jwks.parse(get(d.getString("jwks_uri")), issuer);
        out("jwks.keys", String.valueOf(keys.size()));
        String tokenUrl = d.getString("token_endpoint");
        // Client Credentials 발급은 이 라이브러리의 ClientCredentials(basic·post), ID Token이 필요한 비밀번호 흐름만 시험용 직접 요청
        ClientCredentials basic = ClientCredentials.builder(URI.create(tokenUrl))
                .clientSecretBasic("web-client", System.getenv("KC_WEB_SECRET").toCharArray()).sslContext(tls).build();
        TokenResponse issued = basic.requestToken();
        String cc = issued.accessToken();
        out("cc.basic", issued.tokenType() + "/" + (issued.expiresIn().isPresent() ? "expiresIn" : "noExpiresIn"));
        ClientCredentials post = ClientCredentials.builder(URI.create(tokenUrl))
                .clientSecretPost("web-client", System.getenv("KC_WEB_SECRET").toCharArray()).sslContext(tls).build();
        String ccPost = post.requestToken().accessToken();
        try {
            ClientCredentials.builder(URI.create(tokenUrl)).clientSecretBasic("web-client", "wrong-secret".toCharArray()).sslContext(tls)
                    .build().requestToken();
            out("cc.wrongSecret", "NO_ERROR");
        } catch (TokenRequestException e) {
            out("cc.wrongSecret", e.getReason().name());
        }
        try {
            basic.requestToken("not-a-registered-scope");
            out("cc.invalidScope", "NO_ERROR");
        } catch (TokenRequestException e) {
            out("cc.invalidScope", e.getReason().name() + "/" + e.getOAuthError());
        }
        JwtClaims pw = JwtClaims.parse(post(tokenUrl, "grant_type=password&scope=openid&username=qa-user&password="
                + URLEncoder.encode(System.getenv("KC_USER_PW"), "UTF-8"), "web-client", System.getenv("KC_WEB_SECRET")));
        String user = pw.getString("access_token");
        String id = pw.getString("id_token");
        out("access.header.typ", String.valueOf(Jwt.parseUnverified(cc).type()));
        out("idtoken.claim.typ", String.valueOf(Jwt.parseUnverified(id).claims().getString("typ")));
        AccessTokenVerifier api = AccessTokenVerifier.profile().issuer(issuer).audience("orders-api").keys(keys)
                .requireClaimValue("typ", "Bearer").clientIdClaim("azp").clockSkew(Duration.ofSeconds(60)).build();
        out("access.clientCredentials", verify(api, cc));
        out("access.clientCredentialsPost", verify(api, ccPost));
        out("access.password", verify(api, user));
        out("idtoken.asAccess", verify(api, id));
        AccessTokenVerifier sameAudience = AccessTokenVerifier.profile().issuer(issuer).audience("web-client").keys(keys)
                .requireClaimValue("typ", "Bearer").clientIdClaim("azp").clockSkew(Duration.ofSeconds(60)).build();
        out("idtoken.sameAudience", verify(sameAudience, id));
        AccessTokenVerifier rfc9068 = AccessTokenVerifier.rfc9068().issuer(issuer).audience("orders-api").keys(keys)
                .clockSkew(Duration.ofSeconds(60)).build();
        String at = ClientCredentials.builder(URI.create(tokenUrl)).clientSecretBasic("web-client-9068", System.getenv("KC_9068_SECRET").toCharArray())
                .sslContext(tls).build().requestToken().accessToken();
        out("rfc9068.header.typ", String.valueOf(Jwt.parseUnverified(at).type()));
        out("rfc9068.verify", verify(rfc9068, at));
        out("rfc9068.plainAccess", verify(rfc9068, cc));
        TokenIntrospector introspector = TokenIntrospector.builder(URI.create(d.getString("introspection_endpoint")))
                .clientSecretBasic("orders-api", System.getenv("KC_API_SECRET").toCharArray()).sslContext(tls).build();
        IntrospectionResult active = introspector.introspect(cc, "access_token");
        out("introspect.active", active.active() + "/" + active.clientId());
        out("introspect.inactive", String.valueOf(introspector.introspect("not-a-real-token").active()));
        TokenIntrospector wrong = TokenIntrospector.builder(URI.create(d.getString("introspection_endpoint")))
                .clientSecretBasic("orders-api", "wrong-secret".toCharArray()).sslContext(tls).build();
        try {
            wrong.introspect(cc);
            out("introspect.wrongClient", "NO_ERROR");
        } catch (IntrospectionException e) {
            out("introspect.wrongClient", e.getReason().name() + "/" + e.getStatusCode());
        }
    }

    static String verify(AccessTokenVerifier verifier, String token) {
        try {
            verifier.verify(token);
            return "VALID";
        } catch (JwtException e) {
            return e.getReason().name();
        }
    }

    static void out(String name, String value) {
        System.out.println("KC " + name + "=" + value);
    }

    static String get(String url) throws IOException {
        HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory());
        c.setConnectTimeout(3000);
        c.setReadTimeout(10000);
        return read(c);
    }

    static String post(String url, String form, String clientId, String secret) throws IOException {
        HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory());
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        c.setRequestProperty("Authorization", "Basic " + Encoding.BASE64.encode((URLEncoder.encode(clientId, "UTF-8") + ":"
                + URLEncoder.encode(secret, "UTF-8")).getBytes(StandardCharsets.UTF_8)));
        try (OutputStream o = c.getOutputStream()) {
            o.write(form.getBytes(StandardCharsets.UTF_8));
        }
        return read(c);
    }

    static String read(HttpsURLConnection c) throws IOException {
        if (c.getResponseCode() != 200) throw new IOException("HTTP " + c.getResponseCode());
        try (InputStream in = c.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b = new byte[8192];
            int n;
            while ((n = in.read(b)) != -1) out.write(b, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
KCJAVA
  docker cp "$WORKH/kc/KeycloakCheck.java" "$WB:/w/kc/KeycloakCheck.java" > /dev/null
  KCOUT=$(docker exec -e KC_WEB_SECRET="$KC_WEB_SECRET" -e KC_9068_SECRET="$KC_9068_SECRET" -e KC_API_SECRET="$KC_API_SECRET" \
    -e KC_USER_PW="$KC_USER_PW" "$WB" java -cp /w/jars/public.jar /w/kc/KeycloakCheck.java https://jck-qa-keycloak:8443/realms/jck /w/kc/ca.pem 2>&1)
  printf '%s\n' "$KCOUT" | grep '^KC ' | sed 's/^/   /'
  ! grep -qFf "$SECRETS" <<< "$KCOUT"; check $? "Keycloak 검사 출력에 비밀값(클라이언트 비밀·사용자 비밀번호·토큰) 없음"
  echo "   Keycloak 이미지: $KC_IMAGE (${KC_VERSION:-버전 확인 불가})"
  kc() { grep -qxF "KC $1" <<< "$KCOUT"; check $? "Keycloak: $1${2:+ ($2)}"; }
  kc "ready=OK" "HTTPS 기동·영역 가져오기"
  kc "issuer=OK" "발급자 = 영역 주소"
  kc "jwks.keys=1" "JWKS에서 서명용 RS256 키만(암호화용 키는 건너뜀)"
  kc "cc.basic=Bearer/expiresIn" "ClientCredentials(client_secret_basic)로 실제 토큰 발급"
  kc "cc.wrongSecret=CLIENT_AUTH" "틀린 클라이언트 비밀 → 클라이언트 인증 실패(401, 발급 실패로 구분)"
  kc "cc.invalidScope=OAUTH_ERROR/invalid_scope" "등록되지 않은 scope → invalid_scope"
  kc "access.clientCredentials=VALID" "클라이언트 자격 Access Token, 설정형 프로파일(typ=Bearer, azp)"
  kc "access.clientCredentialsPost=VALID" "ClientCredentials(client_secret_post) 발급 토큰 검증"
  kc "access.password=VALID" "사용자 Access Token"
  kc "idtoken.asAccess=AUDIENCE" "실제 ID Token 거부(대상 다름)"
  kc "idtoken.sameAudience=INVALID_CLAIM" "대상이 같아도 토큰 종류 클레임(typ=ID)으로 거부"
  kc "rfc9068.plainAccess=TYPE" "RFC 9068 검증기는 typ=JWT 토큰 거부"
  if grep -qxF "KC rfc9068.header.typ=at+jwt" <<< "$KCOUT"; then
    kc "rfc9068.verify=VALID" "이 버전·설정에서 at+jwt 발급 확인 → RFC 9068 프로파일 검증"
  else
    echo "   참고: 이 Keycloak 버전·클라이언트 설정에서는 at+jwt 헤더 발급이 확인되지 않음($(grep -F 'KC rfc9068.header.typ=' <<< "$KCOUT")). RFC 9068 실연동은 이 조건에서 미확인으로 기록"
  fi
  kc "introspect.active=true/web-client" "Introspection 활성"
  kc "introspect.inactive=false" "Introspection 비활성(통신 실패와 구분)"
  kc "introspect.wrongClient=CLIENT_AUTH/401" "Introspection 클라이언트 인증 실패"
  docker rm -f -v "$KC" > /dev/null 2>&1
fi

section "8. 결과 확인"
CASE=summary
# 실제 테이블 INSERT 대조: 시나리오 설계(8개 조합 × pass·key 각 1건 = 16, 이중 배포 D01·D02 각 3건 = 6, D05 1건,
# W01 1건, --with-vault면 G01·G03 각 1건 추가)와 INSERT를 요청한 실행 목록, MariaDB의 실행별 행 수가 모두 일치해야 한다.
design_runs=24; [ "$WITH_VAULT" = 1 ] && design_runs=26
[ "${#INSERT_RUNS[@]}" = "$design_runs" ]
check $? "INSERT 시나리오 ${#INSERT_RUNS[@]}개(설계 $design_runs개: 8개 조합 × pass·key + 이중 배포 2 × 3 + D05 1 + W01 1$([ "$WITH_VAULT" = 1 ] && echo ' + Vault 2'))"
want=$(for r in "${INSERT_RUNS[@]}"; do echo "$r 1"; done | sort)
got=$(docker exec -e MYSQL_PWD "$DB" mariadb -uqa_app qadb -N -e "SELECT run, COUNT(*) FROM qa_log GROUP BY run" 2> /dev/null \
  | tr '\t' ' ' | sed '/^$/d' | sort)
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  pass "MariaDB 실제 행 대조: 실행 ${#INSERT_RUNS[@]}개 모두 정확히 1건(누락·중복·예상 밖 행 없음)"
else
  fail "MariaDB 실제 행 대조 불일치 - 기대: $(echo "$want" | tr '\n' ';') / 실제: $(echo "${got:-없음}" | tr '\n' ';')"
fi
leak_files=$(grep -rlFf "$SECRETS" "$RES" 2> /dev/null | wc -l | tr -d ' ')
[ "$leak_files" = 0 ]; check $? "결과 폴더에 비밀번호·키·Passphrase·토큰·암호문 없음(파일 ${leak_files}개)"
cleanup; trap - EXIT    # 임시 폴더(키·토큰·JAR)와 이 실행의 Docker 자원 삭제
left=$(docker ps -aq --filter "label=jck-qa.run=$RID" | grep -c .); leftnet=$(docker network ls -q --filter "label=jck-qa.run=$RID" | grep -c .)
[ "$left" = 0 ] && [ "$leftnet" = 0 ] && [ ! -e "$WORK" ]
check $? "정리: 이 실행의 컨테이너 ${left}개·네트워크 ${leftnet}개 남음, 임시 폴더 삭제"
[ "$KEEP_IMAGES" = 0 ] && [ "${#PULLED[@]}" -gt 0 ] && echo "   내려받았다가 지운 이미지: ${PULLED[*]}"
echo; echo "조합·시나리오별 결과:"; sed 's/^/   /' "$MATRIX"
echo
code=0
if [ "${#FAILS[@]}" = 0 ]; then
  echo "RESULT: PASS (검사 $PASSES개 모두 통과) - 로그: $RES"
else
  echo "RESULT: FAIL (실패 ${#FAILS[@]}개 / 통과 $PASSES개) - 로그: $RES"
  for x in "${FAILS[@]}"; do echo "   실패: $x"; done
  code=1
fi
exec 1>&- 2>&-; wait "$TEE_PID" 2> /dev/null   # 로그 파일에 마지막 줄까지 쓰이도록 기다린다
exit $code
