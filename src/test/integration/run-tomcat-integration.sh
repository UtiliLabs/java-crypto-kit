#!/usr/bin/env bash
# java-crypto-kit 실서버 통합 시험(Docker): Tomcat 8.5/9.0/10.1/11.0 × DBCP2/Tomcat JDBC Pool × MariaDB
#
# 무엇을 확인하나: 빌드한 JAR를 실제 Tomcat 컨테이너의 lib에 넣고 JNDI 조회 -> getConnection() -> SQL까지 확인한다.
#   0  준비: Docker 이미지, MariaDB JDBC 드라이버(SHA-256 확인), 외부와 끊긴 시험 전용 네트워크
#   1  사용자 지정 키 JAR: keygen -> config embed-key -> config set(Pool) -> history·fingerprint·doctor(CLI만 사용)
#   2  실제 CLI: 가상 터미널로 encrypt·decrypt·rekey·verify, 암호문 키ID, 위조 암호문 거부
#   3  MariaDB: 시험 전용 계정·테이블(tmpfs)
#   4  M-*      8개 조합(Tomcat 4개 버전 × DBCP2/Tomcat JDBC Pool): 키 내장 JAR만으로 정상 연결과
#               오류 판정(평문·위조·변조·키ID 불일치·DB 로그인 거부), 실제 테이블 SELECT·INSERT
#   5  E01~E18  설정·보안 시나리오: 우선순위(-D > 외부 Properties > JAR), file·env 키, 언어·경고 끄기, 공개 키 JAR,
#               키 원문 -D 거부, 키 누락 Fail Closed, -D·외부 Properties 오타 거부, 빈 설정 경로 거부,
#               웹앱의 같은 이름 가짜 Pool Factory 차단(E17), GlobalNamingResources + ResourceLink(E18)
#   6  G01~G03  Vault KV v2(--with-vault): 실제 Vault 컨테이너의 키, 권한 부족 토큰, 환경변수 토큰
#   7  결과 확인: 실행별 DB 행 대조(누락·중복·예상 밖 행 0), 결과 폴더의 비밀값 0, Docker 정리
#
# 사용법(저장소 루트에서, 먼저 빌드: ./gradlew clean build 또는 gradlew.bat clean build)
#   bash src/test/integration/run-tomcat-integration.sh                기본 시험(보통 5분 안팎, 이미지를 처음 받으면 더 걸림)
#   bash src/test/integration/run-tomcat-integration.sh --with-vault   Vault KV v2 시험 추가(Vault 코드를 바꿨을 때)
#   bash src/test/integration/run-tomcat-integration.sh --keep-images  이번에 내려받은 Docker 이미지를 지우지 않음(반복 실행용)
#   그 밖의 옵션: --jar <java-crypto-kit JAR>(기본: build/libs의 JAR 하나)
#                 --driver <mariadb-java-client-3.5.11.jar>(인터넷 없이 실행할 때)   --help
# 필요 환경: bash 4 이상(Linux, Windows Git Bash), Docker 엔진, curl(드라이버 내려받기). 호스트 Java는 필요 없다.
# 실행 시점: Tomcat Factory·키 공급·Pool·설정 해석 코드를 바꿨을 때와 Release 전(일반 PR마다 필수는 아님).
#   Gradle test(JUnit)에서 자동 실행되지 않는 독립 Bash/Docker 시험이다(Docker가 필요한 시험을 기본 빌드에 강제하지 않음).
#
# 결과 읽는 법
#   종료 코드: 0 = 모두 PASS, 1 = FAIL 있음, 2 = 실행 환경 문제(Docker 미기동·JAR 없음·다운로드 실패 등, 시험 전에 중단)
#   화면 끝: "조합·시나리오별 결과"(케이스별 PASS/FAIL), "RESULT:" 줄, FAIL이면 "실패: [케이스] 기대 / 실제" 목록
#   원인 표시: 이 라이브러리 오류는 [사유: 코드] 메시지, 그 밖의 예외는 유형과 원인 클래스 이름(cause=..., 메시지 제외)
#     예) cause=ClassNotFoundException(io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory) = Tomcat lib의 JAR 누락·손상
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
#   - 키·DB 비밀번호·토큰은 실행마다 새로 만드는 시험용 값이며 임시 폴더에만 두고 끝나면 지운다.
set -u
export MSYS_NO_PATHCONV=1   # Windows Git Bash: docker 인자의 /경로를 Windows 경로로 바꾸지 않게 한다
[ "${BASH_VERSINFO[0]}" -ge 4 ] || { echo "[환경 오류] bash 4 이상이 필요합니다." >&2; exit 2; }

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$SCRIPT_DIR/../../.." && pwd)   # src/test/integration → 저장소 루트
[ -f "$REPO/build.gradle" ] && [ -f "$REPO/gradlew" ] || { echo "[환경 오류] 저장소 루트를 찾지 못했습니다: $REPO" >&2; exit 2; }
WITH_VAULT=0; KEEP_IMAGES=0; JAR=""; DRIVER_IN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-vault) WITH_VAULT=1 ;;
    --keep-images) KEEP_IMAGES=1 ;;
    --jar) JAR="${2:-}"; shift ;;
    --driver) DRIVER_IN="${2:-}"; shift ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
    *) echo "[환경 오류] 알 수 없는 옵션: $1 (--help 참조)" >&2; exit 2 ;;
  esac
  shift
done

T85=tomcat:8.5-jdk8-temurin; T90=tomcat:9.0-jdk8-temurin; T101=tomcat:10.1-jdk21-temurin; T110=tomcat:11.0-jdk21-temurin
DB_IMAGE=mariadb:12.3.2; VAULT_IMAGE=hashicorp/vault:1.21.4
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
[ -n "$DRIVER_IN" ] || command -v curl > /dev/null 2>&1 || die "curl이 없습니다(--driver로 MariaDB JDBC JAR를 지정할 수 있습니다)."

RID="$(date -u +%H%M%S)$(rand 2)"
P="jck-qa-$RID"
LABELS=(--label jck-qa=1 --label "jck-qa.run=$RID")
NET="$P-net"; DB="$P-db"; WB="$P-bench"; VAULT="$P-vault"
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
PASSES=0; FAILS=(); CASE="-"; INSERT_RUNS=()   # INSERT_RUNS: 실제 테이블 INSERT를 요청한 실행 ID(끝에서 DB와 대조)
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

echo "java-crypto-kit Docker 통합 시험 시작 $(date -u +%Y-%m-%dT%H:%M:%SZ) (실행ID $RID)"
echo "대상 JAR: $(basename "$JAR") sha256=$(sha256 "$JAR" | cut -c1-16)…  결과 폴더: $RES"

section "0. 준비(이미지·드라이버·격리 네트워크)"
CASE=prepare
images=("$T85" "$T90" "$T101" "$T110" "$DB_IMAGE"); [ "$WITH_VAULT" = 1 ] && images+=("$VAULT_IMAGE")
for img in "${images[@]}"; do
  if ! docker image inspect "$img" > /dev/null 2>&1; then
    echo "   이미지 내려받기: $img"
    docker pull -q "$img" > /dev/null || die "이미지를 내려받지 못했습니다: $img"
    PULLED+=("$img")
  fi
done
mkdir -p "$WORK/lib" "$WORK/secure" "$WORK/jars" "$WORK/tokens" "$WORK/runs"
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
for v in "$DBPW" "$WRONGPW" "$PLAINPW" "$ROOTPW" "$RAWDUMMY"; do secret "$v"; done
printf 'crypto.key.source=file\ncrypto.key.id=ext01\ncrypto.key.file=/opt/java-crypto-kit/ext01.key\n' > "$WORK/secure/ext-file.properties"
printf 'crypto.pool.factory=%s\n' "$DBCPF" > "$WORK/secure/pool-dbcp2.properties"
printf 'crypto.pool.factory=%s\ncrypto.jvm.override.enabled=false\n' "$DBCPF" > "$WORK/secure/pool-dbcp2-locked.properties"
printf 'crypto.key.source=file\ncrypto.key.id=ext01\ncrypto.key.file=/opt/java-crypto-kit/no-such.key\n' > "$WORK/secure/missing-key.properties"
printf 'crypto.key.source=embedded\ncrypto.warnning.enabled=false\n' > "$WORK/secure/typo.properties"

section "1. 사용자 지정 키 JAR(CLI만 사용, 소스 수정·재빌드·외부 Properties 없음)"
CASE=company-jar
docker run -d --name "$WB" "${LABELS[@]}" --network "$NET" --entrypoint sleep "$T110" infinity > /dev/null || die "작업용 컨테이너를 시작하지 못했습니다."
docker exec "$WB" mkdir -p /w/jars /w/tokens /w/out
docker cp "$(hostpath "$JAR")" "$WB:/w/jars/public.jar" > /dev/null
docker cp "$WORKH/secure" "$WB:/opt/java-crypto-kit" > /dev/null
quiet wb sh -c 'cd /w && java -jar jars/public.jar keygen --out /opt/java-crypto-kit/company.key'; check $? "keygen(사용자 지정 키)"
quiet wb sh -c 'cd /w && java -jar jars/public.jar config embed-key --from-file /opt/java-crypto-kit/company.key --key-id corp01 --operator qa --reason "integration test" --yes --out jars/company.jar'
check $? "config embed-key: 사용자 지정 키 + 키ID corp01"
quiet wb sh -c "cd /w && java -jar jars/company.jar config set crypto.pool.factory=$TJF --operator qa --yes --out jars/company-tj.jar"
check $? "config set crypto.pool.factory=Tomcat JDBC Pool(키 내장 JAR에서 새 JAR)"
for k in ext01 env01; do quiet wb java -jar /w/jars/public.jar keygen --out "/opt/java-crypto-kit/$k.key" || fail "keygen($k)"; done
hist=$(wb java -jar /w/jars/company-tj.jar config history 2>&1)
[[ "$hist" == *"crypto.key.id: default -> corp01"* && "$hist" == *"crypto.key.embedded: (비공개) -> (교체됨)"* && "$hist" == *"crypto.pool.factory: $DBCPF -> $TJF"* ]]
check $? "config history: 키ID default→corp01, 키 (비공개)→(교체됨), Pool 변경"
fp_jar=$(wb java -jar /w/jars/company.jar fingerprint 2>/dev/null | grep SHA-256 | sed 's/.*: //')
fp_key=$(wb java -jar /w/jars/public.jar fingerprint --key-file /opt/java-crypto-kit/company.key 2>/dev/null | grep SHA-256 | sed 's/.*: //')
[ -n "$fp_jar" ] && [ "$fp_jar" = "$fp_key" ]; check $? "fingerprint: 키 내장 JAR의 키 = 키 파일"
doc=$(wb java -jar /w/jars/company.jar doctor 2>&1); rc=$?
[ $rc = 0 ] && [[ "$doc" != *"[WARN] 공개 기본 키"* ]]; check $? "doctor(키 내장 JAR): 종료 코드 0, 공개 키 WARN 없음"
doc=$(wb java -jar /w/jars/public.jar doctor 2>&1); rc=$?
[ $rc = 0 ] && [[ "$doc" == *"[WARN] 공개 기본 키"* ]]; check $? "doctor(공개 JAR): 공개 키 WARN, 종료 코드 0(FAIL 없음)"
wb java -jar /w/jars/company.jar doctor --config /opt/java-crypto-kit/missing-key.properties > /dev/null 2>&1; rc=$?
[ $rc = 1 ]; check $? "doctor(키 파일 없음): FAIL, 종료 코드 1"

section "2. 실제 CLI encrypt·decrypt·rekey(가상 터미널) - 암호문은 임시 파일에만 저장"
CASE=cli
export QA_ENV_KEY; QA_ENV_KEY=$(docker exec "$WB" cat /opt/java-crypto-kit/env01.key | tr -d '\r\n')
cat > "$WORK/gen-tokens.sh" << 'GEN'
#!/bin/sh
# 안내 문구가 나온 뒤(입력 숨김 상태) 값을 입력한다. 평문·암호문은 화면에 출력하지 않는다.
PUB=/w/jars/public.jar; COMP=/w/jars/company.jar
enc() {
  name="$1"; value="$2"; shift 2
  (sleep 3; printf '%s\n' "$value") | script -qec "java $* encrypt" /dev/null > "/tmp/$name.out" 2>&1
  tr -d '\r' < "/tmp/$name.out" | grep -oE '(ENC\[v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\]|B64\[[A-Za-z0-9+/=_-]+\])' | head -1 > "/w/tokens/$name"
  echo "$name echo=$(grep -cF -- "$value" "/tmp/$name.out")"
  rm -f "/tmp/$name.out"
}
enc CORP_PW "$DBPW" -jar $COMP
enc CORP_USER "qa_app" -jar $COMP
enc CORP_WRONG "$WRONGPW" -jar $COMP
enc CORP_B64 "$DBPW" -Dcrypto.output.encoding=base64 -jar $COMP
enc PUB_PW "$DBPW" -jar $PUB
enc FORGED "$DBPW" -Dcrypto.key.id=corp01 -jar $PUB
enc EXT_PW "$DBPW" -Dcrypto.config.file=/opt/java-crypto-kit/ext-file.properties -jar $COMP
enc ENV_PW "$DBPW" -Dcrypto.key.source=env -Dcrypto.key.env=QA_ENV_KEY -Dcrypto.key.id=env01 -jar $COMP
(sleep 3; printf 'SHOW\n'; sleep 1; cat /w/tokens/CORP_PW) | script -qec "java -jar $COMP decrypt" /dev/null > /tmp/d.out 2>&1
echo "decrypt-show=$(grep -cF -- "$DBPW" /tmp/d.out)"
(sleep 3; printf 'no\n') | script -qec "java -jar $COMP decrypt" /dev/null > /tmp/c.out 2>&1
echo "decrypt-cancel=$(grep -cF -- "$DBPW" /tmp/c.out)"
rm -f /tmp/d.out /tmp/c.out
java -jar $COMP rekey --from-jar $PUB --value "$(cat /w/tokens/PUB_PW)" > /w/tokens/REKEY_PW 2> /dev/null
echo "rekey=$?"
GEN
docker cp "$WORKH/gen-tokens.sh" "$WB:/w/gen-tokens.sh" > /dev/null
gen=$(wb sh /w/gen-tokens.sh 2>&1)
docker cp "$WB:/w/tokens/." "$WORKH/tokens/" > /dev/null
for t in CORP_PW CORP_USER CORP_WRONG CORP_B64 PUB_PW FORGED EXT_PW ENV_PW REKEY_PW; do
  v=$(tr -d '\r\n' < "$WORK/tokens/$t" 2> /dev/null); printf -v "$t" '%s' "$v"; secret "$v"
done
[ "$(grep -c 'echo=0' <<< "$gen")" = 8 ]; check $? "encrypt 8회: 입력한 평문이 화면에 보이지 않음"
[[ "$CORP_PW" == "ENC[v1:corp01:"* && "$CORP_USER" == "ENC[v1:corp01:"* && "$CORP_WRONG" == "ENC[v1:corp01:"* && "$CORP_B64" == "B64["* \
   && "$PUB_PW" == "ENC[v1:default:"* && "$FORGED" == "ENC[v1:corp01:"* && "$EXT_PW" == "ENC[v1:ext01:"* && "$ENV_PW" == "ENC[v1:env01:"* \
   && "$REKEY_PW" == "ENC[v1:corp01:"* ]]
check $? "암호문 키ID: 사용자 지정 corp01·공개 default·위조(공개 키+corp01)·외부 ext01/env01·rekey 결과 corp01·B64 포장"
grep -q '^decrypt-show=1$' <<< "$gen"; check $? "decrypt: 경고 후 SHOW 입력 시에만 평문 표시"
grep -q '^decrypt-cancel=0$' <<< "$gen"; check $? "decrypt: 취소하면 평문 미표시"
grep -q '^rekey=0$' <<< "$gen"; check $? "rekey: 공개 키 암호문 → 사용자 지정 키 암호문"
pre="${CORP_PW%:*}"; idx=$(( ${#pre} + 2 )); c="${CORP_PW:$idx:1}"; n=A; [ "$c" = A ] && n=B
TAMPERED="${CORP_PW:0:$idx}$n${CORP_PW:$((idx + 1))}"; secret "$TAMPERED"
docker cp "$WB:/w/jars/." "$WORKH/jars/" > /dev/null
docker cp "$WB:/opt/java-crypto-kit/." "$WORKH/secure/" > /dev/null
for k in company ext01 env01; do secret "$(tr -d '\r\n' < "$WORK/secure/$k.key")"; done
v8=$(T="$CORP_PW" P="$PUB_PW" F="$FORGED" docker run --rm "${LABELS[@]}" --network none -v "$WORKH/jars:/j:ro" -e T -e P -e F --entrypoint sh "$T85" -c '
  java -jar /j/company.jar verify --value "$T" > /dev/null 2>&1; echo "ok=$?"
  java -jar /j/company.jar verify --value "$P" 2>&1 | grep -c "KEY_ID_MISMATCH" | sed "s/^/public=/"
  java -jar /j/company.jar verify --value "$F" 2>&1 | grep -c "INTEGRITY" | sed "s/^/forged=/"' 2>&1)
grep -q '^ok=0$' <<< "$v8"; check $? "JDK 21에서 만든 암호문을 JDK 8에서 verify"
grep -q '^public=1$' <<< "$v8" && grep -q '^forged=1$' <<< "$v8"; check $? "키 내장 JAR: 공개 키 암호문 KEY_ID_MISMATCH, 위조 암호문 INTEGRITY"

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
EXP_NAMES=(); EXP_VALUES=()
expect() { EXP_NAMES=(); EXP_VALUES=(); while [ $# -gt 1 ]; do EXP_NAMES+=("$1"); EXP_VALUES+=("$2"); shift 2; done; }
WEMB_RE='JAR 내장 키\(embedded\)를 사용 중입니다|A JAR built-in key \(embedded\) is in use'
WPUB_RE='공개 기본 키를 사용 중입니다|The public default key is in use'
MATRIX="$RES/matrix.txt"; : > "$MATRIX"
# run_case <id> <image> <jar> <context.xml Resource들> <기대 경고 "내장:공개" 또는 -> [docker create 옵션...]
#   선택 변수: EXTRA_CLASSES(웹앱 WEB-INF/classes에 넣을 폴더), SERVER_XML, SETENV, RUN_DS(실제 테이블 SELECT·INSERT로 확인할 JNDI 이름)
run_case() {
  local id="$1" image="$2" jar="$3" resources="$4" warn="$5"; shift 5
  CASE="$id"
  local before=${#FAILS[@]}
  local name="$P-tc-$id" app="$WORK/runs/$id"
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
  local up=1 code i
  for i in $(seq 1 90); do
    code=$(docker exec "$name" curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/jck-qa/jck-qa.jsp?ds=probe" 2> /dev/null)
    case "$code" in 200|403|404|500) up=0; break ;; esac
    sleep 1
  done
  local tv; tv=$(docker exec "$name" sh -c 'echo "Tomcat $TOMCAT_VERSION / Java $(java -version 2>&1 | head -1 | cut -d\" -f2)"' 2> /dev/null)
  echo "--- [$id] $tv, JAR=$(basename "$jar")"
  check $up "Tomcat 기동"
  local k ds exp out result=PASS
  for k in "${!EXP_NAMES[@]}"; do
    ds="${EXP_NAMES[$k]}"; exp="${EXP_VALUES[$k]}"
    out=$(docker exec "$name" curl -s "http://127.0.0.1:8080/jck-qa/jck-qa.jsp?ds=$ds")
    case "$exp" in
      OK\ *) if [[ "$out" == "OK ds=$ds pool=${exp#OK } db=MariaDB result=1" ]]; then pass "$ds → $out"; else fail "$ds: 기대 OK(${exp#OK }) / 실제 ${out:-응답 없음}"; result=FAIL; fi ;;
      FAIL\ *) if [[ "$out" == FAIL* && "$out" == *"${exp#FAIL }"* ]]; then pass "$ds → $out"; else fail "$ds: 기대 FAIL(${exp#FAIL }) / 실제 ${out:-응답 없음}"; result=FAIL; fi ;;
    esac
  done
  if [ -n "${RUN_DS:-}" ]; then
    INSERT_RUNS+=("$id")
    out=$(docker exec "$name" curl -s "http://127.0.0.1:8080/jck-qa/jck-qa.jsp?ds=$RUN_DS&run=$id")
    if [[ "$out" == "OK ds=$RUN_DS pool="*" db=MariaDB result=1 marker=java-crypto-kit-qa user=qa_app@% inserted=1" ]]; then
      pass "$RUN_DS 실제 테이블 SELECT·INSERT → $out"
    else fail "$RUN_DS 실제 테이블 SELECT·INSERT: 실제 ${out:-응답 없음}"; result=FAIL; fi
  fi
  local logs leaks cmdline wemb wpub fakes
  logs=$(docker logs "$name" 2>&1)
  leaks=$(printf '%s\n' "$logs" | grep -v 'Command line argument:' | grep -cFf "$SECRETS")
  cmdline=$(printf '%s\n' "$logs" | grep 'Command line argument:' | grep -cFf "$SECRETS")
  wemb=$(printf '%s\n' "$logs" | grep -cE "$WEMB_RE"); wpub=$(printf '%s\n' "$logs" | grep -cE "$WPUB_RE")
  fakes=$(printf '%s\n' "$logs" | grep -c FAKE_POOL_FACTORY_CALLED)
  [ "$leaks" = 0 ]; check $? "Tomcat 로그의 비밀값(평문·키·토큰·암호문) 노출 ${leaks}건"
  [ "$cmdline" != 0 ] && echo "   참고: Tomcat 자체 'Command line argument' 로그에 -D 값 ${cmdline}줄(키 원문 -D를 금지하는 이유)"
  if [ "$warn" != "-" ]; then [ "$wemb:$wpub" = "$warn" ]; check $? "키 안내 WARNING(내장 키:공개 키) = $wemb:$wpub (기대 $warn)"; fi
  if [ -n "${EXTRA_CLASSES:-}" ]; then [ "$fakes" = 0 ]; check $? "웹앱의 같은 이름 가짜 Pool Factory 호출 ${fakes}건"; fi
  if [ "$leaks" = 0 ]; then printf '%s\n' "$logs" | grep -F '[java-crypto-kit]' > "$RES/tomcat-logs/$id.txt"
  else echo "비밀값 노출이 발견되어 로그를 저장하지 않음" > "$RES/tomcat-logs/$id.txt"; fi
  [ "$up" = 0 ] || result=FAIL
  [ "${#FAILS[@]}" -gt "$before" ] && result=FAIL
  echo "$id | $tv | $result" >> "$MATRIX"
  docker rm -f -v "$name" > /dev/null 2>&1
  unset EXTRA_CLASSES SERVER_XML SETENV RUN_DS
}

section "4. Tomcat 8.5/9.0/10.1/11.0 × DBCP2/Tomcat JDBC Pool - 키 내장 JAR만(-D·외부 Properties 없음)"
matrix_resources() { # <Pool 속성>
  res jdbc/qa "$CORP_PW" "$1"; res jdbc/qaEncUser "$CORP_PW" "$1" "$CORP_USER"; res jdbc/qaB64 "$CORP_B64" "$1"
  res jdbc/qaRekeyed "$REKEY_PW" "$1"; res jdbc/qaPublicToken "$PUB_PW" "$1"; res jdbc/qaForged "$FORGED" "$1"
  res jdbc/qaTampered "$TAMPERED" "$1"; res jdbc/qaPlain "$PLAINPW" "$1"; res jdbc/qaWrongDbPw "$CORP_WRONG" "$1"
  res jdbc/qaNoFactory "$CORP_PW" "$1" qa_app ""
}
matrix_expect() { # <Pool 클래스> <오류 메시지의 Pool 이름>
  expect jdbc/qa "OK $1" jdbc/qaEncUser "OK $1" jdbc/qaB64 "OK $1" jdbc/qaRekeyed "OK $1" \
    jdbc/qaPublicToken "FAIL [사유: KEY_ID_MISMATCH]" jdbc/qaForged "FAIL [사유: INTEGRITY]" jdbc/qaTampered "FAIL [사유: INTEGRITY]" \
    jdbc/qaPlain "FAIL [사유: PLAINTEXT_PASSWORD]" jdbc/qaWrongDbPw "FAIL [사유: POOL_FAILURE] Connection Pool($2) 생성에 실패했습니다" \
    jdbc/qaNoFactory "FAIL ds=jdbc/qaNoFactory"
}
for image in "$T85" "$T90" "$T101" "$T110"; do
  v=$(echo "$image" | cut -d: -f2 | cut -d- -f1)
  matrix_expect "$POOL_D" DBCP2; RUN_DS=jdbc/qa
  run_case "M-$v-dbcp2" "$image" "$WORK/jars/company.jar" "$(matrix_resources "$ATTR_D")" 1:0
  matrix_expect "$POOL_T" "Tomcat JDBC Pool"; RUN_DS=jdbc/qa
  run_case "M-$v-tomcat-jdbc" "$image" "$WORK/jars/company-tj.jar" "$(matrix_resources "$ATTR_T")" 1:0
done

section "5. 설정 우선순위(JVM -D > 외부 Properties > JAR 내부) · 키 공급 · 오류·보안"
COMP="$WORK/jars/company.jar"; COMPTJ="$WORK/jars/company-tj.jar"; PUB="$WORK/jars/public.jar"
R_EXT="$(res jdbc/qaExt "$EXT_PW" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")"
R_QA="$(res jdbc/qa "$CORP_PW" "$ATTR_X")"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"
run_case E01-external-by-jvm-property "$T101" "$COMP" "$R_EXT" 0:0 -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/ext-file.properties"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"
run_case E02-external-by-env-var-tomcat8.5 "$T85" "$COMP" "$R_EXT" 0:0 -e "CRYPTO_CONFIG_FILE=/opt/java-crypto-kit/ext-file.properties"
expect jdbc/qa "OK $POOL_D"
run_case E03-external-over-jar "$T101" "$COMPTJ" "$R_QA" 1:0 -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2.properties"
expect jdbc/qa "OK $POOL_T"
run_case E04-jvm-over-external "$T101" "$COMPTJ" "$R_QA" 1:0 \
  -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2.properties -Dcrypto.pool.factory=$TJF"
expect jdbc/qa "OK $POOL_D"
run_case E05-jvm-override-disabled "$T101" "$COMPTJ" "$R_QA" 1:0 \
  -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/pool-dbcp2-locked.properties -Dcrypto.pool.factory=$TJF -Dcrypto.jvm.override.enabled=true"
printf '%s\n' 'CATALINA_OPTS="$CATALINA_OPTS -Dcrypto.key.source=file -Dcrypto.key.file=/opt/java-crypto-kit/ext01.key -Dcrypto.key.id=ext01"' 'export CATALINA_OPTS' > "$WORK/setenv.sh"
expect jdbc/qaExt "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"; SETENV="$WORK/setenv.sh"
run_case E06-jvm-only-file-key-setenv-tomcat9 "$T90" "$COMP" "$R_EXT" 0:0
expect jdbc/qaEnv "OK $POOL_D"
run_case E07-env-key-tomcat11 "$T110" "$COMP" "$(res jdbc/qaEnv "$ENV_PW" "$ATTR_X")" 0:0 -e QA_ENV_KEY \
  -e "CATALINA_OPTS=-Dcrypto.key.source=env -Dcrypto.key.env=QA_ENV_KEY -Dcrypto.key.id=env01"
expect jdbc/qa "OK $POOL_D" jdbc/qaPublicToken "FAIL [reason: KEY_ID_MISMATCH]"
run_case E08-lang-en "$T101" "$COMP" "$(res jdbc/qa "$CORP_PW" "$ATTR_X")
$(res jdbc/qaPublicToken "$PUB_PW" "$ATTR_X")" 1:0 -e "CATALINA_OPTS=-Dcrypto.lang=en"
expect jdbc/qa "OK $POOL_D"
run_case E09-warning-off "$T101" "$COMP" "$R_QA" 0:0 -e "CATALINA_OPTS=-Dcrypto.warning.enabled=false"
expect jdbc/qaPublic "OK $POOL_D" jdbc/qa "FAIL [사유: KEY_ID_MISMATCH]"
run_case E10-public-jar "$T101" "$PUB" "$(res jdbc/qaPublic "$PUB_PW" "$ATTR_X")
$(res jdbc/qa "$CORP_PW" "$ATTR_X")" 0:1
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E11-raw-key-by-jvm-rejected "$T101" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.key.embedded=$RAWDUMMY"
expect jdbc/qaExt "FAIL [사유: KEY_SOURCE]" jdbc/qa "FAIL ds=jdbc/qa "
run_case E12-missing-key-fail-closed "$T101" "$COMP" "$R_EXT" - -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/missing-key.properties"
expect jdbc/qa "FAIL [사유: CONFIGURATION]"
run_case E13-jvm-typo-fail-closed "$T110" "$COMP" "$R_QA" - -e "CATALINA_OPTS=-Dcrypto.key.soruce=file"
expect jdbc/qa "OK $POOL_D"
run_case E14-unrelated-crypto-policy "$T90" "$COMP" "$R_QA" 1:0 -e "CATALINA_OPTS=-Dcrypto.policy=unlimited"
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
  run_case "E17-trust-$v-dbcp2" "$image" "$COMP" "$(res jdbc/qa "$CORP_PW" "$ATTR_D")" 1:0
  expect jdbc/qa "OK $POOL_T"; EXTRA_CLASSES="$WORK/fake-classes"
  run_case "E17-trust-$v-tomcat-jdbc" "$image" "$COMPTJ" "$(res jdbc/qa "$CORP_PW" "$ATTR_T")" 1:0
done

# server.xml GlobalNamingResources + ResourceLink
for spec in "$T101|$COMP|$POOL_D|$ATTR_D" "$T85|$COMPTJ|$POOL_T|$ATTR_T"; do
  IFS='|' read -r image jar pool attr <<< "$spec"; v=$(echo "$image" | cut -d: -f2 | cut -d- -f1)
  sx="$WORK/server-$v.xml"
  docker run --rm "${LABELS[@]}" --network none --entrypoint cat "$image" /usr/local/tomcat/conf/server.xml > "$sx.orig"
  awk -v line="$(res jdbc/qaGlobal "$CORP_PW" "$attr")" '{print} /<GlobalNamingResources>/{print line}' "$sx.orig" > "$sx"
  expect jdbc/linked "OK $pool"; SERVER_XML="$sx"
  run_case "E18-global-resource-link-$v" "$image" "$jar" '  <ResourceLink name="jdbc/linked" global="jdbc/qaGlobal" type="javax.sql.DataSource"/>' 1:0
done

if [ "$WITH_VAULT" = 1 ]; then
  section "6. HashiCorp Vault 1.21.4 실서버(dev TLS, KV v2) - --with-vault"
  CASE=vault
  export VAULT_DEV_ROOT_TOKEN_ID="qa-root-$(rand 10)" VAULT_TOKEN; VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID"; secret "$VAULT_DEV_ROOT_TOKEN_ID"
  docker run -d --name "$VAULT" "${LABELS[@]}" --network "$NET" --network-alias jck-qa-vault --tmpfs /vault/file --tmpfs /vault/logs \
    --tmpfs /vault/tls:rw,mode=1777 -e SKIP_SETCAP=true -e VAULT_DEV_ROOT_TOKEN_ID -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
    "$VAULT_IMAGE" server -dev -dev-tls -dev-tls-san=jck-qa-vault -dev-tls-cert-dir=/vault/tls > /dev/null || die "Vault 컨테이너를 시작하지 못했습니다."
  vx() { docker exec -i -e VAULT_ADDR=https://jck-qa-vault:8200 -e VAULT_CACERT=/vault/tls/vault-ca.pem -e VAULT_TOKEN "$VAULT" vault "$@"; }
  up=1; for i in $(seq 1 60); do vx status > /dev/null 2>&1 && { up=0; break; }; sleep 1; done
  check $up "Vault 기동(TLS)"
  docker exec "$VAULT" cat /vault/tls/vault-ca.pem > "$WORK/secure/vault-ca.pem"
  for k in v1 v2; do wb java -jar /w/jars/public.jar keygen --out "/w/out/vault-$k.key" > /dev/null; done
  docker cp "$WB:/w/out/." "$WORKH/secure/" > /dev/null
  for k in v1 v2; do secret "$(tr -d '\r\n' < "$WORK/secure/vault-$k.key")"; tr -d '\r\n' < "$WORK/secure/vault-$k.key" | vx kv put -mount=secret java-crypto-kit/qa key=- > /dev/null; done
  check $? "KV v2 버전 1·2 저장"
  printf 'path "secret/data/java-crypto-kit/qa" {\n  capabilities = ["read"]\n}\n' | vx policy write jck-qa-read - > /dev/null
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
  docker exec "$WB" rm -rf /opt/java-crypto-kit; docker cp "$WORKH/secure" "$WB:/opt/java-crypto-kit" > /dev/null
  vdoc() { # <설정 이름> <기대 종료 코드> <기대 문구>
    local outv rc; outv=$(wb java -jar /w/jars/company.jar doctor --config "/opt/java-crypto-kit/vault-$1.properties" 2>&1); rc=$?
    [ "$rc" = "$2" ] && [[ "$outv" == *"$3"* ]]; check $? "doctor vault-$1: 종료 코드 $rc, '$3'"
    ! grep -qFf "$SECRETS" <<< "$outv" || fail "doctor vault-$1 출력에 비밀값"
  }
  vdoc good 0 "PASS"; vdoc v1 0 "PASS"; vdoc envtoken 0 "PASS"
  vdoc limited 1 "읽을 권한이 없습니다"; vdoc bad 1 "인증을 거부했습니다"; vdoc noca 1 "TLS 인증서를 신뢰할 수 없거나"
  vdoc wrongpath 1 "crypto.vault.path가 맞는지도 확인하세요"; vdoc v9 1 "찾지 못했습니다"
  fpv() { wb java -jar /w/jars/company.jar fingerprint "$@" 2> /dev/null | grep SHA-256 | sed 's/.*: //'; }
  [ -n "$(fpv --config /opt/java-crypto-kit/vault-good.properties)" ] \
    && [ "$(fpv --config /opt/java-crypto-kit/vault-good.properties)" = "$(fpv --key-file /opt/java-crypto-kit/vault-v2.key)" ] \
    && [ "$(fpv --config /opt/java-crypto-kit/vault-v1.properties)" = "$(fpv --key-file /opt/java-crypto-kit/vault-v1.key)" ]
  check $? "버전 미지정 = 최신(v2) 키, crypto.vault.ver=1 = v1 키(지문 비교)"
  wb sh -c '(sleep 3; printf "%s\n" "$DBPW") | script -qec "java -Dcrypto.config.file=/opt/java-crypto-kit/vault-good.properties -jar /w/jars/company.jar encrypt" /dev/null 2>&1 | tr -d "\r" | grep -oE "ENC\[v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\]" | head -1 > /w/tokens/VAULT_PW'
  docker cp "$WB:/w/tokens/VAULT_PW" "$WORKH/tokens/VAULT_PW" > /dev/null
  VAULT_PW=$(tr -d '\r\n' < "$WORK/tokens/VAULT_PW"); secret "$VAULT_PW"
  [[ "$VAULT_PW" == "ENC[v1:vault02:"* ]]; check $? "Vault 키로 CLI encrypt"
  expect jdbc/qaVault "OK $POOL_D"; RUN_DS=jdbc/qaVault
  run_case G01-vault-key-tomcat10.1 "$T101" "$COMP" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_D")" 0:0 \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-good.properties"
  expect jdbc/qaVault "FAIL 읽을 권한이 없습니다"
  run_case G02-vault-limited-token "$T101" "$COMP" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_D")" - \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-limited.properties"
  expect jdbc/qaVault "OK $POOL_T"; RUN_DS=jdbc/qaVault
  run_case G03-vault-env-token-tomcat8.5 "$T85" "$COMPTJ" "$(res jdbc/qaVault "$VAULT_PW" "$ATTR_T")" 0:0 -e QA_VAULT_TOKEN \
    -e "CATALINA_OPTS=-Dcrypto.config.file=/opt/java-crypto-kit/vault-envtoken.properties"
fi

section "7. 결과 확인"
CASE=summary
# 실제 테이블 INSERT 대조: 시나리오 설계(8개 조합 각 1건, --with-vault면 G01·G03 각 1건 추가)와
# run_case가 INSERT를 요청한 실행 목록, MariaDB의 실행별 행 수가 모두 일치해야 한다(누락·중복·예상 밖 행 0).
design_runs=8; [ "$WITH_VAULT" = 1 ] && design_runs=10
[ "${#INSERT_RUNS[@]}" = "$design_runs" ]
check $? "INSERT 시나리오 ${#INSERT_RUNS[@]}개(설계 $design_runs개: 8개 조합$([ "$WITH_VAULT" = 1 ] && echo ' + Vault 2'))"
want=$(for r in "${INSERT_RUNS[@]}"; do echo "$r 1"; done | sort)
got=$(docker exec -e MYSQL_PWD "$DB" mariadb -uqa_app qadb -N -e "SELECT run, COUNT(*) FROM qa_log GROUP BY run" 2> /dev/null \
  | tr '\t' ' ' | sed '/^$/d' | sort)
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  pass "MariaDB 실제 행 대조: 실행 ${#INSERT_RUNS[@]}개 모두 정확히 1건(누락·중복·예상 밖 행 없음)"
else
  fail "MariaDB 실제 행 대조 불일치 - 기대: $(echo "$want" | tr '\n' ';') / 실제: $(echo "${got:-없음}" | tr '\n' ';')"
fi
leak_files=$(grep -rlFf "$SECRETS" "$RES" 2> /dev/null | wc -l | tr -d ' ')
[ "$leak_files" = 0 ]; check $? "결과 폴더에 비밀번호·키·토큰·암호문 없음(파일 ${leak_files}개)"
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
