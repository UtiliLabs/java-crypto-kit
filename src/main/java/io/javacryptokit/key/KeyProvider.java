package io.javacryptokit.key;

import io.javacryptokit.config.CryptoSettings;
import java.io.IOException;
import java.util.List;

/**
 * <b>내부 확장 지점(공개 API 아님)</b>: 로컬 AES-256 데이터 키를 공급하는 공급원 하나의 계약이다.
 *
 * <p><b>책임 경계</b>: 공급원은 "32바이트 키를 어디에서 어떻게 가져오는지"만 안다(파일·환경변수·Vault·AWS KMS 등). 키 길이
 * 검증·공개 키 경고는 {@link KeyResolver}가, 암복호화는 {@code core.CredentialCipher}가 맡는다. 그래서 새 공급원을 추가해도
 * AES-GCM 구현·Tomcat Factory·CLI 암복호화 명령을 바꾸지 않는다. 인증·네트워크 코드는 해당 공급원 안에만 둔다.</p>
 *
 * <p><b>등록 방식</b>: 공급원은 {@link KeyResolver}의 고정 등록표에만 추가한다. 설정 문자열(클래스 이름)로 임의 공급원을
 * 로딩하지 않는다. 새 공급원 이름은 {@code config.SettingCatalog.KEY_SOURCES}에도 추가한다.</p>
 *
 * <p><b>이 계약으로 처리할 수 없는 경우</b>: Vault Transit·HSM(PKCS#11)처럼 키가 장치 밖으로 나오지 않는 방식은 로컬 키를
 * 돌려줄 수 없으므로 이 계약이 아니라 "원격 암복호화 실행" 계약을 따로 두어야 한다(현재 미구현, 향후 확장 대상).</p>
 *
 * <p><b>자원</b>: 공급원은 연결·스레드 같은 자원을 보관하지 않는다(요청마다 열고 닫는다). 그래서 별도 종료 절차가 없다.
 * 원격 공급원의 키는 {@code core.CryptoService} 인스턴스가 처음 한 번만 조회해 재사용한다(JDBC 연결마다 조회하지 않음).</p>
 */
public interface KeyProvider {
    /** @return {@code crypto.key.source}에 쓰는 공급원 이름 */
    String source();

    /**
     * 공급원에서 키를 읽는다. 실패하면 내장 키 등 다른 키로 바꾸지 않고 예외로 끝낸다(Fail Closed).
     *
     * @param settings 검증된 설정
     * @return 원시 키 바이트(호출자가 길이를 검증하고 사용 후 지운다)
     * @throws IOException              파일·네트워크 입출력 실패(메시지는 버리고 종류만 쓴다)
     * @throws IllegalArgumentException 설정·형식 문제({@code config.SafeMessageException}이면 고정 문구)
     */
    byte[] loadKey(CryptoSettings settings) throws IOException;

    /**
     * 키 위치를 비밀값 없이 설명한다({@code info}·{@code doctor}·{@code fingerprint}용). 파일은 이름만, 환경변수는 이름만 쓴다.
     *
     * @param settings 검증된 설정
     * @return 현재 메시지 언어의 설명
     */
    String describe(CryptoSettings settings);

    /** @return 네트워크로 키를 가져오는 원격 공급원이면 true(서비스 인스턴스 단위로 한 번만 조회한다) */
    boolean remote();

    /**
     * 네트워크 없이 확인할 수 있는 준비 상태를 점검한다({@code doctor}, {@code doctor --offline}). 키 값은 읽거나 출력하지 않는다
     * (파일은 존재·종류·권한만, 환경변수는 존재 여부만).
     *
     * @param settings 검증된 설정
     * @return 점검 결과 목록(문제가 없으면 PASS·INFO)
     */
    List<Diagnostic> offlineChecks(CryptoSettings settings);
}
