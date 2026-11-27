package io.javacryptokit.cli;

import java.nio.file.Path;

/**
 * <b>내부 구현 클래스</b>: 이번 CLI 실행의 관리자 비밀번호 확인 창구. 실제 실행은 {@link AdminAccess}를 쓰고, 시험은 같은 계약의
 * 가짜 구현을 넣어 명령별 동작만 따로 확인한다(제품 코드에는 인증을 건너뛰는 구현이 없다).
 */
interface AdminGate extends AutoCloseable {
    /** @return 실행 중인 CLI JAR의 관리자 비밀번호 상태 */
    AdminPassword.Status status();

    /** @return 실행 중인 CLI JAR(클래스 폴더에서 실행 중이면 null) */
    Path cliJar();

    /**
     * 민감 명령의 관리자 인증: 실행 중인 CLI JAR의 관리자 비밀번호를 확인하고, 이번 명령이 바꾸는 다른 JAR({@code target})·키를
     * 꺼내 쓰는 다른 JAR({@code source})이 관리자 비밀번호를 지원하면 그 JAR의 비밀번호도 따로 확인한다(실행 중인 JAR의 인증으로
     * 대신하지 않음). 실패·취소하면 예외로 끝나며 호출자는 아무 작업도 하지 않는다.
     *
     * @param parsed    해석한 인자({@code --admin-pass-file} 확인)
     * @param terminals 대화형 터미널
     * @param target    이번 명령이 바꾸는 다른 JAR(없으면 null, 실행 중인 JAR와 같으면 한 번만 확인)
     * @param source    키를 꺼내 쓰는 다른 JAR(없으면 null)
     * @throws CryptoCli.CliException 인증 실패·취소·비대화형인데 비밀번호 파일 없음·대상 JAR 미설정/손상
     */
    void authenticate(CliCommands.Parsed parsed, CryptoCli.TerminalProvider terminals, Path target, Path source)
            throws CryptoCli.CliException;

    /**
     * 인증 없이 키만 쓰는 다른 JAR({@code rekey --to-jar}: 새 암호문을 만들 뿐 바꾸지 않음)의 무결성 확인. 관리자 검증값·변경 이력이
     * 손상된 JAR({@link AdminPassword.State#DAMAGED})은 정상 설정으로 보지 않고 거부한다(그 JAR의 비밀번호는 묻지 않음).
     *
     * @throws CryptoCli.CliException 손상(INTEGRITY) 또는 읽을 수 없음
     */
    void checkIntact(Path jar) throws CryptoCli.CliException;

    /** @return 이번 실행에서 실행 중인 CLI JAR의 관리자 인증을 마쳤으면 true */
    boolean authenticated();

    /**
     * @return 이번 실행에서 확인한 CLI JAR 관리자 비밀번호(비밀번호 변경 때 "현재와 같은 새 비밀번호"를 거부하는 데만 쓴다). 인증 전이면
     *         null. 돌려준 배열은 바꾸거나 보관하지 않는다.
     */
    char[] verifiedPassword();

    /** 인증 때 확인한 JAR 상태. 시험용 인증 창구는 지정된 시험 JAR을 읽는다. */
    default JarConfigEditor.Snapshot snapshot(Path jar) throws CryptoCli.CliException {
        return JarConfigEditor.read(jar);
    }

    /** 이번 실행에서 받은 비밀번호를 메모리에서 지운다. */
    @Override
    void close();
}
