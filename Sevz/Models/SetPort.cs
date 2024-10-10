using Sevz.Services;
using System;

public static class SetPort
{
    private static string savedPort = string.Empty;

    // 포트 번호를 설정하는 메서드 (매개변수 포함)
    public static void SetPORT(string portNumber)
    {
        if (IsValidPort(portNumber))
        {
            savedPort = portNumber;
            Console.WriteLine($"포트 번호가 {savedPort}로 설정되었습니다.");
        }
        else
        {
            Console.WriteLine("유효하지 않은 포트 번호입니다. 다시 시도하세요.");
        }
    }

    // 사용자 입력으로 포트 번호를 설정하는 메서드 (매개변수 없음)
    public static void SetPORT()
    {
        Console.Write("포트 번호를 입력하세요: ");
        string portNumber = Console.ReadLine();
        SetPORT(portNumber); // 유효성 검사 및 저장을 위한 메서드 호출
    }

    // 저장된 포트 번호를 반환하는 메서드
    public static string GetSavedPort()
    {
        return !string.IsNullOrEmpty(savedPort) ? savedPort : GetDefaultPort();
    }

    // 기본 포트 번호를 반환하는 메서드 (PasswordService에서 가져오기)
    public static string GetDefaultPort()
    {
        return PasswordService.GetPort(); // PasswordService에서 기본 포트 가져오기
    }

    // 포트 번호 유효성 검사 메서드
    private static bool IsValidPort(string port)
    {
        if (int.TryParse(port, out int portNum))
        {
            // 포트 번호가 0 이상 65535 이하인 경우 유효
            return portNum >= 0 && portNum <= 65535;
        }
        return false; // 숫자로 변환할 수 없는 경우 유효하지 않음
    }
}
