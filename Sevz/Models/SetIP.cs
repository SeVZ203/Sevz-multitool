using Sevz.Services;
using System;

public static class SetIP
{
    private static string savedIp = string.Empty;

    // IP 주소를 설정하는 메서드 (매개변수 포함)
    public static void SetIp(string ipAddress)
    {
        if (IsValidIp(ipAddress))
        {
            savedIp = ipAddress;
            Console.WriteLine($"IP 주소가 {savedIp}로 설정되었습니다.");
        }
        else
        {
            Console.WriteLine("유효하지 않은 IP 주소입니다. 다시 시도하세요.");
        }
    }

    // 사용자 입력으로 IP 주소를 설정하는 메서드 (매개변수 없음)
    public static void SetIp()
    {
        Console.Write("IP 주소를 입력하세요: ");
        string ipAddress = Console.ReadLine();
        SetIp(ipAddress); // 유효성 검사 및 저장을 위한 메서드 호출
    }

    // 저장된 IP를 반환하는 메서드
    public static string GetSavedIp()
    {
        return !string.IsNullOrEmpty(savedIp) ? savedIp : GetDefaultIp();
    }

    // 기본 IP를 반환하는 메서드 (PasswordService에서 가져오기)
    public static string GetDefaultIp()
    {
        return PasswordService.GetIPAddress(); // PasswordService에서 기본 IP 가져오기
    }

    // IP 주소 유효성 검사 메서드
    private static bool IsValidIp(string ip)
    {
        string[] parts = ip.Split('.');
        if (parts.Length != 4) return false;

        foreach (string part in parts)
        {
            if (!int.TryParse(part, out int num) || num < 0 || num > 255)
            {
                return false;
            }
        }
        return true;
    }
}
