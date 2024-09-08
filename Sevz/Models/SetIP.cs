using Sevz.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public static class SetIP
{
    private static string savedIp = string.Empty;
    public static void SetIp()
    {
        Console.Write("IP 주소를 입력하세요: ");
        string ip = Console.ReadLine();

        if (IsValidIp(ip))
        {
            savedIp = ip;
            Console.WriteLine($"IP 주소가 {savedIp}로 설정되었습니다.");
        }
        else
        {
            Console.WriteLine("잘못된 IP 형식입니다. 다시 시도하세요.");
        }
    }


    public static string GetSavedIp()
    {
        // 사용자가 입력한 IP가 있으면 해당 값을 반환, 없으면 기본 IP를 반환
        return !string.IsNullOrEmpty(savedIp) ? savedIp : PasswordService.GetIPAddress();
    }

    // 기본 IP만 반환하는 메서드 (변경 전 기본값)
    public static string GetDefaultIp()
    {
        return PasswordService.GetIPAddress(); // 기본 IP를 반환
    }

    private static bool IsValidIp(string ip)
    {
        //IP 유효성 검사
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