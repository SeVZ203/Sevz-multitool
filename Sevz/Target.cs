using System;

public static class Target
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
        return savedIp;
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