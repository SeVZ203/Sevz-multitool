using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public static class SetPort
{
    private static string savedPort = string.Empty;
    public static void SetPORT()
    {
            Console.Write("Port를 입력하세요 : ");
            string port = Console.ReadLine();

            if (IsValidPort(port))
            {
                savedPort = port;
                Console.WriteLine($"Port 주소가 {savedPort}로 설정되었습니다");
            }
            else
            {
                Console.WriteLine("잘못된 Port입니다, 다시 시도하세요.");
            }
        }
    public static string GetSavedport()
    {
        return savedPort;
    }

    private static bool IsValidPort(string port)
    {
        // 포트 번호 유효성 검사
        if (int.TryParse(port, out int portNum))
        {
            // 포트 번호가 0 이상 65535 이하인 경우 유효
            return portNum >= 0 && portNum <= 65535;
        }
        return false; // 숫자로 변환할 수 없는 경우 유효하지 않음
    }
}
