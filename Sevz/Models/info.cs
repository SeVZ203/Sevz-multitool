using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sevz.Models
{
    public static class info
    {
        public static void ShowInfo()
        {
            string savedIp = SetIP.GetSavedIp();    // 변경된 IP나 기본 IP를 가져옴
            string defaultIp = SetIP.GetDefaultIp(); // 기본 IP
            string savedPort = SetPort.GetSavedPort();  // 변경된 포트나 기본 포트를 가져옴
            string defaultPort = SetPort.GetDefaultPort(); // 기본 포트

            // 테이블 형식으로 IP와 포트 정보 출력
            Console.WriteLine();
            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine("| 설정 항목      |    설정 값       |");
            Console.WriteLine("+----------------+------------------+");

            // IP 주소 출력 
            if (savedIp == defaultIp)
            {
                Console.WriteLine($"| IP 주소        | {defaultIp,-16} |");
            }
            else
            {
                Console.WriteLine($"| IP 주소        | {savedIp,-16} |");
            }

            // 포트 번호 출력
            if (savedPort == defaultPort)
            {
                Console.WriteLine($"| 포트 번호      | {defaultPort,-16} |");
            }
            else
            {
                Console.WriteLine($"| 포트 번호      | {savedPort,-16}|");
            }

            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine();
        }

        public static void AlertWarning()
        {
            // 경고 메시지 출력
            Console.WriteLine("경고: 이 작업은 공격 기법으로 간주될 수 있으며, 사용자는 이에 따른 책임이 있습니다.");
            Console.WriteLine("계속 진행하시겠습니까? (Y/N)");

            // 사용자 입력 받기
            string userInput = Console.ReadLine();

            if (userInput?.ToUpper() != "Y")
            {
                Console.WriteLine("작업이 취소되었습니다.");
                return;
            }
        }
    }
}
