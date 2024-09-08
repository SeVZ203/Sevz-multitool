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
            string savedIp = SetIP.GetSavedIp();
            string savedPort = SetPort.GetSavedport();

            // 테이블 형식 출력
            Console.WriteLine();
            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine("| 설정 항목      |    설정 값       |");
            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine($"| IP 주소        | {savedIp ?? "설정되지 않음"}  |");
            Console.WriteLine($"| 포트 번호      | {savedPort ?? "설정되지 않음"}               |");
            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine();
        }
    }
}
