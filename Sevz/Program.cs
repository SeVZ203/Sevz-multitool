using Sevz;
using System;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        design.PrintSevz();
        while (true)
        {
            Console.WriteLine("원하는 번호를 선택하세요");
            Console.WriteLine("1. 옵션 1");
            Console.WriteLine("2. 옵션 2");
            Console.WriteLine("3. 옵션 3");
            Console.WriteLine("4. 옵션 4");
            Console.WriteLine("5. IP 설정");
            Console.WriteLine("6. 포트 스캔");
            Console.Write(">>");
            string input = Console.ReadLine();

            switch (input)
            {
                case "1":
                    Console.WriteLine("옵션 1을 선택하셨습니다.");
                    break;
                case "2":
                    Console.WriteLine("옵션 2를 선택하셨습니다.");
                    break;
                case "3":
                    Console.WriteLine("옵션 3을 선택하셨습니다.");
                    break;
                case "4":
                    Console.WriteLine("옵션 4를 선택하셨습니다.");
                    break;
                case "5":
                    Target.SetIp(); //IP 설정 메서드 호출
                    break;
                case "6":
                    string savedIp = Target.GetSavedIp(); // 저장된 IP 가져와 포트스캐닝
                    if (!string.IsNullOrEmpty(savedIp))
                    {
                        await PortScanning.ScanPortsAsync(savedIp);
                    }
                    else
                    {
                        Console.WriteLine("먼저 IP 주소를 설정하세요.");
                    }
                    break;
                default:
                    Console.WriteLine("잘못된 입력입니다. 다시 선택하세요.");
                    continue;
            }
        }
    }
}
