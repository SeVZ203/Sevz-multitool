using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.IO;
using Sevz.Ui;
using Sevz.Services;
using Sevz.Models;

class Program
{
    static async Task Main(string[] args)
    {
        PasswordService.LoadConfiguration(); //appsetting 설정된 비밀번호 체크
        design.PrintSevz();

        if (!PasswordService.CheckPassword()) 
        {
            Console.WriteLine("비밀번호가 틀렸습니다. 프로그램을 종료합니다.");
            return;
        }
        Console.WriteLine("비밀번호가 확인되었습니다. 프로그램을 시작합니다.");

        design.PrintSevz();
        while (true)
        {
            Console.WriteLine("원하는 번호를 선택하세요");
            Console.WriteLine("1. 옵션 1");
            Console.WriteLine("2. 옵션 2");
            Console.WriteLine("3. 옵션 3");
            Console.WriteLine("4. 옵션 4");
            Console.WriteLine("5. IP 설정");
            Console.WriteLine("6. 포트 설정");
            Console.WriteLine("7. 포트 스캐닝");
            Console.WriteLine("8. 정보 출력 (IP 및 포트)");
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
                    SetIP.SetIp(); //IP 설정 메서드 호출
                    break;
                case "6":
                    SetPort.SetPORT();
                    break;
                case "7":
                    string savedIp = SetIP.GetSavedIp(); // 저장된 IP 가져와 포트스캐닝
                    if (!string.IsNullOrEmpty(savedIp))
                    {
                        await PortScanning.ScanPortsAsync(savedIp);
                    }
                    else
                    {
                        Console.WriteLine("먼저 IP 주소를 설정하세요.");
                    }
                    break;
                case "8":
                    info.ShowInfo(); // 저장된 IP와 포트 정보를 테이블 형식으로 출력
                    break;

                default:
                    Console.WriteLine("잘못된 입력입니다. 다시 선택하세요.");
                    continue;
            }
        }
    }
}
