using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.IO;
using Sevz.Ui;
using Sevz.Services;
using Sevz.Models;
using VulnerabilityScanner;
using System.Collections.Generic;

class Program
{
    // 사용자 입력과 메서드 실행을 매핑하는 Dictionary
    private static readonly Dictionary<string, Func<Task>> actions = new Dictionary<string, Func<Task>>
    {
        { "1", async () => await ExecuteXssScanner() },
        { "2", async () => await ExecuteSqlInjections() },  // 수정: 비동기 함수로 선언
        { "3", async () => await ExecuteBruteForceAttack(null) },
        { "4", () => { ExecuteIcmpAttack(); return Task.CompletedTask; } },
        { "5", () => { SetIP.SetIp(); return Task.CompletedTask; } },
        { "6", () => { SetPort.SetPORT(); return Task.CompletedTask; } },
        { "7", async () => await ExecutePortScanning() },
        { "8", () => { info.ShowInfo(); return Task.CompletedTask; } },
        { "9", async () => await info.PerformVulnerabilityScan() },
        { "10", async () => await Suggestions.suggetions() },
        { "11", async () => await info.GatheringServerInfo() },
        { "12", () => { GPT.chatgpt(null); return Task.CompletedTask; } }
    };

    static async Task Main(string[] args)
    {
        info.cert();

        while (true)
        {
            DisplayMenu(); // 메뉴 출력

            string input = Console.ReadLine();

            // 입력에 해당하는 메서드가 존재하면 실행, 없으면 오류 메시지 출력
            if (actions.ContainsKey(input))
            {
                await actions[input]();  // 비동기 작업 대기
            }
            else
            {
                Console.WriteLine("잘못된 입력입니다. 다시 선택하세요.");
            }
        }
    }

    // 메뉴 출력 메서드
    static void DisplayMenu()
    {
        Console.WriteLine("\n=== 보안 프로그램 메뉴 ===");
        Console.WriteLine("1. XSS");
        Console.WriteLine("2. SQL Injections");
        Console.WriteLine("3. Brute Force");
        Console.WriteLine("4. ICMP");
        Console.WriteLine("5. IP 설정");
        Console.WriteLine("6. 포트 설정");
        Console.WriteLine("7. 포트 스캐닝");
        Console.WriteLine("8. 정보 출력 (IP 및 포트)");
        Console.WriteLine("9. 분석제안");
        Console.WriteLine("10. 코드분석");
        Console.WriteLine("11. 서버분석");
        Console.WriteLine("12. GPT");
        Console.Write("원하는 번호를 선택하세요: ");
    }

    // XSS 스캐너 실행 메서드
    static async Task ExecuteXssScanner()
    {
        Console.WriteLine("XSS 을 선택하셨습니다.");
        XssScannerTest xssScanner = new XssScannerTest();
        await xssScanner.TestWholeStuffAsync();
    }

    // SQL Injection 실행 메서드 (async 및 await 추가)
    static async Task ExecuteSqlInjections()  // 수정: async 추가
    {
        Console.WriteLine("SQL Injections 를 선택하셨습니다.");
        string url = "http://192.168.0.119:3000/#/login";
        SqlInjectionScanner scanner = new SqlInjectionScanner(url);
        await scanner.TestSqlInjection();  // await 사용하여 작업 완료 후 다음 코드 실행
    }

    // Brute Force 공격 실행 메서드
    static async Task ExecuteBruteForceAttack(string[] args)
    {
        Console.WriteLine("Brute Force 공격을 시작합니다.");
        await BruteforceAttack.PerformBruteforceAttack(args);
    }

    // ICMP 공격 실행 메서드
    static void ExecuteIcmpAttack()
    {
        Console.WriteLine("ICMP 공격을 시작합니다.");
        Sevz.Services.ICMPAttack.ICMP();
    }

    // 포트 스캐닝 실행 메서드
    static async Task ExecutePortScanning()
    {
        string savedIp = SetIP.GetSavedIp(); // 저장된 IP 가져오기
        if (!string.IsNullOrEmpty(savedIp))
        {
            Console.WriteLine("포트 스캐닝을 시작합니다.");
            await PortScanning.ScanPortsAsync(savedIp);
        }
        else
        {
            Console.WriteLine("먼저 IP 주소를 설정하세요.");
        }
    }
}
