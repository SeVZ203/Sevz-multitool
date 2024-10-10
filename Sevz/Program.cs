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
        { "2", async () => await ExecuteSqlInjections() },
        { "3", async () => await ExecuteBruteForceAttack(null) },
        { "4", () => { ExecuteIcmpAttack(); return Task.CompletedTask; } },
        { "5", async () => await ExecutePortScanning() },
        { "6", async () => await info.PerformVulnerabilityScan() },
        { "7", async () => await Suggestions.suggetions() },
        { "8", async () => await info.GatheringServerInfo() },
        { "9", async () => await info.ExecuteCsrfScan() },
        //{ "10", async () => await info.ExecuteOpenRedirectScan() }
    };

    private static string selectedOption = string.Empty; // 선택된 옵션 저장

    static async Task Main(string[] args)
    {
        info.cert();
        PasswordService.LoadConfiguration();
        while (true)
        {
            Console.Write("\n명령어를 입력하세요 (help, select <번호>, run, exit): ");
            string input = Console.ReadLine();
            string[] commandParts = input.Split(' ');

            switch (commandParts[0].ToLower())
            {
                case "help":
                    DisplayMenu();
                    break;

                case "set":
                    if (commandParts.Length > 2)
                    {
                        if (commandParts[1].ToLower() == "ip")
                        {
                            SetIP.SetIp(commandParts[2]);
                        }
                        else if (commandParts[1].ToLower() == "port")
                        {
                            SetPort.SetPORT(commandParts[2]);
                        }
                        else
                        {
                            Console.WriteLine("유효하지 않은 설정입니다. 'set ip' 또는 'set port' 형식으로 입력하세요.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("IP 주소나 포트 번호를 입력하지 않았습니다. 'set ip' 또는 'set port' 형식으로 입력하세요.");
                    }
                    break;

                case "select":
                    if (commandParts.Length > 1 && actions.ContainsKey(commandParts[1]))
                    {
                        selectedOption = commandParts[1];
                        Console.WriteLine($"옵션 {selectedOption}이(가) 선택되었습니다.");
                    }
                    else
                    {
                        Console.WriteLine("유효한 옵션 번호를 선택하세요. (help를 입력하여 옵션 목록을 확인하세요)");
                    }
                    break;

                case "run":
                    if (!string.IsNullOrEmpty(selectedOption))
                    {
                        await RunSelectedOption();
                    }
                    else
                    {
                        Console.WriteLine("먼저 select <번호>를 입력하여 옵션을 선택하세요.");
                    }
                    break;
                case "info":
                    info.ShowInfo();
                    break;
                case "exit":
                    Console.WriteLine("프로그램을 종료합니다.");
                    return;

                default:
                    Console.WriteLine("알 수 없는 명령어입니다. 'help'를 입력하여 사용 가능한 명령어를 확인하세요.");
                    break;
            }
        }
    }

    static void DisplayMenu()
    {
        Console.WriteLine("\n=== 보안 프로그램 메뉴 ===");
        Console.WriteLine("1. XSS");
        Console.WriteLine("2. SQL Injections");
        Console.WriteLine("3. Brute Force");
        Console.WriteLine("4. ICMP");
        //Console.WriteLine("5. IP 설정");
        //Console.WriteLine("6. 포트 설정");
        Console.WriteLine("5. 포트 스캐닝");
        //Console.WriteLine("8. 정보 출력 (IP 및 포트)");
        Console.WriteLine("6. 분석제안");
        Console.WriteLine("7. 코드분석");
        Console.WriteLine("8. 서버분석");
        Console.WriteLine("9. CSRF 취약점 검사");
        //Console.WriteLine("10. Open Redirect 취약점 검사");
        Console.WriteLine("\n명령어 목록:");
        Console.WriteLine("  help                 - 메뉴와 명령어 목록 표시");
        Console.WriteLine("  set ip               - IP 주소 설정");
        Console.WriteLine("  set port             - 포트 번호 설정");
        Console.WriteLine("  info                 - 타겟 IP/Port 확인");
        Console.WriteLine("  select <번호>        - 실행할 공격 유형 선택");
        Console.WriteLine("  run                  - 선택된 공격 실행");
        Console.WriteLine("  exit                 - 프로그램 종료");
    }

    //static void SetIp(string ipAddress)
    //{
    //    SetIP.SetIp(); // SetIP 클래스에 SaveIp 메서드가 정의되어야 합니다
    //    //Console.WriteLine($"IP 주소가 {ipAddress}로 설정되었습니다.");
    //}
        
    //static void SetPort(string portNumber)
    //{
    //    SetPortt.SetPORT(); // SetPort 클래스에 SavePort 메서드가 정의되어야 합니다
    //    //Console.WriteLine($"포트 번호가 {portNumber}로 설정되었습니다.");
    //}

    static async Task RunSelectedOption()
    {
        if (actions.ContainsKey(selectedOption))
        {
            Console.WriteLine($"옵션 {selectedOption} 실행 중...");
            await actions[selectedOption]();
        }
        else
        {
            Console.WriteLine("유효하지 않은 옵션입니다. 'help'를 입력하여 사용 가능한 옵션을 확인하세요.");
        }
    }

    // XSS 스캐너 실행 메서드
    static async Task ExecuteXssScanner()
    {
        Console.WriteLine("XSS 공격을 실행합니다.");
        XssScannerTest xssScanner = new XssScannerTest();
        await xssScanner.TestXSS();
    }

    // SQL Injection 실행 메서드
    static async Task ExecuteSqlInjections()
    {
        Console.WriteLine("SQL Injection 공격을 실행합니다.");
        string url = "http://192.168.0.119:3000/#/login";
        SqlInjectionScanner scanner = new SqlInjectionScanner(url);
        await scanner.TestSqlInjection();
    }

    // Brute Force 공격 실행 메서드
    static async Task ExecuteBruteForceAttack(string[] args)
    {
        Console.WriteLine("Brute Force 공격을 실행합니다.");
        await BruteforceAttack.PerformBruteforceAttack(args);
    }

    // ICMP 공격 실행 메서드
    static void ExecuteIcmpAttack()
    {
        Console.WriteLine("ICMP 공격을 실행합니다.");
        Sevz.Services.ICMPAttack.ICMP();
    }

    // 포트 스캐닝 실행 메서드
    static async Task ExecutePortScanning()
    {
        string savedIp = SetIP.GetSavedIp();
        if (!string.IsNullOrEmpty(savedIp))
        {
            Console.WriteLine("포트 스캐닝을 실행합니다.");
            await PortScanning.ScanPortsAsync(savedIp);
        }
        else
        {
            Console.WriteLine("먼저 IP 주소를 설정하세요.");
        }
    }
}
