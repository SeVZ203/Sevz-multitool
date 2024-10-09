using Microsoft.Extensions.Configuration;
using Sevz.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using VulnerabilityScanner;
using System.Security.Cryptography.X509Certificates;

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
            Console.WriteLine($"| IP 주소        | {savedIp,-16} |");

            // 포트 번호 출력
            Console.WriteLine($"| 포트 번호      | {savedPort,-16} |");

            Console.WriteLine("+----------------+------------------+");
            Console.WriteLine();
        }
        public static bool AlertWarning()
        {
            // 경고 메시지 출력
            Console.WriteLine("경고: 이 작업은 공격 기법으로 간주될 수 있으며, 사용자는 이에 따른 책임이 있습니다.");

            while (true)
            {
                Console.Write("계속 진행하시겠습니까? (Y/N): ");
                string userInput = Console.ReadLine();

                // 입력이 'Y' 또는 'y'일 경우 true 반환
                if (userInput?.ToUpper() == "Y")
                {
                    return true;
                }
                // 입력이 'N' 또는 'n'일 경우 false 반환
                else if (userInput?.ToUpper() == "N")
                {
                    Console.WriteLine("작업이 취소되었습니다.");
                    return false;
                }
                // 다른 입력인 경우 안내 메시지 출력 후 반복
                else
                {
                    Console.WriteLine("잘못된 입력입니다. 'Y' 또는 'N'을 입력하세요.");
                }
            }
        }

        // XSS 및 SQL Injection 스캐너 호출
        public static async Task PerformVulnerabilityScan()
        {
            Console.Write("스캔할 URL을 입력하세요 (http/https 포함): ");
            string url = Console.ReadLine();

            if (string.IsNullOrEmpty(url))
            {
                Console.WriteLine("유효하지 않은 URL입니다. 스캔을 종료합니다.");
                return;
            }

            // 포트 입력받기 또는 저장된 포트 가져오기
            Console.Write("포트를 입력하세요 (빈칸일 경우 저장된 포트 사용): ");
            string portInput = Console.ReadLine();

            string port = string.IsNullOrEmpty(portInput) ? SetPort.GetSavedPort() : portInput;

            Console.WriteLine($"사용 중인 포트: {port}");

            // 포트를 URL에 추가
            string fullUrl = $"{url}:{port}";

            // XSS 및 SQL Injection 스캔 호출
            await Suggestions.ScanForXssAndSqlInjection(fullUrl);
        }

        // 서버 정보를 수집하는 메서드
        public static async Task GatheringServerInfo()
        {
            Console.Write("스캔할 URL을 입력하세요 (http/https 포함): ");
            string url = Console.ReadLine();

            if (string.IsNullOrEmpty(url))
            {
                Console.WriteLine("유효하지 않은 URL입니다. 스캔을 종료합니다.");
                return;
            }

            // 포트 입력받기 또는 저장된 포트 가져오기
            Console.Write("포트를 입력하세요 (빈칸일 경우 저장된 포트 사용): ");
            string portInput = Console.ReadLine();
            string port = string.IsNullOrEmpty(portInput) ? SetPort.GetSavedPort() : portInput;

            Console.WriteLine($"사용 중인 포트: {port}");

            // URL에서 프로토콜과 호스트/경로 분리
            Uri uri;
            try
            {
                uri = new Uri(url);
            }
            catch (UriFormatException)
            {
                Console.WriteLine("유효하지 않은 URL 형식입니다.");
                return;
            }

            // 새로운 URL 생성: 호스트 뒤에 포트를 추가
            string fullUrl = $"{uri.Scheme}://{uri.Host}:{port}{uri.PathAndQuery}";

            Console.WriteLine($"최종 URL: {fullUrl}");

            // 웹 애플리케이션 스캔 호출
            await WebScannerService.ScanWebApplication(fullUrl);
        }
        public static void cert()
        {
            // 인증서 주체 이름 (CN)에 따라 인증서 검색
            string certificateCN = "sevz";

            // 시스템 인증서 저장소에서 인증서 가져오기
            X509Certificate2 certificate = GetCertificateFromStore(certificateCN);

            if (certificate != null)
            {
                Console.WriteLine("인증서가 성공적으로 가져와졌습니다.");
                Console.WriteLine($"주체 이름: {certificate.Subject}");
                Console.WriteLine($"지문: {certificate.Thumbprint}");

                // 여기에서 인증서를 사용한 추가 로직을 작성할 수 있습니다.
            }
            else
            {
                Console.WriteLine("인증서를 찾을 수 없습니다.");
            }
        }
        static X509Certificate2 GetCertificateFromStore(string subjectName)
        {
            // 현재 사용자의 인증서 저장소에서 인증서 검색
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                // 저장소에서 모든 인증서 가져오기
                X509Certificate2Collection certCollection = store.Certificates;

                // 주체 이름으로 인증서 검색
                foreach (var cert in certCollection)
                {
                    if (cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
                    {
                        return cert;
                    }
                }
            }

            // 인증서를 찾지 못했을 경우 null 반환
            return null;
        }


        public static class PasswordManager
        {
            public static List<string> LoadPasswords()
            {
                var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("Configurations/passwordex.json", optional: false, reloadOnChange: true);

                IConfigurationRoot configuration = builder.Build();

                var passwords = configuration.GetSection("passwords").Get<List<string>>();
                return passwords;
            }

            public static List<string> LoadAppsettings()
            {
                var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("Configurations/appsettings.json", optional: false, reloadOnChange: true);

                IConfigurationRoot configuration = builder.Build();

                var appsettings = configuration.GetSection("appsettings").Get<List<string>>();
                return appsettings;
            }
        }
    }
}   