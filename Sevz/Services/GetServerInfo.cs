using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using Sevz.Models; // CVESuggestions.cs 파일을 참조하기 위해 추가

namespace Sevz.Services
{
    public class WebScannerService
    {
        // 웹 애플리케이션 정보 수집
        public static async Task ScanWebApplication(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    HttpResponseMessage response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    // HTTP 헤더 분석
                    Console.WriteLine("\n[HTTP 헤더 정보]");
                    foreach (var header in response.Headers)
                    {
                        Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
                    }

                    // 서버 헤더 정보 확인 및 OS 및 서버 버전 추정
                    if (response.Headers.Contains("Server"))
                    {
                        var serverHeader = response.Headers.GetValues("Server").FirstOrDefault();
                        Console.WriteLine($"\n서버: {serverHeader}");
                        DetectOperatingSystemAndServer(serverHeader);
                    }

                    if (response.Headers.Contains("X-Powered-By"))
                    {
                        var poweredBy = response.Headers.GetValues("X-Powered-By").FirstOrDefault();
                        Console.WriteLine($"\n서버의 X-Powered-By: {poweredBy}");
                        DetectOperatingSystemAndServer(poweredBy);
                    }

                    // 웹 페이지 콘텐츠 분석 (HTML 본문)
                    string content = await response.Content.ReadAsStringAsync();
                    AnalyzeContent(content);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"오류 발생: {ex.Message}");
                }
            }
        }

        // 서버 정보로 OS 및 서버 종류 감지, 버전 무시하고 제안
        private static void DetectOperatingSystemAndServer(string serverHeader)
        {
            string osDetected = "알 수 없음";
            List<string> attackSuggestions = new List<string>();

            // header 정보를 모두 소문자로 변경
            serverHeader = serverHeader.ToLower();

            // '/' 기준으로 분할
            string[] parts = serverHeader.Split('/');
            string version = parts[1];

            // Apache 서버 감지
            if (serverHeader.Contains("apache", StringComparison.OrdinalIgnoreCase))
            {
                osDetected = "Apache 서버";
                attackSuggestions.AddRange(Sevz.Models.AttackSuggestionService.SuggestAttacksForVersion("Apache", version));
            }
            // Nginx 서버 감지
            else if (serverHeader.Contains("nginx", StringComparison.OrdinalIgnoreCase))
            {
                osDetected = "Nginx 서버";
                attackSuggestions.AddRange(Sevz.Models.AttackSuggestionService.SuggestAttacksForVersion("Nginx", version));
            }
            // php 서버 감지
            else if (serverHeader.Contains("php", StringComparison.OrdinalIgnoreCase))
            {
                osDetected = "PHP Package";
                attackSuggestions.AddRange(Sevz.Models.AttackSuggestionService.SuggestAttacksForVersion("php", version));
            }
            // Windows 서버 감지
            else if (serverHeader.Contains("windows", StringComparison.OrdinalIgnoreCase))
            {
                osDetected = "Windows 서버";
                attackSuggestions.AddRange(Sevz.Models.AttackSuggestionService.SuggestAttacksForVersion("IIS", version));
            }
            // Linux/Unix 서버 감지
            else if (serverHeader.Contains("Linux", StringComparison.OrdinalIgnoreCase) ||
                     serverHeader.Contains("Unix", StringComparison.OrdinalIgnoreCase))
            {
                osDetected = "Linux/Unix 서버";
            }

            // 운영 체제 정보 출력
            Console.WriteLine($"운영 체제: {osDetected}");

            // 공격 제안 출력
            if (attackSuggestions.Any())
            {
                Console.WriteLine("\n추천 공격 기법:");
                foreach (var suggestion in attackSuggestions)
                {
                    Console.WriteLine($"{suggestion}");
                }
            }
            else
            {
                Console.WriteLine("운영 체제에 맞는 CVE 제안이 없습니다.");
            }
        }

        // HTML 콘텐츠 분석
        private static void AnalyzeContent(string content)
        {
            Console.WriteLine("\n[HTML 메타 태그 정보]");

            // 메타 태그 분석
            var metaTags = System.Text.RegularExpressions.Regex.Matches(content, @"<meta\s+[^>]*name\s*=\s*[""']?([^'""\s>]+)[""']?\s+content\s*=\s*[""']?([^'""\s>]+)[""']?[^>]*>", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            foreach (var match in metaTags)
            {
                Console.WriteLine($"메타 태그 - {match}");
            }

            // CMS 및 플러그인 탐지
            Console.WriteLine("\n[플러그인 및 CMS 탐지]");
            if (content.Contains("/wp-content/"))
            {
                Console.WriteLine("WordPress 탐지됨");
                DetectPlugins(content, "WordPress");
            }
            else if (content.Contains("Joomla"))
            {
                Console.WriteLine("Joomla 탐지됨");
            }

            // 자바스크립트 라이브러리 탐지
            Console.WriteLine("\n[자바스크립트 라이브러리 탐지]");
            if (content.Contains("jquery"))
            {
                Console.WriteLine("jQuery 탐지됨");
            }

            if (content.Contains("bootstrap"))
            {
                Console.WriteLine("Bootstrap 탐지됨");
            }

            if (content.Contains("angular"))
            {
                Console.WriteLine("AngularJS 탐지됨");
            }
        }

        // 플러그인 탐지 로직 (WordPress용 예시)
        private static void DetectPlugins(string content, string cms)
        {
            if (cms == "WordPress")
            {
                // WordPress 플러그인 탐지
                if (content.Contains("/wp-content/plugins/"))
                {
                    Console.WriteLine("WordPress 플러그인 탐지됨");
                }

                // 추가 플러그인 패턴 탐지 가능
            }
        }
    }
}
