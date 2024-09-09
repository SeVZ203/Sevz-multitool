using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using System;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Sevz.Services;

namespace VulnerabilityScanner
{
    public static class Suggestions
    {
        // XSS 및 SQL Injection 취약점 스캐너
        public static async Task ScanForXssAndSqlInjection(string url)
        {
            try
            {
                string pageSource = await GetPageSourceAsync(url);
                if (!string.IsNullOrEmpty(pageSource))
                {
                    ScanForXss(pageSource);
                    await ScanForSqlInjection(url);  // URL을 활용하여 SQL Injection 공격 시도
                }
                else
                {
                    Console.WriteLine("페이지 소스를 가져올 수 없습니다.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"오류 발생: {ex.Message}");
            }
        }

        // 웹 페이지 소스 가져오기
        private static async Task<string> GetPageSourceAsync(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    return await response.Content.ReadAsStringAsync();
                }
                else
                {
                    Console.WriteLine($"Failed to access {url}. Status Code: {response.StatusCode}");
                    return null;
                }
            }
        }

        // XSS 취약점 스캔
        private static void ScanForXss(string pageSource)
        {
            Console.WriteLine("\nXSS 취약점 스캔 중...");

            string[] xssPatterns = new string[]
            {
                @"<script.*?>.*?</script>",  // 스크립트 태그
                @"javascript:.*",            // 자바스크립트 호출
                @"<img.*?onerror=.*?>",       // 이미지 태그에 onerror 이벤트
                @"<.*?onmouseover=.*?>"       // onmouseover 이벤트
            };
            int detectedxssCount = 0;

            bool found = false;

            foreach (var pattern in xssPatterns)
            {
                MatchCollection matches = Regex.Matches(pageSource, pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0)
                {
                    detectedxssCount++;
                    found = true;
                    Console.WriteLine($"[XSS] 발견됨: {matches.Count}개 잠재적인 XSS 취약점:");
                    foreach (Match match in matches)
                    {
                        Console.WriteLine($" - {match.Value}");
                    }
                }
            }
            
            if (detectedxssCount > 0)
            {
                Console.WriteLine($"\n총 {detectedxssCount}개의 XSS 취약점이 발견되었습니다.");
            }
            else
            {
                Console.WriteLine("XSS 취약점이 발견되지 않았습니다.");
            }
        }

        // SQL Injection 취약점 스캔
        private static async Task ScanForSqlInjection(string url)
        {
            Console.WriteLine("\nSQL Injection 취약점 스캔 중...");

            string[] sqlInjectionPayloads = new string[]
            {
                "' OR 1=1--",        // 기본 SQL Injection 패턴
                "' OR 'a'='a'--",    // 문자열 비교 SQL Injection
                "' UNION SELECT NULL--", // UNION 기반 SQL Injection
                "' OR 1=0 UNION SELECT username, password FROM users--", // 데이터 추출
            };
            int detectedsqlCount = 0;

            foreach (var payload in sqlInjectionPayloads)
            {
                string vulnerableUrl = $"{url}?param={Uri.EscapeDataString(payload)}";
                Console.WriteLine($"Testing: {vulnerableUrl}");

                string result = await SendHttpRequest(vulnerableUrl);

                if (IsSqlInjectionDetected(result))
                {
                    detectedsqlCount++;
                    Console.WriteLine($"[취약] SQL Injection 발견됨! 페이로드: {payload}");
                    return;
                }
            }
            if (detectedsqlCount > 0)
            {
                Console.WriteLine($"\n총 {detectedsqlCount}개의 SQL Injection 취약점이 발견되었습니다.");
            }
            else
            {
                Console.WriteLine("SQL Injection 취약점이 발견되지 않았습니다.");
            }
        }
        //sqlinjections_vulnerable.sqlinjection();
        private static async Task<string> SendHttpRequest(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                return await response.Content.ReadAsStringAsync();
            }
        }

        // SQL Injection 탐지 방법
        private static bool IsSqlInjectionDetected(string responseContent)
        {
            // SQL 오류 메시지나 비정상적인 응답 확인 (간단한 예시)
            return responseContent.Contains("SQL syntax") || responseContent.Contains("database error");
        }
    }
}