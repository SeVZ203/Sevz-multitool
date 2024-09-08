using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace Sevz.Services
{
    public static class PasswordService
    {
        private static string Password;

        // 비밀번호 검증 메서드
        public static bool CheckPassword()
        {
            Console.Write("비밀번호를 입력하세요: ");
            string inputPassword = Console.ReadLine();
            return inputPassword == Password;
        }

        // 설정 파일에서 비밀번호를 로드하는 메서드
        public static void LoadConfiguration()
        {
            var configurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "Configurations"))
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            IConfiguration config = configurationBuilder.Build();
            Password = config["Security:Password"]; // appsettings.json에서 비밀번호 로드
        }
    }
}
