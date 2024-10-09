using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Net;

namespace Sevz.Services
{
    public static class PasswordService
    {
        private static string Password;
        private static string IPAddress;
        private static string Port;

        // 비밀번호 검증 메서드
        public static bool CheckPassword()
        {
            Console.Write("비밀번호를 입력하세요: ");
            string inputPassword = Console.ReadLine();

            if (inputPassword == Password)
            {
                Console.WriteLine("비밀번호가 확인되었습니다. 프로그램을 시작합니다.");
                return true;
            }
            else
            {
                Console.WriteLine("비밀번호가 틀렸습니다. 메인으로 돌아갑니다.");
                return false;
            }
        }

        // appsettings.json에서 비밀번호, 네트워크 설정을 로드
        public static void LoadConfiguration()
        {
            var configurationBuilder = new ConfigurationBuilder()
                .SetBasePath(Path.Combine(Directory.GetCurrentDirectory(), "Configurations"))
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            IConfiguration config = configurationBuilder.Build();

            Password = config["Security:Password"]; 
            IPAddress = config["NetworkSettings:IPAddress"]; 
            Port = config["NetworkSettings:Port"]; 
        }

        // IP 주소를 가져오는 메서드
        public static string GetIPAddress()
        {
            return IPAddress;
        }

        // 포트 번호를 가져오는 메서드
        public static string GetPort()
        {
            return Port;
        }
    }
}
