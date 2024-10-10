using Sevz.Models;
using Sevz.Services;
using System;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

public class CsrfScanner
{
    private readonly HttpClient _client;

    // 다양한 CSRF 토큰 필드 이름 정의
    private readonly string[] csrfTokenFields = { "csrf-token", "authenticity_token", "_csrf", "token" };

    public CsrfScanner()
    {
        _client = new HttpClient();
    }

    public async Task CheckCsrfProtection(string url)
    {
        info.AlertWarning();
        //if (!PasswordService.CheckPassword()) return;
        // 1. GET 요청을 보내 CSRF 토큰 필드 검색
        HttpResponseMessage response = await _client.GetAsync(url);
        string responseBody = await response.Content.ReadAsStringAsync();

        // 2. CSRF 토큰 추출 시도
        string csrfToken = ExtractCsrfToken(responseBody);

        if (!string.IsNullOrEmpty(csrfToken))
        {
            Console.WriteLine("CSRF 토큰이 존재합니다. 토큰을 사용하여 확인 요청을 테스트합니다.");

            // 3. CSRF 토큰을 포함한 POST 요청 만들기
            var postData = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("csrf-token", csrfToken),
                // 테스트용 추가 파라미터
                new KeyValuePair<string, string>("username", "testuser")
            });

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url) { Content = postData };
            HttpResponseMessage testResponse = await _client.SendAsync(request);

            // 4. 서버의 응답 확인
            if (testResponse.IsSuccessStatusCode)
            {
                Console.WriteLine("CSRF 토큰을 사용한 요청이 성공적으로 수행되었습니다. CSRF 보호가 올바르게 구현된 것으로 보입니다.");
            }
            else
            {
                Console.WriteLine("CSRF 토큰이 포함되었음에도 요청이 차단되었습니다. CSRF 보호가 올바르게 구현되지 않았을 수 있습니다.");
            }
        }
        else
        {
            Console.WriteLine("CSRF 토큰이 확인되지 않았습니다. 보호되지 않을 수 있습니다.");
        }
    }

    // 응답 본문에서 CSRF 토큰을 추출하는 메서드
    private string ExtractCsrfToken(string responseBody)
    {
        foreach (var field in csrfTokenFields)
        {
            var regex = new Regex($@"<input[^>]*name=[""']{field}[""'][^>]*value=[""'](?<token>[^""']+)[""']", RegexOptions.IgnoreCase);
            var match = regex.Match(responseBody);

            if (match.Success)
            {
                Console.WriteLine($"CSRF 토큰 필드 '{field}'이(가) 발견되었습니다.");
                return match.Groups["token"].Value;
            }
        }

        return null;
    }
}
