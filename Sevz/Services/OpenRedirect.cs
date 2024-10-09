using System;
using System.Net.Http;
using System.Threading.Tasks;

public class OpenRedirectScanner
{
    private readonly HttpClient _client;

    public OpenRedirectScanner()
    {
        _client = new HttpClient();
    }

    public async Task CheckOpenRedirect(string url, string attackUrl)
    {
        // 공격 URL을 파라미터로 포함하여 테스트할 최종 URL 생성
        string testUrl = $"{url}?redirect={attackUrl}";

        HttpResponseMessage response = await _client.GetAsync(testUrl);

        // 리다이렉트 응답 확인
        if (response.StatusCode == System.Net.HttpStatusCode.Redirect)
        {
            Uri location = response.Headers.Location;
            if (location != null && location.ToString() == attackUrl)
            {
                Console.WriteLine("경고: Open Redirect 취약점이 발견되었습니다!");
            }
            else
            {
                Console.WriteLine("리다이렉트는 발생했지만 외부 URL은 차단되었습니다.");
            }
        }
        else
        {
            Console.WriteLine("리다이렉트가 발생하지 않았습니다. 안전합니다.");
        }
    }
}