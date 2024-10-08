using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

public class GPT
{
    private static readonly string apiKey = "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"; // 올바른 API 키 입력
    private static readonly string apiUrl = "https://api.openai.com/v1/chat/completions"; // 올바른 URL

    public static async Task chatgpt(string[] args)
    {
        await Suggetions(); // 프로그램 시작 시 suggestions 메서드 호출
    }

    public static async Task Suggetions()
    {
        Console.Write("탐색할 폴더 경로를 입력하세요: ");
        string folderPath = Console.ReadLine();

        if (string.IsNullOrEmpty(folderPath) || !Directory.Exists(folderPath))
        {
            Console.WriteLine("유효하지 않은 폴더 경로입니다.");
            return;
        }

        List<string> phpFiles = GetPhpFiles(folderPath);

        if (phpFiles.Count == 0)
        {
            Console.WriteLine("지정된 폴더에 .php 파일이 없습니다.");
            return;
        }

        foreach (string filePath in phpFiles)
        {
            Console.WriteLine($"\n[{filePath}] 파일 내용 분석 중...");
            string fileContent = await File.ReadAllTextAsync(filePath);
            string suggestion = await GetGPTResponse($"이 PHP 코드의 보안 문제를 분석하고 개선 제안을 주세요: {fileContent}");

            if (!string.IsNullOrEmpty(suggestion))
            {
                Console.WriteLine($"ChatGPT의 제안: {suggestion}");
            }
            else
            {
                Console.WriteLine("ChatGPT에서 응답을 받지 못했습니다.");
            }
        }
    }

    private static async Task<string> GetGPTResponse(string prompt)
    {
        using (HttpClient client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");

            var requestBody = new
            {
                model = "gpt-4",  // 모델 이름 (또는 gpt-3.5-turbo 사용 가능)
                messages = new[] { new { role = "user", content = prompt } },
                max_tokens = 500,
                temperature = 0.7
            };

            string requestBodyJson = JsonConvert.SerializeObject(requestBody);
            var content = new StringContent(requestBodyJson, Encoding.UTF8, "application/json");

            HttpResponseMessage response = await client.PostAsync(apiUrl, content);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                var responseJson = JsonConvert.DeserializeObject<dynamic>(responseBody);

                string generatedText = responseJson.choices[0].message.content;
                return generatedText.Trim();
            }
            else
            {
                Console.WriteLine($"Error: {response.StatusCode}, {response.ReasonPhrase}");
                return null;
            }
        }
    }

    private static List<string> GetPhpFiles(string folderPath)
    {
        List<string> phpFiles = new List<string>();
        try
        {
            phpFiles.AddRange(Directory.GetFiles(folderPath, "*.php", SearchOption.AllDirectories));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"오류 발생: {ex.Message}");
        }
        return phpFiles;
    }
}
 