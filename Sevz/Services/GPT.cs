using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections.Generic;

public class GPT
{
    private static readonly string apiKey = "YOUR_OPENAI_API_KEY"; // OpenAI API 키를 여기에 입력하세요
    private static readonly string apiUrl = "https://api.openai.com/v1/completions";

    public static async Task chatgpt(string[] args)
    {
        await Suggetions(); // 프로그램 시작 시 suggetions 메서드 호출
    }

    public static async Task Suggetions()
    {
        // 사용자로부터 폴더 경로 입력받기
        Console.Write("탐색할 폴더 경로를 입력하세요: ");
        string folderPath = Console.ReadLine();

        if (string.IsNullOrEmpty(folderPath) || !Directory.Exists(folderPath))
        {
            Console.WriteLine("유효하지 않은 폴더 경로입니다.");
            return;
        }

        // 각 .php 파일의 내용을 읽어서 변수에 저장
        List<string> phpFiles = GetPhpFiles(folderPath);

        if (phpFiles.Count == 0)
        {
            Console.WriteLine("지정된 폴더에 .php 파일이 없습니다.");
            return;
        }

        // 각 .php 파일의 내용을 읽어서 ChatGPT API로 코드 제안을 요청
        foreach (string filePath in phpFiles)
        {
            Console.WriteLine($"\n[{filePath}] 파일 내용 분석 중...");
            string fileContent = await File.ReadAllTextAsync(filePath);
            string suggestion = await GetGPTResponse($"이 PHP 코드의 보안 문제를 분석하고 개선 제안을 주세요: {fileContent}");
            Console.WriteLine($"ChatGPT의 제안: {suggestion}");
        }
    }

    // OpenAI GPT API 호출 함수
    private static async Task<string> GetGPTResponse(string prompt)
    {
        using (HttpClient client = new HttpClient())
        {
            // API 요청 헤더 설정
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");

            // 요청 내용 설정
            var requestBody = new
            {
                model = "text-davinci-003",  // GPT-4 또는 최신 모델 지정 가능
                prompt = prompt,
                max_tokens = 500,  // 출력될 최대 토큰 수
                temperature = 0.7
            };

            // 요청 본문을 JSON으로 직렬화
            string requestBodyJson = JsonConvert.SerializeObject(requestBody);
            var content = new StringContent(requestBodyJson, Encoding.UTF8, "application/json");

            // API 호출
            HttpResponseMessage response = await client.PostAsync(apiUrl, content);

            // 응답 처리
            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                var responseJson = JsonConvert.DeserializeObject<dynamic>(responseBody);

                // GPT의 제안된 텍스트 추출
                string generatedText = responseJson.choices[0].text;
                return generatedText.Trim();  // 공백 제거
            }
            else
            {
                Console.WriteLine($"Error: {response.StatusCode}");
                return null;
            }
        }
    }

    // 폴더 내의 모든 .php 파일을 가져오는 함수
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

    // 파일 내용의 취약점 스캔 함수 (기본적으로 ChatGPT API로 보냄으로 대체)
    private static void ScanForXssWithLineNumbers(string filePath)
    {

    }
}
