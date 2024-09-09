using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;
using Moq;
using WireMock.Server;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;

namespace Sevz.Services
{
    public class XssScannerTest
    {
        private static readonly HttpClient client = new HttpClient();

        //[Fact]
        public async Task TestWholeStuffAsync()
        {
            // WireMock 서버를 시작하여 HTTP 요청을 모의(mock)함
            var server = WireMockServer.Start();

            // 모의 서버에 대한 GET 및 POST 요청 설정
            server
                .Given(Request.Create().WithPath("/").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody("Hello there"));

            server
                .Given(Request.Create().WithPath("/").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody("Hello there"));

            // 요청을 담을 리스트
            List<HttpRequestMessage> allRequests = new List<HttpRequestMessage>();

            // GET 요청 생성
            var request1 = new HttpRequestMessage(HttpMethod.Get, $"{server.Url}/");
            allRequests.Add(request1);

            // GET 요청 (쿼리 파라미터 포함)
            var request2 = new HttpRequestMessage(HttpMethod.Get, $"{server.Url}/?foo=bar");
            allRequests.Add(request2);

            // POST 요청 (파일 업로드 포함)
            var request3 = new HttpRequestMessage(HttpMethod.Post, $"{server.Url}/?foo=bar");
            var content = new MultipartFormDataContent();
            content.Add(new StringContent("b"), "a");
            content.Add(new ByteArrayContent(new byte[] { 0x01, 0x02, 0x03 }), "file", "testfile.txt");
            request3.Content = content;
            allRequests.Add(request3);

            // 모의 객체를 사용하여 요청 반복
            foreach (var request in allRequests)
            {
                var response = await client.SendAsync(request);
                string responseBody = await response.Content.ReadAsStringAsync();

                Assert.Equal("Hello there", responseBody);
            }

            server.Stop();
        }
    }
}
