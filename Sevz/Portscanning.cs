using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

public static class PortScanning
{
    public static async Task ScanPortsAsync(string ip)
    {
        Console.WriteLine($"IP {ip}의 포트를 스캔합니다...");

        int startPort = 1;  // 시작
        int endPort = 1024; // 끝

        var tasks = new List<Task>(); // 모든 포트를 병렬로 스캔하기 위한 Task 목록

        for (int port = startPort; port <= endPort; port++)
        {
            // 각 포트를 병렬로 스캔
            int portCopy = port; // 포트 번호를 로컬 변수에 복사
            tasks.Add(Task.Run(async () =>
            {
                if (await IsPortOpenAsync(ip, portCopy, 1000)) // 1초 타임아웃
                {
                    Console.WriteLine($"포트 {portCopy}가 열려 있습니다.");
                }
            }));
        }

        await Task.WhenAll(tasks); // 모든 포트 스캔이 완료될 때까지 대기

        Console.WriteLine("포트 스캔이 완료되었습니다.");
    }

    private static async Task<bool> IsPortOpenAsync(string ip, int port, int timeout)
    {
        try
        {
            using (TcpClient tcpClient = new TcpClient())
            {
                var connectTask = tcpClient.ConnectAsync(ip, port);
                var timeoutTask = Task.Delay(timeout);

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    return false; // 타임아웃 발생 시 포트가 닫혀있다고 간주
                }

                return true; // 연결 성공 시 포트가 열려있다고 간주
            }
        }
        catch (Exception)
        {
            return false; // 예외 발생 시 포트가 닫혀있다고 간주
        }
    }
}
