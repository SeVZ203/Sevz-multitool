using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading.Tasks;

public static class PortScanning
{
    public static async Task ScanPortsAsync(string ip)
    {
        Console.WriteLine($"IP {ip}의 포트를 스캔합니다...");

        int startPort = 1;  // 시작 포트
        int endPort = 1024; // 끝 포트
        int totalPorts = endPort - startPort + 1;
        int scannedPorts = 0; // 스캔된 포트의 수

        var openPorts = new List<int>(); // 열린 포트를 저장하는 리스트
        var tasks = new List<Task>();

        for (int port = startPort; port <= endPort; port++)
        {
            int portCopy = port; // 포트 번호를 로컬 변수에 복사
            tasks.Add(Task.Run(async () =>
            {
                if (await IsPortOpenAsync(ip, portCopy, 1000)) // 1초 타임아웃
                {
                    openPorts.Add(portCopy); // 열린 포트 목록에 추가
                }

                // 스캔된 포트 수 증가
                scannedPorts++;

                // 진행률 계산 및 출력
                double progress = (double)scannedPorts / totalPorts * 100;
                DisplayProgress(progress);
            }));
        }

        await Task.WhenAll(tasks); // 모든 포트 스캔이 완료될 때까지 대기
        DisplayProgress(100);
        Console.WriteLine("\n포트 스캔이 완료되었습니다."); // 스캔 완료 후 줄바꿈
        DisplayOpenPorts(openPorts); // 열린 포트 결과 출력
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

    private static void DisplayProgress(double progress)
    {
        int barSize = 50;
        int filledSize = (int)(barSize * (progress / 100));
        string progressBar = new string('=', filledSize) + new string(' ', barSize - filledSize);
        Console.Write($"\r[{progressBar}] {progress:F2}% 진행중");
    }

    private static void DisplayOpenPorts(List<int> openPorts)
    {
        if (openPorts.Count > 0)
        {
            //Console.WriteLine("열려 있는 포트:");
            foreach (var port in openPorts)
            {
                Console.WriteLine($"포트 {port}가 열려 있습니다.");
            }
        }
        else
        {
            Console.WriteLine("열려 있는 포트가 없습니다.");
        }
    }
}
