using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Sevz.Models;

namespace Sevz.Services
{
    public static class PortScanning
    {
        public static async Task ScanPortsAsync(string ip)
        {
            // 경고 메시지 출력 
            info.AlertWarning();
            Console.WriteLine($"IP {ip}의 포트를 스캔합니다...");

            int startPort = 1;  // 시작 포트
            int endPort = 49151; // 끝 포트
            int totalPorts = endPort - startPort + 1;
            int scannedPorts = 0; // 스캔된 포트의 수

            var openPorts = new ConcurrentBag<int>(); // 열린 포트를 저장하는 스레드 안전한 리스트
            var tasks = new List<Task>();

            SemaphoreSlim semaphore = new SemaphoreSlim(1000); // 동시 작업 수 제한

            for (int port = startPort; port <= endPort; port++)
            {
                int portCopy = port; // 포트 번호를 로컬 변수에 복사

                // 비동기 작업 수를 제한하기 위해 세마포어 사용
                await semaphore.WaitAsync();

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        if (await IsPortOpenAsync(ip, portCopy, 1000)) // 1초 타임아웃
                        {
                            openPorts.Add(portCopy); // 열린 포트 목록에 추가
                        }
                    }
                    finally
                    {
                        // 스캔된 포트 수 증가
                        scannedPorts++;

                        // 진행률 계산 및 출력
                        double progress = (double)scannedPorts / totalPorts * 100;
                        DisplayProgress(progress);

                        // 작업 완료 시 세마포어 해제
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks); // 모든 포트 스캔이 완료될 때까지 대기
            DisplayProgress(100); // 진행률을 100%로 표시
            Console.WriteLine("\n포트 스캔이 완료되었습니다."); // 스캔 완료 후 줄바꿈
            DisplayOpenPorts(openPorts.ToList()); // 열린 포트 결과 출력
        }

        // 열린 포트를 출력하는 메서드
        private static void DisplayOpenPorts(List<int> openPorts)
        {
            if (openPorts.Count > 0)
            {
                Console.WriteLine("열린 포트:");
                foreach (var port in openPorts)
                {
                    Console.WriteLine($"- 포트 {port}가 열려 있습니다.");
                }
            }
            else
            {
                Console.WriteLine("열린 포트가 없습니다.");
            }
        }

        // 진행률을 표시하는 메서드
        private static void DisplayProgress(double progress)
        {
            Console.Write($"\r진행률: {progress:F2}%");
        }

        // 포트가 열려 있는지 확인하는 메서드 (비동기)
        private static async Task<bool> IsPortOpenAsync(string ip, int port, int timeout)
        {
            try
            {
                using (var tcpClient = new TcpClient())
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
}
