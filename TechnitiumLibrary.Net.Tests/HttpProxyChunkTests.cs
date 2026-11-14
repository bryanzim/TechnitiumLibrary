using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class HttpProxyChunkTests
    {
        [Fact]
        public async Task ADecodedChunkedRequestIsForwardedInChunks()
        {
            using (TcpListener origin = new TcpListener(IPAddress.Loopback, 0))
            {
                origin.Start();
                int originPort = ((IPEndPoint)origin.LocalEndpoint).Port;
                Task<string> received = ReadOriginRequestAsync(origin);

                using (HttpProxyServer proxy = new HttpProxyServer())
                using (TcpClient client = new TcpClient(IPAddress.Loopback.ToString(), proxy.LocalEndPoint.Port))
                using (NetworkStream stream = client.GetStream())
                {
                    string request = "POST http://127.0.0.1:" + originPort + "/x HTTP/1.1\r\nHost: 127.0.0.1:" + originPort + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

                    string forwarded = await received;
                    Assert.Contains("Transfer-Encoding: chunked", forwarded);
                    Assert.Contains("5\r\nhello\r\n0\r\n\r\n", forwarded);
                }
            }
        }

        static async Task<string> ReadOriginRequestAsync(TcpListener origin)
        {
            using (TcpClient client = await origin.AcceptTcpClientAsync())
            using (NetworkStream stream = client.GetStream())
            {
                byte[] buffer = new byte[2048];
                int total = 0;

                while (total < buffer.Length)
                {
                    int bytesRead = await stream.ReadAsync(buffer, total, buffer.Length - total);
                    if (bytesRead < 1)
                        break;

                    total += bytesRead;

                    if (Encoding.ASCII.GetString(buffer, 0, total).Contains("0\r\n\r\n"))
                        break;
                }

                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
                return Encoding.ASCII.GetString(buffer, 0, total);
            }
        }
    }
}
