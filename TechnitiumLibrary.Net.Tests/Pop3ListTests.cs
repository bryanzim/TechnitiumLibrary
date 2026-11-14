using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Mail;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Pop3ListTests
    {
        [Fact]
        public async Task ListStopsWhenTheServerClosesTheListing()
        {
            using (TcpListener listener = new TcpListener(IPAddress.Loopback, 0))
            {
                listener.Start();
                Task server = Task.Run(async () =>
                {
                    using (TcpClient client = await listener.AcceptTcpClientAsync())
                    using (NetworkStream stream = client.GetStream())
                    using (StreamWriter writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true })
                    using (StreamReader reader = new StreamReader(stream, Encoding.ASCII))
                    {
                        await writer.WriteLineAsync("+OK POP3");
                        await reader.ReadLineAsync();
                        await writer.WriteLineAsync("+OK");
                        await reader.ReadLineAsync();
                        await writer.WriteLineAsync("+OK");
                        await reader.ReadLineAsync();
                        await writer.WriteLineAsync("+OK");
                    }
                });

                using (Pop3Client pop = new Pop3Client(IPAddress.Loopback.ToString(), ((IPEndPoint)listener.LocalEndpoint).Port, "user", "pass", false, false, false))
                {
                    pop.Connect();
                    Assert.Throws<EndOfStreamException>(() => pop.LIST());
                }

                await server;
            }
        }
    }
}
