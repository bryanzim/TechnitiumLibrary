using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc9110HttpTests
    {
        [Fact]
        public async Task ContentLengthRejectsALeadingSign()
        {
            byte[] request = Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nContent-Length: +3\r\n\r\nabc");

            await Assert.ThrowsAsync<HttpRequestException>(() => HttpRequest.ReadRequestAsync(new MemoryStream(request)));
        }

        [Fact]
        public async Task ContentLengthReadsTheDigitCount()
        {
            byte[] request = Encoding.ASCII.GetBytes("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcEXTRA");
            HttpRequest httpRequest = await HttpRequest.ReadRequestAsync(new MemoryStream(request));
            byte[] body = new byte[3];

            Assert.Equal(3, httpRequest.InputStream.Read(body, 0, 3));
            Assert.Equal("abc", Encoding.ASCII.GetString(body));
        }

        [Fact]
        public async Task ResponseWithoutALengthReadsUntilTheConnectionCloses()
        {
            byte[] responseBytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello");
            HttpResponse response = await HttpResponse.ReadResponseAsync(new MemoryStream(responseBytes));

            using (MemoryStream body = new MemoryStream())
            {
                response.OutputStream.CopyTo(body);
                Assert.Equal("hello", Encoding.ASCII.GetString(body.ToArray()));
            }
        }

        [Fact]
        public async Task NoContentResponseHasNoBody()
        {
            byte[] responseBytes = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\n\r\n");
            HttpResponse response = await HttpResponse.ReadResponseAsync(new MemoryStream(responseBytes));

            Assert.Null(response.OutputStream);
        }
    }
}
