using System.IO;
using System.Net.Http;
using System.Text;
using TechnitiumLibrary.Net.Http;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc9112ChunkTests
    {
        [Fact]
        public void ChunkSizeEndsAtTheCarriageReturn()
        {
            byte[] body = ReadChunks("5\r\nhello\r\n0\r\n\r\n");

            Assert.Equal("hello", Encoding.ASCII.GetString(body));
        }

        [Fact]
        public void ADigitAfterTheCarriageReturnIsRejected()
        {
            Assert.Throws<HttpRequestException>(() => ReadChunks("1\r2\nhello\r\n0\r\n\r\n"));
        }

        static byte[] ReadChunks(string wire)
        {
            byte[] payload = Encoding.ASCII.GetBytes(wire);
            HttpContentStream content = new HttpContentStream(new MemoryStream(payload), new byte[64], 0, 0);
            HttpChunkedStream chunked = new HttpChunkedStream(content);
            using (MemoryStream body = new MemoryStream())
            {
                chunked.CopyTo(body);
                return body.ToArray();
            }
        }
    }
}
