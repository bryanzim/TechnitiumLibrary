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

        [Fact]
        public void ChunkLimitCountsTheDecodedBody()
        {
            byte[] body = ReadChunks("5\r\nhello\r\n0\r\n\r\n", 5);

            Assert.Equal("hello", Encoding.ASCII.GetString(body));
        }

        [Fact]
        public void ChunkLimitRejectsABodyPastTheLimit()
        {
            Assert.Throws<HttpRequestException>(() => ReadChunks("6\r\nhello!\r\n0\r\n\r\n", 5));
        }

        [Fact]
        public void ZeroLengthContentReadLeavesTheBodyUnread()
        {
            byte[] payload = Encoding.ASCII.GetBytes("hello");
            HttpContentStream content = new HttpContentStream(new MemoryStream(payload), new byte[64], 0, 0, 5);
            byte[] buffer = new byte[5];

            Assert.Equal(0, content.Read(buffer, 0, 0));
            Assert.Equal(5, content.Read(buffer, 0, 5));
            Assert.Equal("hello", Encoding.ASCII.GetString(buffer));
        }

        static byte[] ReadChunks(string wire, int maxContentLength = -1)
        {
            byte[] payload = Encoding.ASCII.GetBytes(wire);
            HttpContentStream content = new HttpContentStream(new MemoryStream(payload), new byte[64], 0, 0);
            HttpChunkedStream chunked = new HttpChunkedStream(content, maxContentLength);
            using (MemoryStream body = new MemoryStream())
            {
                chunked.CopyTo(body);
                return body.ToArray();
            }
        }
    }
}
