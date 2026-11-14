using System;
using System.Text;
using TechnitiumLibrary;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc4648Base32Tests
    {
        [Theory]
        [InlineData("", "")]
        [InlineData("f", "MY======")]
        [InlineData("fo", "MZXQ====")]
        [InlineData("foo", "MZXW6===")]
        [InlineData("foob", "MZXW6YQ=")]
        [InlineData("fooba", "MZXW6YTB")]
        [InlineData("foobar", "MZXW6YTBOI======")]
        public void EncodeAndDecodeMatchTheRfcVectors(string text, string encoded)
        {
            byte[] data = Encoding.ASCII.GetBytes(text);

            Assert.Equal(encoded, Base32.ToBase32String(data));
            Assert.Equal(data, Base32.FromBase32String(encoded));
            Assert.Equal(data, Base32.FromBase32String(encoded.TrimEnd('=')));
        }

        [Theory]
        [InlineData("AA=")]
        [InlineData("AAAAAAAA======")]
        [InlineData("MY====")]
        public void PaddingThatDoesNotMatchTheQuantumIsRejected(string encoded)
        {
            Assert.Throws<ArgumentException>(() => Base32.FromBase32String(encoded));
        }
    }
}
