using System;
using System.Text;
using TechnitiumLibrary.Net.BitTorrent;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Bep3BencodeTests
    {
        [Fact]
        public void IntegersRejectLeadingZerosAndANegativeZero()
        {
            Assert.Equal(0, Bencoding.Decode(Encoding.ASCII.GetBytes("i0e")).ValueInteger);
            Assert.Equal(3, Bencoding.Decode(Encoding.ASCII.GetBytes("i3e")).ValueInteger);
            Assert.Equal(-3, Bencoding.Decode(Encoding.ASCII.GetBytes("i-3e")).ValueInteger);
            Assert.Throws<FormatException>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("i03e")));
            Assert.Throws<FormatException>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("i-0e")));
            Assert.Throws<FormatException>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("i+1e")));
        }

        [Fact]
        public void ADictionaryTerminatorIsNotAValue()
        {
            Assert.Throws<Exception>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("d1:aee")));
        }

        [Fact]
        public void StringLengthsAreDigits()
        {
            Assert.Equal("spam", Bencoding.Decode(Encoding.ASCII.GetBytes("4:spam")).ValueString);
            Assert.Throws<FormatException>(() => Bencoding.Decode(Encoding.ASCII.GetBytes("4 :spam")));
        }

        [Fact]
        public void ConstructedStringAndIntegerRoundTrip()
        {
            Assert.Equal("spam", new Bencoding(BencodingType.String, "spam").ValueString);
            Assert.Equal(3, new Bencoding(BencodingType.Integer, 3).ValueInteger);
        }
    }
}
