using System;
using System.IO;
using TechnitiumLibrary.Security.Cryptography;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class X690DerTests
    {
        [Fact]
        public void IntegersDropRedundantLeadingZeros()
        {
            Assert.Equal(new byte[] { 0x02, 0x01, 0x01 }, EncodeInteger(new byte[] { 0x00, 0x01 }));
            Assert.Equal(new byte[] { 0x02, 0x02, 0x00, 0x80 }, EncodeInteger(new byte[] { 0x80 }));
            Assert.Equal(new byte[] { 0x02, 0x02, 0x00, 0x80 }, EncodeInteger(new byte[] { 0x00, 0x00, 0x80 }));
            Assert.Equal(new byte[] { 0x02, 0x01, 0x00 }, EncodeInteger(new byte[] { 0x00, 0x00 }));
        }

        [Fact]
        public void AnEmptyIntegerIsRejected()
        {
            Assert.Throws<ArgumentException>(() => EncodeInteger(Array.Empty<byte>()));
        }

        [Fact]
        public void LongFormLengthIsBigEndian()
        {
            byte[] value = new byte[200];

            using (MemoryStream stream = new MemoryStream())
            {
                DEREncoding.Encode(DEREncodingASN1Type.OCTET_STRING, value, stream);
                byte[] encoded = stream.ToArray();

                Assert.Equal(0x04, encoded[0]);
                Assert.Equal(0x81, encoded[1]);
                Assert.Equal(200, encoded[2]);
            }
        }

        static byte[] EncodeInteger(byte[] value)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                DEREncoding.EncodeIntegerValue(value, stream);
                return stream.ToArray();
            }
        }
    }
}
