using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc6891EdnsTests
    {
        [Fact]
        public void RoundTripPreservesPayloadSizeAndDnssecOk()
        {
            DnsDatagram message = new DnsDatagram(7, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)],
                udpPayloadSize: 1232,
                ednsFlags: EDnsHeaderFlags.DNSSEC_OK);

            DnsDatagram read = DnsWire.RoundTrip(message);

            Assert.True(read.DnssecOk);
            Assert.NotNull(read.EDNS);
            Assert.Equal((ushort)1232, read.EDNS.UdpPayloadSize);
            Assert.Empty(read.EDNS.Options);
        }

        [Fact]
        public void OptionLengthMustMatchItsValue()
        {
            byte[] wire = new byte[]
            {
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x01,
                0x00,
                0x00, 0x01,
                0x00, 0x01,
                0x00,
                0x00, 0x29,
                0x01, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x09,
                0x00, 0x09,
                0x00, 0x05,
                0x00, 0x00, 0x00, 0x01, 0xFF
            };

            DnsDatagram message = DnsWire.Read(wire);
            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("option length", ex.Message);
        }
    }
}
