using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc1035DatagramTests
    {
        [Fact]
        public void RoundTripPreservesQuestionAndAnswer()
        {
            DnsDatagram message = new DnsDatagram(0x1234, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN)],
                [new DnsResourceRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.1")))]);

            DnsDatagram read = DnsWire.RoundTrip(message);

            Assert.Equal(0x1234, read.Identifier);
            Assert.True(read.IsResponse);
            Assert.True(read.AuthoritativeAnswer);
            Assert.True(read.RecursionDesired);
            Assert.Equal(DnsResponseCode.NoError, read.RCODE);
            Assert.Equal("www.example.com", read.Question[0].Name);
            Assert.Equal(DnsResourceRecordType.A, read.Question[0].Type);
            Assert.Equal("www.example.com", read.Answer[0].Name);
            Assert.Equal(300u, read.Answer[0].TTL);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)read.Answer[0].RDATA).Address);
        }

        [Fact]
        public void RoundTripPreservesALabelOctetAbove127()
        {
            byte[] wire = new byte[]
            {
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x01, 0xC0, 0x00,
                0x00, 0x01,
                0x00, 0x01
            };

            DnsDatagram read = DnsWire.RoundTrip(DnsWire.Read(wire));

            Assert.Equal("\u00C0", read.Question[0].Name);
            Assert.Equal(0xC0, DnsWire.Write(read)[13]);
        }

        [Fact]
        public void RepeatedNameIsCompressedAndSurvivesTheRoundTrip()
        {
            DnsDatagram message = new DnsDatagram(1, true, DnsOpcode.StandardQuery, true, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN)],
                [new DnsResourceRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.10")))]);

            byte[] wire = DnsWire.Write(message);

            Assert.Contains((byte)0xC0, wire);

            DnsDatagram read = DnsWire.Read(wire);
            Assert.Equal("www.example.com", read.Question[0].Name);
            Assert.Equal("www.example.com", read.Answer[0].Name);
        }

        [Fact]
        public void CompressionPointerMustPointBackward()
        {
            byte[] wire = new byte[]
            {
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0xC0, 0x0C
            };

            DnsDatagram message = DnsWire.Read(wire);
            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("compression pointer", ex.Message);
        }

        [Fact]
        public void RdataLengthMustMatchRdlength()
        {
            byte[] wire = new byte[]
            {
                0x00, 0x01,
                0x84, 0x00,
                0x00, 0x01,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
                0x00, 0x01,
                0x00, 0x01,
                0xC0, 0x0C,
                0x00, 0x01,
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x05,
                192, 0, 2, 1
            };

            DnsDatagram message = DnsWire.Read(wire);
            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("RDLENGTH", ex.Message);
        }
    }
}
