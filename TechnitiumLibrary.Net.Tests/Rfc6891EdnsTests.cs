using System;
using System.Linq;
using IPAddress = System.Net.IPAddress;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
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

        [Fact]
        public void OptionsCloneRequiresAnExistingOptRecord()
        {
            DnsDatagram message = QueryWithoutEdns();

            Assert.Null(message.EDNS);
            Assert.Throws<InvalidOperationException>(() => message.CloneWithEDnsOptions(Array.Empty<EDnsOption>()));
        }

        [Fact]
        public void PayloadCloneAddsAnOptRecordWhenTheDatagramHasNone()
        {
            DnsResourceRecord glue = new DnsResourceRecord("ns.example", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.10")));
            DnsDatagram message = new DnsDatagram(7, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)],
                additional: [glue]);

            DnsDatagram cloned = message.CloneWithEDnsOptions(1232, DnsResponseCode.NoError, 0, EDnsHeaderFlags.DNSSEC_OK, [new EDnsOption(EDnsOptionCode.EDNS_EXPIRE, new EDnsExpireOptionData(60))]);
            DnsDatagram read = DnsWire.RoundTrip(cloned);

            Assert.True(read.DnssecOk);
            Assert.Equal((ushort)1232, read.EDNS.UdpPayloadSize);
            Assert.Equal(EDnsOptionCode.EDNS_EXPIRE, read.EDNS.Options[0].Code);
            Assert.Equal((uint)60, ((EDnsExpireOptionData)read.EDNS.Options[0].Data).Expire);
            Assert.Contains(read.Additional, record => (record.Type == DnsResourceRecordType.A) && (record.Name == "ns.example"));
        }

        static DnsDatagram QueryWithoutEdns()
        {
            return new DnsDatagram(7, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)]);
        }
    }
}
