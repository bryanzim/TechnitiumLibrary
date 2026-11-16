using System;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using DnsResponseCode = TechnitiumLibrary.Net.Dns.DnsResponseCode;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc2136EmptyRdataTests
    {
        [Fact]
        public void ClassAnyDeleteOfAnAddressRoundTrips()
        {
            DnsResourceRecord delete = Empty("www.example.com", DnsResourceRecordType.A, DnsClass.ANY);
            DnsDatagram read = Update(null, delete);

            Assert.Null(read.ParsingException);
            Assert.Equal(DnsResourceRecordType.A, read.Authority[0].Type);
            Assert.Equal(DnsClass.ANY, read.Authority[0].Class);
            Assert.Equal(0u, read.Authority[0].TTL);
            Assert.Equal(0, read.Authority[0].RDATA.RDLENGTH);
        }

        [Fact]
        public void ClassNonePrerequisiteForAaaaRoundTrips()
        {
            DnsResourceRecord prerequisite = Empty("www.example.com", DnsResourceRecordType.AAAA, DnsClass.NONE);
            DnsDatagram read = Update(prerequisite, null);

            Assert.Null(read.ParsingException);
            Assert.Equal(DnsResourceRecordType.AAAA, read.Answer[0].Type);
            Assert.Equal(DnsClass.NONE, read.Answer[0].Class);
            Assert.Equal(0, read.Answer[0].RDATA.RDLENGTH);
        }

        [Fact]
        public void ClassInAddressIsStillParsedAsAnAddress()
        {
            DnsResourceRecord address = new DnsResourceRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.1")));
            DnsDatagram read = DnsWire.RoundTrip(new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN)],
                [address]));

            Assert.Null(read.ParsingException);
            Assert.IsType<DnsARecordData>(read.Answer[0].RDATA);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)read.Answer[0].RDATA).Address);
        }

        static DnsResourceRecord Empty(string name, DnsResourceRecordType type, DnsClass @class)
        {
            return new DnsResourceRecord(name, type, @class, 0, new DnsUnknownRecordData(Array.Empty<byte>()));
        }

        static DnsDatagram Update(DnsResourceRecord prerequisite, DnsResourceRecord update)
        {
            return DnsWire.RoundTrip(new DnsDatagram(1, false, DnsOpcode.Update, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.SOA, DnsClass.IN)],
                prerequisite is null ? null : [prerequisite],
                update is null ? null : [update]));
        }
    }
}
