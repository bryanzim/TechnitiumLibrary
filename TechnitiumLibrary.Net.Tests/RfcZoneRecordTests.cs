using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class RfcZoneRecordTests
    {
        [Fact]
        public void ZoneTtlUnitsThatOverflowAreRejected()
        {
            Assert.False(ZoneFile.TryParseTtl("7102w", out _));
            Assert.True(ZoneFile.TryParseTtl("1w", out uint ttl));
            Assert.Equal(604800u, ttl);
        }

        [Fact]
        public async Task ZeroTtlDirectiveAppliesToLaterRecords()
        {
            string zone = "$ORIGIN example.com.\n$TTL 0\n@ A 1.2.3.4\nwww 300 A 1.2.3.4\nalias CNAME www\n";
            List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(new StringReader(zone));

            Assert.Equal(0u, records[0].TTL);
            Assert.Equal(300u, records[1].TTL);
            Assert.Equal(0u, records[2].TTL);
        }

        [Fact]
        public void CharacterStringEscapeDecodesADecimalOctet()
        {
            Assert.Equal("a", ZoneFile.UnescapeCharacterString(@"\097"));
        }

        [Fact]
        public void SoaMailboxHostIsConvertedToAnALabel()
        {
            Assert.Equal("hostmaster@xn--exmple-cua.com", DnsSOARecordData.GetResponsiblePersonEmailFormat("hostmaster@exämple.com"));
            Assert.Equal("first.last@example.com", DnsSOARecordData.GetResponsiblePersonEmailFormat(@"first\.last.example.com"));
        }

        [Fact]
        public void TruncatedTxtCharacterStringIsAParseError()
        {
            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.TXT, new byte[] { 5, (byte)'a', (byte)'b' }));

            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("character-string", ex.Message);
        }

        [Fact]
        public void CaaTagMustBeAscii()
        {
            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.CAA, new byte[] { 0, 1, 0xE9, (byte)'x' }));

            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("ASCII", ex.Message);
        }

        [Fact]
        public void Nsec3OwnerHashMatchesTheRfc5155Vector()
        {
            DnsNSEC3PARAMRecordData param = new DnsNSEC3PARAMRecordData(DnssecNSEC3HashAlgorithm.SHA1, 0, 12, Convert.FromHexString("AABBCCDD"));

            Assert.Equal("0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM", param.ComputeHashedOwnerNameBase32HexString("example"));
        }

        [Fact]
        public void RrsigLabelCountSkipsALeadingWildcard()
        {
            Assert.Equal(2, DnsRRSIGRecordData.GetLabelCount("*.example.com"));
            Assert.Equal(0, DnsRRSIGRecordData.GetLabelCount(""));
            Assert.Equal(3, DnsRRSIGRecordData.GetLabelCount("www.example.com"));
        }

        [Fact]
        public async Task DomainNameDecimalEscapeBecomesTheOctet()
        {
            string zone = "$ORIGIN example.com.\nex\\097mple A 1.2.3.4\n";
            List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(new StringReader(zone));

            Assert.Equal("example.example.com", records[0].Name);
        }

        [Fact]
        public void SvcbTargetNameRejectsCompression()
        {
            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.SVCB, new byte[] { 0x00, 0x01, 0xC0, 0x00 }));

            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("compression", ex.Message);
        }

        [Fact]
        public void SvcbKeysMustIncrease()
        {
            byte[] rdata = new byte[] { 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x50, 0x00, 0x01 };
            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.SVCB, rdata));

            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("increasing", ex.Message);
        }

        [Fact]
        public void CanonicalMxNameIsLowercase()
        {
            DnsMXRecordData mx = new DnsMXRecordData(10, "Mail.Example.com");

            using (MemoryStream stream = new MemoryStream())
            {
                mx.WriteCanonicalRecordData(stream);
                byte[] wire = stream.ToArray();
                byte[] name = new byte[] { 4, (byte)'m', (byte)'a', (byte)'i', (byte)'l', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0 };

                Assert.Equal(name, wire.AsSpan(2).ToArray());
                Assert.DoesNotContain((byte)'M', wire);
            }
        }

        [Fact]
        public void SrvTargetIsWrittenWithoutCompression()
        {
            DnsSRVRecordData srv = new DnsSRVRecordData(0, 0, 80, "example.com");

            using (MemoryStream stream = new MemoryStream())
            {
                srv.WriteCanonicalRecordData(stream);

                Assert.DoesNotContain((byte)0xC0, stream.ToArray());
            }
        }

        static byte[] MessageWithRData(DnsResourceRecordType type, byte[] rdata)
        {
            byte[] name = new byte[] { 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0 };
            byte[] wire = new byte[12 + name.Length + 4 + 2 + name.Length + 10 + rdata.Length];
            wire[5] = 1;
            wire[7] = 1;
            name.CopyTo(wire, 12);
            int questionType = 12 + name.Length;
            wire[questionType + 1] = 1;
            wire[questionType + 3] = 1;
            int answer = questionType + 4;
            wire[answer] = 0xC0;
            wire[answer + 1] = 0x0C;
            wire[answer + 2] = (byte)((ushort)type >> 8);
            wire[answer + 3] = (byte)type;
            wire[answer + 5] = 1;
            wire[answer + 10] = (byte)(rdata.Length >> 8);
            wire[answer + 11] = (byte)rdata.Length;
            rdata.CopyTo(wire, answer + 12);
            return wire;
        }
    }
}
