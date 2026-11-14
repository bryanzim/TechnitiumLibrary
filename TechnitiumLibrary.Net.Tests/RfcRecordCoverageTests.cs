using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using IPAddress = System.Net.IPAddress;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class RfcRecordCoverageTests
    {
        [Fact]
        public void SoaMxTxtSrvAndCaaRoundTrip()
        {
            DnsSOARecordData soa = new DnsSOARecordData("ns.example.com", "hostmaster@example.com", 2026111401, 3600, 600, 86400, 300);
            DnsMXRecordData mx = new DnsMXRecordData(10, "mail.example.com");
            DnsTXTRecordData txt = new DnsTXTRecordData(new string[] { "hello", "" });
            DnsSRVRecordData srv = new DnsSRVRecordData(0, 5, 443, "Target.Example.com");
            DnsCAARecordData caa = new DnsCAARecordData(0, "ISSUE", "letsencrypt.org");

            DnsDatagram message = new DnsDatagram(9, true, DnsOpcode.StandardQuery, true, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.SOA, DnsClass.IN)],
                [
                    new DnsResourceRecord("example.com", DnsResourceRecordType.SOA, DnsClass.IN, 60, soa),
                    new DnsResourceRecord("example.com", DnsResourceRecordType.MX, DnsClass.IN, 60, mx),
                    new DnsResourceRecord("example.com", DnsResourceRecordType.TXT, DnsClass.IN, 60, txt),
                    new DnsResourceRecord("_443._tcp.example.com", DnsResourceRecordType.SRV, DnsClass.IN, 60, srv),
                    new DnsResourceRecord("example.com", DnsResourceRecordType.CAA, DnsClass.IN, 60, caa)
                ]);

            DnsDatagram read = DnsWire.RoundTrip(message);

            DnsSOARecordData soaRead = (DnsSOARecordData)read.Answer[0].RDATA;
            Assert.Equal("ns.example.com", soaRead.PrimaryNameServer);
            Assert.Equal("hostmaster@example.com", soaRead.ResponsiblePerson);
            Assert.Equal(2026111401u, soaRead.Serial);
            Assert.Equal(3600u, soaRead.Refresh);
            Assert.Equal(300u, soaRead.Minimum);

            Assert.Equal((ushort)10, ((DnsMXRecordData)read.Answer[1].RDATA).Preference);
            Assert.Equal("mail.example.com", ((DnsMXRecordData)read.Answer[1].RDATA).Exchange);
            Assert.Equal(new string[] { "hello", "" }, ((DnsTXTRecordData)read.Answer[2].RDATA).GetCharacterStrings());
            Assert.Equal((ushort)443, ((DnsSRVRecordData)read.Answer[3].RDATA).Port);
            Assert.Equal("Target.Example.com", ((DnsSRVRecordData)read.Answer[3].RDATA).Target);
            Assert.Equal("issue", ((DnsCAARecordData)read.Answer[4].RDATA).Tag);
            Assert.Equal("letsencrypt.org", ((DnsCAARecordData)read.Answer[4].RDATA).Value);
        }

        [Fact]
        public void SerialArithmeticUsesTheRfc1982HalfRange()
        {
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(0xFFFFFFF0, 5));
            Assert.False(DnsSOARecordData.IsZoneUpdateAvailable(1, 1));
            Assert.False(DnsSOARecordData.IsZoneUpdateAvailable(0, 0x80000000));
            Assert.True(DnsSOARecordData.IsZoneUpdateAvailable(0, 1));
        }

        [Fact]
        public void NaptrReplacementMayBeACompressionPointer()
        {
            byte[] wire = new byte[]
            {
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x01,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0x03, (byte)'c', (byte)'o', (byte)'m', 0x00,
                0x00, 0x01,
                0x00, 0x01,
                0xC0, 0x0C,
                0x00, 0x23,
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C,
                0x00, 0x0A,
                0x00, 0x0A,
                0x00, 0x14,
                0x01, (byte)'u',
                0x00,
                0x00,
                0xC0, 0x0C
            };

            DnsDatagram read = DnsWire.Read(wire);

            Assert.Null(read.ParsingException);
            DnsNAPTRRecordData naptr = (DnsNAPTRRecordData)read.Answer[0].RDATA;
            Assert.Equal((ushort)10, naptr.Order);
            Assert.Equal((ushort)20, naptr.Preference);
            Assert.Equal("u", naptr.Flags);
            Assert.Equal("example.com", naptr.Replacement);
        }

        [Fact]
        public void NaptrCanonicalFormLowercasesTheReplacement()
        {
            DnsNAPTRRecordData naptr = new DnsNAPTRRecordData(1, 1, "u", "", "", "Example.COM");

            using (MemoryStream stream = new MemoryStream())
            {
                naptr.WriteCanonicalRecordData(stream);

                byte[] canonical = stream.ToArray();
                Assert.True(ContainsSequence(canonical, Encoding.ASCII.GetBytes("example")));
                Assert.False(ContainsSequence(canonical, Encoding.ASCII.GetBytes("Example")));
            }
        }

        [Fact]
        public void DnameSubstitutionReplacesTheOwnerSuffix()
        {
            DnsDNAMERecordData dname = new DnsDNAMERecordData("example.net");

            Assert.Equal("www.example.net", dname.Substitute("www.example.com", "example.com"));
            Assert.Equal("www.example.com.example.net", dname.Substitute("www.example.com", ""));
            Assert.Equal("www", new DnsDNAMERecordData("").Substitute("www.example.com", "example.com"));
            Assert.Equal("www.example.com", new DnsDNAMERecordData("").Substitute("www.example.com", ""));
        }

        [Fact]
        public void RootZoneIsTheParentOfEveryOtherName()
        {
            Assert.True(DnsDatagram.IsNameUnder("www.example.com", ""));
            Assert.False(DnsDatagram.IsNameUnder("", ""));
            Assert.True(DnsDatagram.IsNameUnder("www.example.com", "example.com"));
            Assert.False(DnsDatagram.IsNameUnder("example.com", "example.com"));
        }

        [Fact]
        public void NsecTypeBitInWindowOneRoundTrips()
        {
            DnsDatagram message = new DnsDatagram(1, true, DnsOpcode.StandardQuery, true, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.NSEC, DnsClass.IN)],
                [new DnsResourceRecord("example.com", DnsResourceRecordType.NSEC, DnsClass.IN, 60, new DnsNSECRecordData("example.com", [DnsResourceRecordType.URI]))]);

            DnsNSECRecordData nsec = (DnsNSECRecordData)DnsWire.RoundTrip(message).Answer[0].RDATA;

            Assert.Contains(DnsResourceRecordType.URI, nsec.Types);
        }

        [Fact]
        public void NsecBitmapLongerThan32BytesIsRejected()
        {
            byte[] bitmap = new byte[1 + 1 + 1 + 33];
            bitmap[2] = 33;
            bitmap[3 + 32] = 0x80;

            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.NSEC, bitmap));
            DnsClientException ex = Assert.IsType<DnsClientException>(message.ParsingException);
            Assert.Contains("bitmap", ex.Message);
        }

        [Fact]
        public void NsecCanonicalOrderComparesTheRightmostLabelFirst()
        {
            Assert.True(DnsNSECRecordData.CanonicalComparison("example", "a.example") < 0);
            Assert.True(DnsNSECRecordData.CanonicalComparison("b.example", "a.example") > 0);
        }

        [Fact]
        public void UriTargetKeepsItsOriginalOctets()
        {
            byte[] target = Encoding.ASCII.GetBytes("http://example.com");
            byte[] rdata = new byte[4 + target.Length];
            rdata[1] = 1;
            rdata[3] = 1;
            target.CopyTo(rdata, 4);

            byte[] wire = MessageWithRData(DnsResourceRecordType.URI, rdata);
            DnsDatagram read = DnsWire.Read(wire);
            Assert.Null(read.ParsingException);

            byte[] written = DnsWire.Write(read);
            Assert.True(ContainsSequence(written, target));
            Assert.False(ContainsSequence(written, Encoding.ASCII.GetBytes("http://example.com/")));
        }

        [Fact]
        public void EdeExtraTextLengthIsUtf8Bytes()
        {
            EDnsExtendedDnsErrorOptionData ede = new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "caf\u00e9");

            Assert.Equal(2 + Encoding.UTF8.GetByteCount("caf\u00e9"), ede.UncompressedLength);

            DnsDatagram message = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)],
                udpPayloadSize: 1232,
                options: [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, ede)]);

            EDnsExtendedDnsErrorOptionData read = (EDnsExtendedDnsErrorOptionData)DnsWire.RoundTrip(message).EDNS.Options[0].Data;
            Assert.Equal(EDnsExtendedDnsErrorCode.Other, read.InfoCode);
            Assert.Equal("caf\u00e9", read.ExtraText);
        }

        [Fact]
        public void Ipv4EmbeddedInIpv6UsesTheRfc6052PrefixLayout()
        {
            IPAddress mapped = IPAddress.Parse("192.0.2.1").MapToIPv6(NetworkAddress.Parse("2001:db8::/32"));

            Assert.Equal(IPAddress.Parse("2001:db8:c000:201::"), mapped);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), mapped.MapToIPv4(32));
        }

        [Fact]
        public void Ip6ArpaLabelsAreSingleHexDigits()
        {
            Assert.False(IPAddressExtensions.TryParseReverseDomain("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0a.ip6.arpa", out _));

            IPAddress parsed = IPAddressExtensions.ParseReverseDomain("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa");
            Assert.Equal(IPAddress.Parse("::1"), parsed);
        }

        [Fact]
        public void NegativePrefixIsRejected()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => IPAddressExtensions.GetSubnetMask(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => IPAddress.Parse("1.2.3.4").GetNetworkAddress(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => IPAddress.IPv6Any.GetNetworkAddress(-1));
        }

        [Fact]
        public void AddressMapDoesNotFillTheGapBetweenTwoNetworks()
        {
            NetworkMap<string> map = new NetworkMap<string>(AddressFamily.InterNetwork);
            map.Add("10.0.0.1/32", "a");
            map.Add("10.0.0.3/32", "a");
            map.Add("192.0.2.0/24", "doc");

            Assert.False(map.TryGetValue(IPAddress.Parse("10.0.0.2"), out _));
            Assert.True(map.TryGetValue(IPAddress.Parse("10.0.0.1"), out string host));
            Assert.Equal("a", host);
            Assert.True(map.TryGetValue(IPAddress.Parse("192.0.2.20"), out string documentation));
            Assert.Equal("doc", documentation);
            Assert.False(map.TryGetValue(IPAddress.Parse("192.0.3.1"), out _));
        }

        static bool ContainsSequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                    return true;
            }

            return false;
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
