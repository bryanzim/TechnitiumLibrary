using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class RfcRecordGapTests
    {
        [Fact]
        public void DnsKeyDigestMatchesTheRfc4034Vector()
        {
            string publicKey = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==";
            DnsDNSKEYRecordData dnsKey = new DnsDNSKEYRecordData(DnsDnsKeyFlag.ZoneKey, 3, DnssecAlgorithm.RSASHA1, DnssecPublicKey.Parse(DnssecAlgorithm.RSASHA1, Convert.FromBase64String(publicKey)));
            DnsDSRecordData ds = dnsKey.CreateDS("dskey.example.com", DnssecDigestType.SHA1);

            Assert.Equal((ushort)60485, dnsKey.ComputedKeyTag);
            Assert.Equal((ushort)60485, ds.KeyTag);
            Assert.Equal("2BB183AF5F22588179A53B0A98631FAD1A292118", Convert.ToHexString(ds.Digest));
        }

        [Fact]
        public void SshfpJsonNamesTheFingerprintType()
        {
            DnsSSHFPRecordData sshfp = new DnsSSHFPRecordData(DnsSSHFPAlgorithm.RSA, DnsSSHFPFingerprintType.SHA1, new byte[20]);

            using (MemoryStream stream = new MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(stream))
                {
                    sshfp.SerializeTo(writer);
                }

                string json = Encoding.UTF8.GetString(stream.ToArray());
                Assert.Contains("\"FingerprintType\":\"SHA1\"", json);
            }
        }

        [Fact]
        public void AplDropsTrailingZeroOctetsAndKeepsNegation()
        {
            DnsAPLRecordData apl = new DnsAPLRecordData(new DnsAPLRecordData.APItem[]
            {
                new DnsAPLRecordData.APItem(NetworkAddress.Parse("192.168.32.0/21"), false),
                new DnsAPLRecordData.APItem(NetworkAddress.Parse("192.168.38.0/28"), true)
            });

            DnsDatagram read = DnsWire.RoundTrip(new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("foo.example.com", DnsResourceRecordType.APL, DnsClass.IN)],
                [new DnsResourceRecord("foo.example.com", DnsResourceRecordType.APL, DnsClass.IN, 3600, apl)]));

            List<DnsAPLRecordData.APItem> items = new List<DnsAPLRecordData.APItem>(((DnsAPLRecordData)read.Answer[0].RDATA).APItems);

            Assert.Equal(new byte[] { 0xC0, 0xA8, 0x20 }, items[0].AFDPart);
            Assert.False(items[0].Negation);
            Assert.Equal((byte)21, items[0].Prefix);
            Assert.Equal(new byte[] { 0xC0, 0xA8, 0x26 }, items[1].AFDPart);
            Assert.True(items[1].Negation);
            Assert.Equal("!1:192.168.38.0/28", items[1].ToZoneFileEntry());
        }

        [Fact]
        public void AnUnknownAplFamilyIsIgnoredByTheAccessList()
        {
            DnsDatagram message = DnsWire.Read(MessageWithRData(DnsResourceRecordType.APL, new byte[] { 0x00, 0x03, 0x08, 0x01, 0x0A }));

            Assert.Null(message.ParsingException);

            DnsAPLRecordData apl = (DnsAPLRecordData)message.Answer[0].RDATA;
            DnsAPLRecordData.APItem item = null;

            foreach (DnsAPLRecordData.APItem apItem in apl.APItems)
                item = apItem;

            Assert.Null(item.NetworkAddress);
            Assert.Equal("3:0A/8", item.ToZoneFileEntry());
            Assert.Empty(NetworkAccessControl.ConvertFromAPLRecordData(apl));
        }

        [Fact]
        public void SvcbMandatoryKeysAreStoredInIncreasingOrder()
        {
            DnsSvcMandatoryParamValue value = new DnsSvcMandatoryParamValue(new DnsSvcParamKey[] { DnsSvcParamKey.Port, DnsSvcParamKey.ALPN });

            using (MemoryStream stream = new MemoryStream())
            {
                value.WriteTo(stream);
                stream.Position = 0;

                DnsSvcMandatoryParamValue read = new DnsSvcMandatoryParamValue(stream);
                Assert.Equal(new DnsSvcParamKey[] { DnsSvcParamKey.ALPN, DnsSvcParamKey.Port }, read.Keys);
                Assert.Equal(value, read);
            }
        }

        [Fact]
        public void ARepeatedSvcbMandatoryKeyIsRejected()
        {
            Assert.Throws<ArgumentException>(() => new DnsSvcMandatoryParamValue(new DnsSvcParamKey[] { DnsSvcParamKey.ALPN, DnsSvcParamKey.ALPN }));
            Assert.Throws<ArgumentException>(() => new DnsSvcMandatoryParamValue(new DnsSvcParamKey[] { DnsSvcParamKey.Mandatory, DnsSvcParamKey.Port }));
        }

        [Fact]
        public async Task AnUnsupportedNsec3IterationCountIsNotAWildcardProof()
        {
            DnsNSEC3RecordData nsec3 = new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, 0, 101, new byte[] { 0xAA }, new byte[20], new DnsResourceRecordType[] { DnsResourceRecordType.A });
            DnsResourceRecord record = new DnsResourceRecord("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example.com", DnsResourceRecordType.NSEC3, DnsClass.IN, 60, nsec3);

            DnssecProofOfNonExistence proof = await DnsNSEC3RecordData.GetValidatedProofOfNonExistenceAsync(new DnsResourceRecord[] { record }, "www.example.com", DnsResourceRecordType.A, true, "www.example.com", "example.com");

            Assert.Equal(DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue, proof);
        }

        [Fact]
        public async Task AnUnknownNsec3HashAlgorithmIsSkipped()
        {
            DnsNSEC3RecordData nsec3 = new DnsNSEC3RecordData((DnssecNSEC3HashAlgorithm)2, 0, 0, Array.Empty<byte>(), new byte[20], new DnsResourceRecordType[] { DnsResourceRecordType.A });
            DnsResourceRecord record = new DnsResourceRecord("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example.com", DnsResourceRecordType.NSEC3, DnsClass.IN, 60, nsec3);

            DnssecProofOfNonExistence proof = await DnsNSEC3RecordData.GetValidatedProofOfNonExistenceAsync(new DnsResourceRecord[] { record }, "www.example.com", DnsResourceRecordType.A, false, null, null);

            Assert.Equal(DnssecProofOfNonExistence.NoProof, proof);
        }

        [Fact]
        public void HinfoCharacterStringsRoundTripAndRejectALongString()
        {
            DnsHINFORecordData hinfo = new DnsHINFORecordData("PC", "Windows");
            DnsDatagram read = DnsWire.RoundTrip(Record("example.com", DnsResourceRecordType.HINFO, hinfo));
            DnsHINFORecordData parsed = (DnsHINFORecordData)read.Answer[0].RDATA;

            Assert.Equal("PC", parsed.CPU);
            Assert.Equal("Windows", parsed.OS);

            DnsHINFORecordData tooLong = new DnsHINFORecordData(new string('x', 256), "os");
            Assert.Throws<DnsClientException>(() => tooLong.WriteCanonicalRecordData(new MemoryStream()));
        }

        [Fact]
        public void ZoneMdSha384DigestIs48Octets()
        {
            byte[] digest = new byte[48];
            digest[0] = 0x11;
            DnsZONEMDRecordData zoneMd = new DnsZONEMDRecordData(2026111401, ZoneMdScheme.Simple, ZoneMdHashAlgorithm.SHA384, digest);

            Assert.Throws<ArgumentException>(() => new DnsZONEMDRecordData(1, ZoneMdScheme.Simple, ZoneMdHashAlgorithm.SHA384, new byte[47]));

            DnsDatagram read = DnsWire.RoundTrip(Record("example.com", DnsResourceRecordType.ZONEMD, zoneMd));
            DnsZONEMDRecordData parsed = (DnsZONEMDRecordData)read.Answer[0].RDATA;

            Assert.Equal(2026111401u, parsed.Serial);
            Assert.Equal(ZoneMdScheme.Simple, parsed.Scheme);
            Assert.Equal(ZoneMdHashAlgorithm.SHA384, parsed.HashAlgorithm);
            Assert.Equal(digest, parsed.Digest);
        }

        [Fact]
        public void RpMailboxUsesTheFirstLabelAsTheLocalPart()
        {
            DnsRPRecordData rp = new DnsRPRecordData("louie.example.com", "louie-txt.example.com");

            Assert.Equal("louie@example.com", rp.Mailbox);

            DnsDatagram read = DnsWire.RoundTrip(Record("example.com", DnsResourceRecordType.RP, rp));
            DnsRPRecordData parsed = (DnsRPRecordData)read.Answer[0].RDATA;

            Assert.Equal("louie@example.com", parsed.Mailbox);
            Assert.Equal("louie-txt.example.com", parsed.TxtDomain);
        }

        [Fact]
        public void Nsec3ParamEmptySaltIsADash()
        {
            DnsNSEC3PARAMRecordData param = new DnsNSEC3PARAMRecordData(DnssecNSEC3HashAlgorithm.SHA1, 0, 0, Array.Empty<byte>());

            Assert.Equal("1 0 0 -", param.ToZoneFileEntry());
        }

        [Fact]
        public void TlsaSha256AssociationRoundTrips()
        {
            byte[] association = new byte[32];
            association[0] = 0xAB;
            DnsTLSARecordData tlsa = new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.SPKI, DnsTLSAMatchingType.SHA2_256, association);

            DnsDatagram read = DnsWire.RoundTrip(new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("_443._tcp.example.com", DnsResourceRecordType.TLSA, DnsClass.IN)],
                [new DnsResourceRecord("_443._tcp.example.com", DnsResourceRecordType.TLSA, DnsClass.IN, 3600, tlsa)]));

            DnsTLSARecordData parsed = (DnsTLSARecordData)read.Answer[0].RDATA;
            Assert.Equal(DnsTLSACertificateUsage.DANE_EE, parsed.CertificateUsage);
            Assert.Equal(DnsTLSASelector.SPKI, parsed.Selector);
            Assert.Equal(DnsTLSAMatchingType.SHA2_256, parsed.MatchingType);
            Assert.Equal(association, parsed.CertificateAssociationData);
        }

        static DnsDatagram Record(string name, DnsResourceRecordType type, DnsResourceRecordData data)
        {
            return new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord(name, type, DnsClass.IN)],
                [new DnsResourceRecord(name, type, DnsClass.IN, 3600, data)]);
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
