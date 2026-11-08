using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc7871ClientSubnetTests
    {
        [Fact]
        public void RoundTripClearsBitsOutsideTheSourcePrefix()
        {
            EDnsOption[] options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(20, 0, IPAddress.Parse("192.0.2.255"));
            DnsDatagram message = new DnsDatagram(9, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)],
                udpPayloadSize: 1232,
                options: options);

            EDnsClientSubnetOptionData ecs = DnsWire.RoundTrip(message).GetEDnsClientSubnetOption();

            Assert.NotNull(ecs);
            Assert.Equal((byte)20, ecs.SourcePrefixLength);
            Assert.Equal((byte)0, ecs.ScopePrefixLength);
            Assert.Equal(IPAddress.Parse("192.0.0.0"), ecs.Address);
        }
    }
}
