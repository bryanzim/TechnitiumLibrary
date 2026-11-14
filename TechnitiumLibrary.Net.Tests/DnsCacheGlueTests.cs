using System.Linq;
using IPAddress = System.Net.IPAddress;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class DnsCacheGlueTests
    {
        [Fact]
        public async Task IdenticalGlueIsStoredOnce()
        {
            DnsResourceRecord nameServer = new DnsResourceRecord("example.com", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns1.example.com"));
            DnsResourceRecord glue = Glue("192.0.2.1");
            DnsResourceRecord sameGlue = Glue("192.0.2.1");
            DnsResourceRecord otherGlue = Glue("192.0.2.2");
            DnsDatagram response = new DnsDatagram(1, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.NS, DnsClass.IN)],
                [nameServer],
                additional: [glue, sameGlue, otherGlue]);

            DnsCache cache = new DnsCache();
            cache.CacheResponse(response);

            DnsDatagram request = new DnsDatagram(2, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.NS, DnsClass.IN)]);
            DnsDatagram cached = await cache.QueryAsync(request);

            Assert.Equal(2, cached.Additional.Count(record => record.Type == DnsResourceRecordType.A));
            Assert.Contains(cached.Additional, record => (record.Type == DnsResourceRecordType.A) && ((DnsARecordData)record.RDATA).Address.Equals(IPAddress.Parse("192.0.2.1")));
            Assert.Contains(cached.Additional, record => (record.Type == DnsResourceRecordType.A) && ((DnsARecordData)record.RDATA).Address.Equals(IPAddress.Parse("192.0.2.2")));
        }

        static DnsResourceRecord Glue(string address)
        {
            DnsResourceRecord record = new DnsResourceRecord("ns1.example.com", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse(address)));
            record.SetDnssecStatus(DnssecStatus.Indeterminate);
            return record;
        }
    }
}
