using IPAddress = System.Net.IPAddress;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class QnameMinimizationCacheTests
    {
        [Fact]
        public async Task CacheQueryKeepsTheFullNameWhileMinimizationIsEnabled()
        {
            DnsQuestionRecord question = new DnsQuestionRecord("www.example.com", DnsResourceRecordType.A, DnsClass.IN);
            question.ZoneCut = "";
            RecordingCache cache = new RecordingCache();

            DnsDatagram response = await DnsClient.RecursiveResolveAsync(question, cache, udpPayloadSize: 1232);

            Assert.Equal("com", question.MinimizedName);
            Assert.Equal("www.example.com", cache.QueriedQuestion.Name);
            Assert.Equal(DnsResourceRecordType.A, cache.QueriedQuestion.Type);
            Assert.Null(cache.QueriedQuestion.MinimizedName);
            Assert.Null(response.Question[0].MinimizedName);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), ((DnsARecordData)response.Answer[0].RDATA).Address);
        }

        sealed class RecordingCache : IDnsCache
        {
            public DnsQuestionRecord QueriedQuestion;

            public Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
            {
                QueriedQuestion = request.Question[0];
                DnsResourceRecord answer = new DnsResourceRecord(QueriedQuestion.Name, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.1")));
                DnsDatagram response = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, [answer]);
                return Task.FromResult(response);
            }

            public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null)
            { }
        }
    }
}
