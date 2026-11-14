using System;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc9520FailureCacheTests
    {
        [Fact]
        public void FailureRecordTtlStaysInsideTheRfc9520Range()
        {
            DnsCache cache = new DnsCache();

            Assert.Equal(DnsCache.FAILURE_RECORD_TTL_MIN, 1u);
            Assert.Equal(DnsCache.FAILURE_RECORD_TTL_MAX, 300u);
            Assert.Equal(10u, cache.FailureRecordTtl);

            cache.FailureRecordTtl = DnsCache.FAILURE_RECORD_TTL_MIN;
            cache.FailureRecordTtl = DnsCache.FAILURE_RECORD_TTL_MAX;

            Assert.Throws<ArgumentOutOfRangeException>(() => cache.FailureRecordTtl = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => cache.FailureRecordTtl = DnsCache.FAILURE_RECORD_TTL_MAX + 1);
            Assert.Equal(DnsCache.FAILURE_RECORD_TTL_MAX, cache.FailureRecordTtl);
        }

        [Fact]
        public async Task ServerFailureIsReturnedFromTheFailureCache()
        {
            DnsCache cache = new DnsCache();
            cache.MinimumRecordTtl = 86400;
            cache.FailureRecordTtl = 10;
            DnsQuestionRecord question = new DnsQuestionRecord("failure.example", DnsResourceRecordType.A, DnsClass.IN);
            DnsDatagram failure = new DnsDatagram(1, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.ServerFailure, [question]);

            cache.CacheResponse(failure);

            DnsDatagram request = new DnsDatagram(2, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("failure.example", DnsResourceRecordType.A, DnsClass.IN)]);
            DnsDatagram cached = await cache.QueryAsync(request);

            Assert.NotNull(cached);
            Assert.Equal(DnsResponseCode.ServerFailure, cached.RCODE);
        }
    }
}
