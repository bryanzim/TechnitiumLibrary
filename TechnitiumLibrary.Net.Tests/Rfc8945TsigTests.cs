using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc8945TsigTests
    {
        [Fact]
        public void SignedRequestRoundTripVerifies()
        {
            TsigKey key = Key();
            DnsDatagram request = Query();
            DnsDatagram signed = DnsWire.RoundTrip(request.SignRequest(key, 300));

            bool verified = signed.VerifySignedRequest(Keys(key), out DnsDatagram unsignedRequest, out DnsDatagram errorResponse);

            Assert.True(verified);
            Assert.Null(errorResponse);
            Assert.Equal("example.com", unsignedRequest.Question[0].Name);
            Assert.False(unsignedRequest.IsSigned);
        }

        [Fact]
        public void SignedResponseRoundTripVerifies()
        {
            TsigKey key = Key();
            DnsDatagram signedRequest = Query().SignRequest(key, 300);
            DnsDatagram response = new DnsDatagram(signedRequest.Identifier, true, DnsOpcode.StandardQuery, true, false, true, true, false, false, DnsResponseCode.NoError,
                signedRequest.Question,
                [new DnsResourceRecord("example.com", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(System.Net.IPAddress.Parse("192.0.2.1")))]);

            DnsDatagram signedResponse = DnsWire.RoundTrip(response.SignResponse(signedRequest, Keys(key)));

            bool verified = signedResponse.VerifySignedResponse(signedRequest, key, out DnsDatagram unsignedResponse, out bool requestFailed, out DnsResponseCode rCode, out DnsTsigError error, out _);

            Assert.True(verified);
            Assert.False(requestFailed);
            Assert.Equal(DnsResponseCode.NoError, rCode);
            Assert.Equal(DnsTsigError.NoError, error);
            Assert.Equal("example.com", unsignedResponse.Question[0].Name);
            Assert.Single(unsignedResponse.Answer);
        }

        [Fact]
        public void ChangedMacDoesNotVerify()
        {
            TsigKey key = Key();
            byte[] wire = DnsWire.Write(Query().SignRequest(key, 300));
            wire[wire.Length - 7] ^= 0xFF;

            DnsDatagram signed = DnsWire.Read(wire);
            bool verified = signed.VerifySignedRequest(Keys(key), out DnsDatagram unsignedRequest, out DnsDatagram errorResponse);

            Assert.False(verified);
            Assert.Null(unsignedRequest);
            Assert.NotNull(errorResponse);
            Assert.Equal(DnsTsigError.BADSIG, errorResponse.TsigError);
        }

        static DnsDatagram Query()
        {
            return new DnsDatagram(0x2222, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.com", DnsResourceRecordType.A, DnsClass.IN)]);
        }

        static TsigKey Key()
        {
            return new TsigKey("tsig.example", Convert.ToBase64String(new byte[32]), TsigAlgorithm.HMAC_SHA256);
        }

        static IReadOnlyDictionary<string, TsigKey> Keys(TsigKey key)
        {
            return new Dictionary<string, TsigKey> { { key.KeyName, key } };
        }
    }
}
