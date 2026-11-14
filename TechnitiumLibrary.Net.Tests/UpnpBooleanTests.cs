using System;
using TechnitiumLibrary.Net.UPnP.Networking;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class UpnpBooleanTests
    {
        [Theory]
        [InlineData("1", true)]
        [InlineData("true", true)]
        [InlineData("YES", true)]
        [InlineData("0", false)]
        [InlineData("false", false)]
        [InlineData("no", false)]
        public void BooleanTokensFollowTheUpnpVocabulary(string text, bool expected)
        {
            Assert.Equal(expected, InternetGatewayDevice.ParseBoolean(text));
        }

        [Fact]
        public void AnUnknownBooleanTokenIsRejected()
        {
            Assert.Throws<FormatException>(() => InternetGatewayDevice.ParseBoolean("maybe"));
        }
    }
}
