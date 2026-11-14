using System;
using System.Text;
using TechnitiumLibrary;
using TechnitiumLibrary.Security.OTP;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Rfc6238TotpTests
    {
        [Theory]
        [InlineData(0, "755224")]
        [InlineData(30, "287082")]
        [InlineData(59, "94287082")]
        [InlineData(1111111109, "07081804")]
        [InlineData(1111111111, "14050471")]
        [InlineData(1234567890, "89005924")]
        [InlineData(2000000000, "69279037")]
        public void TimeStepMatchesTheRfcVector(long unixTime, string expected)
        {
            int digits = expected.Length;
            Authenticator authenticator = Create(digits);
            DateTime utc = DateTime.UnixEpoch.AddSeconds(unixTime);

            Assert.Equal(expected, authenticator.GetTOTP(utc));
            Assert.Equal(expected, authenticator.GetTOTP(DateTime.SpecifyKind(utc, DateTimeKind.Unspecified)));
            Assert.Equal(expected, authenticator.GetTOTP(utc.ToLocalTime()));
        }

        [Fact]
        public void KeyUriEncodesSpacesAndRejectsAMissingValue()
        {
            AuthenticatorKeyUri uri = new AuthenticatorKeyUri("totp", "Foo Bar", "user", "AAAA");

            Assert.Contains("Foo%20Bar", uri.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("Foo+Bar", uri.ToString(), StringComparison.Ordinal);

            AuthenticatorKeyUri parsed = AuthenticatorKeyUri.Parse(uri.ToString());
            Assert.Equal("Foo Bar", parsed.Issuer);
            Assert.Equal("user", parsed.AccountName);

            Assert.Throws<ArgumentOutOfRangeException>(() => new AuthenticatorKeyUri("totp", "Example", "alice", "AAAA", period: 0));
            Assert.Throws<ArgumentException>(() => AuthenticatorKeyUri.Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer"));
        }

        static Authenticator Create(int digits)
        {
            string secret = Base32.ToBase32String(Encoding.ASCII.GetBytes("12345678901234567890"), true);
            return new Authenticator(new AuthenticatorKeyUri("totp", "Example", "user", secret, digits: digits));
        }
    }
}
