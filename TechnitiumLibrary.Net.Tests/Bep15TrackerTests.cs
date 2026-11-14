using System.Text;
using TechnitiumLibrary.Net.BitTorrent;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class Bep15TrackerTests
    {
        [Fact]
        public void AnErrorActionKeepsTheTrackerMessage()
        {
            byte[] message = Encoding.UTF8.GetBytes("torrent not registered");
            byte[] packet = new byte[8 + message.Length];
            packet[3] = 3;
            message.CopyTo(packet, 8);

            TrackerClientException ex = Assert.Throws<TrackerClientException>(() => UdpTrackerClient.ThrowIfTrackerError(packet, packet.Length));

            Assert.Equal("torrent not registered", ex.Message);
        }
    }
}
