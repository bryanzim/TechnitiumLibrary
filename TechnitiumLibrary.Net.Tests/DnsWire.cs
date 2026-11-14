using System.IO;
using TechnitiumLibrary.Net.Dns;

namespace TechnitiumLibrary.Net.Tests
{
    static class DnsWire
    {
        public static byte[] Write(DnsDatagram message)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                message.WriteTo(stream);
                return stream.ToArray();
            }
        }

        public static DnsDatagram Read(byte[] wire)
        {
            using (MemoryStream stream = new MemoryStream(wire, writable: false))
                return DnsDatagram.ReadFrom(stream);
        }

        public static DnsDatagram RoundTrip(DnsDatagram message)
        {
            return Read(Write(message));
        }
    }
}
