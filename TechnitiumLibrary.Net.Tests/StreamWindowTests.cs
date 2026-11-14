using System;
using System.IO;
using TechnitiumLibrary.IO;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class StreamWindowTests
    {
        [Fact]
        public void AWindowLargerThanInt32CanBeRead()
        {
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            OffsetStream window = new OffsetStream(new MemoryStream(data), 0, (long)int.MaxValue + 5, true);
            byte[] buffer = new byte[4];

            Assert.Equal(4, window.Read(buffer, 0, 4));
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, buffer);
        }

        [Fact]
        public void ANegativeWindowPositionIsRejected()
        {
            OffsetStream window = new OffsetStream(new MemoryStream(new byte[] { 1, 2, 3, 4 }), 0, 4, true);

            Assert.Throws<ArgumentOutOfRangeException>(() => window.Position = -1);
        }

        [Fact]
        public void DisposingOnePipeEndStillReturnsBufferedBytes()
        {
            Pipe pipe = new Pipe();
            pipe.Stream1.Write(new byte[] { 9, 8, 7, 6, 5 }, 0, 5);

            byte[] first = new byte[2];
            Assert.Equal(2, pipe.Stream2.Read(first, 0, 2));
            Assert.Equal(new byte[] { 9, 8 }, first);

            pipe.Stream1.Dispose();

            byte[] rest = new byte[3];
            Assert.Equal(3, pipe.Stream2.Read(rest, 0, 3));
            Assert.Equal(new byte[] { 7, 6, 5 }, rest);
            Assert.Equal(0, pipe.Stream2.Read(rest, 0, 3));
        }
    }
}
