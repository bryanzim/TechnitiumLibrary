using System.Collections.Generic;
using TechnitiumLibrary.ByteTree;
using Xunit;

namespace TechnitiumLibrary.Net.Tests
{
    public sealed class ByteTreeTests
    {
        [Fact]
        public void ReverseEnumerationPassesAnEmptyStem()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(new byte[] { 2 }, "gone");
            tree.Add(new byte[] { 2, 1 }, "child");
            Assert.True(tree.TryRemove(new byte[] { 2 }, out _));
            Assert.True(tree.TryRemove(new byte[] { 2, 1 }, out _));
            tree.Add(new byte[] { 1 }, "left");
            tree.Add(new byte[] { 9 }, "right");

            Assert.Equal(new string[] { "left", "right" }, Values(tree));
            Assert.Equal(new string[] { "right", "left" }, Values(tree.GetReverseEnumerable()));

            Assert.True(tree.TryRemove(new byte[] { 1 }, out _));
            Assert.True(tree.TryRemove(new byte[] { 9 }, out _));
            Assert.True(tree.IsEmpty);
        }

        static string[] Values(IEnumerable<string> values)
        {
            List<string> list = new List<string>();

            foreach (string value in values)
                list.Add(value);

            return list.ToArray();
        }
    }
}
