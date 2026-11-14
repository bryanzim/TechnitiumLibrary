/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsURIRecordData : DnsResourceRecordData
    {
        #region variables

        ushort _priority;
        ushort _weight;
        string _target;
        Uri _uri;

        #endregion

        #region constructor

        public DnsURIRecordData(ushort priority, ushort weight, Uri uri)
        {
            _priority = priority;
            _weight = weight;
            _target = uri.OriginalString;
            _uri = uri;
        }

        public DnsURIRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _priority = DnsDatagram.ReadUInt16NetworkOrder(s);
            _weight = DnsDatagram.ReadUInt16NetworkOrder(s);
            _target = Encoding.UTF8.GetString(s.ReadExactly(_rdLength - 4));
            Uri.TryCreate(_target, UriKind.Absolute, out _uri);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_priority, s);
            DnsDatagram.WriteUInt16NetworkOrder(_weight, s);
            s.Write(Encoding.UTF8.GetBytes(_target));
        }

        #endregion

        #region internal

        internal static async Task<DnsURIRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsURIRecordData(rdata);

            ushort priority = ushort.Parse(await zoneFile.PopItemAsync());
            ushort weight = ushort.Parse(await zoneFile.PopItemAsync());
            Uri uri = new Uri(await zoneFile.PopItemAsync());

            return new DnsURIRecordData(priority, weight, uri);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return _priority + " " + _weight + " \"" + _target + "\"";
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsURIRecordData other)
            {
                if (_priority != other._priority)
                    return false;

                if (_weight != other._weight)
                    return false;

                return _target.Equals(other._target, StringComparison.Ordinal);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_priority, _weight, _target);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("Priority", _priority);
            jsonWriter.WriteNumber("Weight", _weight);
            jsonWriter.WriteString("URI", _target);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort Priority
        { get { return _priority; } }

        public ushort Weight
        { get { return _weight; } }

        public Uri Uri
        { get { return _uri; } }

        public override int UncompressedLength
        { get { return 2 + 2 + Encoding.UTF8.GetByteCount(_target); } }

        #endregion
    }
}
