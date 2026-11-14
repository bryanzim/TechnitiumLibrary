/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Security.Cryptography;

namespace TechnitiumLibrary.Security.Cryptography
{
    static class HashAlgorithms
    {
        public static HashAlgorithm Create(string name)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            switch (name.ToUpperInvariant())
            {
                case "MD5":
                case "SYSTEM.SECURITY.CRYPTOGRAPHY.MD5":
                    return MD5.Create();

                case "SHA":
                case "SHA1":
                case "SHA-1":
                case "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA1":
                    return SHA1.Create();

                case "SHA256":
                case "SHA-256":
                case "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA256":
                    return SHA256.Create();

                case "SHA384":
                case "SHA-384":
                case "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA384":
                    return SHA384.Create();

                case "SHA512":
                case "SHA-512":
                case "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA512":
                    return SHA512.Create();

                default:
                    throw new CryptoException("Hash algorithm not supported.");
            }
        }
    }
}
