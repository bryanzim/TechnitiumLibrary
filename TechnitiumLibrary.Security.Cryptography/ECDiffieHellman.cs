/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Buffers.Binary;
using System.Security.Cryptography;

using ECAlgorithm = System.Security.Cryptography.ECDiffieHellman;

namespace TechnitiumLibrary.Security.Cryptography
{
    public class ECDiffieHellman : KeyAgreement
    {
        #region variables

        const uint ECDH_PUBLIC_P256_MAGIC = 0x314B4345;
        const uint ECDH_PUBLIC_P384_MAGIC = 0x334B4345;
        const uint ECDH_PUBLIC_P521_MAGIC = 0x354B4345;

        readonly ECAlgorithm _ecdh;

        #endregion

        #region constructor

        public ECDiffieHellman(int keySize, KeyAgreementKeyDerivationFunction kdFunc, KeyAgreementKeyDerivationHashAlgorithm hashAlgo)
            : base(kdFunc, hashAlgo)
        {
            switch (hashAlgo)
            {
                case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                    break;

                default:
                    throw new CryptoException("Key derivation hash algorithm not supported.");
            }

            _ecdh = ECAlgorithm.Create(CurveForKeySize(keySize));
        }

        #endregion

        #region overrides

        public override byte[] GetPublicKey()
        {
            ECParameters parameters = _ecdh.ExportParameters(false);
            int fieldSize = parameters.Q.X.Length;
            byte[] x = parameters.Q.X;
            byte[] y = parameters.Q.Y;

            byte[] blob = new byte[8 + (fieldSize * 2)];
            BinaryPrimitives.WriteUInt32LittleEndian(blob, MagicForFieldSize(fieldSize));
            BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), (uint)fieldSize);
            x.CopyTo(blob, 8);
            y.CopyTo(blob, 8 + fieldSize);
            return blob;
        }

        protected override byte[] ComputeKey(byte[] otherPartyPublicKey)
        {
            using (ECAlgorithm other = ImportPublicKey(otherPartyPublicKey))
            {
                byte[] raw = _ecdh.DeriveRawSecretAgreement(other.PublicKey);

                using (HashAlgorithm hash = HashAlgorithms.Create(HashName(KeyDerivationHashAlgorithm)))
                    return hash.ComputeHash(raw);
            }
        }

        #endregion

        #region private

        static ECCurve CurveForKeySize(int keySize)
        {
            switch (keySize)
            {
                case 256:
                    return ECCurve.NamedCurves.nistP256;

                case 384:
                    return ECCurve.NamedCurves.nistP384;

                case 521:
                    return ECCurve.NamedCurves.nistP521;

                default:
                    throw new ArgumentException("Key size must be 256, 384, or 521.", nameof(keySize));
            }
        }

        static uint MagicForFieldSize(int fieldSize)
        {
            switch (fieldSize)
            {
                case 32:
                    return ECDH_PUBLIC_P256_MAGIC;

                case 48:
                    return ECDH_PUBLIC_P384_MAGIC;

                case 66:
                    return ECDH_PUBLIC_P521_MAGIC;

                default:
                    throw new CryptographicException("EC public key field size is not supported.");
            }
        }

        static string HashName(KeyAgreementKeyDerivationHashAlgorithm hashAlgo)
        {
            switch (hashAlgo)
            {
                case KeyAgreementKeyDerivationHashAlgorithm.SHA256:
                    return "SHA256";

                case KeyAgreementKeyDerivationHashAlgorithm.SHA384:
                    return "SHA384";

                case KeyAgreementKeyDerivationHashAlgorithm.SHA512:
                    return "SHA512";

                default:
                    throw new CryptoException("Key derivation hash algorithm not supported.");
            }
        }

        static ECAlgorithm ImportPublicKey(byte[] otherPartyPublicKey)
        {
            if ((otherPartyPublicKey == null) || (otherPartyPublicKey.Length < 8))
                throw new CryptographicException("EC public key blob is not valid.");

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(otherPartyPublicKey);
            int fieldSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(otherPartyPublicKey.AsSpan(4));

            if ((fieldSize < 1) || (otherPartyPublicKey.Length != (8 + (fieldSize * 2))) || (magic != MagicForFieldSize(fieldSize)))
                throw new CryptographicException("EC public key blob is not valid.");

            ECParameters parameters = new ECParameters();
            parameters.Curve = CurveForFieldSize(fieldSize);
            parameters.Q.X = new byte[fieldSize];
            parameters.Q.Y = new byte[fieldSize];
            Buffer.BlockCopy(otherPartyPublicKey, 8, parameters.Q.X, 0, fieldSize);
            Buffer.BlockCopy(otherPartyPublicKey, 8 + fieldSize, parameters.Q.Y, 0, fieldSize);

            ECAlgorithm other = ECAlgorithm.Create(parameters.Curve);
            try
            {
                other.ImportParameters(parameters);
                return other;
            }
            catch
            {
                other.Dispose();
                throw;
            }
        }

        static ECCurve CurveForFieldSize(int fieldSize)
        {
            switch (fieldSize)
            {
                case 32:
                    return ECCurve.NamedCurves.nistP256;

                case 48:
                    return ECCurve.NamedCurves.nistP384;

                case 66:
                    return ECCurve.NamedCurves.nistP521;

                default:
                    throw new CryptographicException("EC public key field size is not supported.");
            }
        }

        #endregion
    }
}
