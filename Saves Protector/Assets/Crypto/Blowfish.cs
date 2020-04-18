using Assets.Crypto.Blowfish;
using System;
using System.Text;

namespace Crypto
{
    public class BlowFish
    {
        private Converters converters;
        private ByteHelpers byteHelpers;

        private uint[] bf_s0;
        private uint[] bf_s1;
        private uint[] bf_s2;
        private uint[] bf_s3;
        private uint[] bf_P;
        private byte[] key;
        private uint xl_par;
        private uint xr_par;

        public BlowFish(string hexKey)
        {
            converters = new Converters();
            byteHelpers = new ByteHelpers();
            SetupKey(converters.ConvertHexToByte(hexKey));
        }
        public string Encrypt(string text)
        {
            return converters.ConvertByteToHex(ProcessEncryption(Encoding.ASCII.GetBytes(text)));
        }

        public string Decrypt(string cipher)
        {
            return Encoding.ASCII.GetString(ProcessDecryption(converters.ConvertHexToByte(cipher))).Replace("\0", "");
        }

        private byte[] ProcessEncryption(byte[] pt)
        {
            return Crypt(pt, false);
        }

        private byte[] ProcessDecryption(byte[] ct)
        {
            return Crypt(ct, true);
        }

        private void SetupKey(byte[] cipherKey)
        {
            bf_P = BlowfishBlocks.P;
            bf_s0 = BlowfishBlocks.S0;
            bf_s1 = BlowfishBlocks.S1;
            bf_s2 = BlowfishBlocks.S2;
            bf_s3 = BlowfishBlocks.S3;

            key = new byte[cipherKey.Length];

            if (cipherKey.Length > 56)
            {
                throw new Exception("Key too long. 56 bytes required.");
            }

            Buffer.BlockCopy(cipherKey, 0, key, 0, cipherKey.Length);
            int j = 0;
            for (int i = 0; i < 18; i++)
            {
                uint d = (uint)(((key[j % cipherKey.Length] * 256 + key[(j + 1) % cipherKey.Length]) * 256 + key[(j + 2) % cipherKey.Length]) * 256 + key[(j + 3) % cipherKey.Length]);
                bf_P[i] ^= d;
                j = (j + 4) % cipherKey.Length;
            }

            xl_par = 0;
            xr_par = 0;
            for (int i = 0; i < 18; i += 2)
            {
                Encipher();
                bf_P[i] = xl_par;
                bf_P[i + 1] = xr_par;
            }

            for (int i = 0; i < 256; i += 2)
            {
                Encipher();
                bf_s0[i] = xl_par;
                bf_s0[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encipher();
                bf_s1[i] = xl_par;
                bf_s1[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encipher();
                bf_s2[i] = xl_par;
                bf_s2[i + 1] = xr_par;
            }
            for (int i = 0; i < 256; i += 2)
            {
                Encipher();
                bf_s3[i] = xl_par;
                bf_s3[i + 1] = xr_par;
            }
        }

        private byte[] Crypt(byte[] text, bool decrypt)
        {
            int paddedLen = (text.Length % 8 == 0 ? text.Length : text.Length + 8 - (text.Length % 8));
            byte[] plainText = new byte[paddedLen];
            Buffer.BlockCopy(text, 0, plainText, 0, text.Length);
            byte[] block = new byte[8];
            for (int i = 0; i < plainText.Length; i += 8)
            {
                Buffer.BlockCopy(plainText, i, block, 0, 8);
                if (decrypt)
                {
                    BlockDecrypt(ref block);
                }
                else
                {
                    BlockEncrypt(ref block);
                }
                Buffer.BlockCopy(block, 0, plainText, i, 8);
            }
            return plainText;
        }

        private void BlockEncrypt(ref byte[] block)
        {
            SplitBlock(block);
            Encipher();
            MergeBlocks(ref block);
        }

        private void BlockDecrypt(ref byte[] block)
        {
            SplitBlock(block);
            Decipher();
            MergeBlocks(ref block);
        }

        private void SplitBlock(byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            Buffer.BlockCopy(block, 0, block1, 0, 4);
            Buffer.BlockCopy(block, 4, block2, 0, 4);
            Array.Reverse(block1);
            Array.Reverse(block2);
            xl_par = BitConverter.ToUInt32(block1, 0);
            xr_par = BitConverter.ToUInt32(block2, 0);
        }

        private void MergeBlocks(ref byte[] block)
        {
            byte[] block1 = new byte[4];
            byte[] block2 = new byte[4];
            block1 = BitConverter.GetBytes(xl_par);
            block2 = BitConverter.GetBytes(xr_par);
            Array.Reverse(block1);
            Array.Reverse(block2);
            Buffer.BlockCopy(block1, 0, block, 0, 4);
            Buffer.BlockCopy(block2, 0, block, 4, 4);
        }

        private void Encipher()
        {
            xl_par ^= bf_P[0];
            for (uint i = 0; i < 16; i += 2)
            {
                xr_par = Stage(xr_par, xl_par, i + 1);
                xl_par = Stage(xl_par, xr_par, i + 2);
            }
            xr_par = xr_par ^ bf_P[17];

            uint swap = xl_par;
            xl_par = xr_par;
            xr_par = swap;
        }

        private void Decipher()
        {
            xl_par ^= bf_P[17];
            for (uint i = 16; i > 0; i -= 2)
            {
                xr_par = Stage(xr_par, xl_par, i);
                xl_par = Stage(xl_par, xr_par, i - 1);
            }
            xr_par = xr_par ^ bf_P[0];

            uint swap = xl_par;
            xl_par = xr_par;
            xr_par = swap;
        }

        private uint Stage(uint a, uint b, uint n)
        {
            uint x1 = (bf_s0[byteHelpers.GetFirstByte(b)] + bf_s1[byteHelpers.GetSecondByte(b)]) ^ bf_s2[byteHelpers.GetThirdByte(b)];
            uint x2 = x1 + bf_s3[byteHelpers.GetFourthByte(b)];
            uint x3 = x2 ^ bf_P[n];
            return x3 ^ a;
        }
    }
}
