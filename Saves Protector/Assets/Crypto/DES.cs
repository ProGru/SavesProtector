using Assets.Crypto.Blowfish;
using System;
using System.Collections;
using System.Text;
using UnityEngine;

namespace Crypto
{
    public class DES
    {
        public static int[] PC1 =
                {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };

        public static int[] PC2 =
        {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };

        public static int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        public static int[] IPINV =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };

        public static int[] E =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        public static int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };

        public static byte[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };

        public static int[] LeftShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        string hexKey;

        public DES(string hexKey)
        {
            //SetupKey(converters.ConvertHexToByte(hexKey));
            SetupKey(hexKey);
        } //klucz 16 znaków po 4 bity każdy

        private void SetupKey(string hexKey)
        {
            this.hexKey = hexKey;
        }

        public string TestEncrypt(string hexText)
        {
            BitArray bitKey = KeyPermutation(hexKey);

            //podział klucza na 2
            BitArray C0 = new BitArray(bitKey.Length / 2);
            BitArray D0 = new BitArray(bitKey.Length / 2);

            for (int i = 0; i < bitKey.Length; i++)
            {
                if (i < bitKey.Length / 2)
                {
                    C0[i] = bitKey[i];
                }
                else
                {
                    D0[i - bitKey.Length / 2] = bitKey[i];
                }
            }


            var int64 = Int64.Parse(hexText, System.Globalization.NumberStyles.HexNumber);
            var bytes = BitConverter.GetBytes(int64);
            BitArray permutedBlock = BlockPermutation(bytes);

            //podział bloku na 2
            BitArray L0 = new BitArray(permutedBlock.Length / 2);
            BitArray R0 = new BitArray(permutedBlock.Length / 2);

            for (int i = 0; i < permutedBlock.Length; i++)
            {
                if (i < permutedBlock.Length / 2)
                {
                    L0[i] = permutedBlock[i];
                }
                else
                {
                    R0[i - permutedBlock.Length / 2] = permutedBlock[i];
                }
            }

            BitArray L = L0;
            BitArray R = R0;
            BitArray C = C0;
            BitArray D = D0;
            for (int i = 0; i < 16; i++)
            {
                C = KeyLeftShift(C, i);
                D = KeyLeftShift(D, i);
                BitArray K = KeyJoinPermuted(C, D);
                BitArray curentL = R;
                BitArray curentR = L.Xor(F(R, K));
                L = curentL;
                R = curentR;


            }

            DebugBits(FinalPermutation(R, L));
            DebugBits(R);
            DebugBits(L);
            Debug.Log(hexText);
            return ConvertToHex(FinalPermutation(R, L));
        }

        public string TestDecrypt(string text)
        {
            BitArray bitKey = KeyPermutation(hexKey);

            //podział klucza na 2
            BitArray C0 = new BitArray(bitKey.Length / 2);
            BitArray D0 = new BitArray(bitKey.Length / 2);

            for (int i = 0; i < bitKey.Length; i++)
            {
                if (i < bitKey.Length / 2)
                {
                    C0[i] = bitKey[i];
                }
                else
                {
                    D0[i - bitKey.Length / 2] = bitKey[i];
                }
            }


            var int64 = Int64.Parse(text, System.Globalization.NumberStyles.HexNumber);
            var bytes = BitConverter.GetBytes(int64);
            BitArray permutedBlock = BlockPermutation(bytes);

            //podział bloku na 2
            BitArray L0 = new BitArray(permutedBlock.Length / 2);
            BitArray R0 = new BitArray(permutedBlock.Length / 2);

            for (int i = 0; i < permutedBlock.Length; i++)
            {
                if (i < permutedBlock.Length / 2)
                {
                    L0[i] = permutedBlock[i];
                }
                else
                {
                    R0[i - permutedBlock.Length / 2] = permutedBlock[i];
                }
            }

            BitArray L = L0;
            BitArray R = R0;
            BitArray C = C0;
            BitArray D = D0;
            for (int i = 0; i < 16; i++)
            {

                BitArray K = InverseKey(C0, D0, 16 - i);
                BitArray curentL = R;
                BitArray curentR = L.Xor(F(R, K));
                L = curentL;
                R = curentR;

            }
            Debug.Log(ConvertToHex(FinalPermutation(R, L)));
            return (ConvertToHex(FinalPermutation(R, L)));
        }
        public string Encrypt(string text)
        {

            byte[] coded = Encoding.ASCII.GetBytes(text);

            //uzupełnienie textu do pełnych 8 znaków
            if (coded.Length % 16 != 0)
            {
                byte[] code = new byte[coded.Length + coded.Length % 8];
                Buffer.BlockCopy(coded, 0, code, 0, coded.Length);
                coded = code;

            }
            //podział tekstu na 64bit bloki
            byte[] curentBlock = new byte[8];

            for (int i = 0; i < coded.Length / 8; i++)
            {

                Buffer.BlockCopy(coded, i * 8, curentBlock, 0, 8);
                curentBlock =StringToByteArray(Crypt(ByteArrayToString(curentBlock)));
                Buffer.BlockCopy(curentBlock, 0, coded, i * 8, 8);
            }


            return ByteArrayToString(coded);
        }   

        public string Decrypt(string text)
        {
            byte[] coded = StringToByteArray(text);

            //uzupełnienie textu do pełnych 8 znaków
            if (coded.Length % 16 != 0)
            {
                byte[] code = new byte[coded.Length + coded.Length % 8];
                Buffer.BlockCopy(coded, 0, code, 0, coded.Length);
                coded = code;

            }
            //podział tekstu na 64bit bloki
            byte[] curentBlock = new byte[8];

            for (int i = 0; i < coded.Length / 8; i++)
            {

                Buffer.BlockCopy(coded, i * 8, curentBlock, 0, 8);
                curentBlock = StringToByteArray(DeCrypt(ByteArrayToString(curentBlock)));
                Buffer.BlockCopy(curentBlock, 0, coded, i * 8, 8);
            }
            return  ConvertHex(ByteArrayToString(coded));
        }

        public static string ConvertHex(string hexString)
        {
            try
            {
                string ascii = string.Empty;

                for (int i = 0; i < hexString.Length; i += 2)
                {
                    string hs = string.Empty;

                    hs = hexString.Substring(i, 2);
                    ulong decval = Convert.ToUInt64(hs, 16);
                    long deccc = Convert.ToInt64(hs, 16);
                    char character = Convert.ToChar(deccc);
                    ascii += character;

                }

                return ascii;
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }

            return string.Empty;
        }
        public string Crypt (string hexText)
        {
            BitArray bitKey = KeyPermutation(hexKey);

            //podział klucza na 2
            BitArray C0 = new BitArray(bitKey.Length / 2);
            BitArray D0 = new BitArray(bitKey.Length / 2);

            for (int i = 0; i < bitKey.Length; i++)
            {
                if (i < bitKey.Length / 2)
                {
                    C0[i] = bitKey[i];
                }
                else
                {
                    D0[i - bitKey.Length / 2] = bitKey[i];
                }
            }
            var int64 = Int64.Parse(hexText, System.Globalization.NumberStyles.HexNumber);
            var bytes = BitConverter.GetBytes(int64);
            BitArray permutedBlock = BlockPermutation(bytes);

            //podział bloku na 2
            BitArray L0 = new BitArray(permutedBlock.Length / 2);
            BitArray R0 = new BitArray(permutedBlock.Length / 2);

            for (int i = 0; i < permutedBlock.Length; i++)
            {
                if (i < permutedBlock.Length / 2)
                {
                    L0[i] = permutedBlock[i];
                }
                else
                {
                    R0[i - permutedBlock.Length / 2] = permutedBlock[i];
                }
            }

            BitArray L = L0;
            BitArray R = R0;
            BitArray C = C0;
            BitArray D = D0;
            for (int i = 0; i < 16; i++)
            {
                C = KeyLeftShift(C, i);
                D = KeyLeftShift(D, i);
                BitArray K = KeyJoinPermuted(C, D);
                BitArray curentL = R;
                BitArray curentR = L.Xor(F(R, K));
                L = curentL;
                R = curentR;


            }

            return ConvertToHex(FinalPermutation(R, L));

        }

        public string DeCrypt(string hexText)
        {
            BitArray bitKey = KeyPermutation(hexKey);

            //podział klucza na 2
            BitArray C0 = new BitArray(bitKey.Length / 2);
            BitArray D0 = new BitArray(bitKey.Length / 2);

            for (int i = 0; i < bitKey.Length; i++)
            {
                if (i < bitKey.Length / 2)
                {
                    C0[i] = bitKey[i];
                }
                else
                {
                    D0[i - bitKey.Length / 2] = bitKey[i];
                }
            }


            var int64 = Int64.Parse(hexText, System.Globalization.NumberStyles.HexNumber);
            var bytes = BitConverter.GetBytes(int64);
            BitArray permutedBlock = BlockPermutation(bytes);

            //podział bloku na 2
            BitArray L0 = new BitArray(permutedBlock.Length / 2);
            BitArray R0 = new BitArray(permutedBlock.Length / 2);

            for (int i = 0; i < permutedBlock.Length; i++)
            {
                if (i < permutedBlock.Length / 2)
                {
                    L0[i] = permutedBlock[i];
                }
                else
                {
                    R0[i - permutedBlock.Length / 2] = permutedBlock[i];
                }
            }

            BitArray L = L0;
            BitArray R = R0;
            BitArray C = C0;
            BitArray D = D0;
            for (int i = 0; i < 16; i++)
            {

                BitArray K = InverseKey(C0, D0, 16 - i);
                BitArray curentL = R;
                BitArray curentR = L.Xor(F(R, K));
                L = curentL;
                R = curentR;

            }

            return (ConvertToHex(FinalPermutation(R, L)));
        }

        public BitArray InverseKey(BitArray C,BitArray D, int iteration)
        {
            for (int i =0; i < iteration; i++)
            {
                C = KeyLeftShift(C, i);
                D = KeyLeftShift(D, i);
            }
            BitArray K = KeyJoinPermuted(C, D);
            return K;
        }
        public BitArray FinalPermutation(BitArray R, BitArray L)
        {
            var bitKey = new BitArray(IPINV.Length);
            for (int i = 0; i < IPINV.Length; i++)
            {
                if (IPINV[i] <= R.Length)
                {
                    bitKey[i] = R[IPINV[i] - 1];
                }
                else
                {
                    bitKey[i] = L[IPINV[i] - R.Length - 1];
                }

            }
            return bitKey;
        }

        public void DebugBits(BitArray array)
        {
            string text = "";
            for (int i = 0; i < array.Length; i++)
            {
                if (array.Get(i))
                {
                    text += "1";
                }
                else
                {
                    text += "0";
                }
            }
            Debug.Log(text);
        }

        public BitArray F(BitArray rightPart,BitArray key)
        {
            BitArray ERight = Epermutation(rightPart);
            BitArray xoredERandKey = ERight.Xor(key);
            BitArray sixBitArray = new BitArray(6);
            BitArray bitArray32 = new BitArray(32);
            //podział na 8 bloków po 6 bitów i zmiana z 48 na 32 bit
            int iteration = 0;
            int indexAppend = 0;
            for (int i = 0; i < xoredERandKey.Length;)
            {
                for (int j = 0; j < sixBitArray.Length; j++)
                {
                    sixBitArray[j] = xoredERandKey[i];
                    i++;
                }
                int row = ConvertToNoumber(new bool[] { sixBitArray.Get(0), sixBitArray.Get(5) });
                int column = ConvertToNoumber(new bool[] { sixBitArray.Get(1), sixBitArray.Get(2), sixBitArray.Get(3), sixBitArray.Get(4) });

                foreach (char cha in ConvertToBinary(SBoxes[iteration, row * 16 + column])){
                    if (cha == '1')
                    {
                        bitArray32[indexAppend] = true;
                    }
                    else
                    {
                        bitArray32[indexAppend] = false;

                    }
                    indexAppend++;
                }
                iteration++;
            }

            return Ppermutation(bitArray32);
        }

        public int ConvertToNoumber(bool[] bools)
        {
            int value = 0;

            for (int i = 0; i < bools.Length; i++)
            {
                if (bools[i])
                {
                    value += (int)Math.Pow(2, bools.Length -1-i);
                }
            }

            return value;
        }

        public string ConvertToBinary(int n)
        {

            string bits = "";

            for (int i = 0; i < 4; i++)
            {
                var g = n / 2;
                var remainder = n % 2;
                bits += remainder;
                n = g;
            }

            char[] arr = bits.ToCharArray();
            Array.Reverse(arr);
            bits = new string(arr);

            return bits;
        }

        public BitArray Ppermutation(BitArray block)
        {
            BitArray permutedBlock = new BitArray(P.Length);
            //wykonanie permutacji P na bloku M
            for (int i = 0; i < P.Length; i++)
            {
                permutedBlock[i] = block[P[i] - 1];
            }

            return permutedBlock;
        }
        public BitArray Epermutation(BitArray block)
        {
            BitArray permutedBlock = new BitArray(E.Length);
            //wykonanie permutacji IP na bloku M
            for (int i = 0; i < E.Length; i++)
            {
                permutedBlock[i] = block[E[i]-1];
            }

            return permutedBlock;
        }

        public BitArray BlockPermutation(byte[] block)
        {
            var bitArray = new BitArray(block);
            BitArray permutedBlock = new BitArray(bitArray.Length);
            //wykonanie permutacji IP na bloku M
            for (int i =0; i < IP.Length; i++)
            {
                permutedBlock[i] = bitArray[bitArray.Length - IP[i]];
            }

            return permutedBlock;
        }

        public BitArray KeyPermutation(string hexKey)
        {
            //Konwersja klucza z hex na bity
            var int64 = Int64.Parse(hexKey, System.Globalization.NumberStyles.HexNumber);
            var bytes = BitConverter.GetBytes(int64);
            var bitArray = new BitArray(bytes);

            //tworzenie klucza pomijając co 8 bit z permutacji PC1
            var bitKey = new BitArray(56);
            for (int i = 0; i < PC1.Length; i++)
            {
                bitKey[i] = bitArray[bitArray.Length - PC1[i]];
            }

            return bitKey;

        }

        public BitArray KeyLeftShift(BitArray key, int iteration)
        {
            BitArray shiftedKey = new BitArray(key.Length);
            int j = 0;
            int indexFromStart = 0;
            for (int i = LeftShifts[iteration]; i < key.Length + LeftShifts[iteration]; i++)
            {
                if (i < key.Length)
                {
                    shiftedKey[j] = key[i];
                }
                else
                {
                    shiftedKey[j] = key[indexFromStart];
                    indexFromStart++;
                }
                j++;
            }

            return shiftedKey;
        }

        public BitArray KeyJoinPermuted(BitArray C, BitArray D)
        {
            var bitKey = new BitArray(PC2.Length);
            for (int i = 0; i < PC2.Length; i++)
            {
                if (PC2[i] <= C.Length)
                {
                    bitKey[i] = C[PC2[i] - 1];
                }
                else
                {
                    bitKey[i] = D[PC2[i] - C.Length - 1];
                }

            }
            return bitKey;
        }

        public string ConvertToHex(BitArray bits)
        {
            StringBuilder sb = new StringBuilder(bits.Length / 4);

            for (int i = 0; i < bits.Length; i += 4)
            {
                int v = (bits[i] ? 8 : 0) |
                        (bits[i + 1] ? 4 : 0) |
                        (bits[i + 2] ? 2 : 0) |
                        (bits[i + 3] ? 1 : 0);

                sb.Append(v.ToString("x1")); // Or "X1"
            }

            String result = sb.ToString();
            return result;
        }

        public byte[] ConvertToByte(BitArray bits)
        {
            byte[] ret = new byte[(bits.Length - 1) / 8 + 1];
            bits.CopyTo(ret, 0);
            return ret;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}