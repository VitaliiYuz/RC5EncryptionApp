using System;
using System.IO;
using System.Text;

namespace RC5EncryptionApp.Services
{
    public class MD5Service
    {
        private uint[] T = new uint[64];
        private int[] S = new int[] { 7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21 };

        public MD5Service()
        {
            InitT();
        }

        private void InitT()
        {
            for (int i = 0; i < 64; i++)
            {
                T[i] = (uint)(4294967296 * Math.Abs(Math.Sin(i + 1)));
            }
        }

        public string ComputeMD5Hash(byte[] data)
        {
            byte[] message = PadMessage(data);
            uint A = 0x67452301;
            uint B = 0xEFCDAB89;
            uint C = 0x98BADCFE;
            uint D = 0x10325476;

            for (int i = 0; i < message.Length / 64; i++)
            {
                uint[] M = new uint[16];
                Buffer.BlockCopy(message, i * 64, M, 0, 64);

                uint a = A, b = B, c = C, d = D;

                for (int j = 0; j < 64; j++)
                {
                    uint F = 0;
                    int g = 0;

                    if (j < 16)
                    {
                        F = (b & c) | (~b & d);
                        g = j;
                    }
                    else if (j < 32)
                    {
                        F = (d & b) | (~d & c);
                        g = (5 * j + 1) % 16;
                    }
                    else if (j < 48)
                    {
                        F = b ^ c ^ d;
                        g = (3 * j + 5) % 16;
                    }
                    else
                    {
                        F = c ^ (b | ~d);
                        g = (7 * j) % 16;
                    }

                    F = F + a + T[j] + M[g];
                    a = d;
                    d = c;
                    c = b;
                    b = b + LeftRotate(F, S[(j / 16) * 4 + j % 4]);
                }

                A += a;
                B += b;
                C += c;
                D += d;
            }

            return LittleEndianToString(A) + LittleEndianToString(B) + LittleEndianToString(C) + LittleEndianToString(D);
        }

        private byte[] PadMessage(byte[] message)
        {
            int originalLength = message.Length;
            int paddingLength = (originalLength % 64 < 56) ? 56 - (originalLength % 64) : 120 - (originalLength % 64);

            byte[] paddedMessage = new byte[originalLength + paddingLength + 8];
            Buffer.BlockCopy(message, 0, paddedMessage, 0, originalLength);
            paddedMessage[originalLength] = 0x80;

            ulong lengthBits = (ulong)originalLength * 8;
            byte[] lengthBytes = BitConverter.GetBytes(lengthBits);
            Buffer.BlockCopy(lengthBytes, 0, paddedMessage, paddedMessage.Length - 8, 8);

            return paddedMessage;
        }

        private uint LeftRotate(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        private string LittleEndianToString(uint value)
        {
            return BitConverter.ToString(BitConverter.GetBytes(value)).Replace("-", "").ToLower();
        }
    }
}
