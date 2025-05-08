using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class AES : CryptographicTechnique
    {
        //************************************************ ENCRYPTION HELPER FUNCTIONS *****************************************************
        static byte[] sBox = new byte[256]
        {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
            0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
            0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
            0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
            0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
            0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
            0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
            0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
            0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
            0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
            0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
            0xB0, 0x54, 0xBB, 0x16
        };

        byte[,] HexStringToMatrix(string hex)
        {
            byte[,] matrix = new byte[4, 4];
            for (int i = 0; i < 16; i++)
            {
                int val = Convert.ToInt32(hex.Substring(i * 2, 2), 16);
                matrix[i % 4, i / 4] = (byte)val;
            }
            return matrix;
        }

        string MatrixToHexString(byte[,] matrix)
        {
            StringBuilder sb = new StringBuilder();
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    sb.Append(matrix[row, col].ToString("X2"));
                }
            }
            return "0x" + sb.ToString();
        }

        byte[,] SubBytes(byte[,] state)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    result[i, j] = sBox[state[i, j]];
            return result;
        }

        byte[,] ShiftRows(byte[,] state)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    result[i, j] = state[i, (j + i) % 4];
            return result;
        }

        byte[,] MixColumns(byte[,] state)
        {
            byte[,] result = new byte[4, 4];
            byte[,] matrix =
            {
                { 0x02, 0x03, 0x01, 0x01 },
                { 0x01, 0x02, 0x03, 0x01 },
                { 0x01, 0x01, 0x02, 0x03 },
                { 0x03, 0x01, 0x01, 0x02 }
            };

            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    result[r, c] = (byte)(
                        GFMul(matrix[r, 0], state[0, c]) ^
                        GFMul(matrix[r, 1], state[1, c]) ^
                        GFMul(matrix[r, 2], state[2, c]) ^
                        GFMul(matrix[r, 3], state[3, c])
                    );

            return result;
        }

        byte[,] AddRoundKey(byte[,] state, byte[,] roundKey)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    result[i, j] = (byte)(state[i, j] ^ roundKey[i, j]);
            return result;
        }

        byte GFMul(byte a, byte b)
        {
            byte result = 0;
            while (b > 0)
            {
                if ((b & 1) != 0) result ^= a;
                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet) a ^= 0x1b;
                b >>= 1;
            }
            return result;
        }

        List<byte[,]> GenerateRoundKeys(byte[,] initialKey)
        {
            string binaryKey = "";
            for (int col = 0; col < 4; col++)
                for (int row = 0; row < 4; row++)
                    binaryKey += Convert.ToString(initialKey[row, col], 2).PadLeft(8, '0');

            List<string> roundKeyStrings = getKeys(binaryKey);
            List<byte[,]> roundKeys = new List<byte[,]>();

            foreach (string roundKey in roundKeyStrings)
            {
                byte[,] matrix = new byte[4, 4];
                for (int i = 0; i < 16; i++)
                {
                    int val = Convert.ToInt32(roundKey.Substring(i * 8, 8), 2);
                    matrix[i % 4, i / 4] = (byte)val;
                }
                roundKeys.Add(matrix);
            }

            return roundKeys;
        }

        List<string> getKeys(string binaryKey)
        {
            List<string> keyWords = new List<string>();

            for (int i = 0; i < 128; i += 32)
                keyWords.Add(binaryKey.Substring(i, 32));

            for (int i = 4; i < 44; i++)
            {
                string prevWord = keyWords[i - 1];
                if (i % 4 == 0)
                    prevWord = gFunction(prevWord, i / 4);

                StringBuilder result = new StringBuilder();
                for (int j = 0; j < keyWords[i - 4].Length; j++)
                    result.Append(keyWords[i - 4][j] == prevWord[j] ? '0' : '1');

                keyWords.Add(result.ToString());
            }

            List<string> roundKeys = new List<string>();
            for (int i = 0; i < 44; i += 4)
                roundKeys.Add(string.Join("", keyWords.GetRange(i, 4)));

            return roundKeys;
        }

        string gFunction(string word, int round)
        {
            string rotated = word.Substring(8) + word.Substring(0, 8);

            string substituted = "";
            for (int i = 0; i < rotated.Length; i += 8)
            {
                string byteStr = rotated.Substring(i, 8);
                int byteVal = Convert.ToInt32(byteStr, 2);
                substituted += Convert.ToString(sBox[byteVal], 2).PadLeft(8, '0');
            }

            string roundConst = roundConstant(round);
            string result = "";
            for (int i = 0; i < 8; i++)
                result += (substituted[i] ^ roundConst[i]).ToString();

            result += substituted.Substring(8);
            return result;
        }

        string roundConstant(int round)
        {
            string[] rconHex = { "00", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36" };

            string rconByte = rconHex[round];
            string binary = Convert.ToString(Convert.ToInt32(rconByte, 16), 2).PadLeft(8, '0');

            return binary + "000000000000000000000000";
        }

        //************************************************ Decryption HELPER FUNCTIONS *****************************************************
        // Reverses the SubBytes
        byte[,] InvSubBytes(byte[,] state)
        {
            byte[] invSBox = new byte[256];
            for (int i = 0; i < 256; i++)
                invSBox[sBox[i]] = (byte)i;

            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    result[i, j] = invSBox[state[i, j]];
            return result;
        }

        // Reverses the ShiftRows 
        byte[,] InvShiftRows(byte[,] state)
        {
            byte[,] result = new byte[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    result[i, j] = state[i, (j - i + 4) % 4];
            return result;
        }

        // Reverses the MixColumns 
        byte[,] InvMixColumns(byte[,] state)
        {
            byte[,] result = new byte[4, 4];
            byte[,] matrix =
            {
        { 0x0E, 0x0B, 0x0D, 0x09 },
        { 0x09, 0x0E, 0x0B, 0x0D },
        { 0x0D, 0x09, 0x0E, 0x0B },
        { 0x0B, 0x0D, 0x09, 0x0E }
    };

            for (int c = 0; c < 4; c++)
                for (int r = 0; r < 4; r++)
                    result[r, c] = (byte)(
                        GFMul(matrix[r, 0], state[0, c]) ^
                        GFMul(matrix[r, 1], state[1, c]) ^
                        GFMul(matrix[r, 2], state[2, c]) ^
                        GFMul(matrix[r, 3], state[3, c])
                    );

            return result;
        }

        //************************************************ Encryption *****************************************************
        public override string Encrypt(string plainText, string key)
        {
            byte[,] state = HexStringToMatrix(plainText.Substring(2));
            byte[,] initialKey = HexStringToMatrix(key.Substring(2));
            List<byte[,]> roundKeys = GenerateRoundKeys(initialKey);

            state = AddRoundKey(state, roundKeys[0]);

            for (int round = 1; round <= 9; round++)
            {
                state = SubBytes(state);
                state = ShiftRows(state);
                state = MixColumns(state);
                state = AddRoundKey(state, roundKeys[round]);
            }

            state = SubBytes(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, roundKeys[10]);

            return MatrixToHexString(state);
        }

        //************************************************ Decryption *****************************************************

        public override string Decrypt(string cipherText, string key)
        {
            byte[,] state = HexStringToMatrix(cipherText.Substring(2));
            byte[,] initialKey = HexStringToMatrix(key.Substring(2));
            List<byte[,]> roundKeys = GenerateRoundKeys(initialKey);

            state = AddRoundKey(state, roundKeys[10]);

            for (int round = 9; round >= 1; round--)
            {
                state = InvShiftRows(state);
                state = InvSubBytes(state);
                state = AddRoundKey(state, roundKeys[round]);
                state = InvMixColumns(state);
            }

            state = InvShiftRows(state);
            state = InvSubBytes(state);
            state = AddRoundKey(state, roundKeys[0]);

            return MatrixToHexString(state);
        }
    }
}
