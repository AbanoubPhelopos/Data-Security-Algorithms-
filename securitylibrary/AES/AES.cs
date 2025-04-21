using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        Dictionary<char, string> hexToBinaryMap = new Dictionary<char, string>
        {
            { '0', "0000" }, { '1', "0001" }, { '2', "0010" }, { '3', "0011" },
            { '4', "0100" }, { '5', "0101" }, { '6', "0110" }, { '7', "0111" },
            { '8', "1000" }, { '9', "1001" }, { 'A', "1010" }, { 'B', "1011" },
            { 'C', "1100" }, { 'D', "1101" }, { 'E', "1110" }, { 'F', "1111" }
        };

        Dictionary<string, char> binaryToHexMap = new Dictionary<string, char>
        {
            { "0000", '0' }, { "0001", '1' }, { "0010", '2' }, { "0011", '3' },
            { "0100", '4' }, { "0101", '5' }, { "0110", '6' }, { "0111", '7' },
            { "1000", '8' }, { "1001", '9' }, { "1010", 'A' }, { "1011", 'B' },
            { "1100", 'C' }, { "1101", 'D' }, { "1110", 'E' }, { "1111", 'F' }
        };

        private readonly int[] Sbox = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {

            string plainTextBinary = "";
            for (int i = 2; i < plainText.Length; i++)
            {
                plainTextBinary += hexToBinaryMap[char.ToUpper(plainText[i])];
            }

            string binaryKey = "";

            for (int i = 2; i < key.Length; i++)
            {
                char c = char.ToUpper(key[i]);
                binaryKey += hexToBinaryMap[c];
            }

            Console.WriteLine(binaryKey + "\n\n\n");

            List<string> keys;


            keys = getKeys(binaryKey);

            foreach (var item in keys)
            {
                Console.WriteLine(item + '\n');
            }


            return plainText;
        }

        public List<string> getKeys(string binaryKey)
        {
            List<string> keyWords = new List<string>();

            for (int i = 0; i < 128; i += 32)
                keyWords.Add(binaryKey.Substring(i, 32));

            for (int i = 4; i < 44; i++)
            {
                string prevWord = keyWords[i - 1];
                if (i % 4 == 0)
                {
                    prevWord = gFunction(prevWord, i / 4);
                }
                StringBuilder result = new StringBuilder();
                for (int j = 0; j < keyWords[i - 4].Length; j++)
                {
                    result.Append(keyWords[i - 4][j] == prevWord[j] ? '0' : '1');
                }
                keyWords.Add(result.ToString());
            }

            List<string> roundKeys = new List<string>();
            for (int i = 0; i < 44; i += 4)
                roundKeys.Add(string.Join("", keyWords.GetRange(i, 4)));

            return roundKeys;
        }

        public string gFunction(string word, int round)
        {
            string rotated = word.Substring(8) + word.Substring(0, 8);

            string substituted = "";
            for (int i = 0; i < rotated.Length; i += 8)
            {
                string byteStr = rotated.Substring(i, 8);
                int byteVal = Convert.ToInt32(byteStr, 2);
                substituted += Convert.ToString(Sbox[byteVal], 2).PadLeft(8, '0');
            }

            string roundConst = roundConstant(round);
            string result = "";
            for (int i = 0; i < 8; i++)
                result += (substituted[i] ^ roundConst[i]).ToString();

            result += substituted.Substring(8);
            return result;
        }
        public string roundConstant(int round)
        {
            string[] rconHex = { "00", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36" };

            string rconByte = rconHex[round];
            string binary = Convert.ToString(Convert.ToInt32(rconByte, 16), 2).PadLeft(8, '0');

            return binary + "000000000000000000000000";
        }

    }
}
