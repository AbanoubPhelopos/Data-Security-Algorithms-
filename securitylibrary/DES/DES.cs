using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        // Initial Permutation (IP)
        private readonly int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        private static readonly int[] P_Table = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        };
        // Final Permutation (IP inverse)
        private readonly int[] IP_inv = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };



        private readonly int[,,] sbox = new int[8, 4, 16] {
            // S1
            {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            // S2
            {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            // S3
            {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            // S4
            {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            // S5
            {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            // S6
            {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            // S7
            {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            // S8
            {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };

        int itr = 0;
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

        public override string Decrypt(string cipherText, string key)
        {
            string cipherTextBinary = "";
            for (int i = 2; i < cipherText.Length; i++)
            {
                cipherTextBinary += hexToBinaryMap[cipherText[i]];
            }

            string plainText = "";
            string key56Bit = transformKey(key);
            Console.WriteLine("56BitKey: " + key56Bit);

            List<string> subKeys = getSubKey(key56Bit);
            subKeys.Reverse(); // Reverse the subkeys for decryption

            string txtAfterIP = ApplyPermutation(cipherTextBinary, IP);

            string left = txtAfterIP.Substring(0, 32);
            string right = txtAfterIP.Substring(32, 32);

            for (int i = 0; i < 16; i++)
            {
                string temp = right;
                right = xor(left, Mangler(right, subKeys[i]));
                left = temp;
            }

            string concat = right + left;
            plainText = ApplyPermutation(concat, IP_inv);

            StringBuilder ans = new StringBuilder(cipherText.Length);
            ans.Append("0x");
            for (int i = 0; i < plainText.Length; i += 4)
            {
                string block = plainText.Substring(i, 4);
                ans.Append(binaryToHexMap[block]);
            }

            Console.WriteLine($"Decrypted text : {ans.ToString()}");
            return ans.ToString();

        }


     //***********************************************************************************************************************************\\

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            //Console.WriteLine(plainText);
            //plainText: 0x0123456789ABCDEF

            //Console.WriteLine(key);
            //Key: 0x133457799BBCDFF1
            string plainTextBinary = "";
            for (int i = 2; i < plainText.Length; i++)
            {
                plainTextBinary += hexToBinaryMap[plainText[i]];
            }


            string cipherText = "";

            string key56Bit = transformKey(key);
            Console.WriteLine("56BitKey: " + key56Bit);


            /*for (int i = 0; i < 16; i++)
            {
                Console.WriteLine("subKey " + i + ": "+ getSubKey(key56Bit, itr++));
            }*/

            List<string> subKeys = getSubKey(key56Bit);

            foreach (var subKey in subKeys)
            {
                Console.WriteLine(subKey);
            }

            string txtAfterIP = ApplyPermutation(plainTextBinary, IP);

            string left = txtAfterIP.Substring(0, 32);
            string right = txtAfterIP.Substring(32, 32);


            for (int i = 0; i < 16; i++)
            {
                string temp = right;
                right = xor(left, Mangler(right, subKeys[i]));
                left = temp;
            }

            string concat = right + left;


            cipherText = ApplyPermutation(concat, IP_inv);
            //Console.WriteLine(plainTextBinary);
            //plainTexBinary: 0000 0001 0010 0011 0100 0101 0110 0111 1000 1001 1010 1011 1100 1101 1110 1111

            StringBuilder ans = new StringBuilder(plainText.Length);
            ans.Append("0x");
            for (int i = 0; i < cipherText.Length; i += 4)
            {
                string block = cipherText.Substring(i, 4);
                ans.Append(binaryToHexMap[block]);
            }

            Console.WriteLine($"final answer : {ans.ToString()}");
            //                            0x85E813540F0AB405
            return ans.ToString();
        }

    //***********************************************************************************************************************************\\
        public string transformKey(string key)
        {

            int[] PC1 = {57, 49, 41, 33, 25, 17, 9,
                          1, 58, 50, 42, 34, 26, 18,
                         10, 2, 59, 51, 43, 35, 27,
                         19, 11, 3, 60, 52, 44, 36,
                         63, 55, 47, 39, 31, 23, 15,
                          7, 62, 54, 46, 38, 30, 22,
                         14, 6, 61, 53, 45, 37, 29,
                         21, 13, 5, 28, 20, 12, 4};

            string key64Bit = "";

            for (int i = 2; i < 18; i++)
            {
                key64Bit += hexToBinaryMap[key[i]];

            }
            Console.WriteLine(key64Bit);
            Console.WriteLine("key64Bit Length: " + key64Bit.Length);

            string key56Bit = "";

            for (int i = 0; i < 56; i++)
            {
                key56Bit += key64Bit[PC1[i] - 1];
            }
            Console.WriteLine(key56Bit);

            return key56Bit;
        }

        public List<string> getSubKey(string key56Bit)
        {
            List<string> subKeys = new List<string>();


            int[] PC2 = {14, 17, 11, 24, 1, 5,
                          3, 28, 15, 6, 21, 10,
                          23, 19, 12, 4, 26, 8,
                          16, 7, 27, 20, 13, 2,
                          41, 52, 31, 37, 47, 55,
                          30, 40, 51, 45, 33, 48,
                          44, 49, 39, 56, 34, 53,
                          46, 42, 50, 36, 29, 32 };

            int[] shift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

            string leftKey = key56Bit.Substring(0, 28);
            string rightKey = key56Bit.Substring(28, 28);

            Console.WriteLine("LeftKey: " + leftKey);
            Console.WriteLine("RIghtKey: " + rightKey);

            for (int i = 0; i < 16; i++)
            {
                leftKey = leftKey.Substring(shift[i]) + leftKey.Substring(0, shift[i]);
                rightKey = rightKey.Substring(shift[i]) + rightKey.Substring(0, shift[i]);

                string combine = leftKey + rightKey;


                StringBuilder subKey = new StringBuilder(48);
                //Console.WriteLine(combine.Length);
                for (int j = 0; j < 48; j++)
                {
                    subKey.Append(combine[PC2[j] - 1]);
                }
                subKeys.Add(subKey.ToString());
            }

            return subKeys;
        }

        private string ApplyPermutation(string text, int[] permutation)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < permutation.Length; i++)
            {
                sb.Append(text[permutation[i] - 1]);
            }
            return sb.ToString();
        }

        private string Mangler(string right, string key)
        {
            string expandedRight = expansion(right);
            string xorResult = xor(expandedRight, key);
            string sboxResult = sboxSubstitution(xorResult);
            //string res = right + sboxResult;

            return sboxResult;
        }

        /*
         * foreach 
            0->5    6->11     
                            0 1010 1 
                    i=0      row  01   col  1010
         */

        /*
            yousef ->> Yousif
         */

        private string expansion(string right)
        {
            int[] E = { 32, 1, 2, 3, 4, 5,
                        4, 5, 6, 7, 8, 9,
                        8, 9, 10, 11, 12, 13,
                        12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29,
                        28, 29, 30, 31, 32, 1 };
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 48; i++)
            {
                sb.Append(right[E[i] - 1]);
            }
            return sb.ToString();
        }

        private string xor(string a, string b)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < a.Length; i++)
            {
                sb.Append(a[i] ^ b[i]);
            }
            return sb.ToString();
        }

        private string sboxSubstitution(string txt)
        {
            StringBuilder res = new StringBuilder(32);
            for (int i = 0; i < 8; i++)
            {
                string block = txt.Substring(i * 6, 6);
                string Srow = block[0].ToString() + block[5].ToString();
                int row = Convert.ToInt32(Srow, 2);
                string Scol = block.Substring(1, 4);
                int col = Convert.ToInt32(Scol, 2);
                int value = sbox[i, row, col];
                res.Append(Convert.ToString(value, 2).PadLeft(4, '0'));
            }
            return ApplyPermutation(res.ToString(), P_Table);
        }
    }
}
