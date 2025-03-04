using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();


            char[] key = new char[26];
            for (int i = 0; i < 26; i++)
            {
                key[i] = '\0';
            }


            bool[] Used_Letter = new bool[26];


            int postion = 0;
            foreach (char letter in plainText)
            {
                int index = letter - 'a';
                char cipher_Char = cipherText[postion];
                key[index] = cipher_Char;
                Used_Letter[cipher_Char - 'a'] = true;
                postion++;
            }



            int Unused_Letter = 0;
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == '\0')
                {

                    while (Unused_Letter < 26 && Used_Letter[Unused_Letter])
                    {
                        Unused_Letter++;
                    }
                    if (Unused_Letter < 26)
                    {
                        key[i] = (char)('a' + Unused_Letter);
                        Used_Letter[Unused_Letter] = true;
                    }
                }
            }
            return new string(key);
        }



        public string Decrypt(string cipherText, string key)
        {
          
            cipherText = cipherText.ToLower();
            string PL2_Text = "";
            int index = -1;
            //Console.Write("Plain text : ");
            foreach (var letter in cipherText)
            {

                index = key.IndexOf(letter);
               
                PL2_Text += (char)(index + 'a');

            }
            
            return PL2_Text;
        }

        public string Encrypt(string plainText, string key)
        {
            string CI_Text = "";
            foreach (var letter in plainText)
            {

                CI_Text += (key[letter - 'a']);

            }
            return CI_Text;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string PL_Text= "" ;
            Dictionary<char, int> Cipher_Freq = new Dictionary<char, int>();
            Dictionary<char, char> substitution = new Dictionary<char, char>();
            Dictionary<char, double> Eng_Letter_Freq = new Dictionary<char, double>
    {
        {'e', 12.51},
        {'t', 9.25},
        {'a', 8.04},
        {'o', 7.60},
        {'i', 7.26},
        {'n', 7.09},
        {'s', 6.54},
        {'r', 6.12},
        {'h', 5.49},
        {'l', 4.14},
        {'d', 3.99},
        {'c', 3.06},
        {'u', 2.71},
        {'m', 2.53},
        {'f', 2.30},
        {'p', 2.00},
        {'g', 1.96},
        {'w', 1.92},
        {'y', 1.73},
        {'b', 1.54},
        {'v', 0.99},
        {'k', 0.67},
        {'x', 0.19},
        {'j', 0.16},
        {'q', 0.11},
        {'z', 0.09}
    };
            var English_Ordered = Eng_Letter_Freq.OrderByDescending(pair => pair.Value).Select(pair => pair.Key).ToList();
            
            foreach (char letter in cipher)
            {
                if (Cipher_Freq.ContainsKey(letter))
                {
                    Cipher_Freq[letter]++;
                }
                else 
                    Cipher_Freq[letter] = 1;  
            }

            var Cipher_Ordered = Cipher_Freq.OrderByDescending(pair => pair.Value).Select(pair => pair.Key).ToList();
           
           
            for (int i = 0; i < Cipher_Ordered.Count; i++)
            {
                substitution[Cipher_Ordered[i]] = English_Ordered[i];
            }
            foreach (char letter in cipher)
            {
              char sub = substitution[letter];
              PL_Text += (char)(sub);
            }
            return PL_Text;
        }
    }
}
