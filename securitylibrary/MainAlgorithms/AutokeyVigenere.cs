using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            string key = "";

            foreach (var pair in plainText.Zip(cipherText, (letter_PL, letter_CI) => (letter_PL, letter_CI)))
            {
                int pos = (pair.letter_CI - pair.letter_PL + 26) % 26;
                key += (char)('a' + pos);
            }

            int maxK = Math.Min(key.Length, plainText.Length);
            for (int k = maxK; k >= 0; k--)
            {
                if (k == 0)
                {
                    break;
                }
                if (key.Length < k || plainText.Length < k)
                    continue;
                string key_Suffix = key.Substring(key.Length - k);
                string plain_Prefix = plainText.Substring(0, k);
                if (key_Suffix == plain_Prefix)
                {
                    key = key.Substring(0, key.Length - k);
                    break;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            key = key.ToLower();

            int PTSize = cipherText.Length;
            string myKey = key;
            string plainText = "";

            for (int i = 0; i < PTSize; i++)
            {
                char c = (char)(((cipherText[i] - 'a') - (myKey[i] - 'a') + 26) % 26 + 'a');
                plainText += c;

                if (myKey.Length < PTSize)
                {
                    myKey += c;
                }

            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            key = key.ToLower();

            int PTSize = plainText.Length;
            int keySize = key.Length;
            int n = 0, m = 0;
            string myKey = "";
            for (int i = 0; i < PTSize; i++)
            {
                if (n < keySize)
                    myKey += key[n % keySize];
                else
                {

                    myKey += plainText[m % PTSize];
                    m++;
                }
                n++;
            }
            Console.WriteLine(key);

            string cipherText = "";

            for (int i = 0; i < PTSize; i++)
            {
                char c = (char)(((plainText[i] - 'a') + (myKey[i] - 'a')) % 26 + 'a');
                cipherText += c;
            }


            return cipherText;
        }
    }
}
