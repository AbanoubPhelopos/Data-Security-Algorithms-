using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            StringBuilder cipherBuilder = new StringBuilder();

            foreach (char c in plainText)
            {
                int originalPos = c - 'a'; 
                int newPos = (originalPos + key) % 26;
                if (newPos < 0) newPos += 26; 

                char newChar = (char)('a' + newPos);
                cipherBuilder.Append(newChar);
            }

            return cipherBuilder.ToString().ToUpper();
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            StringBuilder plainBuilder = new StringBuilder();

            foreach (char c in cipherText)
            {
                int originalPos = c - 'a';
                int newPos = (originalPos - key) % 26;
                if (newPos < 0) newPos += 26; 
                char newChar = (char)('a' + newPos);
                plainBuilder.Append(newChar);
            }

            return plainBuilder.ToString().ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int p = plainText[0] - 'a';
            int c = cipherText[0] - 'a';

            int key = (c - p) % 26;
            if (key < 0) key += 26;

            return key;
        }
    }
}
