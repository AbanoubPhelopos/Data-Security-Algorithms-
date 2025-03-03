using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int candidateKey = 2; candidateKey <= plainText.Length; candidateKey++)
            {
                string attempt = Encrypt(plainText, candidateKey);
                if (attempt.Equals(cipherText))
                    return candidateKey;
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int length = cipherText.Length;
            char[] plainChars = new char[length];

            int currentPos = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < length; j += key)
                {
                    plainChars[j] = cipherText[currentPos++];
                }
            }

            return new string(plainChars);
        }

        public string Encrypt(string plainText, int key)
        {
            
            plainText = plainText.ToLower();

            StringBuilder cipherBuilder = new StringBuilder();

            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                {
                    cipherBuilder.Append(plainText[j]);
                }
            }

            return cipherBuilder.ToString().ToUpper();
        }
    }
}
