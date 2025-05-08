using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string key = "";
            int length = plainText.Length;

            for (int i = 0; i < length; i++)
            {
                int plainValue = plainText[i] - 'a';
                int cipherValue = cipherText[i] - 'a';

                int shift = (cipherValue - plainValue + 26) % 26; 
                key += (char)(shift + 'a'); 
            }

            Console.WriteLine(key);

            for (int patternLength = 1; patternLength <= length / 2; patternLength++)
            {
                string pattern = key.Substring(0, patternLength);
                bool isRepeating = true;

                for (int j = patternLength; j < length; j++)
                {
                    if (key[j] != pattern[j % patternLength])
                    {
                        isRepeating = false;
                        break;
                    }
                }

                if (isRepeating)
                {
                    return pattern; 
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
            int keySize = key.Length;

            string myKey = "";
            for (int i = 0; i < PTSize; i++)
            {
                myKey += key[i % keySize];
            }
            Console.WriteLine(myKey);

            string plainText = "";

            for (int i = 0; i < PTSize; i++)
            {
                char c = (char)(((cipherText[i] - 'a') - (myKey[i] - 'a') + 26) % 26 + 'a');
                plainText += c;
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

            string myKey = "";
            for (int i = 0; i < PTSize; i++)
            {
                myKey += key[i % keySize];
            }
            Console.WriteLine(myKey);

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