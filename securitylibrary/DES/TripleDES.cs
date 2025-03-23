using System;
using System.Collections.Generic;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        private DES des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            // throw new NotImplementedException();
            string plaintext = null;
            plaintext = des.Decrypt(cipherText, key[2]);
            plaintext = des.Encrypt(plaintext, key[1]);
            plaintext = des.Decrypt(plaintext, key[0]);
            return plaintext;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            // throw new NotImplementedException();
            string cipheredtext = null;
            cipheredtext = des.Encrypt(plainText, key[0]);
            cipheredtext = des.Decrypt(cipheredtext, key[1]);
            cipheredtext = des.Encrypt(cipheredtext, key[2]);
            return cipheredtext;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}