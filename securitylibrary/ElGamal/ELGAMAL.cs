using System;
using System.Collections.Generic;
using SecurityLibrary.DiffieHellman;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        
       
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long c1 = SecurityLibrary.DiffieHellman.DiffieHellman.modAndPower(alpha, k, q);
            long c2 = (m * SecurityLibrary.DiffieHellman.DiffieHellman.modAndPower(y, k, q)) % q;

            return new List<long> { c1, c2 };
        }

      
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int s = SecurityLibrary.DiffieHellman.DiffieHellman.modAndPower(c1, x, q);
            int s_inv = ModularInverseForDecrypt(s, q);
            int m = (c2 * s_inv) % q;

            return (int)m;
        }



        // Extended Euclidean Algorithm
        private int ModularInverseForDecrypt(int a, int mod)
        {
            // I think using "long" is better (not sure)
            int originalValue = mod, temp, q;
            int x = 0, y = 1;

            if (mod == 1) { return 0; }

            while (a > 1)
            {
                q = a / mod;
                temp = mod;

                mod = a % mod; 
                a = temp;

                temp = x;

                x = y - q * x;
                y = temp;
            }

            if (y < 0)  { y += originalValue; }

            return y;
        }
    }
}
