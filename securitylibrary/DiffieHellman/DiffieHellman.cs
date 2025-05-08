using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            int Ya = modAndPower(alpha, xa, q);
            int Yb = modAndPower(alpha, xb, q);

            int Ka = modAndPower(Yb, xa, q);
            int Kb = modAndPower(Ya, xb, q);

            List<int> ans = new List<int>();
            ans.Add(Ka);
            ans.Add(Kb);

            return ans;
                
        }

       public static int modAndPower(int b, int p, int mod)
        {
            int pro = 1;

            for (int i = 0; i < p; i++)
            {
                pro = (pro * b) % mod;
            }

            return pro;
        }
    }
}
