using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            //key generation
            /*
            1) n=pq
             2)o(n)euler,s totient =(p-1)*(q-1)
            3) find d= decryption exponent 
            d*e mod o(n) =1
             */
            //encryption
            /*
             C = (M^e) mod n

             */
            int n = p * q;
            M = M % n;
            int res = 1;
            for(int i = 0; i < e; i++)
            {
                res = (res * M) % n;
            }
            return res;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
           // throw new NotImplementedException();
            //decryption
            /*
             m=(c^D) mod n

             */
           
            int on =(p-1)*(q-1);
            int n = p * q;
            int d= findprivatekey(e, on);
            C = C % n;
            int res = 1;
            for (int i = 0; i < d; i++)
            {
                res = (res * C) % n;
            }
            return res;
        }
        public int findprivatekey( int e,int phi)
        {
            int t = 0, nt = 1;
            int r = phi, nr = e;
            while(nr!=0)
            {
                int qoutient =r/nr;
                int tempt = t;
                t = nt;
                nt = tempt - qoutient * nt;
                int tempr= r;
                r = nr;
                nr= tempr-qoutient*nr;

            }
            if (t < 0) t += phi;
            return t;
        }
    }
}
