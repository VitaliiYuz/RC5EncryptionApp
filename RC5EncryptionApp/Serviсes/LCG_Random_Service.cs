using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RC5EncryptionApp.Serviсes
{
    public class LCG_Random_Service
    {
        private int m = 2147483647; // m = 2^31 - 1
        private int a = 16807;          // a = 7^5
        private int c = 17711;
        //int X0 = DateTime.Now.Second; //adding time for more random number
        public LCG_Random_Service(){ }


        public int GenerateNext(int previous)
        {
            return (a * previous + c) % m;
        }

    }
     
       
}
