using Impersonation;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ImpersonationTutorial
{
    class Program
    {
        public static string path = @"d:\testordner";
        static void Main(string[] args)
        {
            var identity = WindowsIdentity.GetCurrent();
            ThreadPool.QueueUserWorkItem(new WaitCallback(ThreadProc), "Thread");
            while (true)
            {
                Thread.Sleep(1000);
            }
            Console.ReadLine();
        }

        private static void PrintIdentity(string destination, WindowsIdentity identity)
        {
            Console.WriteLine(String.Format("Name: {0} \t Destination: {1}", identity.Name, destination));
        }

        static void ThreadProc(Object stateInfo)
        {
            var destination = stateInfo as string;

            var identity = WindowsIdentity.GetCurrent();
            while (true)
            {
                PrintIdentity("Thread", identity);
                //Using the ImpersonationManager
                using (var impersonationNative = new ImpersonationManager())
                {
                    impersonationNative.ImpersonateByProcessId(5280);
                    ReadFiles(destination);
                    identity = WindowsIdentity.GetCurrent();
                    PrintIdentity("Thread", identity);
                }
                Thread.Sleep(1000);
                identity = WindowsIdentity.GetCurrent();
                PrintIdentity("Thread", identity);
            }
        }

        private static void ReadFiles(string destination)
        {
            for (int i = 1; i <= 3; i++)
            {
                try
                {
                    using (FileStream sf = new FileStream(path + "\\test" + i + ".txt", FileMode.Open, FileAccess.Read))
                    {
                        using (StreamReader reader = new StreamReader(sf))
                        {
                            Console.WriteLine("Read from:" + destination);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Read from:" + e.Message);
                }
            }
        }
    }
}
