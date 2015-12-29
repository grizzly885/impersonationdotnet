using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
    public class ImpersonationManager : IImpersonation, IDisposable
    {
        private WindowsIdentity identity;

        public WindowsIdentity ImpersonateByProcessId(int pid)
        {
            identity = WindowsIdentity.GetCurrent();
            IntPtr usertoken = WinApi.GetUserTokenFromProcessId(5280);
            WindowsIdentity.Impersonate(usertoken);
            return WindowsIdentity.GetCurrent();
        }

        public WindowsIdentity UndoImpersonation()
        {
            identity.Impersonate();
            return WindowsIdentity.GetCurrent();
        }

        public void Dispose()
        {
            UndoImpersonation();
        }
    }
}
