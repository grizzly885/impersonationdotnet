using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace Impersonation
{
    public interface IImpersonation
    {
        WindowsIdentity ImpersonateByProcessId(int pid);
        WindowsIdentity UndoImpersonation();
    }
}
