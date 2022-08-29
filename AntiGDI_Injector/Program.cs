using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiGDI_Injector
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Int32 targetPID = 0;
            string targetExe = null;
            string channelName = null;

            ProcessArgs(args, out targetPID, out targetExe);

            if (targetPID <= 0 && string.IsNullOrEmpty(targetExe))
                return;

            EasyHook.RemoteHooking.IpcCreateServer<AntiGDI.ServerInterface>(ref channelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            string injectionLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "AntiGDI.dll");

            try
            {
                if (targetPID > 0)
                {
                    Console.WriteLine("[INFO] Пытаюсь внедрить AntiGDI в процесс {0}", targetPID);

                    EasyHook.RemoteHooking.Inject(
                        targetPID,
                        injectionLibrary,
                        injectionLibrary,
                        channelName
                    );
                }
                else if (!string.IsNullOrEmpty(targetExe))
                {
                    Console.WriteLine("[INFO] Пытаюсь открыть exe файл и внедрить AntiGDI в {0}", targetExe);

                    EasyHook.RemoteHooking.CreateAndInject(
                        targetExe,
                        "",
                        0,
                        EasyHook.InjectionOptions.DoNotRequireStrongName,
                        injectionLibrary,
                        injectionLibrary,
                        out targetPID, 
                        channelName 
                    );
                }
            }
            catch (Exception e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] Произошла непредвиденная ошибка:");
                Console.ResetColor();
                Console.WriteLine(e.ToString());
            }

            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine("<Press any key to exit>");
            Console.ResetColor();
            Console.ReadKey();
        }

        static void ProcessArgs(string[] args, out int targetPID, out string targetExe)
        {
            targetPID = 0;
            targetExe = null;

            while ((args.Length != 1) || !Int32.TryParse(args[0], out targetPID) || !File.Exists(args[0]))
            {
                if (targetPID > 0)
                {
                    break;
                }
                if (args.Length != 1 || !File.Exists(args[0]))
                {
                    Console.WriteLine("AntiGDI Injector (c0d9d by DesConnet)");
                    Console.WriteLine("Введи ID процесса или путь до exe файла");
                    Console.Write("> ");

                    args = new string[] { Console.ReadLine() };

                    if (String.IsNullOrEmpty(args[0])) return;
                }
                else
                {
                    targetExe = args[0];
                    break;
                }
            }
        }
    }
}
