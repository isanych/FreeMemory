﻿using System;

namespace FreeMemory
{
    internal class Program
    {
        public static readonly object SyncRoot = new object();
        public static readonly string TempFolder;
        public static readonly string MyName;

        static Program()
        {
            MyName = System.IO.Path.GetFileNameWithoutExtension(AppDomain.CurrentDomain.FriendlyName);
            TempFolder = Environment.GetEnvironmentVariable("Temp");
            if (string.IsNullOrEmpty(TempFolder) || !(new System.IO.DirectoryInfo(TempFolder).Exists))
            {
                TempFolder = AppDomain.CurrentDomain.BaseDirectory;
            }

            if (!TempFolder.EndsWith("\\"))
            {
                TempFolder += '\\';
            }
        }

        private static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
#if DEBUG
            var fi = new System.IO.FileInfo(TempFolder + MyName + ".FirstChance.log");
            if (fi.Exists) { fi.Delete(); }
            AppDomain.CurrentDomain.FirstChanceException += FirstChanceException;
#endif
            try
            {
                using (var work = new Worker())
                {
                    work.PurgeStandby();
                }
            }
            catch (Exception ex)
            {
                HandleException(ex);
            }
        }

        private static void HandleException(Exception Ex)
        {
            Console.Error.WriteLine(Ex.GetBaseException().Message);
            System.Diagnostics.Debugger.Break();
            if (System.Threading.Monitor.TryEnter(SyncRoot, 500))
            {
                try
                {
                    using (var sw = new System.IO.StreamWriter(TempFolder + MyName + ".Errors.log", true))
                    {
                        sw.WriteLine("{0:yyyy.MM.dd HH:mm:ss.fffffff K}: {1}\r\n{2}",
                                DateTime.Now, Ex.GetBaseException().Message, Ex.StackTrace);
                    }
                }
                finally
                {
                    System.Threading.Monitor.Pulse(SyncRoot);
                    System.Threading.Monitor.Exit(SyncRoot);
                }
            }
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            HandleException((Exception)e.ExceptionObject);
        }

#if DEBUG
        private static void FirstChanceException(object sender, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
        {
            if (System.Threading.Monitor.TryEnter(SyncRoot, 500))
            {
                try
                {
                    using (var sw = new System.IO.StreamWriter(TempFolder + MyName + ".FirstChance.log", true))
                    {
                        sw.WriteLine("{0:yyyy.MM.dd HH:mm:ss.fffffff K}:\r\n{1}\r\n{2}\r\n{3}",
                            DateTime.Now, e.Exception.StackTrace, new string('-', 20), new System.Diagnostics.StackTrace(1, true).ToString(), new string('*', 80));
                    }
                }
                finally
                {
                    System.Threading.Monitor.Pulse(SyncRoot);
                    System.Threading.Monitor.Exit(SyncRoot);
                }
            }
        }
#endif

    }

}
