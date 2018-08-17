using System;

namespace FreeMemory
{
	class Program
	{
		public readonly static object
			SyncRoot = new object();

		public readonly static string
			TempFolder,
			MyName;

		static Program()
		{
			MyName = System.IO.Path.GetFileNameWithoutExtension(AppDomain.CurrentDomain.FriendlyName);
			TempFolder = Environment.GetEnvironmentVariable("Temp");
			if(String.IsNullOrEmpty(TempFolder) || !(new System.IO.DirectoryInfo(TempFolder).Exists))
				TempFolder = AppDomain.CurrentDomain.BaseDirectory;
			if (!TempFolder.EndsWith("\\"))
				TempFolder += '\\';
		}

		static void Main(string[] args)
		{
			AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
#if DEBUG
#if NET40
			System.IO.FileInfo
				fi = new System.IO.FileInfo(TempFolder + MyName + ".FirstChance.log");
			if(fi.Exists)
				fi.Delete();
			AppDomain.CurrentDomain.FirstChanceException += FirstChanceException;
#endif
#endif
			Worker
				work = null;
			try
			{
				work = new Worker();
				work.PurgeStandby();
			}
			catch (Exception ex)
			{
				HandleException(ex);
			}
			finally
			{
				if (work != null)
				{
					work.Dispose();
					work = null;
				}
			}
		}

		static void HandleException(Exception Ex)
		{
			Console.Error.WriteLine(Ex.GetBaseException().Message);
			System.Diagnostics.Debugger.Break();
			System.IO.StreamWriter
				sw = null;
			if (System.Threading.Monitor.TryEnter(SyncRoot, 500))
				try
				{
					sw = new System.IO.StreamWriter(TempFolder + MyName + ".Errors.log", true);
					sw.WriteLine("{0:yyyy.MM.dd HH:mm:ss.fffffff K}: {1}\r\n{2}",
						DateTime.Now, Ex.GetBaseException().Message, Ex.StackTrace);
					sw.Close();
					sw = null;
				}
				catch { }
				finally
				{
					if (sw != null)
						try { sw.Close(); }
						catch { }
					System.Threading.Monitor.Pulse(SyncRoot);
					System.Threading.Monitor.Exit(SyncRoot);
				}
		}

		static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
		{
			HandleException((Exception)e.ExceptionObject);
		}

#if DEBUG
#if NET40
		static void FirstChanceException(object sender, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
		{
			System.IO.StreamWriter
				sw = null;
			if (System.Threading.Monitor.TryEnter(SyncRoot, 500))
				try
				{
					sw = new System.IO.StreamWriter(TempFolder + MyName + ".FirstChance.log", true);
					sw.WriteLine("{0:yyyy.MM.dd HH:mm:ss.fffffff K}:\r\n{1}\r\n{2}\r\n{3}",
						DateTime.Now, e.Exception.StackTrace, new string('-', 20), new System.Diagnostics.StackTrace(1, true).ToString(), new string('*', 80));
					sw.Close();
					sw = null;
				}
				catch { }
				finally
				{
					if (sw != null)
						try { sw.Close(); }
						catch { }
					System.Threading.Monitor.Pulse(SyncRoot);
					System.Threading.Monitor.Exit(SyncRoot);
				}
		}
#endif // NET40
#endif // DEBUG

	} // class Program



} // namespace FreeMemory
