using System;
using System.Linq;
using System.Text;
using Meebey.SmartIrc4net;
using System.Threading;
using System.Net;
using Newtonsoft.Json;
using Frida;
using System.Windows.Threading;
/// <summary>
/// SF5TwichBot example.
/// https://github.com/dantarion
/// Coded by Eric "dantarion" Sheppard, 2016
/// Will need to have address updated for future patches of SFV. Works for 1.02 "Alex" patch.
/// Not a lot of error checking being done. Use with caution.
/// </summary>
namespace SF5TwitchBot
{
    class Program
    {
        static string COOKIE = null;
        static string host = "api.prod.capcomfighters.net";
        public static IrcClient irc = new IrcClient();
        public static void fridaThread()
        {
            Thread.CurrentThread.Name = "Frida";
            var processes = System.Diagnostics.Process.GetProcessesByName("StreetFighterV");
            System.Diagnostics.Process SFVProcess = null;
            foreach (var process in processes)
            {
                if (process.Threads.Count > 3)
                    SFVProcess = process;
            }
            if (SFVProcess == null)
            {
                Console.Write("Couldn't find SFV\n");
                Exit();
            }

            Console.Write("Found SFV Process PID {0:X}\n", SFVProcess.Id);
            var dms = new Frida.DeviceManager(Dispatcher.CurrentDispatcher).EnumerateDevices();
            var dm = dms.First();
            var session = dm.Attach((uint)SFVProcess.Id);
            var text = @"'use strict';
Interceptor.attach(ptr('0x140AEDD7E'), function(args) {
                //console.log(JSON.stringify(this.context));
                send(Memory.readUtf16String(Memory.readPointer(this.context.rcx.add(0x10))));
            }); ";
            var script = session.CreateScript(text);
            script.Message += onMessage;

            Console.Write("We are in there!");
            script.Load();
            Dispatcher.Run();

        }
        private static void onMessage(object sender, ScriptMessageEventArgs e)
        {
            dynamic message = JsonConvert.DeserializeObject(e.Message);
            if (message.type == "info" || message.type == "log")
                Console.WriteLine(message.payload);
            else if (message.type == "error")
            {
                Console.WriteLine(message.stack);
            }
            else
            {
                Console.WriteLine("Updated Cookie: " + COOKIE);
                COOKIE = message.payload;
            }
        }
        public static void inviteCFNUser(string cfnname)
        {
            System.Net.ServicePointManager.ServerCertificateValidationCallback +=
delegate (object sender, System.Security.Cryptography.X509Certificates.X509Certificate certificate,
                        System.Security.Cryptography.X509Certificates.X509Chain chain,
                        System.Net.Security.SslPolicyErrors sslPolicyErrors)
{
    return true; // **** Always accept
};
            if (COOKIE == null)
            {
                irc.SendMessage(SendType.Action, channel, "cookie error: " + cfnname);
                return;

            }
            var sessionId = COOKIE.Split(new string[] { "%3A" }, StringSplitOptions.None)[0];

            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(String.Format("https://{0}/bentov2/sf5/myinfo/{1}/searchrival/fightersid;id={2}:sort=lp:page=1:sortdir=d", host, sessionId, cfnname));

            httpWebRequest.CookieContainer = new CookieContainer();
            httpWebRequest.CookieContainer.Add(new Cookie("binf", COOKIE) { Domain = host });
            var response = httpWebRequest.GetResponse();
            var dataStream = response.GetResponseStream();
            System.IO.StreamReader reader = new System.IO.StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            dynamic responseJSON = JsonConvert.DeserializeObject(responseFromServer);
            if (responseJSON.response[0].searchresult[0].publicid == null)
            {
                irc.SendMessage(SendType.Action, channel, "error inviting: " + cfnname);
                return;
            }
            string cfnID = responseJSON.response[0].searchresult[0].publicid;
            httpWebRequest = (HttpWebRequest)WebRequest.Create(String.Format("https://{0}/bentov2/sf5/battlelounge/{1}/invite", host, sessionId));
            httpWebRequest.CookieContainer = new CookieContainer();
            httpWebRequest.CookieContainer.Add(new Cookie("binf", COOKIE) { Domain = host });
            byte[] byteArray = Encoding.UTF8.GetBytes(String.Format("invite_user_public_id={0}", cfnID));
            httpWebRequest.ContentType = "application/x-www-form-urlencoded";
            httpWebRequest.ContentLength = byteArray.Length;
            httpWebRequest.Method = "POST";
            dataStream = httpWebRequest.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();
            response = httpWebRequest.GetResponse();
            dataStream = response.GetResponseStream();
            reader = new System.IO.StreamReader(dataStream);
            responseFromServer = reader.ReadToEnd();
            responseJSON = JsonConvert.DeserializeObject(responseFromServer);
            if (responseJSON.response[0].result == "-1")
            {
                irc.SendMessage(SendType.Action, channel, "error inviting: " + cfnname);
                return;
            }
            irc.SendMessage(SendType.Action, channel, "invited " + cfnname);
        }
        public static void OnError(object sender, ErrorEventArgs e)
        {
            System.Console.WriteLine("Error: " + e.ErrorMessage);
            Exit();
        }
        public static void OnRawMessage(object sender, IrcEventArgs e)
        {
            System.Console.WriteLine("Received: " + e.Data.RawMessage);
            if (e.Data.Message != null && e.Data.Message.StartsWith("!invite "))
            {
                try
                { 
                    inviteCFNUser(e.Data.Message.Substring(8));
                }
                catch(Exception err)
                {
                    irc.SendMessage(SendType.Action, channel, "exception inviting: " + e.Data.Message.Substring(8));
                    Console.WriteLine("Exception:"+err.Message);
                    Console.WriteLine("Exception:"+err.StackTrace);
                }
            }
        }
        static string channel = "";
        static string username = "";
        static string password = "";
        public static void Main(string[] args)
        {
            if (!System.IO.File.Exists("config.json"))
            {
                Console.WriteLine("Need config for IRC Stuff! Rename sampleConfig.json to config.json and type in channel, username, and twitch oauth key");
                Console.ReadLine();
            }
            //Load config
            dynamic config = JsonConvert.DeserializeObject(System.IO.File.ReadAllText("config.json"));
            channel = config.channel;
            username = config.username;
            password = config.password;
            new Thread(new ThreadStart(fridaThread)).Start();
            Thread.CurrentThread.Name = "Main";
            irc.Encoding = System.Text.Encoding.UTF8;
            irc.SendDelay = 200;
            irc.ActiveChannelSyncing = true;
            irc.OnError += new ErrorEventHandler(OnError);
            irc.OnRawMessage += new IrcEventHandler(OnRawMessage);

            string[] serverlist;
            serverlist = new string[] { "irc.twitch.tv" };
            int port = 6667;

            try
            {
                irc.Connect(serverlist, port);
            }
            catch (ConnectionException e)
            {
                System.Console.WriteLine("couldn't connect! Reason: " + e.Message);
                Console.ReadLine();
                Exit();
            }

            try
            {
                irc.Login(username, username, 0, username, password);
                irc.RfcJoin(channel);
                irc.SendMessage(SendType.Action, channel, "SF5TwitchBot by @dantarion Enabled! Type !invite <id> to get invited to the lobby!");
                irc.Listen();
                irc.Disconnect();
            }
            catch (Exception e)
            {
                System.Console.WriteLine("Error occurred! Message: " + e.Message);
                System.Console.WriteLine("Exception: " + e.StackTrace);
                Console.ReadLine();
                Exit();

            }
            Console.ReadLine();
        }
        public static void Exit()
        {
            System.Console.WriteLine("Exiting...");
            System.Environment.Exit(0);
        }
    }
}
