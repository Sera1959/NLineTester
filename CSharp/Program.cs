//Created by Dagger -- https://github.com/gavazquez

namespace ConsoleApplication
{
    public class Program
    {
        static void Main(string[] args)
        {
            var server = "server.myserver.us";
            var port = 9999;
            var username = "user";
            var password = "pass";
            var configKey = "01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14";
            
            new NlineTester().TestNline(server, port, username, password, configKey);
        }
    }
}
