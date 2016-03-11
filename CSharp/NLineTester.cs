using System;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApplication
{
    public class NlineTester
    {
        private static readonly Socket Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public void TestNline(string host, int port, string username, string password, byte[] configKey)
        {
            //Based on this documentation: https://3color.googlecode.com/svn/trunk/cardservproxy/etc/protocol.txt
            //It doesnt work :(
            try
            {
                Socket.Connect(host, port);

                var helloBytes = new byte[14];//Receive the first 14 bytes
                Socket.Receive(helloBytes);

                byte[] desKey16 = GetLoginKey(configKey, helloBytes);

                byte[] data = Encoding.Unicode.GetBytes(password + "$1$abcdefgh$"); //Encript the password with MD5 and hash it with $1$abcdefgh$
                var passwordBytes = new MD5CryptoServiceProvider().ComputeHash(data);
                
                var networkBuffer = new byte[2 + Common.GetBytes(username).Length + 1 + passwordBytes.Length + 1];

                networkBuffer[0] = 0xe0; //This is the login byte

                Array.Copy(Common.GetBytes(username), 0, networkBuffer, 2, Common.GetBytes(username).Length);
                Array.Copy(passwordBytes, 0, networkBuffer, Common.GetBytes(username).Length +3, passwordBytes.Length);

                //Array must be: [loginbyte, 0, usernamebytes, 0 , hashedpassword, 0]
                
                Console.WriteLine("Data to encript: " + BitConverter.ToString(networkBuffer));

                var encryptedBuffer = EncriptData(networkBuffer, desKey16); //Encript with tripple DES in CBC with keysize of 128bits (16 bytes)

                try
                {
                    Socket.Send(encryptedBuffer);

                    byte[] receivedBuffer = new byte[999];
                    Socket.Receive(receivedBuffer);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to connect. Details: " + e.Message);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to connect. Details: " + e.Message);
            }
            Socket.Close();
        }

        private static byte[] EncriptData(byte[] data, byte[] desKey16)
        {
            //This does a triple DES encription. I had to do it with reflection
            //because otherwise It detects that the Key is not safe

            TripleDES desCrypto = new TripleDESCryptoServiceProvider
            {
                KeySize = 128,
                Mode = CipherMode.CBC
            };

            MethodInfo mi = desCrypto.GetType().GetMethod("_NewEncryptor", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] par = { desKey16, desCrypto.Mode, desCrypto.IV, desCrypto.FeedbackSize, 0};
            ICryptoTransform transform = mi.Invoke(desCrypto, par) as ICryptoTransform;

            var encryptedBuffer = transform?.TransformFinalBlock(data, 0, data.Length);
            return encryptedBuffer;
        }

        private static byte[] GetLoginKey(byte[] configKey, byte[] helloBytes)
        {
            //The login key is a 16 byte key made by xor of hello bytes and config key
            
            byte[] xoredKey = new byte[14];
            for (int i = 0; i < 14; i++) xoredKey[i] = (byte)(configKey[i] ^ helloBytes[i]);
            
            var loginKey = new byte[16];
            loginKey[0] = (byte)(xoredKey[0] & 0xfe);
            loginKey[1] = (byte)(((xoredKey[0] << 7) | (xoredKey[1] >> 1)) & 0xfe);
            loginKey[2] = (byte)(((xoredKey[1] << 6) | (xoredKey[2] >> 2)) & 0xfe);
            loginKey[3] = (byte)(((xoredKey[2] << 5) | (xoredKey[3] >> 3)) & 0xfe);
            loginKey[4] = (byte)(((xoredKey[3] << 4) | (xoredKey[4] >> 4)) & 0xfe);
            loginKey[5] = (byte)(((xoredKey[4] << 3) | (xoredKey[5] >> 5)) & 0xfe);
            loginKey[6] = (byte)(((xoredKey[5] << 2) | (xoredKey[6] >> 6)) & 0xfe);
            loginKey[7] = (byte)(xoredKey[6] << 1);
            loginKey[8] = (byte)(xoredKey[7] & 0xfe);
            loginKey[9] = (byte)(((xoredKey[7] << 7) | (xoredKey[8] >> 1)) & 0xfe);
            loginKey[10] = (byte)(((xoredKey[8] << 6) | (xoredKey[9] >> 2)) & 0xfe);
            loginKey[11] = (byte)(((xoredKey[9] << 5) | (xoredKey[10] >> 3)) & 0xfe);
            loginKey[12] = (byte)(((xoredKey[10] << 4) | (xoredKey[11] >> 4)) & 0xfe);
            loginKey[13] = (byte)(((xoredKey[11] << 3) | (xoredKey[12] >> 5)) & 0xfe);
            loginKey[14] = (byte)(((xoredKey[12] << 2) | (xoredKey[13] >> 6)) & 0xfe);
            loginKey[15] = (byte)(xoredKey[13] << 1);


            for (var i = 0; i < 16; i++)
            {
                var parity = 1;
                for (var j = 1; j < 8; j++)
                    if (((loginKey[i] >> j) & 0x1) == 1)
                        parity = ~parity & 0x01;
                loginKey[i] |= (byte)parity;
            }

            return loginKey;
        }
    }
}
