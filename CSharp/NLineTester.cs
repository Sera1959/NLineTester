using System;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ConsoleApplication.CustomMD5;

namespace ConsoleApplication
{
    public class NlineTester
    {
        private static readonly Socket Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public void TestNline(string host, int port, string username, string password, byte[] configKey)
        {
            //Based on the OSCAM code (except the tripple des encription)
            //Check also this documentation: https://3color.googlecode.com/svn/trunk/cardservproxy/etc/protocol.txt
            
            //It doesnt work :(
            try
            {
                Socket.Connect(host, port);

                var helloBytes = new byte[14]; //Receive the first 14 bytes
                Socket.Receive(helloBytes);
                
                byte[] desKey16 = GetLoginKey(configKey, helloBytes);

                var passwordMd5 = CustomMd5.crypt(password, "$1$abcdefgh$");
                var passwordBytes = Encoding.ASCII.GetBytes(passwordMd5);

                var networkBuffer = new byte[3 + Common.GetBytes(username).Length + 1 + passwordBytes.Length + 1];

                networkBuffer[0] = 0xe0; //This is the login byte
                networkBuffer[1] = (byte)((0 & 0xf0) | (((username.Length + 1) >> 8) & 0x0f));
                networkBuffer[2] = (byte)(username.Length + 1 & 0xff);

                Array.Copy(Common.GetBytes(username), 0, networkBuffer, 3, Common.GetBytes(username).Length);
                Array.Copy(passwordBytes, 0, networkBuffer, Common.GetBytes(username).Length +4, passwordBytes.Length);
                
                networkBuffer = AddHeaderToBuffer(networkBuffer);

                Console.WriteLine("Data to encript: " + BitConverter.ToString(networkBuffer));

                var encryptedBuffer = EncriptData(networkBuffer, desKey16); //Encript with tripple DES in CBC with keysize of 128bits (16 bytes)
                
                encryptedBuffer = AddLengthHeader(encryptedBuffer);
                
                try
                {
                    Socket.Send(encryptedBuffer);

                    byte[] receivedBuffer = new byte[999];
                    var recvC = Socket.Receive(receivedBuffer);
                    while (recvC == 0)
                    {
                        recvC = Socket.Receive(receivedBuffer);
                    }
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

        private static byte[] AddLengthHeader(byte[] encryptedBuffer)
        {
            var newencryptedBuffer = new byte[encryptedBuffer.Length + 2];
            Array.Copy(encryptedBuffer, 0, newencryptedBuffer, 2, encryptedBuffer.Length);
            newencryptedBuffer[0] = (byte) (encryptedBuffer.Length >> 8);
            newencryptedBuffer[1] = (byte) (encryptedBuffer.Length & 0xff);

            return newencryptedBuffer;
        }

        private byte[] AddHeaderToBuffer(byte[] networkBuffer)
        {
            var newByte = new byte[networkBuffer.Length + 12];
            Array.Copy(networkBuffer, 0, newByte, 12, networkBuffer.Length);

            return newByte;
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
            for (int i = 0; i < 14; i++) xoredKey[i] = (byte)(configKey[i % 14] ^ helloBytes[i]);
            
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

            byte[] array1;
            byte[] array2;

            Split<byte>(loginKey, 8, out array1, out array2);
            doPC1(array1);
            doPC1(array2);

            array1.CopyTo(loginKey, 0);
            array2.CopyTo(loginKey, array1.Length);

            return loginKey;
        }

        public static void Split<T>(T[] source, int index, out T[] first, out T[] last)
        {
            int len2 = source.Length - index;
            first = new T[index];
            last = new T[len2];
            Array.Copy(source, 0, first, 0, index);
            Array.Copy(source, index, last, 0, len2);
        }

        private static void doPC1(byte[] data)
        {
            byte[,] PC1 = new byte[7, 8]
            {
                { 57, 49, 41, 33, 25, 17,  9, 1 },
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 60, 52, 44, 36, 63, 55, 47,39 },
                { 31, 23, 15,  7, 62, 54, 46,38 },
                { 30, 22, 14,  6, 61, 53, 45,37 },
                { 29, 21, 13,  5, 28, 20, 12, 4 }
            };

            byte[] buf = new byte[8];
            byte i, j;

            for (j = 0; j < 7; j++)
            {
                for (i = 0; i < 8; i++)
                {
                    byte lookup = PC1[j,i];
                    buf[j] |= (byte)(((data[(lookup >> 3)] >> (8 - (lookup & 7))) & 1) << (7 - i));
                }
            }

            Array.Copy(buf, data, buf.Length);
        }
    }
}
