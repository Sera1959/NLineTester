//Created by Dagger -- https://github.com/DaggerES

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using ConsoleApplication.CustomMD5;

namespace ConsoleApplication
{
    public class NlineTester
    {
        private static readonly Socket Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        public void TestNline(string host, int port, string username, string password, string configKey)
        {
            try
            {
                Socket.Connect(host, port);

                var helloBytes = new byte[14]; //Receive the first 14 bytes
                Socket.Receive(helloBytes);

                var configKeyBytes = ParseConfigKey(configKey);
                byte[] loginKey = GetLoginKey(configKeyBytes, helloBytes);

                //CAUTION! Md5 hash must be done as in UNIX Crypt() function.
                //You can also use the CryptAPI dll (http://cryptapi.sourceforge.net/) and send "abcdefgh" as salt
                //The one that I'm using I grabbed it from: https://gist.github.com/otac0n/1092558
                var hashedPassword = Encoding.ASCII.GetBytes(UnixLikeMD5.crypt(password, "$1$abcdefgh$"));

                var loginMessage = new List<byte>();
                Add10EmptyHeaderBytes(loginMessage);

                loginMessage.Add(0xE0); //This is the login byte
                loginMessage.Add(0);
                loginMessage.Add(50); //No idea what this is

                loginMessage.AddRange(Encoding.ASCII.GetBytes(username)); //Add username as bytes
                loginMessage.Add(0); //Add a "0" as separator
                loginMessage.AddRange(hashedPassword); //Add md5 hashed password
                loginMessage.Add(0); //Add a "0" as separator

                AddChecksumFooter(loginMessage);

                Console.WriteLine("Data to encript: " + BitConverter.ToString(loginMessage.ToArray()));

                var iv = Get8BytesRandomIv();

                var encryptedBuffer = EncriptData(loginMessage, loginKey, iv);

                encryptedBuffer.AddRange(iv); //Add initialization vector to the bottom
                encryptedBuffer = AddLengthHeader(encryptedBuffer); //Add 2 bytes header

                try
                {
                    Socket.Send(encryptedBuffer.ToArray()); //Send the encripted data!

                    byte[] receivedBuffer = new byte[100];
                    var receiveCount = Socket.Receive(receivedBuffer);

                    if (receiveCount == 0)
                    {
                        Console.WriteLine("Failed to receive answer, check 14 byte config key");
                    }
                    else
                    {
                        //Proceed to decript the message...
                        var receivedData = receivedBuffer.ToList();

                        //Remove trailing '0' from buffer
                        receivedData.RemoveRange(receiveCount, receivedData.Count - receiveCount);

                        //Remove first 2 sum bytes
                        receivedData.RemoveAt(0);
                        receivedData.RemoveAt(0);

                        //Get the 8 bytes IV
                        iv = receivedData.GetRange(receivedData.Count - 8, 8).ToArray();

                        //Decrypt using TripleDES
                        receivedData = DecriptData(receivedData.ToArray(), loginKey, iv);

                        //Remove the 10 '0' header bytes
                        receivedData.RemoveRange(0, 10);

                        //225 (0xE1) = ACK (acknowledge, all ok)
                        //226 (0xE2) = NACK (bad data)
                        Console.WriteLine(receivedData.First() == 0xE1 ? "SUCCESS!" : "Wrong username or password!");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Failed to send the data. Details: " + e.Message);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed to connect. Details: " + e.Message);
            }
            Socket.Close();
        }

        private static byte[] ParseConfigKey(string desKey)
        {
            //This method parse the config key from a string and puts it as an array of bytes
            desKey = desKey.Replace(",", string.Empty);
            desKey = desKey.Replace(" ", string.Empty);
            desKey = desKey.Replace(":", string.Empty);
            byte[] byteDesKey = new byte[desKey.Length / 2];
            int arrayCounter = 0;
            for (int i = 0; i < byteDesKey.Length; i++)
            {
                byteDesKey[i] = Convert.ToByte(desKey.Substring(arrayCounter, 2), 16);
                arrayCounter = arrayCounter + 2;
            }
            return byteDesKey;
        }

        private static byte[] Get8BytesRandomIv()
        {
            //Get a random initialization vector for the TripleDES
            byte[] iv = new byte[8];
            new Random().NextBytes(iv);
            return iv;
        }

        private static void Add10EmptyHeaderBytes(List<byte> networkBuffer)
        {
            for (int i = 0; i < 10; i++)
            {
                networkBuffer.Add(0); //Add 10 '0' header bytes
            }
        }

        private static void AddChecksumFooter(List<byte> networkBuffer)
        {
            byte xorSum = 0;
            networkBuffer.ForEach(b => { xorSum = (byte) (xorSum ^ b); });
            networkBuffer.Add(xorSum);
        }

        private static List<byte> AddLengthHeader(List<byte> encryptedBuffer)
        {
            var newEncriptedBuff = new List<byte>
            {
                (byte) (encryptedBuffer.Count >> 8),
                (byte) (encryptedBuffer.Count & 0xff)
            };
            newEncriptedBuff.AddRange(encryptedBuffer);

            encryptedBuffer = newEncriptedBuff;
            return encryptedBuffer;
        }

        private static List<byte> DecriptData(IEnumerable<byte> data, byte[] loginKey, byte[] iv)
        {
            TripleDES tripleDes = TripleDES.Create();
            tripleDes.Mode = CipherMode.CBC;
            tripleDes.Padding = PaddingMode.Zeros;
            tripleDes.IV = iv;
            tripleDes.Key = loginKey;

            ICryptoTransform cryptoTransform = tripleDes.CreateDecryptor();
            return cryptoTransform.TransformFinalBlock(data.ToArray(), 0, data.Count()).ToList();
        }

        private static List<byte> EncriptData(IEnumerable<byte> data, byte[] loginKey, byte[] iv)
        {
            TripleDES tripleDes = TripleDES.Create();
            tripleDes.Mode = CipherMode.CBC;
            tripleDes.Padding = PaddingMode.Zeros;
            tripleDes.IV = iv;
            tripleDes.Key = loginKey;

            ICryptoTransform cryptoTransform = tripleDes.CreateEncryptor();
            return cryptoTransform.TransformFinalBlock(data.ToArray(), 0, data.Count()).ToList();
        }

        private static byte[] GetLoginKey(byte[] configKey, byte[] helloBytes)
        {
            //The login key is a 16 byte key made by xor of hello bytes and config key
            byte[] xoredKey = new byte[14];
            for (int i = 0; i < 14; i++) xoredKey[i] = (byte)(configKey[i] ^ helloBytes[i]);

            //Do the key spread from 14 bytes to 16 bytes as tripleDES needs
            byte[] loginKey = {
                (byte)(xoredKey[0] & 0xfe),
                (byte)((xoredKey[0] << 7 | xoredKey[1] >> 1) & 0xfe),
                (byte)((xoredKey[1] << 6 | xoredKey[2] >> 2) & 0xfe),
                (byte)((xoredKey[2] << 5 | xoredKey[3] >> 3) & 0xfe),
                (byte)((xoredKey[3] << 4 | xoredKey[4] >> 4) & 0xfe),
                (byte)((xoredKey[4] << 3 | xoredKey[5] >> 5) & 0xfe),
                (byte)((xoredKey[5] << 2 | xoredKey[6] >> 6) & 0xfe),
                (byte)(xoredKey[6] << 1),
                (byte)(xoredKey[7] & 0xfe),
                (byte)((xoredKey[7] << 7 | xoredKey[8] >> 1) & 0xfe),
                (byte)((xoredKey[8] << 6 | xoredKey[9] >> 2) & 0xfe),
                (byte)((xoredKey[9] << 5 | xoredKey[10] >> 3) & 0xfe),
                (byte)((xoredKey[10] << 4 | xoredKey[11] >> 4) & 0xfe),
                (byte)((xoredKey[11] << 3 | xoredKey[12] >> 5) & 0xfe),
                (byte)((xoredKey[12] << 2 | xoredKey[13] >> 6) & 0xfe),
                (byte)(xoredKey[13] << 1)
            };

            //Here we adjust the parity?
            for (int i = 0; i < loginKey.Length; i++)
            {
                loginKey[i] = (byte)(loginKey[i] & 0xfe |
                    (loginKey[i] >> 1 ^ loginKey[i] >> 2 ^ loginKey[i] >> 3 ^ loginKey[i] >> 4 ^
                    loginKey[i] >> 5 ^ loginKey[i] >> 6 ^ loginKey[i] >> 7 ^ 1) & 1);
            }

            return loginKey;
        }
    }
}
