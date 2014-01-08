using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace Sodium_NaCl_NET {
    class Program {

        static void Main(string[] args) {

            Program program = new Program();

            while (true) {
                program.Menu();
            }
        }

        void Menu() {

            String choice;

            Console.Clear();
            Console.WriteLine("\nThis is example of the libSodium-net implementation. Welcome.\n\n--Author: Eugen Štimac\n--december 2013.");
            Console.Write("\n\nMENU\n\n1. SymmetricBox\n2. SymmetricAuth\n3. AsymmetricBox\n4. AsymmetricAuth\n5. Salsa\n\t\nChoose: ");
            choice = Console.ReadLine();
            Console.Clear();

            switch (choice) {
                case "1":
                    SymmetricBox();
                    break;
                case "2":
                    SymmetricAuth();
                    break;
                case "3":
                    AsymmetricBox();
                    break;
                case "4":
                    AsymmetricAuth();
                    break;
                case "5":
                    Salsa();
                    break;
                default:
                    Console.WriteLine("\nWrong input! Try again.");
                    Console.ReadLine();
                    break;
            }
        }

        #region SYMMETRIC
        void SymmetricBox() {

            String choice;
            byte[] data, nonce, key, encrypted, decrypted;

            data = InputData();
            key = Sodium.SecretBox.GenerateKey();
            nonce = Sodium.SecretBox.GenerateNonce();

            encrypted = Sodium.SecretBox.Create(data, nonce, key);

            Console.WriteLine("Tamper with encrypted data? (y/n)");
            choice = Console.ReadLine();
            if (choice == "y") encrypted[32] = 1;

            try {
                decrypted = Sodium.SecretBox.Open(encrypted, nonce, key);
                Console.WriteLine("Successfully decrypted! Text: {0}", Encoding.UTF8.GetString(decrypted));
            }
            catch (CryptographicException) {
                Console.WriteLine("Could not decrypt. Message was tampered with!");
            }

            Console.ReadLine();
        }

        void SymmetricAuth() {

            byte[] key, data, dataSigned, dataNew;

            data = InputData();
            key = Sodium.OneTimeAuth.GenerateKey();
            dataSigned = Sodium.OneTimeAuth.Sign(data, key);

            Console.WriteLine("Tamper the data now, if you wish, then press enter.");
            Console.ReadLine();
            dataNew = InputData();

            if (Sodium.OneTimeAuth.Verify(dataNew, dataSigned, key))
                Console.WriteLine("Signature verified!");
            else
                Console.WriteLine("Signature illegitimate!");

            Console.ReadLine();
        }

        void Salsa() {

            byte[] data, nonce, key, encrypted, decrypted;

            data = InputData();
            key = Sodium.StreamEncryption.GenerateKey();
            nonce = Sodium.StreamEncryption.GenerateNonce();

            encrypted = Sodium.StreamEncryption.Encrypt(data, nonce, key);
            decrypted = Sodium.StreamEncryption.Decrypt(encrypted, nonce, key);
        }
        #endregion

        #region ASYMMETRIC
        void AsymmetricBox() {

            String choice;
            byte[] data, nonce, encrypted, decrypted;
            Sodium.KeyPair keypair = new Sodium.KeyPair();

            data = InputData();
            keypair = Sodium.PublicKeyBox.GenerateKeyPair();
            nonce = Sodium.SecretBox.GenerateNonce();

            encrypted = Sodium.PublicKeyBox.Create(data, nonce, keypair.PrivateKey, keypair.PublicKey);
            decrypted = Sodium.PublicKeyBox.Open(encrypted, nonce, keypair.PrivateKey, keypair.PublicKey);

            Console.WriteLine("Tamper with encrypted data? (y/n)");
            choice = Console.ReadLine();
            if (choice == "y") encrypted[32] = 1;

            try {
                decrypted = Sodium.PublicKeyBox.Open(encrypted, nonce, keypair.PrivateKey, keypair.PublicKey);
                Console.WriteLine("Successfully decrypted! Text: {0}", Encoding.UTF8.GetString(decrypted));
            }
            catch (CryptographicException) {
                Console.WriteLine("Could not decrypt. Message was tampered with!");
            }
            Console.ReadLine();
        }

        void AsymmetricAuth() {

            byte[] data, dataSigned, dataNew, dataNewSigned;
            Sodium.KeyPair keypair = new Sodium.KeyPair();

            data = InputData();
            keypair = Sodium.PublicKeyAuth.GenerateKeyPair();
            dataSigned = Sodium.PublicKeyAuth.Sign(data, keypair.PrivateKey);

            Console.WriteLine("Tamper the data now, if you wish, then press enter.");
            Console.ReadLine();

            dataNew = InputData();
            dataNewSigned = Sodium.PublicKeyAuth.Sign(dataNew, keypair.PrivateKey);

            if (Encoding.UTF8.GetString(Sodium.PublicKeyAuth.Verify(dataSigned, keypair.PublicKey)) == Encoding.UTF8.GetString(Sodium.PublicKeyAuth.Verify(dataNewSigned, keypair.PublicKey)))
                Console.WriteLine("Signature verified!");
            else
                Console.WriteLine("Signature illegitimate!");

            Console.ReadLine();
        }
        #endregion

        #region HELPERS
        byte[] GetByte(String data) {

            byte[] bytes = new byte[data.Length * sizeof(char)];
            System.Buffer.BlockCopy(data.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        byte[] InputData() {

            String message, file;
            byte[] data;

            file = @"../../testFiles/testData.txt";

            if (File.Exists(file))
                using (BinaryReader reader = new BinaryReader(File.Open(file, FileMode.Open))) {
                    long totalBytes = new System.IO.FileInfo(file).Length;
                    data = reader.ReadBytes((Int32)totalBytes);

                    return data;
                }

            else {
                Console.WriteLine("\nFile not found! Input text for data: ");
                message = Console.ReadLine();
                return GetByte(message);
            }
        }
        #endregion
    }

}
