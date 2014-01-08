using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Sodium_NaCl {
    class Program {
      

        static void Main(string[] args) {
            
            Program program = new Program();

            while (true) { 
                program.Menu();          
                Console.ReadLine();
            }
        }

        void Menu() {

            String choice;

            Console.Clear();
            Console.WriteLine("\nThis is example of the libSodium-net implementation. Welcome.\n\n--Author: Eugen Štimac\n--december 2013.");
            Console.Write("\n\nMENU\n\n1.     \n2.     \n3.    \n\t\nChoose: ");
            choice = Console.ReadLine();
            Console.Clear();

            switch (choice) {
                case "1":
                    SymmetricBox();
                    break;
                case "2":
                    Asymmetric();
                    break;
                case "3":
                    SymmetricAuth();
                    break;
                case "4":
                    Salsa();
                    break;
                default:
                    Console.WriteLine("\nWrong input! Try again.");
                    break;
            }
        }

        #region SYMMETRIC
        void SymmetricBox() {

            byte[] data,data2, nonce, key, encrypted, decrypted;            

           // data = InputData();
            key = Sodium.SecretBox.GenerateKey();
            nonce = Sodium.SecretBox.GenerateNonce();
           

            using (BinaryReader reader = new BinaryReader(File.Open("C:\\Users\\Personal\\Desktop\\test.txt", FileMode.Open))) {

                long totalBytes = new System.IO.FileInfo("C:\\Users\\Personal\\Desktop\\test.txt").Length;
                data = reader.ReadBytes((Int32)totalBytes);             
            }

            encrypted = Sodium.SecretBox.Create(data, nonce, key);

            using (BinaryWriter writer = new BinaryWriter(File.Open("C:\\Users\\Personal\\Desktop\\AAA\\enc.txt", FileMode.Create))) {
                writer.Write(encrypted);
            }

            using (BinaryReader reader = new BinaryReader(File.Open("C:\\Users\\Personal\\Desktop\\AAA\\enc.txt", FileMode.Open))) {

                long totalBytes = new System.IO.FileInfo("C:\\Users\\Personal\\Desktop\\AAA\\enc.txt").Length;
                data2 = reader.ReadBytes((Int32)totalBytes);
            }

            decrypted = Sodium.SecretBox.Open(data2, nonce, key);

            using (BinaryWriter writer = new BinaryWriter(File.Open("C:\\Users\\Personal\\Desktop\\dec.txt", FileMode.Create))) {
                writer.Write(decrypted);
            }

            if (data == decrypted) Console.WriteLine("RADI");
            else Console.WriteLine("N ERADI");

            Console.ReadLine();
        }

        void SymmetricAuth() {

            byte[] key, data, sign, dataNew;

            data = InputData();
            key = Sodium.OneTimeAuth.GenerateKey();
            sign = Sodium.OneTimeAuth.Sign(data, key);

            dataNew = InputData();

            if (Sodium.OneTimeAuth.Verify(dataNew, sign, key)) 
                Console.WriteLine("Signature verified!");
            else 
                Console.WriteLine("Signature illegitimate!");
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
        void Asymmetric() {

            byte[] data, nonce, encrypted, decrypted;
            Sodium.KeyPair keypair = new Sodium.KeyPair();

            data = InputData();
            keypair = Sodium.PublicKeyBox.GenerateKeyPair();
            nonce = Sodium.SecretBox.GenerateNonce();

            encrypted = Sodium.PublicKeyBox.Create(data, nonce, keypair.PrivateKey, keypair.PublicKey);
            decrypted = Sodium.PublicKeyBox.Open(encrypted, nonce, keypair.PrivateKey, keypair.PublicKey);          
        }

        void AsymmetricAuth() {

            byte[] data, dataSigned;
            Sodium.KeyPair keypair = new Sodium.KeyPair();

            data = InputData();
            keypair = Sodium.PublicKeyAuth.GenerateKeyPair();
            dataSigned = Sodium.PublicKeyAuth.Sign(data, keypair.PrivateKey);
            
        }
        #endregion

        #region HELPERS
        byte[] GetByte(String podatak) {

            byte[] bytes = new byte[podatak.Length * sizeof(char)];
            System.Buffer.BlockCopy(podatak.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        byte[] InputData() {

            String message, file;
            byte[] data;

            file = "C:\\Users\\Personal\\Desktop\\tes2t.txt";
            message = Console.ReadLine();

            if(File.Exists(file))
                using (BinaryReader reader = new BinaryReader(File.Open(file, FileMode.Open))) {

                    long totalBytes = new System.IO.FileInfo(file).Length;
                    data = reader.ReadBytes((Int32)totalBytes);                 

                    return data;
                }
            else 
                return GetByte(message);
            
        }
        #endregion
    }

}
