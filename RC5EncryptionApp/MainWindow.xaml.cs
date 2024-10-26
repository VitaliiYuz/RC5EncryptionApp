using RC5EncryptionApp.Services;
using RC5EncryptionApp.Serviсes;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace RC5EncryptionApp
{
    public partial class MainWindow : Window
    {
        private const int WordSize = 16; // 16-bit words
        private const int Rounds = 12;   // 12 rounds
        private const int KeyLengthBytes = 8; // 64-bit key (8 bytes)
        private const int BlockSize = 4; // 2 words = 4 bytes block size

        private MD5Service md5Service = new MD5Service();
        private LCG_Random_Service LCG_Random_Service = new LCG_Random_Service();
        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string passphrase = PassphraseTextBox.Text;
            var fileToEncrypt = GetFileFromDialog();

            if (!string.IsNullOrEmpty(fileToEncrypt) && !string.IsNullOrEmpty(passphrase))
            {
                byte[] key = GenerateKeyFromPassphrase(passphrase);
                EncryptFile(fileToEncrypt, key);
                MessageBox.Show("File Encrypted Successfully");
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string passphrase = PassphraseTextBox.Text;
            var fileToDecrypt = GetFileFromDialog();

            if (!string.IsNullOrEmpty(fileToDecrypt) && !string.IsNullOrEmpty(passphrase))
            {
                byte[] key = GenerateKeyFromPassphrase(passphrase);
                DecryptFile(fileToDecrypt, key);
                
            }
        }

        private byte[] GenerateKeyFromPassphrase(string passphrase)
        {
            // Use your custom MD5Service
            MD5Service md5Service = new MD5Service();

            // Compute the hash from the passphrase using MD5Service
            byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            string md5HashString = md5Service.ComputeMD5Hash(passphraseBytes);

            // Convert the hash string back to byte array
            byte[] hash = Enumerable.Range(0, md5HashString.Length / 2)
                                    .Select(x => Convert.ToByte(md5HashString.Substring(x * 2, 2), 16))
                                    .ToArray();

            // Return the lower 64 bits (8 bytes) as the key
            if (KeyLengthBytes == 8) // 64 bits
            {
                return hash.Take(8).ToArray(); // Lower 64 bits
            }

            throw new InvalidOperationException("Invalid key length.");
        }


        private void EncryptFile(string filePath, byte[] key)
        {
            byte[] fileData = File.ReadAllBytes(filePath);
            byte[] iv = GenerateRandomIV();
            byte[] encryptedIV = RC5EncryptECB(iv, key);

            // Create a new file name by appending "_encrypted" before the original file extension
            string newFilePath = Path.Combine(Path.GetDirectoryName(filePath),
                              Path.GetFileNameWithoutExtension(filePath) + "_encrypted" + Path.GetExtension(filePath));

            using (FileStream fs = new FileStream(newFilePath, FileMode.Create))
            {
                fs.Write(encryptedIV, 0, encryptedIV.Length); // Write IV first
                byte[] encryptedData = RC5EncryptCBC(fileData, key, iv);
                fs.Write(encryptedData, 0, encryptedData.Length);
            }
        }


        private void DecryptFile(string filePath, byte[] key)
        {
            byte[] encryptedFileData = File.ReadAllBytes(filePath);
            byte[] encryptedIV = new byte[BlockSize]; // Read the IV
            Array.Copy(encryptedFileData, 0, encryptedIV, 0, BlockSize);
            byte[] iv = RC5DecryptECB(encryptedIV, key); // Decrypt the IV

            byte[] encryptedData = new byte[encryptedFileData.Length - BlockSize];
            Array.Copy(encryptedFileData, BlockSize, encryptedData, 0, encryptedData.Length);

            byte[] unpaddedData = null;
            try
            {
                byte[] decryptedData = RC5DecryptCBC(encryptedData, key, iv);
                unpaddedData = UnpadData(decryptedData);

            }
            catch (InvalidOperationException ex)
            {

                MessageBox.Show("Decryption failed. Possible wrong passphrase or corrupted data.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;  
            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred during decryption: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;  
            }

            string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(filePath);
            if (fileNameWithoutExtension.EndsWith("_encrypted"))
            {
                fileNameWithoutExtension = fileNameWithoutExtension.Substring(0, fileNameWithoutExtension.Length - "_encrypted".Length);
            }

            string outputFile = Path.Combine(Path.GetDirectoryName(filePath), fileNameWithoutExtension + "_decrypted" + Path.GetExtension(filePath));

            File.WriteAllBytes(outputFile, unpaddedData);
            MessageBox.Show("File Decrypted Successfully");
        }




        private byte[] GenerateRandomIV()
        {
            byte[] iv = new byte[BlockSize]; // 4-byte IV to match block size
            
            int current = DateTime.Now.Second;
            LCG_Random_Service = new LCG_Random_Service();

            for (int i = 0; i < BlockSize; i++)
            {
                current = LCG_Random_Service.GenerateNext(current); // Generate next LCG random number
                iv[i] = (byte)(current % 256);  // Convert to a byte
            }

            return iv;
        }

        private string GetFileFromDialog()
        {
            Microsoft.Win32.OpenFileDialog openFileDialog = new Microsoft.Win32.OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                return openFileDialog.FileName;
            }
            return null;
        }

        private byte[] RC5EncryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            ushort[] S = RC5KeyExpansion(key);
            byte[] paddedData = PadData(data); // Apply padding

            byte[] encryptedData = new byte[paddedData.Length];
            byte[] previousBlock = iv;

            for (int i = 0; i < paddedData.Length; i += BlockSize)
            {
                byte[] block = paddedData.Skip(i).Take(BlockSize).ToArray();
                block = XORBlocks(block, previousBlock); // XOR with previous block (IV for the first block)
                byte[] encryptedBlock = RC5EncryptBlock(block, S);
                Array.Copy(encryptedBlock, 0, encryptedData, i, BlockSize);
                previousBlock = encryptedBlock; // Set for next round
            }

            return encryptedData;
        }

        private byte[] RC5DecryptCBC(byte[] encryptedData, byte[] key, byte[] iv)
        {
            ushort[] S = RC5KeyExpansion(key);
            byte[] decryptedData = new byte[encryptedData.Length];

            byte[] previousBlock = iv;
            for (int i = 0; i < encryptedData.Length; i += BlockSize)
            {
                byte[] block = encryptedData.Skip(i).Take(BlockSize).ToArray();
                byte[] decryptedBlock = RC5DecryptBlock(block, S);
                decryptedBlock = XORBlocks(decryptedBlock, previousBlock); // XOR with previous block (IV for first block)
                Array.Copy(decryptedBlock, 0, decryptedData, i, BlockSize);
                previousBlock = block; // For next round
            }

            return decryptedData;
        }

        private byte[] RC5EncryptBlock(byte[] block, ushort[] S)
        {
            ushort A = BitConverter.ToUInt16(block, 0);
            ushort B = BitConverter.ToUInt16(block, 2);

            unchecked
            {
                A = (ushort)(A + S[0]);
                B = (ushort)(B + S[1]);

                for (int i = 1; i <= Rounds; i++)
                {
                    int rotationA = B & (WordSize - 1);
                    A = (ushort)(LeftRotate((ushort)(A ^ B), rotationA) + S[2 * i]);

                    int rotationB = A & (WordSize - 1);
                    B = (ushort)(LeftRotate((ushort)(B ^ A), rotationB) + S[2 * i + 1]);
                }
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(BitConverter.GetBytes(A), 0, result, 0, 2);
            Array.Copy(BitConverter.GetBytes(B), 0, result, 2, 2);
            return result;
        }

        private byte[] RC5DecryptBlock(byte[] block, ushort[] S)
        {
            ushort A = BitConverter.ToUInt16(block, 0);
            ushort B = BitConverter.ToUInt16(block, 2);

            unchecked
            {
                for (int i = Rounds; i > 0; i--)
                {
                    int rotationB = A & (WordSize - 1);
                    B = (ushort)(RightRotate((ushort)(B - S[2 * i + 1]), rotationB) ^ A);

                    int rotationA = B & (WordSize - 1);
                    A = (ushort)(RightRotate((ushort)(A - S[2 * i]), rotationA) ^ B);
                }

                B = (ushort)(B - S[1]);
                A = (ushort)(A - S[0]);
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(BitConverter.GetBytes(A), 0, result, 0, 2);
            Array.Copy(BitConverter.GetBytes(B), 0, result, 2, 2);
            return result;
        }


        private ushort[] RC5KeyExpansion(byte[] key)
        {
            int u = WordSize / 8; // Word size is 2 bytes (16 bits)
            int c = KeyLengthBytes / u; // c is the number of words in the key
            ushort[] L = new ushort[c];

            // Convert key bytes into words
            for (int i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt16(key, i * u);
            }

            int t = 2 * (Rounds + 1);
            ushort[] S = new ushort[t];
            S[0] = 0xB7E1; // P for 16-bit words

            for (int i = 1; i < t; i++)
            {
                S[i] = (ushort)(S[i - 1] + 0x9E37); // Q for 16-bit words
            }

            ushort A = 0, B = 0;
            int i1 = 0, j = 0;
            int n = 3 * Math.Max(c, t);

            for (int k = 0; k < n; k++)
            {
                A = S[i1] = LeftRotate((ushort)(S[i1] + A + B), 3);
                B = L[j] = LeftRotate((ushort)(L[j] + A + B), (A + B) & (WordSize - 1));
                i1 = (i1 + 1) % t;
                j = (j + 1) % c;
            }

            return S;
        }

        private ushort LeftRotate(ushort value, int count)
        {
            count = count % WordSize;
            return (ushort)((value << count) | (value >> (WordSize - count)));
        }

        private ushort RightRotate(ushort value, int count)
        {
            count = count % WordSize;
            return (ushort)((value >> count) | (value << (WordSize - count)));
        }

        private byte[] PadData(byte[] data)
        {
            int paddingLength = BlockSize - (data.Length % BlockSize);
            if (paddingLength == 0) paddingLength = BlockSize; // Add a full block if already aligned

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, paddedData, data.Length);

            // Fill padding bytes with paddingLength value
            for (int i = data.Length; i < paddedData.Length; i++)
            {
                paddedData[i] = (byte)paddingLength; // Set all padding bytes to paddingLength
            }

            return paddedData;
        }

        private byte[] UnpadData(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentException("Data is empty or null.");
            }

            // Read the padding length from the last byte
            int paddingLength = data[data.Length - 1];

            // Validate padding length
            if (paddingLength < 1 || paddingLength > BlockSize || paddingLength > data.Length)
            {
                throw new InvalidOperationException("Invalid padding length.");
            }

            for (int i = 0; i < paddingLength; i++)
            {
                if (data[data.Length - 1 - i] != paddingLength)
                {
                    // Padding bytes are inconsistent
                    throw new InvalidOperationException("Decryption failed. Possible wrong passphrase or corrupted data.");
                }
            }

            // Create the unpadded array
            byte[] unpaddedData = new byte[data.Length - paddingLength];
            Array.Copy(data, unpaddedData, unpaddedData.Length);

            return unpaddedData;
        }

        private byte[] XORBlocks(byte[] blockA, byte[] blockB)
        {
            byte[] result = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
            {
                result[i] = (byte)(blockA[i] ^ blockB[i]);
            }
            return result;
        }

        private byte[] RC5EncryptECB(byte[] data, byte[] key)
        {
            ushort[] S = RC5KeyExpansion(key);
            byte[] encryptedBlock = RC5EncryptBlock(data, S);
            return encryptedBlock;
        }

        private byte[] RC5DecryptECB(byte[] encryptedData, byte[] key)
        {
            ushort[] S = RC5KeyExpansion(key);
            byte[] decryptedBlock = RC5DecryptBlock(encryptedData, S);
            return decryptedBlock;
        }
    }
}
