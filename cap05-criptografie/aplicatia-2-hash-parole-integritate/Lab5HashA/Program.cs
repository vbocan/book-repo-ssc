using System.Numerics;
using System.Security.Cryptography;
using System.Text;

string msg1 = "Securitatea sistemelor de calcul";
string msg2 = "securitatea sistemelor de calcul"; // doar prima literă diferă

byte[] hash1 = SHA256.HashData(Encoding.UTF8.GetBytes(msg1));
byte[] hash2 = SHA256.HashData(Encoding.UTF8.GetBytes(msg2));

Console.WriteLine($"Hash 1: {Convert.ToHexString(hash1)}");
Console.WriteLine($"Hash 2: {Convert.ToHexString(hash2)}");

// Distanța Hamming: câți biți diferă între cele două rezumate
int differentBits = 0;
for (int i = 0; i < hash1.Length; i++)
    differentBits += BitOperations.PopCount((uint)(hash1[i] ^ hash2[i]));

int totalBits = hash1.Length * 8;
Console.WriteLine($"Biți diferiți: {differentBits} din {totalBits} ({100.0 * differentBits / totalBits:F1}%)");
