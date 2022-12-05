
#Author : ElementalX
# A tool which encrypts your shellcode encrypts and prints the encrypted buffer.

$shellcode = "" #Insert your shellcode here.
# Generate a random key for AES encryption
$key = New-Object Byte[] 16
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)

# Create an instance of the AES algorithm
$aes = New-Object Security.Cryptography.AESCryptoServiceProvider

# Set the key and mode for the AES algorithm
$aes.Key = $key
$aes.Mode = [Security.Cryptography.CipherMode]::ECB

# Create a memory stream to hold the encrypted shellcode
$ms = New-Object IO.MemoryStream

# Create a cryptographic stream to encrypt the shellcode
$cs = New-Object Security.Cryptography.CryptoStream($ms, $aes.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Write)

# Convert the shellcode to a byte array
$shellcodeBytes = [System.Text.Encoding]::ASCII.GetBytes($shellcode)

# Write the shellcode to the cryptographic stream to encrypt it
$cs.Write($shellcodeBytes, 0, $shellcodeBytes.Length)
$cs.FlushFinalBlock()

# Convert the encrypted shellcode to a string of hexadecimal values in the \x format
$hexString = ""
foreach ($byte in $ms.ToArray()) {
    $hexString += "\x" + "{0:x2}" -f $byte
}

# Write the encrypted shellcode to a text file
$hexString | Out-File "encrypted_shellcode.txt"
