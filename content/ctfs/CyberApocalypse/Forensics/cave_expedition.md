---
title: Cave Expedition
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Forensics
date: 2025-03-24T00:00:00Z
---
Rumors of a black drake terrorizing the fields of Dunlorn have spread far and wide. The village has offered a hefty bounty for its defeat. Sir Alaric and Thorin answered the call also returning with treasures from its lair. Among the retrieved items they found a map. Unfortunately it cannot be used directly because a custom encryption algorithm was probably used. Luckily it was possible to retrieve the original code that managed the encryption process. Can you investigate about what happened and retrieve the map content?

In the context of a forensic analysis of a ransomware incident, the execution of Base64-encoded PowerShell scripts that encrypted the victim's files with a .secured extension was detected. The procedure followed to decrypt and recover these files is documented below.

**Initial analysis (Event Log EVTX)**  
  
From the `.evtx` file, specifically from the Sysmon event with `EventID=1`, a fragment of a Base64 encoded PowerShell script was retrieved:  

```powershell
powershell -c "'bnVsbCAtb3IgJHQ5MFZ2Lkxlbmd0aCAtZXEgMCkgew0KICAgICAgICByZXR1cm4gJG51bGwNCiAgICB9DQoNCiAgICAkeTkwVmEgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR1MTJWdykNCiAgICAkejEyVmIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpVVEY4LkdldEJ5dGVzKCR2MzRWeCkNCiAgICAkYTM0VmMgPSBsMzRWbiAkdDkwVnYgJHk5MFZhICR6MTJWYg0KDQogICAgcmV0dXJuIFtDb252ZXJ0XTo6VG9CYXNlNjRTdHJpbmcoJGEzNFZjKQ0KfQ0KDQpmdW5jdGlvbiBvMTJWcSB7DQogICAgcGFyYW0oW3N3aXRjaF0kcDM0VnIpDQoNCiAgICB0cnkgew0KICAgICAgICBpZiAoJHAzNFZyKSB7DQogICAgICAgICAgICBmb3JlYWNoICgkcTU2' | Out-File -Encoding ascii -FilePath b -Append -NoNewline"  
```
  
Decoding this content in Base64 revealed that it was part of a script to encrypt files using XOR.  
  
**Extraction of keys and functions of the ransomware**  
  
After decoding all the fragments of the EVTX event, the complete script was obtained with the encryption keys included in Base64 format:  
  
Identified keys:  

```shell
$key1 = "NXhzR09iakhRaVBBR2R6TGdCRWVJOHUwWVNKcTc2RWl5dWY4d0FSUzdxYnRQNG50UVk1MHlIOGR6S1plQ0FzWg=="  
$key2 = "n2mmXaWy5pL4kpNWr7bcgEKxMeUx50MJ"
```
  
Decoding of the keys:  
  
- key1 (Base64) → UTF-8 string 
- key2 (Base64) → UTF-8 string  
  
These keys were used in an XOR cipher combined with Base64.  
  
**Encryption algorithm identified (XOR + Base64)**  
  
The encryption function was reconstructed in PowerShell from the parsed fragments, revealing the following encryption method:  
- The original file is read as bytes.  
- The bytes are XOR encrypted using the two keys (key1, key2).  
- The result of the encryption is encoded in Base64.  
- The original file is replaced with its encrypted version, with the extension .secured.  

  
Reconstruction of the decryption script (solution)  
  
Using the recovered information, a simplified script was developed to decrypt all affected files:  
  
Final decryptor (`decrypt.ps1`):  

```powershell
function XOR-Decrypt($base64EncryptedData, $keyA, $keyB) {  
	$encryptedBytes = [Convert]::FromBase64String($base64EncryptedData)  
	$keyABytes = [System.Text.Encoding]::UTF8.GetBytes($keyA)  
	$keyBBytes = [System.Text.Encoding]::UTF8.GetBytes($keyB)  
	$decryptedBytes = New-Object byte[] ($encryptedBytes.Length)  
	  
	for ($i = 0; $i -lt $encryptedBytes.Length; $i++) {  
		$decryptedBytes[$i] = $encryptedBytes[$i] -bxor $keyABytes[$i % $keyABytes.Length] -bxor $keyBBytes[$i % $keyBBytes.Length]  
	}  
	return $decryptedBytes  
}  
```

Direct execution on encrypted files:

```powershell
Get-ChildItem -Path "D:\forensics_cave_expedition" -Filter "*.secured" -Recurse | ForEach-Object {  
$encryptedContent = [IO.File]::ReadAllText($_.FullName)  
$decryptedContent = XOR-Decrypt $encryptedContent $keyA $keyB  
  
$originalFileName = $_.FullName -replace '\.secured$', ''  
[IO.File]::WriteAllBytes($originalFileName, $decryptedContent)  
```

Delete encrypted file after recovery:

```powershell
Remove-Item $_.FullName -Force 
```
  
**Execution and results**  
  
The script was executed on the compromised path:  

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\decrypt.ps1  
```