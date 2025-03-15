Step 1: I set up a VM to run the malware.

![image](https://github.com/user-attachments/assets/fb549f2e-09fd-43ca-918e-f61a575396ca)

Step 2: Create a new scan for Tenable and import the .yar file.

![image](https://github.com/user-attachments/assets/c9338422-7665-4e5d-bf62-3bbb69c610a4)
![image](https://github.com/user-attachments/assets/f89dede8-f626-4ec7-8358-46bbdb30f722)
![image](https://github.com/user-attachments/assets/1640f770-f2ee-4f0f-9d11-f43e98ae121f)
![image](https://github.com/user-attachments/assets/eb79fce6-40e5-4dfa-b454-a25fa3ed7d73)
![image](https://github.com/user-attachments/assets/b004cfb2-9766-4779-a9d8-2345631c4a9b)
![image](https://github.com/user-attachments/assets/b887360f-7e0c-4e2a-926a-f8883e85fbe8)
![image](https://github.com/user-attachments/assets/c3401cef-ffdb-4918-bc46-fc27997cdcd4)
![image](https://github.com/user-attachments/assets/ce631038-8dd5-4e72-b028-b92ff13f6c5f)
![image](https://github.com/user-attachments/assets/7b398c4d-a50a-401b-af65-939fc890d461)
![image](https://github.com/user-attachments/assets/09ae4596-fc9f-4b7e-b80e-55c424bafd2f)
![image](https://github.com/user-attachments/assets/d087ec2e-bd16-4890-b393-1c17addfa51f)


Step 3: I ran a baseline scan to show that the machine was not infected.

Wannacry YARA Rule:

```
rule WannaCry_Ransomware

{
    meta:
        description = "Detects WannaCry ransomware based on known indicators"
        author = "James Harrington"
        date = "2025-03-15"
        reference = "https://www.wannacry.com"
        malware_family = "Ransom.WannaCry"
    
       strings:
      // Core WannaCry identifiers
      $s1 = "WannaDecryptor" nocase
      $s2 = "WNcry@2ol7" nocase
      $s3 = "Please Read Me.txt" nocase
      $s4 = "Ooops, your files have been encrypted!" nocase
      $s5 = "bprv.dll"  // WannaCry component
      $s6 = "tasksche.exe" // WannaCry process name
      $s7 = "mssecsvc.exe" // Exploit component
      
      // Additional key WannaCry behavior
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x3 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii // Kill-switch domain
      
      // Network spreading indicators
      $net1 = "\\\\192.168.56.20\\IPC$" fullword wide
      $net2 = "\\\\172.16.99.5\\IPC$" fullword wide
      
      // Hex patterns from WannaCry executable
      $h1 = { 57 6F 72 6C 64 20 62 61 63 6B 75 70 20 64 65 63 72 79 70 74 6F 72 }
      $h2 = { 77 63 72 79 70 74 2E 64 65 63 }
   
   condition:
      uint16(0) == 0x5a4d and filesize < 10MB and 
      (any of ($s*) or any of ($x*) or any of ($h*))
}

```
