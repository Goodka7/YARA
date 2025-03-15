Step 1: I set up a VM to run the malware.

![image](https://github.com/user-attachments/assets/fb549f2e-09fd-43ca-918e-f61a575396ca)

Step 2: I ran a basic scan on my VM (YaraMalwareLab) to establish a baseline.

![image](https://github.com/user-attachments/assets/2476b59d-195d-402e-8266-50a3a0b3d600)


Step 3: I imported the YARA rule into Tenable so I can scan the VM for the malware.

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
