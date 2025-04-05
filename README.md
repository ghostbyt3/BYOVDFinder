# BYOVDFinder
BYOVDFinder helps you check which drivers from loldrivers.io are not blocked by the current HVCI (Hypervisor Code Integrity) blocklist on your system. This is particularly useful for BYOVD (Bring Your Own Vulnerable Driver) attacks where attackers try to load drivers that should have been blocked by HVCI.

### Why HVCI Blocks Drivers?
HVCI is a security feature in Windows that helps protect against attacks like kernel exploits by verifying the integrity of code running at the kernel level. It blocks drivers that are unsigned or known to be malicious by checking them against an internal blocklist. If a driver is not recognized, it will be blocked to prevent possible exploitation.

### Requirements
- Python 3.x
- `driversipolicy.p7b` file containing HVCI blocklist data

### Usage

**Step 1: Extract driversipolicy.p7b to XML**
- To extract the `driversipolicy.p7b` file into XML format, you can use the script from [Mattifestation](https://gist.github.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e)'s Gist.
```powershell
IEX(New-Object net.WebClient).DownloadString("https://gist.githubusercontent.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e/raw/a9b55d31075f91b467a8a37b9d8b2d84a0aa856b/CIPolicyParser.ps1")
ConvertTo-CIPolicy -BinaryFilePath 'C:\Windows\System32\CodeIntegrity\driversipolicy.p7b' -XmlFilePath (Join-Path $env:USERPROFILE 'Desktop\driversipolicy.xml')
```

Alternatively, you can get the Microsoft Vulnerable Driver Blocklist XML directly from [Microsoft's Vulnerable Driver Blocklist page](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml). Copy the XML contents and use it directly without the need to parse the .p7b file.

**Step 2: Run the Python Script**
- After extracting the `driversipolicy.p7b` file to XML format, run the Python script with the following command:
```bash
python3 finder.py driversipolicy.xml
```

### Output

```bash
$ python3 finder.py driversipolicy.xml

      _____   _______   _____  ___ _         _         
     | _ ) \ / / _ \ \ / /   \| __(_)_ _  __| |___ _ _ 
     | _ \\ V / (_) \ V /| |) | _|| | ' \/ _` / -_) '_|
     |___/ |_| \___/ \_/ |___/|_| |_|_||_\__,_\___|_|  
                                                       
DRIVER: <driver>.sys
  Link: https://www.loldrivers.io/drivers/<id>
  MD5: <hash>
  SHA1: <hash>
  SHA256: <hash>
--------------------------------------------------------------------------------
DRIVER: <driver>.sys
  Link: https://www.loldrivers.io/drivers/<id>
  MD5: <hash>
  SHA1: <hash>
  SHA256: <hash>
--------------------------------------------------------------------------------

[::]

[+] Number of Blocked Drivers: XXXX
[+] Number of Allowed Drivers: XX

```
- Retrieves the latest list of Bring Your Own Vulnerable Driver (BYOVD) entries from loldrivers.io API, including hashes, signatures, and exploitation metadata.
- Parses Microsoft's Hypervisor-Protected Code Integrity (HVCI) policy XML to detect which vulnerable drivers are actively blocked by hash or certificate rules, providing clear allow/block classification.
- Cross-checks driver hashes (MD5/SHA1/SHA256) and certificates from loldrivers.io against deny rules in HVCI policy XML to identify vulnerable drivers that are not blocked.


