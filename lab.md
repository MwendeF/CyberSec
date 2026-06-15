# 🧪 Lab Challenges

I took **43rd place 🥇 in CyberGame 2025**  

The game featured challenges across multiple categories:
- Web Exploitation & Binary Exploitation  
- Forensics  
- OSINT (Open Source Intelligence)  
- Cryptography  
- Malware Analysis & Reverse Engineering  
- Process and Governance  
- PyJails _(JAILE series)_

---

## [★★☆] The Chronicles of Greg – SystemUpdate Incident
**Description:**  
Greg didn’t ask for this. Greg wanted a quiet Friday. Instead, he found suspicious logs pointing to a fake “SystemUpdate” binary.  

**Approach:**  
While reverse engineering the binary, I identified a suspicious subroutine performing XOR, subtraction, and negation operations on a 24-byte array.  
I wrote a Python script to emulate and reverse these operations.

**Solution Script (excerpt):**
```python
def solve():
    target = [int(x, 16) for x in "F9 FF 8F E0 EA C6 FE 2A CC 9D ...".split()]
    # decoding logic here
    print("SK-CERT{g3771ng_p4yl04d}")

if __name__ == "__main__":
    solve()
SK-CERT{g3771ng_p4yl04d}


## [★★☆] Jaile
---
# 🧩 CyberGames 2025 – Reverse Engineering Write-up

In this write-up I solved two series called **“Sanity Checker”** & **“Connection Checker”**, each consisting of 3 challenges.  
Let’s start with the first series **Sanity Checker**.

---

## [☆☆☆] SanityChecker — Sleepy Python

We are provided with a Python code:

```python
import time
import os

def deobfuscate1(string):
    mapping = {
        'a': 'n', 'b': 'o', 'c': 'p', 'd': 'q', 'e': 'r', 'f': 's', 'g': 't',
        'h': 'u', 'i': 'v', 'j': 'w', 'k': 'x', 'l': 'y', 'm': 'z',
        'n': 'a', 'o': 'b', 'p': 'c', 'q': 'd', 'r': 'e', 's': 'f', 't': 'g',
        'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm',

        'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T',
        'H': 'U', 'I': 'V', 'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z',
        'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G',
        'U': 'H', 'V': 'I', 'W': 'J', 'X': 'K', 'Y': 'L', 'Z': 'M',

        '0': '5', '1': '6', '2': '7', '3': '8', '4': '9',
        '5': '0', '6': '1', '7': '2', '8': '3', '9': '4',

        '_': '-', '-': '_'
    }
    return ''.join(mapping.get(c, c) for c in string)


def deobfuscate2(string):
    def reverse_alpha(c):
        if 'a' <= c <= 'z':
            return chr(ord('z') - (ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            return chr(ord('Z') - (ord(c) - ord('A')))
        return c

    digit_map = {str(i): str(9 - i) for i in range(10)}
    symbol_map = {'_': '=', '=': '_', '-': '+', '+': '-'}
    result = []
    for c in string:
        if c.isalpha():
            result.append(reverse_alpha(c))
        elif c in digit_map:
            result.append(digit_map[c])
        elif c in symbol_map:
            result.append(symbol_map[c])
        else:
            result.append(c)
    return ''.join(result)


def deobfuscate3(string):
    def reverse_char(c):
        if 'a' <= c <= 'z':
            return chr(ord('z') - (ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            return chr(ord('Z') - (ord(c) - ord('A')))
        elif '0' <= c <= '9':
            return str(9 - int(c))
        elif c == '_':
            return '*'
        elif c == '*':
            return '_'
        elif c == '-':
            return '!'
        elif c == '!':
            return '-'
        else:
            return c
    return ''.join(reverse_char(c) for c in string)
command2 = "./yby.fu #FX!PREG{5osh0p9265a*9aq*0y88c}"
SK-CERT{0bfu5c4710n_4nd_5l33p}
**This completes the Calculator series in CyberGame 2025**




# Remote Code Execution (RCE) via Arbitrary Command Injection in MCP Connection Endpoint

## Overview

During a security assessment, I identified a critical Remote Code Execution (RCE) vulnerability in an application's Model Context Protocol (MCP) connection API. The issue allowed an attacker to supply arbitrary executables and arguments through user-controlled JSON input, resulting in command execution on the underlying host system.

By abusing this functionality, an attacker could execute arbitrary operating system commands and ultimately gain interactive shell access to the server.

---

## Vulnerability Summary

| Attribute               | Value                                                                     |
| ----------------------- | ------------------------------------------------------------------------- |
| Vulnerability Type      | Remote Code Execution (RCE)                                               |
| Severity                | Critical                                                                  |
| Attack Complexity       | Low                                                                       |
| Authentication Required | No                                                                        |
| Impact                  | Full Server Compromise                                                    |
| CWE                     | CWE-78: Improper Neutralization of Special Elements Used in an OS Command |

---

## Technical Analysis

The vulnerable endpoint accepted a JSON payload containing MCP server configuration details. Users could specify both the executable (`command`) and its arguments (`args`).

Example request structure:

```json
{
  "serverConfig": {
    "type": "stdio",
    "command": "python3",
    "args": [
      "-c",
      "<attacker-controlled code>"
    ]
  },
  "serverId": "example"
}
```

The backend passed these values directly into a process creation function without validation or restrictions.

Conceptually, the application behaved similarly to:

```python
subprocess.Popen(
    [user_command] + user_args,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE
)
```

Because the executable path and arguments were fully user-controlled, attackers could invoke arbitrary programs available on the host.

---

## Proof of Concept

An attacker could specify a legitimate interpreter such as Python and provide malicious code through the argument list.

Example payload:

```json
{
  "serverConfig": {
    "type": "stdio",
    "command": "python3",
    "args": [
      "-c",
      "<arbitrary attacker code>"
    ]
  },
  "serverId": "malicious"
}
```

Successful exploitation resulted in arbitrary code execution under the privileges of the application service account.

---

## Impact

### Confidentiality

* Access to source code repositories
* Exposure of environment variables and secrets
* Database credential disclosure
* Access to customer and internal data

### Integrity

* Modification of application files
* Data tampering
* Deployment of malicious payloads
* Unauthorized administrative actions

### Availability

* Service disruption
* Resource exhaustion
* Malware deployment
* Internal network pivoting

---

## Root Cause

The vulnerability stemmed from a trust boundary violation:

1. User input directly controlled executable selection.
2. No allowlist or validation existed for permitted commands.
3. Process creation occurred without security restrictions.
4. Sensitive functionality lacked authentication and authorization controls.

---

## Remediation

### 1. Implement Command Allowlisting

Only permit approved MCP executables through a predefined lookup table.

Example:

```python
ALLOWED_MCP_COMMANDS = {
    "sqlite-mcp": "/usr/local/bin/mcp-sqlite",
    "postgres-mcp": "/usr/local/bin/mcp-postgres",
    "git-mcp": "/usr/local/bin/mcp-git"
}
```

Reject any command not explicitly defined in the allowlist.

---

### 2. Enforce Authentication and Authorization

* Require authenticated access to the MCP endpoint.
* Implement role-based access control (RBAC).
* Restrict MCP process creation to trusted administrative users.

---

### 3. Harden Runtime Isolation

* Run services as non-root users.
* Use container isolation (Docker, Kubernetes, Firecracker, etc.).
* Enable read-only root filesystems where possible.
* Apply the principle of least privilege.

Example Kubernetes security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
```

---

### 4. Apply Network Egress Controls

Restrict outbound connections to approved destinations only.

Recommended controls:

* Default-deny outbound firewall policy
* Explicit allowlists for required services
* Proxy-controlled external access
* Monitoring and alerting for unusual outbound traffic

---

## Key Takeaways

This vulnerability demonstrates the risks of exposing process execution functionality to user-controlled input. Even when shell metacharacters are not involved, allowing users to select arbitrary executables can lead directly to full remote code execution.

A combination of strict allowlisting, authentication, runtime isolation, and network controls is necessary to prevent exploitation and limit impact if a compromise occurs.

---

**Skills Demonstrated**

* API Security Assessment
* Remote Code Execution Discovery
* Threat Modeling
* Secure Code Review
* Process Execution Abuse Analysis
* Container and Infrastructure Hardening
* Vulnerability Reporting
