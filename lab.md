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
