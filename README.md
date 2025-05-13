# DataIntegrity_Demo
# Length Extension Attack and HMAC Mitigation

## Overview

This project demonstrates a **Message Authentication Code (MAC) forgery attack** using a **Length Extension Attack** against an insecure implementation (`MAC = hash(secret || message)`), and how switching to **HMAC** effectively prevents it.

---

## Part 1: Insecure Implementation – Vulnerable Server

File: 'server_vulnerable.py'
- Generates a MAC using:
    -hashlib.md5(secret + message)

    - Simulates a server that verifies messages using this weak construction.
    - Calls perform_attack() from client.py to demonstrate forgery.

 - Expected output:
     -MAC verified successfully (unexpected). Attack succeeded!

   
## Part 2: Forgery via Length Extension Attack

File: 'client.py'
  - Uses a custom implementation of MD5 (pymd5.py) to:
     - Forge a new message: original_message + padding + &admin=true
     - Recreate the internal MD5 state from a known MAC
     - Continue hashing appended data without knowing the secret key

- Parameters used:
    - Original message: amount=100&to=alice
    - Original MAC: 614d28d808af46d3702fe35fae67267c
    - Guessed key length: 14
    - Appended data: &admin=true

- Output:
   - Forged message: b'amount=100&to=alice...[padding]...&admin=true'
   - Forged MAC: 97312a73075b6e1589117ce55e0a3ca6

  
## Part 3: Secure Implementation with HMAC

File: 'server_secure.py'

 - Replaces weak MAC generation with a secure version using HMAC:
   hmac.new(secret, message, hashlib.md5).hexdigest()
 - Verifies that forged messages are rejected
 - Expected output:
   MAC verification failed. Attack prevented!
   
Files Included :
| File                   | Description                                              |
| ---------------------- | -------------------------------------------------------- |
| `server_vulnerable.py` | Insecure server using raw MD5                            |
| `server_secure.py`     | Secure server using HMAC                                 |
| `client.py`            | Forgery attack script                                    |
| `pymd5.py`             | Custom MD5 class to simulate internal state manipulation |
| `background.pdf`       | Explanation of MAC and Length Extension Attack           |
| `mitigation.pdf`       | Why HMAC mitigates the attack                            |


## Conclusion

This project shows that:
  - Naively implementing MAC = hash(secret || message) is insecure.
  - Length Extension Attacks can forge valid MACs without knowing the key.

    Using HMAC properly prevents this class of attacks and ensures secure authentication.
