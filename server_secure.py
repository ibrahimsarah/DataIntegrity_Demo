# Secure server using HMAC to prevent length extension attacks

import hmac
import hashlib

SECRET_KEY = b'supersecretkey'

def generate_mac(message: bytes) -> str:
    # Secure MAC generation using HMAC
    return hmac.new(SECRET_KEY, message, hashlib.md5).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return mac == expected_mac

def main():
    message = b"amount=100&to=alice"
    mac = generate_mac(message)

    print("=== Secure Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")

    # Try forged message (will fail)
    forged_message = message + b"&admin=true"
    forged_mac = mac  # Reusing the old MAC should fail

    print("\n--- Verifying forged message ---")
    if verify(forged_message, forged_mac):
        print("MAC verified successfully (unexpected).")
    else:
        print("MAC verification failed. Attack prevented!")

if __name__ == "__main__":
    main()
