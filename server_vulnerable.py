#(UNCHANGED)!!
# Vulnerable server using insecure MAC = MD5(secret || message)

import hashlib

SECRET_KEY = b'supersecretkey'  # Hidden from attacker

def generate_mac(message: bytes) -> str:
    # Insecure MAC generation
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    # Verify message authenticity
    expected_mac = generate_mac(message)
    return mac == expected_mac

def main():
    # Legitimate message
    message = b"amount=100&to=alice"
    mac = generate_mac(message)

    print("=== Insecure Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")

    # Simulate attack
    from client import perform_attack
    forged_msg, forged_mac = perform_attack()

    print("\n--- Verifying forged message ---")
    if verify(forged_msg, forged_mac):
        print("MAC verified successfully (unexpected). Attack succeeded!")
    else:
        print("MAC verification failed. Attack blocked.")

if __name__ == "__main__":
    main()
