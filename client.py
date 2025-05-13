from pymd5 import md5, padding

def perform_attack():
    # The original message and its MAC, intercepted from the insecure server
    original_message = b"amount=100&to=alice"

    # This MAC is what the server originally generated for the message
    # Copy this from the output of server_vulnerable.py
    original_mac = "614d28d808af46d3702fe35fae67267c"  # <- Update this if needed

    # This is the data we want to maliciously append
    data_to_append = b"&admin=true"

    # Length of the secret key used by the server (we assume it)
    guessed_key_length = 14  # Length of 'supersecretkey'

    # Total byte length of (key + original_message)
    total_len = guessed_key_length + len(original_message)

    # Compute the padding MD5 would internally add after the original message
    glue_padding = padding(total_len * 8)  # padding() expects bits, not bytes

    # This is the forged message we will send to the server
    forged_message = original_message + glue_padding + data_to_append

    # We initialize MD5 with the original MAC's internal state
    # Set count to the number of bits already hashed (key + message + padding)
    m = md5(state=bytes.fromhex(original_mac), count=(total_len + len(glue_padding)) * 8)

    # We now continue hashing as if we’re the original hash function
    m.update(data_to_append)

    # This is the forged MAC that matches the forged message
    forged_mac = m.hexdigest()

    # Output for debugging
    print("=== Length Extension Attack with pymd5 ===")
    print("Forged message:", forged_message)
    print("Forged MAC:", forged_mac)

    # Return the forged values to be passed to the server
    return forged_message, forged_mac

# Run the attack if this file is executed
if __name__ == "__main__":
    perform_attack()
