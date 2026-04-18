from encryption import decrypt_file, encrypt_with_generated_key
from sniffer import generate_sample_traffic

sample_data = b"mini soc smoke test"
encrypted, key = encrypt_with_generated_key(sample_data)
decrypted = decrypt_file(encrypted, key)
traffic = generate_sample_traffic(count=10)

print("Decryption successful:", decrypted == sample_data)
print("Traffic records generated:", len(traffic))
