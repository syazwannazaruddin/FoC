import csv
import os
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RUNS = 10
LFSR_SEED = 10296
REGISTER_WIDTH = 16
TAP_POSITIONS = (0, 2, 3, 5)
AES_KEY = AESGCM.generate_key(bit_length=256)
NONCE_SIZE = 12

TEST_FILES = {
    "1 KB": 1024,
    "100 KB": 102400,
    "1 MB": 1048576,
}


class LFSR:
    def __init__(self, seed):
        if not 0 < seed < (1 << REGISTER_WIDTH):
            raise ValueError("Seed must be a non-zero 16-bit integer.")
        self.state = seed

    def next_bit(self):
        output_bit = self.state & 1
        feedback = 0

        for tap in TAP_POSITIONS:
            feedback ^= (self.state >> tap) & 1

        self.state = (self.state >> 1) | (feedback << (REGISTER_WIDTH - 1))
        return output_bit

    def next_byte(self):
        value = 0

        for bit_position in range(8):
            value |= self.next_bit() << bit_position

        return value


def lfsr_xor(data):
    """LFSR encryption and decryption use the same XOR function."""
    lfsr = LFSR(LFSR_SEED)
    return bytes(value ^ lfsr.next_byte() for value in data)


def aes_encrypt(data):
    """Encrypt data using AES-256-GCM."""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext_with_tag = AESGCM(AES_KEY).encrypt(nonce, data, None)

    # Store nonce together with ciphertext and authentication tag.
    return nonce + ciphertext_with_tag


def aes_decrypt(encrypted_data):
    """Decrypt AES-256-GCM encrypted data."""
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext_with_tag = encrypted_data[NONCE_SIZE:]

    return AESGCM(AES_KEY).decrypt(nonce, ciphertext_with_tag, None)


def create_test_files():
    """Create random 1 KB, 100 KB, and 1 MB files."""
    test_data = {}

    for label, size in TEST_FILES.items():
        filename = Path(f"test_{label.replace(' ', '')}.bin")
        data = os.urandom(size)

        filename.write_bytes(data)
        test_data[label] = data

        print(f"Created {filename}: {size:,} bytes")

    return test_data


def benchmark_algorithm(name, data, encrypt_function, decrypt_function):
    """Measure encryption and decryption time in milliseconds."""

    # Warm-up run. This result is not recorded.
    warm_ciphertext = encrypt_function(data)

    if decrypt_function(warm_ciphertext) != data:
        raise ValueError(f"{name} failed the warm-up decryption check.")

    encryption_times = []
    decryption_times = []

    for _ in range(RUNS):
        start = time.perf_counter_ns()
        ciphertext = encrypt_function(data)
        encryption_time = (time.perf_counter_ns() - start) / 1_000_000
        encryption_times.append(encryption_time)

        start = time.perf_counter_ns()
        decrypted = decrypt_function(ciphertext)
        decryption_time = (time.perf_counter_ns() - start) / 1_000_000
        decryption_times.append(decryption_time)

        if decrypted != data:
            raise ValueError(f"{name} failed the decryption check.")

    return (
        statistics.mean(encryption_times),
        statistics.stdev(encryption_times),
        statistics.mean(decryption_times),
        statistics.stdev(decryption_times),
    )


def main():
    test_data = create_test_files()
    rows = []

    print(f"\nBenchmark settings: {RUNS} timed runs, file I/O excluded")
    print("All decrypted outputs must match the original files.\n")

    for label, data in test_data.items():
        algorithms = [
            ("LFSR", lfsr_xor, lfsr_xor),
            ("AES-256-GCM", aes_encrypt, aes_decrypt),
        ]

        for algorithm_name, encrypt_function, decrypt_function in algorithms:
            enc_avg, enc_std, dec_avg, dec_std = benchmark_algorithm(
                algorithm_name,
                data,
                encrypt_function,
                decrypt_function,
            )

            throughput = (len(data) / (1024 * 1024)) / (enc_avg / 1000)

            print(
                f"{algorithm_name:12} | {label:6} | "
                f"Encrypt: {enc_avg:.3f} ms | "
                f"Decrypt: {dec_avg:.3f} ms | PASS"
            )

            rows.append({
                "Algorithm": algorithm_name,
                "File size": label,
                "Bytes": len(data),
                "Encryption average ms": f"{enc_avg:.3f}",
                "Encryption std dev ms": f"{enc_std:.3f}",
                "Decryption average ms": f"{dec_avg:.3f}",
                "Decryption std dev ms": f"{dec_std:.3f}",
                "Encryption throughput MB/s": f"{throughput:.3f}",
                "Decryption correct": "PASS",
            })

    with open("benchmark_results.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("\nSaved results to benchmark_results.csv")


if __name__ == "__main__":
    main()