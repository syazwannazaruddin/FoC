"""

This program demonstrates keystream generation and XOR encryption. A basic
LFSR is not suitable for protecting real confidential data.
"""

import argparse
import secrets
from pathlib import Path


REGISTER_WIDTH = 16
# Tap bit positions for this right-shift Fibonacci LFSR implementation.
TAP_POSITIONS = (0, 2, 3, 5)


class LFSR:
    """Generate a keystream from a non-zero 16-bit seed."""

    def __init__(self, seed: int, width: int = REGISTER_WIDTH):
        # __init__ runs when an LFSR object is created. It checks that the
        # seed is a valid non-zero value, then stores the seed as the current
        # register state. A zero seed is not allowed because it would only
        # produce zero output bits.
        if not 0 < seed < (1 << width):
            raise ValueError(f"Seed must be a non-zero {width}-bit integer.")
        self.state = seed
        self.width = width

    def next_bit(self) -> int:
        """Shift the register once and return one output bit."""
        # next_bit produces one keystream bit. First, it reads the current
        # output bit. Next, it combines the selected tap bits using XOR to
        # create a feedback bit. Finally, it shifts the register and inserts
        # the feedback bit at the left side.
        output_bit = self.state & 1
        feedback = 0
        for tap in TAP_POSITIONS:
            feedback ^= (self.state >> tap) & 1

        self.state = (self.state >> 1) | (feedback << (self.width - 1))
        return output_bit

    def next_byte(self) -> int:
        """Combine eight generated bits into one keystream byte."""
        # next_byte calls next_bit eight times. The eight generated bits are
        # joined together to form one byte, which is used by the XOR process.
        value = 0
        for bit_position in range(8):
            value |= self.next_bit() << bit_position
        return value


def lfsr_xor(data: bytes, seed: int) -> bytes:
    """Encrypt or decrypt data by XORing it with the LFSR keystream."""
    # lfsr_xor creates a new LFSR using the given seed. It generates one
    # keystream byte for every data byte, then uses XOR to combine them.
    # The same function works for encryption and decryption because XORing
    # the ciphertext with the same keystream returns the original plaintext.
    lfsr = LFSR(seed)
    return bytes(byte ^ lfsr.next_byte() for byte in data)


def generate_seed() -> int:
    """Generate a random non-zero seed for this educational demonstration."""
    return secrets.randbelow((1 << REGISTER_WIDTH) - 1) + 1


def run_demo(seed: int | None) -> None:
    """Run the message demonstration required for Part A1."""
    message = b"Hello, this is our LFSR project."
    seed = generate_seed() if seed is None else seed
    ciphertext = lfsr_xor(message, seed)
    decrypted = lfsr_xor(ciphertext, seed)

    print(f"Seed: {seed}")
    print(f"Plaintext: {message.decode()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Decrypted: {decrypted.decode()}")
    print("Result:", "PASS" if decrypted == message else "FAIL")


def process_file(input_path: Path, output_path: Path, seed: int) -> None:
    """Encrypt or decrypt one file. The same function works for both actions."""
    data = input_path.read_bytes()
    output_path.write_bytes(lfsr_xor(data, seed))
    print(f"Input file: {input_path}")
    print(f"Output file: {output_path}")
    print(f"File size: {len(data)} bytes")
    print(f"Seed: {seed}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Educational LFSR stream cipher")
    subparsers = parser.add_subparsers(dest="command")

    demo_parser = subparsers.add_parser("demo", help="Encrypt and decrypt a sample message")
    demo_parser.add_argument("--seed", type=int, help="Optional non-zero 16-bit seed")

    for command_name in ("encrypt-file", "decrypt-file"):
        file_parser = subparsers.add_parser(command_name, help=f"{command_name.replace('-', ' ')}")
        file_parser.add_argument("input", type=Path, help="Input file path")
        file_parser.add_argument("output", type=Path, help="Output file path")
        file_parser.add_argument("--seed", type=int, required=True, help="Non-zero 16-bit seed")

    args = parser.parse_args()

    if args.command in (None, "demo"):
        run_demo(getattr(args, "seed", None))
    else:
        process_file(args.input, args.output, args.seed)


if __name__ == "__main__":
    main()
