import hashlib
import time

from bitarray import bitarray
from electrum.gui.qt.wizard.virtual_token_utils.enrollment_utils import enrollmentUtils


class protocolUtils:

    def generate_f_double_circle(self, file_bytes: bytes, kc, d: int) -> bytes:
        """
        Generate f_double_circle by hashing the file content bytes, concatenating with omega,
        and using SHAKE-256.

        Args:
            file_bytes (bytes): The file content as bytes.
            kc (list): A list containing the omega and s bitarrays.
            d (int): The desired output size in bits.

        Returns:
            bytes: The generated f_double_circle as a byte sequence of length d // 8.
        """

        if not isinstance(kc, list) or len(kc) != 2 or not all(isinstance(k, bitarray) for k in kc):
            raise ValueError("kc must be a list containing two bitarrays.")

        print(f"[DEBUG generate_f_double_circle] Input type: {type(file_bytes)}")
        print(f"[DEBUG generate_f_double_circle] Input length: {len(file_bytes)}")
        print(f"[DEBUG generate_f_double_circle] First 32 bytes (hex): {file_bytes[:32].hex()}")
        print(f"[DEBUG generate_f_double_circle] Last 32 bytes (hex): {file_bytes[-32:].hex()}")

        # Hash the file content bytes
        h = hashlib.sha256()
        h.update(file_bytes)
        file_hash = h.hexdigest()
        print(f"[DEBUG generate_f_double_circle] SHA-256 of input: {file_hash}")

        # Convert digest to a bitarray
        digest = h.digest()
        h_bits = bitarray()
        h_bits.frombytes(digest)

        # Concatenate the hash with omega (kc[0])
        concatenated = h_bits + kc[0]
        concatenated_bytes = concatenated.tobytes()

        # Use SHAKE-256 to generate f_double_circle of length d // 8
        shake = hashlib.shake_256()
        shake.update(concatenated_bytes)
        f_double_circle = shake.digest(d // 8)  # Convert bits to bytes

        return f_double_circle


    def generate_challenges(self, s, D):
        """
        Generate a list of challenges from a given bitarray (s) and a challenge size (D).

        Args:
        s (bitarray): The input bitarray from which to generate challenges.
        D (int): The size of each challenge in bits.

        Returns:
        list: A list of challenges of size D (bitarrays).
        """

        if not isinstance(s, bitarray):
            raise ValueError("s must be a bitarray.")

        if D <= 0:
            raise ValueError("D must be a positive integer.")

        # Number of challenges to generate (256 + 1)
        num_challenges = 256 + 1
        #num_challenges = 256 # Not + 1 because we don't need any abstract for now
        total_bits = num_challenges * D
        total_bytes = (total_bits + 7) // 8  # Round up to the nearest byte

        # Convert s to bytes and hash it
        s_bytes = s.tobytes()
        shake = hashlib.shake_256()
        shake.update(s_bytes)

        # Generate a digest of length total_bytes
        digest = shake.digest(total_bytes)

        # Convert the digest to a binary string
        bit_string = ''.join(format(byte, '08b') for byte in digest)

        # Split the bit string into chunks of size D
        challenges = [bit_string[i:i+D] for i in range(0, len(bit_string), D)]

        return challenges

    def generate_responses(self, f_double_circle, challenges, alpha, beta, P, d):
        """
        Generate a list of bitarrays (responses) from the f_double_circle, challenges
        and linear congruent parameters.

        Args:
        f_double_circle (bytes): The input byte data (e.g., hash digest).
        challenges (list): A list of bit strings challenges.
        alpha (int): The multiplier parameter for the linear congruent RNG.
        beta (int): The increment parameter for the linear congruent RNG.
        P (int): The number of bits to collect from each response.
        d (int): The modulo parameter for the linear congruent RNG.

        Returns:
        list: A list of bitarrays responses.
        """
        # Convert challenges into a list of integers
        digits = [int(chunk, 2) for chunk in challenges]

        # Convert f_double_circle to a bitarray
        f_bits = bitarray()
        f_bits.frombytes(f_double_circle)

        responses = []

        # Loop through each challenge
        for i, digit in enumerate(digits):
            # Set the target response length: 256 bits for the first challenge, P bits for the rest
            target_length = 256 if i == 0 else P
            #target_length = P # We don't need any abstract for now

            # Generate positions using the linear congruent RNG
            positions = enrollmentUtils().linear_congruent_rng(alpha, beta, digit, target_length, d)

            # Generate the response bitarray
            response = bitarray()
            for j, pos in enumerate(positions):
                try:
                    if pos >= len(f_bits):
                        raise IndexError(f"Position {pos} is out of bounds for response {i}.")
                    response.append(f_bits[pos])
                    if len(response) == target_length:
                        break  # Stop if we reach the target length
                except IndexError as e:
                    print(f"Error at digit {i}, position {j}: {e}")
                    continue

            responses.append(response)

        return responses

    def hash_key(self, key):
        if isinstance(key, str):
            key = key.encode("utf-8")
        elif isinstance(key, bitarray):
            key = key.tobytes()

        return hashlib.sha3_256(key).hexdigest()

    def log_timing(self, start_time, message):
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"{message} took: {elapsed_time:.6f} seconds")
        return elapsed_time
