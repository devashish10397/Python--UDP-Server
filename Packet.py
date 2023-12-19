import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import RsaKey
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import zlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

"""
====================================================================
( 4 bytes ) Unique Packet ID for the checksummed binary
====================================================================
1
( 4 bytes ) Packet Sequence # (Total Checksums Processed)
====================================================================
( 2 bytes ) Multibyte Repeating XOR Key | ( 2 bytes ) # of Checksums
====================================================================
( Variable ) Repeating key XOR'd Cyclic Checksum CRC32 DWORDs
....
....
....
====================================================================
( 64 bytes ) RSA 512 SHA-256 Digital Signature (for above fields)
====================================================================
"""

class Packet:
    def __init__(self, data):
        self.packetData = data
        self.uniquePacketID = data[:4]
        self.packetSequence = data[4:8]
        self.xorKeyAndNumChecksums = data[8:12]
        self.cyclicChecksums = data[12:-64]  # Variable length
        self.digitalSignature = data[-64:]  # Last 64 bytes

    def display_fields(self):
        print("Unique Packet ID:", self.uniquePacketID)
        print("Packet Sequence:", self.packetSequence)
        print("XOR Key and Num Checksums:", self.xorKeyAndNumChecksums)
        print("Cyclic Checksums:", self.cyclicChecksums)
        print("Digital Signature:", self.digitalSignature)

    def verify_structural_integrity(self):
        expected_length = 4 * int.from_bytes(self.xorKeyAndNumChecksums[2:], byteorder='big')  # Calculate the expected length
        actual_length = len(self.cyclicChecksums)
        if actual_length != expected_length:
            return False
        else:
            return True
        
    def get_packet_data(self):
        return self.packetData

    def load_private_key(self, public_key_path):
        try:
            with open(public_key_path, "rb") as key_file:
                key_bytes = key_file.read()
            # Extract the modulus and exponent from the raw binary data
            modulus_length = struct.unpack("!H", key_bytes[:2])[0]
            modulus = int.from_bytes(key_bytes[2 : 2 + modulus_length], byteorder="big")
            exponent = int.from_bytes(key_bytes[2 + modulus_length :], byteorder="big")
            # Create an RSA key object using the modulus and exponent
            rsa_key = RsaKey(n=modulus, e=exponent)

            return rsa_key
        except Exception as e:
            print("load_public_key Exception:", e)

    #return mod and exp values
    def load_key(self, key_path):
        try:
            # Read the binary key data from the file
            with open(key_path, "rb") as key_file:
                key_data = key_file.read()

            # Define the modulus
            modulus_size = 512
            
            # Extract the modulus and exponent from the key data
            modulus_bytes = key_data[:modulus_size // 8]
            exponent_bytes = key_data[modulus_size // 8:]
            
            # Convert the modulus and exponent to integers
            modulus = int.from_bytes(modulus_bytes, byteorder="big")
            exponent = int.from_bytes(exponent_bytes, byteorder="big")
            return modulus, exponent
        except Exception as e:
            print("Error loading key:", e)
            return None

    def verify_signature(self, key_path):
        key = self.load_key(key_path)
        if key:
            key_modulus, key_exponent = key
            # Extract the data and signature from the packet
            data = self.packetData
            signature = self.digitalSignature

            # Create an RSA public key
            public_numbers = rsa.RSAPublicNumbers(key_exponent, key_modulus)
            # Create an RSAPublicKey object
            public_key = public_numbers.public_key(default_backend())
            

            try:
                # Create a verifier with the sender's public key
                verifier = public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                verifier.verify()
                print("Signature is valid. Data integrity is verified.")
                return True
            except:
                print("Signature verification failed. Data integrity check failed.")
                # If verification failed, get the expected hash
                received_hash = self.calculate_received_hash()
                # Calculate the received hash (SHA-256 hash of the received data)
                expected_hash = self.calculate_expected_hash()
                self.log_verification_failure(received_hash, expected_hash)
                return False
        else:
            print("Key is not present")
            return False

    
    def verify_checksum(self):
        received_crc32 = self.calculate_crc32()
        expected_crc32 = int.from_bytes(self.cyclicChecksums[-4:], byteorder='big')  # Assuming the last 4 bytes are the CRC32 value
        print(type(received_crc32), received_crc32)
        print(type(expected_crc32), expected_crc32)
        if received_crc32 == expected_crc32:
            print("why not here duffer")
            return True
        else:
            print("Why lord why?")
            self.log_checksum_failure(received_crc32, expected_crc32)
            return False
    
    def calculate_received_hash(self):
        try:
            # Calculate SHA-256 hash for the received packet data (excluding the signature)
            packet_data = self.packetData[:-64]  # Exclude the signature
            hasher = SHA256.new()
            hasher.update(packet_data)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Error calculating received hash: {str(e)}")
            return None

    def calculate_expected_hash(self):
        try:
            # Calculate SHA-256 hash for the data before it was signed
            packet_data_for_signature = self.packetData
            hasher = SHA256.new()
            hasher.update(packet_data_for_signature)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Error calculating expected hash: {str(e)}")
            return None
        
    def log_verification_failure(self, received_hash, expected_hash):
        packet_id_hex = hex(int.from_bytes(self.uniquePacketID, byteorder='big'))
        sequence_number = int.from_bytes(self.packetSequence, byteorder='big')

        log_entry = f"0x{packet_id_hex[2:]} ({packet_id_hex})\n{sequence_number}\n{received_hash}\n{expected_hash}\n"
        with open("verification_failures.log", "a") as log_file:
            log_file.write(log_entry)
    
    def log_checksum_failure(self, received_crc32, expected_crc32):
        packet_id_hex = hex(int.from_bytes(self.uniquePacketID, byteorder='big'))
        packet_sequence = int.from_bytes(self.packetSequence, byteorder='big')
        cyclic_checksum_iteration = int.from_bytes(self.xorKeyAndNumChecksums[2:], byteorder='big')  # 2 bytes for # of Checksums
        log_entry = (
            f"0x{packet_id_hex[2:]} (Packet ID - in hex)\n"
            f"{packet_sequence} (Packet sequence number)\n"
            f"{cyclic_checksum_iteration} (Cyclic checksum iteration)\n"
            f"{received_crc32:x} (Received CRC32)\n"
            f"{expected_crc32:x} (Expected CRC32)\n\n"
        )

        # Write the log to the file
        with open("checksum_failures.log", "a") as log_file:
            log_file.write(log_entry)
    
    def calculate_crc32(self):
        try:
            # Initialize the CRC32 checksum
            crc32_checksum = zlib.crc32(bytes([0xFF, 0xFF, 0xFF, 0xFF]))  # Initial value of 0xFFFFFFFF

            # Process the fields for CRC32 calculation
            crc32_checksum = zlib.crc32(self.uniquePacketID, crc32_checksum)
            crc32_checksum = zlib.crc32(self.packetSequence, crc32_checksum)
            crc32_checksum = zlib.crc32(self.xorKeyAndNumChecksums, crc32_checksum)

            # Ensure that cyclicChecksums is a byte sequence
            if not isinstance(self.cyclicChecksums, bytes):
                raise ValueError("cyclicChecksums should be a byte sequence")

            crc32_checksum = zlib.crc32(self.cyclicChecksums, crc32_checksum)

            # Finalize the CRC32 checksum by inverting the bits
            crc32_checksum = crc32_checksum ^ 0xFFFFFFFF

            return crc32_checksum

        except Exception as e:
            print(f"Error calculating CRC32 checksum: {str(e)}")
            return None
