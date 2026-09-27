from typing import Optional,List
from dataclasses import dataclass
import base64
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

@dataclass
class MessageBlock:
    key_guid:bytes
    header:bytes
    initialization_vector:bytes
    encryption_message:bytes
    
    def is_valid(self)->bool:
        return self.header[1:]==b"\x00\x00\x00"

@dataclass
class EnvelopeMessage:
    magic:int
    integrity_length:int
    plaintext_length:int
    integrity:bytes
    plaintext:bytes

    @staticmethod
    def get_envelope_message(unpad_message:bytes)->Optional[EnvelopeMessage]:

        MSSQL_MAGIC_NUMBER = 0xBAADF00D

        magic,integrity_length,plaintext_length = struct.unpack_from("<IHH",unpad_message,0)

        if magic != MSSQL_MAGIC_NUMBER:
            return None

        if 8+integrity_length+plaintext_length != len(unpad_message):
            return None

        return EnvelopeMessage(
            magic=magic,
            integrity_length=integrity_length,
            plaintext_length=plaintext_length,
            integrity=unpad_message[8:8+integrity_length],
            plaintext=unpad_message[8+integrity_length:8+integrity_length+plaintext_length]
        )

@dataclass
class DecryptedMessage:
    message:Optional[str]
    is_tamper:bool
    is_tamper_check:bool


class MSSQLDecrypt:
    """
    Class to decrypt the message by EncryptByKey that use AES256 and base64 encoded
    """
    def __init__(self,key_source:str):
        self.__key_source = key_source

    def decrypt(self,\
                cipher_b64:str,\
                authenticator:bytes=None,\
                is_default_key_algorithm:bool=True)->Optional[DecryptedMessage]:
        """
        cipher_b64 = base64 encoded cipher text
        authenticator = seed that the message been encrypted with. Used in checking whether message have been tamper with
        is_default_key_algorithm = whether to use the possible default algorithm or search with all possible algorithm
        Return decrypted message or null on issue
        """
        blob = base64.b64decode(cipher_b64)

        message_block = self.__get_message_block(blob)

        if not message_block.is_valid():
            return DecryptedMessage(
                message=None,
                is_tamper=False,
                is_tamper_check=False
            )

        key_candiate:List[bytes] = self.__get_key(key_source=self.__key_source,\
                                                  is_default_key_algorithm=is_default_key_algorithm)

        for key in key_candiate:

            decryptor = None

            try:

                decryptor = Cipher(algorithms.AES(key),\
                                modes.CBC(message_block.initialization_vector)).decryptor()
            except Exception:
                continue

            encryption_block = decryptor.update(message_block.encryption_message) + decryptor.finalize()

            unpadded_envelope_message = self.__unpad_message(data=encryption_block)

            if unpadded_envelope_message is None:
                continue

            envelope_message = EnvelopeMessage.get_envelope_message(unpad_message=unpadded_envelope_message)

            if envelope_message is None:
                continue

            is_tamper = False

            is_tamper_check = False

            # additional check which verified whether the message been tamper proof
            if authenticator is not None and\
                envelope_message.integrity_length:

                is_tamper_check = True

                is_tamper = hashlib.sha1(envelope_message.plaintext+authenticator).digest() == envelope_message.integrity

            return DecryptedMessage(
                message=self.__decode_text(plaintext=envelope_message.plaintext),\
                is_tamper_check=is_tamper_check,
                is_tamper=is_tamper
            )
        
        return DecryptedMessage(
            message=None,
            is_tamper=False,
            is_tamper_check=False
        )

    def __decode_text(self,plaintext:bytes)->Optional[str]:
        if plaintext == b"":
            return None

        if len(plaintext)%2 == 0 and\
        len(plaintext) >=2 :
            odd_bytes = plaintext[1::2]

            zero_fraction = odd_bytes.count(0) / len(odd_bytes)

            if zero_fraction >= 0.7:
                try:
                    return plaintext.decode("utf-16-le")
                except UnicodeDecodeError:
                    pass

        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def __unpad_message(self,data:bytes,block_size:int=16)->Optional[bytes]:

        if not data or len(data)%block_size!=0:
            return None

        pad_len = data[-1]

        if pad_len < 1 or pad_len > block_size:
            return None

        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            return None

        return data[:-pad_len]
       
    def __get_key(self,key_source:str,is_default_key_algorithm:bool)->List[bytes]:
        """
        Since we do not know which 256 bit (32 byte) that Microsoft use to encode, we are going to try the possible key.
        is_default_key_algorithm = whether to just use possible key
        Return possible key
        """

        encoding = ["utf-8","utf-16-le"]

        key_candiate:List[bytes] = list()

        if is_default_key_algorithm:
            for enc in encoding:
                encoded = key_source.encode(enc)
                key_candiate.append(hashlib.sha512(encoded).digest()[:32])
        else:

            for enc in encoding:
                encoded = key_source.encode(enc)

                key_candiate.append(hashlib.sha256(encoded).digest())
                key_candiate.append(self.__expand(key_bytes=hashlib.sha256(encoded).digest(),\
                                                  hash_algorithm=hashlib.sha256)[:32])
                key_candiate.append(hashlib.sha384(encoded).digest()[:32])
                key_candiate.append(hashlib.sha512(encoded).digest()[:32])
                key_candiate.append(self.__expand(key_bytes=hashlib.sha1(encoded).digest(),\
                                                  hash_algorithm=hashlib.sha1)[:32])

        return key_candiate

    def __expand(self,key_bytes:bytes,hash_algorithm)->bytes:
        """
        stretching a hash to a longer key by XOR
        """
        buffer1 = bytearray(b"\x36" * 64)

        buffer2 = bytearray(b"\x5c" * 64)

        for index,byte in enumerate(key_bytes):
            buffer1[index] ^= byte
            buffer2[index] ^= byte

        return hash_algorithm(bytes(buffer1)).digest() + hash_algorithm(bytes(buffer2)).digest() 

    def __get_message_block(self,cipher_bytes:bytes)->MessageBlock:

        return MessageBlock(
            key_guid=cipher_bytes[0:16],
            header=cipher_bytes[16:20],
            initialization_vector=cipher_bytes[20:36],
            encryption_message=cipher_bytes[36:]
        )


