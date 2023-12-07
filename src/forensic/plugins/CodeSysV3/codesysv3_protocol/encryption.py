class CodeSysV3Encryption:
    ENC_ARRAY = [0x7A, 0x65, 0x44, 0x52, 0x39, 0x36, 0x45, 0x66, 0x55, 0x23, 0x32, 0x37, 0x76, 0x75, 0x70, 0x68,
                     0x37, 0x54, 0x68, 0x75, 0x62, 0x3F, 0x70, 0x68, 0x61, 0x44, 0x72, 0x2A, 0x72, 0x55, 0x62, 0x52]
    PASSWORD_MIN_SIZE = 32
    CHALLENGE = 0x12345678

    @staticmethod
    def hash_password(challenge:int, password: str):
        password_len = len(password)
        full_password_len = password_len
        if CodeSysV3Encryption.PASSWORD_MIN_SIZE <= password_len + 1:
            if full_password_len & 3:
                full_password_len += 4 - (full_password_len & 3)
        else:
            full_password_len = CodeSysV3Encryption.PASSWORD_MIN_SIZE

        challenge_array = bytearray(challenge.to_bytes(4, "little"))
        challenge_array[1] = 0
        challenge_array[2] = 0
        challenge_array[3] = 0
        crypto_password_char_index = 0
        loop_index = 0

        new_hashed_password = bytearray(32)

        while loop_index < full_password_len:
            current_crypto_hash_char = CodeSysV3Encryption.ENC_ARRAY[crypto_password_char_index]

            if loop_index >= password_len:
                current_password_char = 0
            else:
                current_password_char = ord(password[loop_index])

            crypto_password_char_index = (crypto_password_char_index + 1) % 33

            challenge_char = (challenge_array[loop_index % 4] + current_crypto_hash_char) & 0xff
            new_hashed_password[loop_index] = current_password_char ^ challenge_char
            loop_index += 1

        return new_hashed_password