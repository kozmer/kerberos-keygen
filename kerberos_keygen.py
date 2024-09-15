#!/usr/bin/env python3

# https://snovvcrash.rocks/2021/05/21/calculating-kerberos-keys.html

import argparse
from binascii import unhexlify, hexlify, Error
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key, Key
from Cryptodome.Hash import MD4

CIPHERS = {
    'rc4_hmac': constants.EncryptionTypes.rc4_hmac.value,
    'aes128_cts_hmac_sha1': constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
    'aes256_cts_hmac_sha1': constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
    'des_cbc_md5': constants.EncryptionTypes.des_cbc_md5.value
}

def generate_kerberos_keys(password: bytes, salt: bytes) -> dict:
    """Generate AES, RC4, and DES Kerberos keys and return them as a dictionary."""
    fixed_password = password.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
    keys = {}

    for name, cipher in CIPHERS.items():
        if cipher == constants.EncryptionTypes.rc4_hmac.value:
            md4 = MD4.new()
            md4.update(password)
            key = Key(cipher, md4.digest())
        else:
            key = string_to_key(cipher, fixed_password, salt)
        keys[name] = hexlify(key.contents).decode("utf-8")

    return keys

def process_kerberos_keys(domain: str, account_name: str, password: str, is_machine: bool) -> None:
    """Generate and print AES, RC4, and DES Kerberos keys for both machine and user accounts."""
    salt = (f'{domain.upper()}host{account_name.rstrip("$").lower()}.{domain.lower()}' if is_machine 
            else f'{domain.upper()}{account_name}').encode('utf-8')
    
    try:
        raw_password = unhexlify(password) if is_machine else password.encode('utf-16-le')
    except Error:
        raw_password = password.encode('utf-16-le')

    print(f'[*] Input username             : {account_name}')
    print(f'[*] Input password             : {password}')
    print(f'[*] Input domain               : {domain}')
    print(f'[*] Salt                       : {salt.decode("utf-8")}')

    keys = generate_kerberos_keys(raw_password, salt)

    for name, key in keys.items():
        print(f'[*]       {name:<20} : {key}')

def main() -> None:
    """Parse arguments and determine if the target is a machine or user account."""
    parser = argparse.ArgumentParser(description="Generate AES, RC4, and DES Kerberos keys for users or machines")
    parser.add_argument('-d', '--domain', required=True, help="The domain (e.g. EXAMPLE.COM)")
    parser.add_argument('-u', '--username', required=True, help="The username (e.g. user1 or hostname$ for machines). "
                                                                "Note: Usernames are case-sensitive and will affect the outputted keys.")
    parser.add_argument('-p', '--password', required=True, help="The password for the user or machine (plain text or hex for machines)")

    args = parser.parse_args()

    is_machine = args.username.endswith('$')
    process_kerberos_keys(args.domain, args.username, args.password, is_machine)

if __name__ == '__main__':
    main()