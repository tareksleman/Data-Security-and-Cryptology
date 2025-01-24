import hashlib
import hmac
import os

def generate_mac(padded_message):

        # generate random key
        mac_key = os.urandom(16)
        if isinstance(mac_key, str):
            mac_key = mac_key.encode('utf-8')
        if isinstance(padded_message, str):
            padded_message = padded_message.encode('utf-8')
    
        hmac_calculated = hmac.new(mac_key, padded_message, hashlib.sha256)
        return mac_key, hmac_calculated.digest()


def verify_mac(Dec_Data, mac, mac_key):
        if isinstance(mac_key, str):
            mac_key = mac_key.encode('utf-8')
        if isinstance(Dec_Data, str):
            Dec_Data = Dec_Data.encode('utf-8')
        hmac_calculated = hmac.new(mac_key, Dec_Data, hashlib.sha256)
        hmac_digest = hmac_calculated.digest()
        print("Mac for the decrypted image:",hmac_digest)
        if hmac.compare_digest(mac, hmac_digest):
            print("\nMAC verification successful.")
        else:
            print("\nMAC verification failed.")
            
            