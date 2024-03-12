from PyKCS11 import *
import binascii


pkcs11 = PyKCS11Lib()        
pkcs11.load("C:\SoftHSM2\lib\softhsm2-x64.dll")
print("dll load ok: ", pkcs11)


slots = pkcs11.getSlotList()
print("slotlar: ", slots)


slot = 577229486
pin = "9999"

usession = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
usession.login(pin)
print("session login ok: ", usession)


aes_key_template = [(CKA_LABEL, "aes128")]
key_control = usession.findObjects(aes_key_template)
print("key control: ", len(key_control))

if len(key_control) > 0:
    key = key_control[0]
else:
    aes_key_template = [
        (CKA_CLASS, CKO_SECRET_KEY),
        (CKA_KEY_TYPE, CKK_AES),
        (CKA_VALUE_LEN, 16),  #16 byte => 128-bit
        (CKA_TOKEN, True),
        (CKA_ENCRYPT, True),
        (CKA_LABEL, "aes128"),
        (CKA_DECRYPT, True)
    ]

    key = usession.generateKey(aes_key_template)

    print("key generate ok")
    

mechanism = Mechanism(CKM_AES_CBC, '0000000000000000')
message = "99999999999999999999999999999999"

encrypted = usession.encrypt(key, binascii.unhexlify(message), mechanism)
print("encrypt ok: ", encrypted)

decrypted = usession.decrypt(key, encrypted, mechanism)
print("decrypt ok: ", decrypted)

usession.logout()
usession.closeSession()
