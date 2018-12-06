#!/usr/bin/env python2

import base64
import binascii
import struct


def main():
    challenge = 'proxy-Authenticate: NTLM TlRMTVNTUAACAAAAEAAQADgAAAA1goriluCDYHcYI/sAAAAAAAAAAFQAVABIAAAABQLODgAAAA9TAFAASQBSAEkAVAAxAEIAAgAQAFMAUABJAFIASQBUADEAQgABABAAUwBQAEkAUgBJAFQAMQBCAAQAEABzAHAAaQByAGkAdAAxAGIAAwAQAHMAcABpAHIAaQB0ADEAYgAAAAAA'
    response = 'proxy-Authorization: NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAYABgAigAAABIAEgBIAAAABgAGAFoAAAASABIAYAAAABAAEACiAAAANYKI4gUBKAoAAAAPTABBAEIAUwBNAE8ASwBFADMAXwBxAGEATABBAEIAUwBNAE8ASwBFADMA0NKq8HYYhj8AAAAAAAAAAAAAAAAAAAAAOIiih3mR+AkyM4r99sy1mdFonCu2ILODro1WTTrJ4b4JcXEzUBA2Ig=='

    challenge = base64.b64decode(challenge.split(' ')[2])
    response = base64.b64decode(response.split(' ')[2])
    
    serverchallenge = binascii.b2a_hex(challenge[24:32]) #offset to the challenge, 8 bytes long
    lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack("12xhhihhihhihhi", response[:44])
    lmhash = binascii.b2a_hex(response[lmoff:lmoff+lmlen])
    nthash = binascii.b2a_hex(response[ntoff:ntoff+ntlen])
    domain = response[domoff:domoff+domlen].replace("\0", "")
    user = response[useroff:useroff+userlen].replace("\0", "")
    if ntlen == 24:
        print('Type = NetNTLMv1 (hashcat id = 5500)')
        print user+"::"+domain+":"+lmhash+":"+nthash+":"+serverchallenge
    else:
        print('Type = NetNTLMv2 (hashcat id = 5600)')
        print user+"::"+domain+":"+serverchallenge+":"+nthash[:32]+":"+nthash[32:]


if __name__ == '__main__':
    main()