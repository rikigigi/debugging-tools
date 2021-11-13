import sys
write=True
fname_counters={}
write_limit = 100
write_count = 0

executable=[]
arguments=[]

try:
   write = sys.argv[1].upper() == 'TRUE'
   executable = sys.argv[2:]
except:
   print (f'''
USAGE: {sys.argv[0]} true|false /path/to/executable [args]
''') 
   sys.exit(-1)



import numpy as np
import hashlib
import subprocess
import time
import frida

def on_message(message, data):
   try:
       message=message['payload']
       if 'enter' in message:
         print ('====='+message+'=====')
       if data is not None:
         #print(f"data {data.__class__} in {message} is present: testing it")
         global fname_counters
         global write_count
         k = hashlib.sha224(bytes(message, encoding='ascii')).hexdigest()
         fname_counters.setdefault(k,0)
         fname_counters[k] += 1
         fname = f'{write_count}.npy'
         dn=np.frombuffer(data,dtype='float64')
         if write_count < write_limit:
           try:
            if write:
               print(f'writing to {fname}')
               np.save(fname, dn)
            else:
               print(f'reading from {fname}')
               dl = np.load(fname)
               print (np.abs((dl-dn)).sum())
           except FileNotFoundError:
               print(f'file not found {fname}')

           write_count += 1
       if 'exit' in message:
          print ('====='+message+'=====')
   except KeyError:
      print (message,data)

   
scr= open('frida.js','r')
scr_=scr.read()
scr.close()
dbg_symbols=f'''//DebugSymbol.load("{executable[0]}");
'''
print(dbg_symbols)
pid = frida.spawn(executable)
print(executable)
session = frida.attach(pid)
script = session.create_script(dbg_symbols+scr_)
script.on("message", on_message)
script.load()
frida.resume(pid)
sys.stdin.read()
frida.kill(pid)
