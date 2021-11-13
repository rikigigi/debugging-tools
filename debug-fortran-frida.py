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
import frida
import hashlib
import subprocess
import time

def on_message(message, data):
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
         fname = f'{k}.{fname_counters[k]}'
         dn=np.frombuffer(data,dtype='float64')
         if write_count < write_limit:
            if write:
               print(f'writing to {fname}')
               np.save(fname, dn)
            else:
               print(f'reading from {fname}')
               dl = np.load(fname)
               print ((dl-dn).sum())
            write_count += 1
       if 'exit' in message:
          print ('====='+message+'=====')

print(executable)
with subprocess.Popen(executable,stdin=subprocess.PIPE,stdout=subprocess.PIPE) as proc:
   
   scr= open('frida.js','r')
   scr_=scr.read()
   print(scr_)
   time.sleep(0.1)
   session = frida.attach(proc.pid)
   script = session.create_script(scr_)
   scr.close()
   script.on("message", on_message)
   script.load()
   while proc.poll() is None:
     print('.', end='', flush=True)
     time.sleep(1)
