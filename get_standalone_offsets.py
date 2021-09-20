import subprocess

def extractValues(line):
  chunks = line.split()
  for ind in range(len(chunks)):
    val = chunks[ind]
    if val.startswith(b'0'):
      chunks[ind] = int(val,16)
  return chunks

result = subprocess.run(['readelf','-l','standalone'], capture_output=True)
output = result.stdout.split(b'\n')
lines = []
for line in output:
  if line.startswith(b'  LOAD') or line.startswith(b'  DYNAMIC'):
    values = extractValues(line)
    lines.append(values)
print('Exec address 0x%x, size 0x%x'%(lines[0][2],lines[2][1]+lines[2][5]))
dataaddr = lines[3][2] & 0xfffff000
datasize = (lines[3][5] & 0xfffff000) + 0x2000
dataoffs = lines[3][1] & 0xfffff000
print('Data address 0x%x, size 0x%x, offset 0x%x'%(dataaddr,datasize,dataoffs))
memstart = lines[3][2]+lines[3][4]
memlen = (dataaddr + datasize) - memstart
print('Memset: 0x%x, 0x%x'%(memstart,memlen))
