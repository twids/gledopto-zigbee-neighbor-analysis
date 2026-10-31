import pathlib,struct,json,hashlib
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE
from unicorn.arm_const import *
path=pathlib.Path(__file__).with_name('GL-G-001P.ota'); b=path.read_bytes()
assert hashlib.sha256(b).hexdigest()=='5426ec7e0da55cb899ebc32c5a00ab9de745c750d73b8007c86ed94bb35551cd'
image=bytearray(b'\xff'*0x50000); pos=62
while pos+8<=len(b):
 tag,n=struct.unpack_from('<II',b,pos); v=b[pos+8:pos+8+n]; assert len(v)==n
 if tag==0xfd0303fd:
  addr=struct.unpack_from('<I',v)[0];image[addr:addr+n-4]=v[4:]
 pos+=8+n
assert image[0x3a950:0x3a960].hex()=='2046013cfff7eefee4b201340e35e4b2'
P=lambda n:struct.pack('<I',n)
ids={'A':b'AAAAAAAA','B':b'BBBBBBBB','C':b'CCCCCCCC','D':b'DDDDDDDD'}
def test(records,needle='A',nwk=0x1111):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB|UC_MODE_MCLASS);u.mem_map(0,0x50000);u.mem_write(0,bytes(image));u.mem_map(0x20000000,0x10000);u.mem_map(0x10000000,0x1000)
 obj=0x20006000; table=0x20007000; parallel=0x20007800; src=0x20008000
 u.mem_write(0x20004fcc,P(obj));u.mem_write(obj+0x28,P(table));u.mem_write(obj+0x2c,bytes([16,len(records)]));u.mem_write(obj+0x30,P(parallel));u.mem_write(0x20001fb0,P(0x20003000));u.mem_write(0x20001fb4,b'\0');u.mem_write(src,ids[needle])
 for i,(name,address) in enumerate(records):u.mem_write(table+14*i,struct.pack('<H',address)+b'\0'*4+ids[name]);u.mem_write(parallel+4*i,P(i+1))
 u.reg_write(UC_ARM_REG_SP,0x2000f000);u.reg_write(UC_ARM_REG_LR,0x10000001);u.reg_write(UC_ARM_REG_R0,src);u.reg_write(UC_ARM_REG_R1,nwk)
 removed=[];visited=[]
 def hook(uc,addr,size,_):
  if addr==0x10000000:uc.emu_stop();return
  if addr==0x3a93c:visited.append({'index':uc.reg_read(UC_ARM_REG_R4),'pointer_index':(uc.reg_read(UC_ARM_REG_R5)-table-6)//14})
  if addr==0x3a734:removed.append(uc.reg_read(UC_ARM_REG_R0))
  if False and addr==0x58f2:
   r0,r1,n=(uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2));x=bytes(uc.mem_read(r0,n));y=bytes(uc.mem_read(r1,n));uc.reg_write(UC_ARM_REG_R0,0 if x==y else 1);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  elif False and addr==0x582c:
   dst,source,n=(uc.reg_read(x) for x in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2));uc.mem_write(dst,bytes(uc.mem_read(source,n)));uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  elif addr==0x2c2be:uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
  elif addr==0x6b00:raise AssertionError('firmware assertion')
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x3a91d,0,count=10000)
 count=bytes(u.mem_read(obj+0x2d,1))[0]; out=[]
 for i in range(count):
  v=bytes(u.mem_read(table+14*i,14));out.append((v[6:14].decode(),hex(struct.unpack('<H',v[:2])[0])))
 return {'in':[(x,hex(y)) for x,y in records], 'needle':needle,'target_nwk':hex(nwk),'out':out,'removed_indices':removed,'visited':visited}
cases=[ [('A',0x2222),('B',0x3333),('C',0x4444)], [('A',0x1111),('B',0x3333)], [('A',0x2222),('B',0x3333),('A',0x4444),('C',0x5555)], [('A',0x2222),('A',0x4444),('B',0x3333)], [('B',0x3333),('A',0x2222),('A',0x4444),('C',0x5555)] ]
results=[test(x) for x in cases]
assert [x[0] for x in results[0]['out']]==['BBBBBBBB','CCCCCCCC']
assert [x[0] for x in results[1]['out']]==['AAAAAAAA','BBBBBBBB']
assert [x[0] for x in results[2]['out']]==['AAAAAAAA','CCCCCCCC']
assert [x[0] for x in results[3]['out']]==['AAAAAAAA','BBBBBBBB']
assert [x[0] for x in results[4]['out']]==['BBBBBBBB','AAAAAAAA','CCCCCCCC']

print(json.dumps(results,indent=2))


