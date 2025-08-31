We are given a windows executable:
`misc200.exe`
![[Pasted image 20250830193250.png|900]]
Messing around a little with the options, its clear that decompilation is going to be necessary, as the program itself does not provide any clues.
In Ghidra, finding the main function is easy enough, and by simple examination, a special subroutine stands out:
```c
    case 4:
      FUN_00401ad0((int *)cout_exref,"Insert first string: ");
      FUN_00402490(cin_exref,(int)local_dc);
      FUN_00401ad0((int *)cout_exref,"Insert second string: ");
      FUN_00402490(cin_exref,(int)local_78);
      pbVar5 = local_78;
      pbVar10 = &DAT_004045c0;
      do {
        bVar1 = *pbVar5;
        bVar11 = bVar1 < *pbVar10;
        if (bVar1 != *pbVar10) {
LAB_004016d0:
          uVar6 = -(uint)bVar11 | 1;
          goto LAB_004016d5;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar5[1];
        bVar11 = bVar1 < pbVar10[1];
        if (bVar1 != pbVar10[1]) goto LAB_004016d0;
        pbVar5 = pbVar5 + 2;
        pbVar10 = pbVar10 + 2;
      } while (bVar1 != 0);
      uVar6 = 0;
LAB_004016d5:
      if (uVar6 == 0) {
        uVar6 = 0x10;
        uStack_e8 = 0xcd8fe1cc;
        local_e4 = 0x8dcdebe1;
        uStack_f0 = 0x33537334;
        uStack_ec = 0x336c626d;
        local_e0 = 0xc3d2cbd8;
        local_f8 = 0x474c467b;
        pauStack_f4 = (undefined (*) [32])0x7369643a;
        do {
          *(byte *)((int)&local_f8 + uVar6) = *(byte *)((int)&local_f8 + uVar6) ^ 0xbe;
          uVar6 = uVar6 + 1;
        } while (uVar6 < 0x1c);
        piVar7 = FUN_00402070((int *)cout_exref,'{');
        unaff_ESI = FUN_00401cf0;
      }
      else {
        eVar8 = strcat_s(local_dc,100,(char *)local_78);
        unaff_ESI = FUN_00401cf0;
        if (eVar8 == 0) {
          piVar7 = FUN_00401ad0((int *)cout_exref,"The concatenated string is: ");
          piVar7 = FUN_00401ad0(piVar7,local_dc);
        }
        else {
          piVar7 = FUN_00401ad0((int *)cout_exref,"Error in string concatenation!");
        }
      }
```
This is from the switch statement that handles the string concatenation feature. We can see that the program enters a special part where it XORs a few strings, depending on the order that they have on the stack.
To trigger the hidden branch, enter this exact “second string”: DAT_004045c0
`UmV2ZXJzZSB0aGUgbXlzdGVyeQ==`

The XOR loop flips bytes at (&local_f8 + 0x10) .. +0x1B (12 bytes), which spans three dwords. We place the 7 dwords at their actual stack offsets (relative to &local_f8), in little-endian:
- local_f8 @ +0x00
- pauStack_f4 @ +0x04
- uStack_f0 @ +0x08
- uStack_ec @ +0x0C
- uStack_e8 @ +0x10  <-- starts the XOR window
- local_e4  @ +0x14
- local_e0  @ +0x18
Putting this all together into a python script:
```python
# Build buffer using known variable dwords placed at specific offsets relative to &local_f8
def dword_to_bytes_le(x):
    return [(x >> (8*i)) & 0xff for i in range(4)]

# replace these with the 32-bit immediates from the decompilation
values = {
    'local_f8': 0x474c467b,
    'pauStack_f4': 0x7369643a,
    'uStack_f0': 0x33537334,
    'uStack_ec': 0x336c626d,
    'local_e0': 0xc3d2cbd8,
    'local_e4': 0x8dcdebe1,
    'uStack_e8': 0xcd8fe1cc,
}

# offsets : relative to &local_f8
offsets = {
    'local_f8': 0,
    'pauStack_f4': 4,
    'uStack_f0': 8,
    'uStack_ec': 12,
    'local_e0': 24,
    'local_e4': 20,
    'uStack_e8': 16,
}

# build buffer large enough
max_off = max(offsets.values()) + 4
buf = [0] * max_off
for name, off in offsets.items():
    b = dword_to_bytes_le(values[name])
    buf[off:off+4] = b

# apply XOR for bytes at (&local_f8 + 0x10) .. +0x1b
for i in range(0x10, 0x1c):
    if i < len(buf):
        buf[i] ^= 0xBE

print(''.join(chr(b) if 32<=b<127 else f"\\x{b:02x}" for b in buf))
```
we get 
`{FLG:dis4sS3mbl3r_1s_Us3ful}`
done!