#!/usr/bin/python
'''
This script takes a .s file as input and overwrites that .s file with a
modified version, in which each function label is preceded by ".align 16"
and has a single "nop" inserted as its first instruction.
Also, a subset of indirect call instructions are padded so that the instruction
after the call is 16-byte aligned.
'''
import sys,re

func_label = re.compile('	.type	.*, @function')
first_inst = re.compile('	[^.].*')

# Will not match all indirect calls: only call r32 and call [r32] for now
# This is actually quite difficult to use, because we want to ensure
# that the instruction AFTER a call is 16-byte aligned.  The problem with
# this is that we don't know how long an indirect call will be without
# using knowledge about instruction encoding.  For now, do I just match
# for a subset of instructions with known lengths and then align accordingly?
# Pattern for 2-byte call instructions
call_indirect = re.compile('\s+call\s+[*]?[%]...')
# Pattern for 6-byte call instructions with 4-byte offset
call_indirect_offset = re.compile('\s+call\s+\*.+\(%...\)')

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print('Usage: %s <.s file>'%sys.argv[0])
    sys.exit()
  out_buf = ''
  with open(sys.argv[1]) as f:
    print('%s invoked for %s')%(sys.argv[0],sys.argv[1])
    lines = f.read().split('\n')
    nop_ind = -1
    for i in range(len(lines)):
      # Find function label: unindented, no ".", no comment, marked as func
      if not lines[i].startswith('\t') and \
         not lines[i].startswith('.') and \
         not lines[i].startswith('#') and \
         i != 0 and func_label.match(lines[i-1]):
        # 16-byte align start of function
        out_buf += '\t.align 16\n%s\n'%lines[i]
        # Find first instruction in function so we can insert a nop there
        for j in range(i,len(lines)):
          if first_inst.match(lines[j]):
            nop_ind = j
            break
      elif i == nop_ind:
        # We want to insert a nop right before this instruction
        # WARNING: If the first instruction in a function were to be an
        # indirect call, then we would insert a nop here but not align the
        # instruction after it.
        out_buf +='\tnop\n%s\n'%lines[i]
      elif call_indirect.match(lines[i]):
        # We want the instruction after this indirect call to be 16-byte aligned
        out_buf +='\t.align 16\n\tnopw (%%eax)\n\tnopw (%%eax)\n\tnopw (%%eax)\n\txchg %%ax,%%ax\n%s\n\tnop\n'%lines[i]
      elif call_indirect_offset.match(lines[i]):
        # We want the instruction after this indirect call to be 16-byte aligned
        out_buf +='\t.align 16\n\tnopw (%%eax)\n\tnopw (%%eax)\n\txchg %%ax,%%ax\n%s\n\tnop\n'%lines[i]
      else:
        # Copy all irrelevant lines without modification
        out_buf += '%s\n'%lines[i]
  with open(sys.argv[1],'w') as f:
    f.write(out_buf)
