#!/usr/bin/python
import json
import os

#modify this to match your path
os.chdir("/Users/kevin/Library/Application Support/Hopper/Scripts")

#syscall tables stolen from here
#https://github.com/dyjakan/osx-syscalls-list

#SYSCALL_CLASS_NONE = NULL
SYSCALL_CLASS_MACH = 0x01
SYSCALL_CLASS_UNIX = 0x02
SYSCALL_CLASS_MDEP = 0x03
SYSCALL_CLASS_DIAG = 0x04

with open("./osx-mach-traps.json","r") as f:
	mach_syscalls = json.load(f)

with open("./osx-bsd-syscalls.json","r") as f:
	bsd_syscalls = json.load(f)



doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()

adr = doc.getCurrentAddress()
inst = seg.getInstructionAtAddress(adr)
instStr = inst.getInstructionString()


def down():
	doc.moveCursorOneLineDown()

def up():
	 doc.moveCursorOneLineUp()

def oep():
	doc.moveCursorAtEntryPoint()

def instString():
	adr = doc.getCurrentAddress()
	inst = seg.getInstructionAtAddress(adr)
	return  inst.getInstructionString()


segBegin = seg.getStartingAddress()
segSize = seg.getLength()
pos = doc.getCurrentAddress()

while (pos  < (segBegin + segSize)):
	try:
		if instString() == "syscall":
			#print("syscall found")
			print(hex(pos))
			up()
			#print(instString())
			#print(inst.getArgumentCount())
			#print(inst.getFormattedArgument(0))
			#print(inst.getRawArgument(2))
			#print(inst.getInstructionLength())
			bytesx = doc.readBytes(doc.getCurrentAddress(),inst.getInstructionLength())
			
			if (bytesx[-1]) == SYSCALL_CLASS_MACH:
				print("mach syscall")
				print(mach_syscalls[bytesx[-4]][2])
				seg.setInlineCommentAtAddress(pos,mach_syscalls[bytesx[-4]][2])
				print(bytesx[4],bytesx[3],bytesx[2],hex(bytesx[1]))		
			elif bytesx[-1] == SYSCALL_CLASS_UNIX:
				print("unix syscall")
				print(bsd_syscalls[bytesx[-4]][2])
				seg.setInlineCommentAtAddress(pos,bsd_syscalls[bytesx[-4]][2])
				print(bytesx[4],bytesx[3],bytesx[2],hex(bytesx[1]))		
			elif bytesx[-1] == SYSCALL_CLASS_MDEP:
				print("mdep syscall")
				#machine dependent, will have to look into this further
				print(bytesx[4],bytesx[3],bytesx[2],hex(bytesx[1]))		
			elif bytesx[-1] == SYSCALL_CLASS_DIAG:
				print("diag syscall")
				#this is also something that has to be researched
				print(bytesx[4],bytesx[3],bytesx[2],hex(bytesx[1]))		
			else:
				print("obfuscated call?")
				seg.setInlineCommentAtAddress(pos,"Possible start of something interesting")
				print(bytesx[4],bytesx[3],bytesx[2],hex(bytesx[1]))			
			print("\n")	
			down()			
		
		down()
		
		pos = doc.getCurrentAddress()
	except SystemError:
		#print("not instx")
		down()
		pos = doc.getCurrentAddress()

oep()

