import subprocess
import sys
import os
import re
# -*- coding: utf-8 -*-
#
# Copyright 2019 Vulnwarex LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

def sc_bin(obj, syntax):
	lines = subprocess.check_output(['objdump', '-d', '-M', syntax, obj])
	lines = lines.split(b'Disassembly of section')[1]
	lines = lines.split(b'\n')[3:]
	shellcode = ''
	opcode = []
	code = []
	for l in lines:
		l = l.strip()

		tabs = l.split(b'\t')
		if (len(tabs) < 2):
			continue
		bytes = tabs[1].strip()
		bytes = bytes.split(b' ')
		sh3llshock = ""
		for byte in bytes:
			sh3llshock += "\\x" + byte.decode("utf-8")
		shellcode += sh3llshock
		show_shell =  (32, '"'+sh3llshock+'"')
		code.append(show_shell)
	return shellcode

def sc_arr(obj, syntax):
	lines = subprocess.check_output(['objdump', '-d', '-M', syntax, obj])
	lines = lines.split(b'Disassembly of section')[1]
	lines = lines.split(b'\n')[3:]
	shellcode = ""
	opcode = []
	code = []
	for l in lines:
		l = l.strip()

		tabs = l.split(b'\t')
		if (len(tabs) < 2):
			continue
		bytes = tabs[1].strip()
		bytes = bytes.split(b' ')
		sh3llshock = ""
		for byte in bytes:
			opcode.append("0x"+byte.decode("utf-8"))
	return shellcode,opcode

def x86_x86_64(arch,payload,obj,target, lib=''):
	if sys.argv[4] == "x86":
		if target == 'win':
			subprocess.call(['/usr/bin/nasm', '-f', 'win32', payload])
			subprocess.call(['/usr/bin/ld', '-m', 'i386pe', '-o' , 'shellcode.exe', os.path.splitext(obj)[0]+'.obj'])
		elif target == "linux":
			subprocess.call(['/usr/bin/nasm', '-f', 'elf32', payload])
			ld = subprocess.call(['/usr/bin/ld', '-m', 'elf_i386', '-o' , 'shellcode', os.path.splitext(obj)[0]+'.o'])
			print(ld)
		else:
			print('OS not supported')
	elif sys.argv[4] == "x64":
		if target == 'win':
			subprocess.call(['/usr/bin/nasm', '-f', 'win64', payload])
			subprocess.call(['/usr/bin/ld', '-m', 'i386pep', '-o' , 'shellcode.exe', os.path.splitext(obj)[0]+'.obj', lib])
		elif target == "linux":
			subprocess.call(['/usr/bin/nasm', '-f', 'elf64', payload])
			subprocess.call(['/usr/bin/ld', '-m', 'elf_x86_64','-o' , 'shellcode', os.path.splitext(obj)[0]+'.o'])
		else:
			print('OS not supported')
	else:
		print("arch not supported")

if __name__ == '__main__':
	try:
	  lib = sys.argv[5]
	except IndexError:
	  lib = None

	if lib == None:
	    x86_x86_64(sys.argv[4],sys.argv[1],sys.argv[1],sys.argv[3])
	else:
	    x86_x86_64(sys.argv[4],sys.argv[1],sys.argv[1],sys.argv[3], sys.argv[5])

	if sys.argv[2] == "sc_app":
		if sys.argv[3] == "linux":
			opcode = sc_bin('shellcode', 'intel')
		elif sys.argv[3] == "win":
			opcode = sc_bin('shellcode.exe', 'intel')
		else:
			pass
		sc_header = 'shellcode = ""'
		shellcode = 'shellcode += "'
		for i in range(len(opcode)):
		    if i % 40 == 0 and i > 0:
		        shellcode += '"\nshellcode += "'
		    shellcode += opcode[i]
		shellcode += '"'
		print("[+] block Shellcode")
		print(sc_header)
		print(shellcode)
		print("\n[+] linear shellcode\n")
		print(opcode)
	elif sys.argv[2] == 'sc_arr':
		if sys.argv[3] == "linux":
			opcode = sc_arr('shellcode', 'intel')
		elif sys.argv[3] == "win":
			opcode = sc_arr('shellcode.exe', 'intel')
		else:
			pass
		for sublist in opcode:
			shellcode = sublist
		print("\n[+] linear shellcode\n")
		print('shellcode = {}'.format(str(shellcode).replace("'", '').replace('u','')))
	else:
		print("not shellcode format found")
