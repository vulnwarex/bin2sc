import subprocess
import sys
import os
import re
# -*- coding: utf-8 -*-
#
# Copyright 2019 skybulk LLC
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


if __name__ == '__main__':
	if os.name == 'nt':
		pass # Windows
	elif os.name == 'posix':
		subprocess.call(['/usr/bin/nasm', '-f', 'elf32', sys.argv[1]])
		subprocess.call(['/usr/bin/ld', '-m', 'elf_i386', '-o' , 'shellcode', os.path.splitext(sys.argv[1])[0]+'.o'])
		if sys.argv[2] == "sc_app" and sys.argv[3] == "linux":
			opcode = sc_bin('shellcode', 'intel')
			shellcode = re.sub("(.{32})", "\\1\n",opcode, 0, re.DOTALL)
			print("[+] block Shellcode")
			print(shellcode)
			print("\n[+] linear shellcode\n")
			print(opcode)
		elif sys.argv[2] == 'sc_arr' and sys.argv[3] == "linux":
			opcode = sc_arr('shellcode', 'intel')
			for sublist in opcode:
				shellcode = sublist
			print("\n[+] linear shellcode\n")
			print('shellcode = {}'.format(str(shellcode).replace("'", '')))
		else:
			print("not shellcode format found")
	else:
		pass
