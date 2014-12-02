global _start

section .text
_start:
	;movdqu xmm0, [AES_TEST]					;Get test string
	;movdqu [PLAINTEXT], xmm0
	;movdqu xmm0, [KEY_TEST]					;Get test key
	;movdqu [KEY], xmm0
	;movdqu xmm0, [KEY_TEST + 0x10]			;Get test key
	;movdqu [KEY + 0x10], xmm0
	;movdqu xmm0, [IV_TEST]					;Get test IV
	;movdqu [IV], xmm0
	
	mov ecx, MsgOrig
	mov edx, 0x0B
	call Print
	mov ecx, AES_TEST
	mov edx, 73
	call Print
	mov ecx, MsgNL
	mov edx, 0x01
	call Print
	
	mov rax, AES_TEST
	mov rbx, 73
	mov rcx, KEY_TEST
	mov rdx, IV_TEST
	call AESEncrypt							;Return pointer to Cipher in rax
	
	mov ecx, MsgEnc
	mov edx, 0x0C
	call Print
	mov rcx, rax
	mov rdx, [TOTAL_SIZE]
	call Print
	mov ecx, MsgNL
	mov edx, 0x01
	call Print
	
	mov rbx, 80								;length of cipher (rax points to it)
	mov rcx, KEY_TEST						;pointer to key
	mov rdx, IV_TEST						;pointer to IV
	call AESDecrypt
	
	mov ecx, MsgDec
	mov edx, 0x0C
	call Print
	mov rcx, rax
	mov rdx, [REAL_SIZE]
	call Print
	mov ecx, MsgNL
	mov edx, 0x01
	call Print

	jmp Exit
	
	;rax = src, rbx = dest, rcx = size
Memcpy:
	push rdx
Memcpy_Loop:
	mov dl, byte [rax + rcx - 1]
	mov [rbx + rcx - 1], dl
	loop Memcpy_Loop
	pop rdx
	ret

	;rax = ptr plaintext, rbx = text size, rcx = ptr key, rdx = ptr IV
AESEncrypt:
	push rbp
	
	;Store Args (Can't push/pop because we change the stack)
	movq xmm0, rax
	movq xmm1, rbx
	movq xmm2, rcx
	movq xmm3, rdx
	
	;Create room on stack
	mov [REAL_SIZE], rbx					;store
	mov rax, rbx
	xor rdx, rdx							;clear the destination
	mov rcx, 0x10							;16 bytes block size
	div rcx									;remainder stored in rdx
	xor rax, rax
	mov al, 0x10							;One block size
	sub al, dl								;Get difference between remainder and size
	mov byte [PAD_SIZE], al					;store
	mov rdx, [REAL_SIZE]					;Message size
	add rdx, rax							;Size needed for AES operations (multiple of 16)
	mov [TOTAL_SIZE], rdx
	shl rdx, 1								;Multiply by 2 (plaintext & cipher)
	add rdx, 0x30							;Add size of IV + Key
	sub rsp, rdx							;Create room on stack for local vars
	mov rbp, rsp
	
	;Get Args Back
	movq rdx, xmm3							;iv addr
	movq rcx, xmm2							;key addr
	movq rbx, xmm1							;plaintext size
	movq rax, xmm0							;plaintext addr
	
	movdqu xmm0, [rdx]						;Get IV													|--------|-----------|
	movdqu [rbp], xmm0						;Store first on stack									|   0x00 | IV		 |
	movdqu xmm0, [rcx]						;Get key pt 1											|--------|-----------|
	movdqu [rbp + 0x10], xmm0				;Store next												|   0x10 | Key Pt 1	 |
	add rcx, 0x10							;														|--------|-----------|
	movdqu xmm0, [rcx]						;Get key pt 2											|	0x20 | Key Pt 2	 |
	movdqu [rbp + 0x20], xmm0				;Store													|--------|-----------|
											;														|	0x30 | Plaintext |
	mov rcx, rbx							;store size in the correct register for the call		|--------|-----------|
	lea rbx, [rbp + 0x30]					;destination of copy (stack)							|   0xYY | Cipher	 |
	call Memcpy								;copy the plaintext to stack							|--------|-----------|
	
AESEncrypt_Pad:
	xor rax, rax
	mov al, byte [PAD_SIZE]					;Get number to write
	xor rcx, rcx
	mov cl, al								;which (according to PKCS 7) is times to write
	lea rbx, [rbp + 0x30]					;Point to start of plaintext in stack
	add rbx, [REAL_SIZE]					;Point to end of plaintext (where to pad)
AESEncrypt_Pad_Loop:
	mov [rbx + rcx - 1], al
	loop AESEncrypt_Pad_Loop
	
	call CreateSchedule

	mov rbx, [TOTAL_SIZE]					;Will only store the size
	xor rcx, rcx							;Will keep track of progress through
AESEncrypt_Loop:
	movdqu xmm0, [rbp + 0x30 + rcx]			;Initial block data
	lea rdx, [ROUNDKEYS]
	movdqu xmm1, [rbp]						;Get the IV
	movdqu xmm2, [rbp + 0x10]				;Get Key Pt 1
	pxor xmm0, xmm1
	pxor xmm0, xmm2
	
	movdqu xmm1, [edx + 0x10]
	movdqu xmm2, [edx + 0x20]
	movdqu xmm3, [edx + 0x30]
	movdqu xmm4, [edx + 0x40]
	movdqu xmm5, [edx + 0x50]
	movdqu xmm6, [edx + 0x60]
	movdqu xmm7, [edx + 0x70]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7
	
	movdqu xmm1, [edx + 0x80]
	movdqu xmm2, [edx + 0x90]
	movdqu xmm3, [edx + 0xA0]
	movdqu xmm4, [edx + 0xB0]
	movdqu xmm5, [edx + 0xC0]
	movdqu xmm6, [edx + 0xD0]
	movdqu xmm7, [edx + 0xE0]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenclast xmm0, xmm7

	lea rax, [rbp + 0x30]					;Start of Plaintext
	add rax, rbx							;Start of Cipher
	add rax, rcx							;Current pos in Cipher
	movdqu [rax], xmm0						;store block
	movdqu [rbp], xmm0						;Overwrite IV with State (for CBC)
	add rcx, 0x10							;Add one block to count
	cmp rcx, rbx
	jne AESEncrypt_Loop
	
	lea rax, [rbp + 0x30]					;Start of Plaintext
	add rax, rbx							;Start of Cipher
	movq xmm0, rax
	
	mov	rax, 45		;sys_brk
	xor	ebx, ebx
	int	80h

	mov rbx, [TOTAL_SIZE]
	add	rbx, rax							;plus current edge of mem
	mov	rax, 45								;sys_brk
	int	80h
	
	sub rax, [TOTAL_SIZE]					;Get mem address to place cipher
	movq xmm1, rax
	mov rbx, rax							;store in correct register
	movq rax, xmm0							;cipher addr (source)
	mov rcx, [TOTAL_SIZE]					;bytes to write
	call Memcpy
	
	mov rax, [TOTAL_SIZE]					;size of plaintext+padding
	shl rax, 1								;double (cipher + decrypt)
	add rax, 0x30							;add IV + Key
	add rsp, rax							;adjust stack pointer back
	pop rbp
	
	movq rax, xmm1
	
	ret

	;rax = ptr cipher, rbx = size, rcx = ptr key, rdx = ptr IV
AESDecrypt:
	push rbp
	
	mov [TOTAL_SIZE], rbx
	
	;Store Args
	movq xmm0, rax
	movq xmm1, rbx
	movq xmm2, rcx
	movq xmm3, rdx
	
	shl rbx, 1
	add rbx, 0x30
	sub rsp, rbx							;Reserve SIZE bytes on stack for local vars
	mov rbp, rsp
	
	;Get Args Back
	movq rdx, xmm3							;iv addr
	movq rcx, xmm2							;key addr
	movq rbx, xmm1							;cipher size
	movq rax, xmm0							;cipher addr
	
	movdqu xmm0, [rdx]						;Get IV													|--------|-----------|
	movdqu [rbp], xmm0						;Store first on stack									|   0x00 | IV		 |
	movdqu xmm0, [rcx]						;Get key pt 1											|--------|-----------|
	movdqu [rbp + 0x10], xmm0				;Store next												|   0x10 | Key Pt 1	 |
	add rcx, 0x10							;														|--------|-----------|
	movdqu xmm0, [rcx]						;Get key pt 2											|	0x20 | Key Pt 2	 |
	movdqu [rbp + 0x20], xmm0				;Store													|--------|-----------|
											;														|	0x30 | Cipher 	 |
	mov rcx, rbx							;store size in the correct register for the call		|--------|-----------|
	lea rbx, [rbp + 0x30]					;destination of copy (stack)							|   0xYY | Plaintext |
											;														|--------|-----------|
	call Memcpy								;copy the cipher to stack	
	
	call CreateSchedule

	mov ecx, ROUNDKEYS
	call InvMixColRounds

	mov rbx, [TOTAL_SIZE]					;Will only store the size
	xor rcx, rcx							;Will keep track of progress through
	mov rdx, ROUNDKEYS
AESDecrypt_Loop:
	movdqu xmm0, [rbp + 0x30 + rcx]			;Initial block data	
	movdqu xmm8, xmm0						;Store to be next IV
	
	movdqu xmm1, [rdx + 0x80]
	movdqu xmm2, [rdx + 0x90]
	movdqu xmm3, [rdx + 0xA0]
	movdqu xmm4, [rdx + 0xB0]
	movdqu xmm5, [rdx + 0xC0]
	movdqu xmm6, [rdx + 0xD0]
	movdqu xmm7, [rdx + 0xE0]
	pxor xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdec xmm0, xmm1
	
	movdqu xmm1, [rdx + 0x10]
	movdqu xmm2, [rdx + 0x20]
	movdqu xmm3, [rdx + 0x30]
	movdqu xmm4, [rdx + 0x40]
	movdqu xmm5, [rdx + 0x50]
	movdqu xmm6, [rdx + 0x60]
	movdqu xmm7, [rdx + 0x70]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdec xmm0, xmm1
	
	movdqu xmm1, [rbp]	 					;Get IV
	movdqu xmm2, [rbp + 0x10]				;Get Key Pt 1
	aesdeclast xmm0, xmm2
	pxor xmm0, xmm1
	
	lea rax, [rbp + 0x30]					;Start of Cipher
	add rax, rbx							;Start of Plaintext
	add rax, rcx							;Current pos in Plaintext
	movdqu [rax], xmm0						;Store block
	movdqu [rbp], xmm8						;Overwrite IV with original state (for CBC)
	add rcx, 0x10							;Add one block to count
	cmp rcx, rbx
	jne AESDecrypt_Loop
	
	add rax, 0x0F							;last byte of plaintext
	xor rbx, rbx
	mov bl, byte [rax]
	mov rax, [TOTAL_SIZE]
	sub rax, rbx							;PKCS 7
	mov [REAL_SIZE], rax
	
	lea rax, [rbp + 0x30]					;Start of Cipher
	add rax, [TOTAL_SIZE]					;Start of Plaintext
	movq xmm0, rax
	
	mov	rax, 45		;sys_brk
	xor	ebx, ebx
	int	80h

	mov rbx, [REAL_SIZE]
	add	rbx, rax							;plus current edge of mem
	mov	rax, 45								;sys_brk
	int	80h
	
	sub rax, [REAL_SIZE]					;Get mem address to place plaintext
	movq xmm1, rax
	mov rbx, rax							;store in correct register
	movq rax, xmm0							;cipher addr (source)
	mov rcx, [REAL_SIZE]					;bytes to write
	call Memcpy
	
	mov rax, [TOTAL_SIZE]					;size of cipher
	shl rax, 1								;double (cipher + plaintext)
	add rax, 0x30							;add IV + Key
	add rsp, rax							;adjust stack pointer back
	pop rbp
	
	movq rax, xmm1

	ret

CreateSchedule:
	movdqu xmm1, [rbp + 0x10]				;Bytes 0-15 of 256bit private key
	movdqu [ROUNDKEYS], xmm1				;Store in schedule first
	movdqu xmm2, [rbp + 0x20]				;Bytes 16-31 of 256bit private key
	movdqu [ROUNDKEYS + 0x10], xmm2			;Store in schedule second
	
	lea eax, [ROUNDKEYS + 0x20]				;Roundkeys offset, set to 32 bytes
	aeskeygenassist xmm3, xmm2, 0x01
	call KeyExpansion_1
	movdqu [eax], xmm1						;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0x10], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x02
	call KeyExpansion_1
	movdqu [eax + 0x20], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0x30], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x04
	call KeyExpansion_1
	movdqu [eax + 0x40], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0x50], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x08
	call KeyExpansion_1
	movdqu [eax + 0x60], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0x70], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x10
	call KeyExpansion_1
	movdqu [eax + 0x80], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0x90], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x20
	call KeyExpansion_1
	movdqu [eax + 0xA0], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [eax + 0xB0], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x40
	call KeyExpansion_1
	movdqu [eax + 0xC0], xmm1				;Store in schedule
	ret

InvMixColRounds:
	movdqu xmm2, [ecx + 0x10]
	movdqu xmm3, [ecx + 0x20]
	movdqu xmm4, [ecx + 0x30]
	movdqu xmm5, [ecx + 0x40]
	movdqu xmm6, [ecx + 0x50]
	movdqu xmm7, [ecx + 0x60]
    aesimc xmm1, xmm2
    movdqu [ecx + 0x10], xmm1
    aesimc xmm1, xmm3
    movdqu [ecx + 0x20], xmm1
    aesimc xmm1, xmm4
    movdqu [ecx + 0x30], xmm1
    aesimc xmm1, xmm5
    movdqu [ecx + 0x40], xmm1
    aesimc xmm1, xmm6
    movdqu [ecx + 0x50], xmm1
    aesimc xmm1, xmm7
    movdqu [ecx + 0x60], xmm1
	
	movdqu xmm2, [ecx + 0x70]
	movdqu xmm3, [ecx + 0x80]
	movdqu xmm4, [ecx + 0x90]
	movdqu xmm5, [ecx + 0xA0]
	movdqu xmm6, [ecx + 0xB0]
	movdqu xmm7, [ecx + 0xC0]
    aesimc xmm1, xmm2
    movdqu [ecx + 0x70], xmm1
    aesimc xmm1, xmm3
    movdqu [ecx + 0x80], xmm1
    aesimc xmm1, xmm4
    movdqu [ecx + 0x90], xmm1
    aesimc xmm1, xmm5
    movdqu [ecx + 0xA0], xmm1
    aesimc xmm1, xmm6
    movdqu [ecx + 0xB0], xmm1
    aesimc xmm1, xmm7
    movdqu [ecx + 0xC0], xmm1
	
	movdqu xmm2, [ecx + 0xD0]
    aesimc xmm1, xmm2
    movdqu [ecx + 0xD0], xmm1
	ret 

KeyExpansion_1:
	pshufd xmm3, xmm3, 0xFF
	vpslldq xmm4, xmm1, 4
	pxor xmm1, xmm4
	pslldq xmm4, 4
	pxor xmm1, xmm4
	pslldq xmm4, 4
	pxor xmm1, xmm4
	pxor xmm1, xmm3
	ret

KeyExpansion_2:
	aeskeygenassist xmm4, xmm1, 0x00
	pshufd xmm3, xmm4, 0xaa
	vpslldq xmm4, xmm2, 4
	pxor xmm2, xmm4
	pslldq xmm4, 4
	pxor xmm2, xmm4
	pslldq xmm4, 4
	pxor xmm2, xmm4
	pxor xmm2, xmm3
	ret

	;ecx = Buffer location, edx = buffer length
Print:
	push rax
	push rbx
	;sys_write(stdout, message, length);
	mov rax, 4								;sys_write
	mov rbx, 1								;stdout
	int 80h									;Interrupt80 = "Do It!"
	pop rbx
	pop rax
	ret

Exit:
	mov eax, 1								;sys_exit
	mov ebx, 0								;return 0
	int 80h

section .data
MsgNL db 0x0A
MsgOrig db "Original: ", 0x00
MsgEnc db "Encrypted: ", 0x00
MsgDec db "Decrypted: ", 0x00
AES_TEST db "Hello there world! This tests aribitrarily sized plaintext! Did it work?!"
KEY_TEST db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
IV_TEST db 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0

section .bss
KEY resq 4									;256 bit AES key
IV	resq 2									;the initialization vector
ROUNDKEYS resq 30							;All of the 14 round keys + initial key
REAL_SIZE resq 1							;Actual message size (without padding)
PAD_SIZE resb 1								;Pad [1, 16]
TOTAL_SIZE resq 1							;Actual + Pad