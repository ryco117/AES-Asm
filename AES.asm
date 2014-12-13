global Encrypt
global Decrypt

IV				equ 0x0000
ROUND_KEYS		equ 0x0010
TOTAL_SIZE		equ 0x0100
REAL_SIZE		equ 0x0108
PADDED_BLOCK	equ 0x0110
PAD_SIZE		equ 0x0120

section .text

	;rax = src, rbx = dest, rcx = size
Memcpy:
	push rdx
	test rcx, rcx
	jz Memcpy_Loop_Exit
Memcpy_Loop:
	mov dl, byte [rax + rcx - 1]
	mov [rbx + rcx - 1], dl
	loop Memcpy_Loop
Memcpy_Loop_Exit:
	pop rdx
	ret
	
	;rax = dest, rcx = size
Zero:
	push rdx
	mov dl, 0
Zero_Loop:
	mov [rax + rcx - 1], dl
	loop Zero_Loop
	pop rdx
	ret

	;void Encrypt(char* Text, int64 size, char* IV, char* Key, char* Buffer)
Encrypt:
	mov rbx, rsi							;Get second parameter (Text Size)
	mov rax, rdi							;Get first parameter (Plaintext Ptr)
	call AESEncrypt
	ret
	
	;rax = ptr plaintext, rbx = text size, rcx = ptr key, rdx = ptr IV, r8 = Buffer to fill
AESEncrypt:
	push rbp
	
	;Stack
	;|------------------------------------------|
	;|	0x0000	|	IV							|
	;|----------|-------------------------------|
	;|	0x0010	|	Round Keys (15 in total)	|
	;|----------|-------------------------------|
	;|	0x0100	|	Total Size (Qword)			|
	;|----------|-------------------------------|
	;|	0x0108	|	Real Size (Qword)			|
	;|----------|-------------------------------|
	;|	0x0110	|	Padded Block				|
	;|----------|-------------------------------|
	;|	0x0120	|	Pad Size (Byte)				|
	;|----------|-------------------------------|
	
	sub rsp, 0x121							;Create room on stack for local vars
	mov rbp, rsp
	
	movdqu xmm0, [rdx]						;Grab IV
	movdqu [rbp + IV], xmm0					;Store On Stack
	movdqu xmm0, [rcx]						;Grab Key Pt 1
	movdqu [rbp + ROUND_KEYS], xmm0			;Store On Stack
	movdqu xmm0, [rcx + 0x10]				;Grab Key Pt 2
	movdqu [rbp + ROUND_KEYS + 0x10], xmm0	;Store On Stack
	mov [rbp + REAL_SIZE], rbx				;Store Real Size
	
	push rax								;Store plaintext ptr
	
	;Get Padding Info
	xor rdx, rdx							;Clear the destination
	mov rax, [rbp + REAL_SIZE]				;Get message size
	mov rcx, 0x10							;16 bytes block size
	div rcx									;Remainder stored in rdx
	xor rax, rax
	mov al, 0x10							;One block size
	sub al, dl								;Get difference between remainder and size
	mov byte [rbp + PAD_SIZE], al			;Store
	add rax, [rbp + REAL_SIZE]
	mov [rbp + TOTAL_SIZE], rax
	
	pop rax
	push rax
AESEncrypt_Pad:
	add rax, [rbp + TOTAL_SIZE]				;Theoretical end of padded message
	sub rax, 0x10							;Beginning of padded block (if message is multiple of 16, then equals REAL_SIZE value)
	lea rbx, [rbp + PADDED_BLOCK]			;Place the result on stack
	mov rcx, 0x10							;Get block size
	sub cl, byte [rbp + PAD_SIZE]			;Subtract pad size to get bytes of padded block that are from original message (may be equal to zero)
	call Memcpy
	
	xor rcx, rcx
	mov cl, byte [rbp + PAD_SIZE]			;Pad size (according to PKCS 7) is times to write (rcx)
	mov rax, rcx
	lea rbx, [rbp + PADDED_BLOCK]			;Point to our final (padded) block
	add rbx, 0x10							;End of padded block
	xor rdx, rdx
	mov dl, byte [rbp + PAD_SIZE]			;Start of where to pad in block
	sub rbx, rdx
AESEncrypt_Pad_Loop:
	mov byte [rbx + rcx - 1], al
	loop AESEncrypt_Pad_Loop
	
	lea rax, [rbp + ROUND_KEYS]
	call CreateSchedule
	pop rax

	xor rcx, rcx							;Will keep track of progress through
AESEncrypt_Loop:
	mov rbx, [rbp + TOTAL_SIZE]				;Get total padded size
	cmp rcx, rbx
	je AESEncrypt_Finish					;We have encrypted the last (padded) block
	sub rbx, rcx							;Bytes left to encrypt
	cmp rbx, 0x10
	jnz AESEncrypt_Loop_RegBlock			;If we are encrypting more than one block, not padding yet
	movdqu xmm0, [rbp + PADDED_BLOCK]
	jmp AESEncrypt_Loop_Enc
	
AESEncrypt_Loop_RegBlock:
	movdqu xmm0, [rax + rcx]				;Initial block data
AESEncrypt_Loop_Enc:
	lea rdx, [rbp + ROUND_KEYS]
	movdqu xmm1, [rbp + IV]					;Get the IV
	movdqu xmm2, [rdx]						;Get Key Pt 1
	pxor xmm0, xmm1
	pxor xmm0, xmm2
	
	movdqu xmm1, [rdx + 0x10]
	movdqu xmm2, [rdx + 0x20]
	movdqu xmm3, [rdx + 0x30]
	movdqu xmm4, [rdx + 0x40]
	movdqu xmm5, [rdx + 0x50]
	movdqu xmm6, [rdx + 0x60]
	movdqu xmm7, [rdx + 0x70]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7
	
	movdqu xmm1, [rdx + 0x80]
	movdqu xmm2, [rdx + 0x90]
	movdqu xmm3, [rdx + 0xA0]
	movdqu xmm4, [rdx + 0xB0]
	movdqu xmm5, [rdx + 0xC0]
	movdqu xmm6, [rdx + 0xD0]
	movdqu xmm7, [rdx + 0xE0]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenclast xmm0, xmm7

	lea rdx, [r8 + rcx]						;Position in buffer
	movdqu [rdx], xmm0						;store block
	movdqu [rbp + IV], xmm0					;Overwrite IV with State (for CBC)
	add rcx, 0x10							;Add one block to count
	jmp AESEncrypt_Loop
AESEncrypt_Finish:
	mov rax, rbp							;Position of variables in stack
	mov rcx, 0x121							;Size of stack allocated
	call Zero								;Zero it all!
	
	add rsp, 0x121							;adjust stack pointer back
	pop rbp
	
	ret

	;int _Decrypt(char* Cipher, int64 size, char* IV, char* Key, char* Buffer)
Decrypt:
	mov rbx, rsi							;Get second parameter (Text Size)
	mov rax, rdi							;Get first parameter (Plaintext Ptr)
	call AESDecrypt
	ret
	
	;rax = ptr cipher, rbx = size, rcx = ptr key, rdx = ptr IV
AESDecrypt:
	push rbp
	
	;Stack
	;|------------------------------------------|
	;|	0x0000	|	IV							|
	;|----------|-------------------------------|
	;|	0x0010	|	Round Keys (15 in total)	|
	;|----------|-------------------------------|
	;|	0x0100	|	Total Size (Qword)			|
	;|----------|-------------------------------|
	
	sub rsp, 0x108							;Create room on stack for local vars
	mov rbp, rsp	
	
	movdqu xmm0, [rdx]						;Grab IV
	movdqu [rbp + IV], xmm0					;Store On Stack
	movdqu xmm0, [rcx]						;Grab Key Pt 1
	movdqu [rbp + ROUND_KEYS], xmm0			;Store On Stack
	movdqu xmm0, [rcx + 0x10]				;Grab Key Pt 2
	movdqu [rbp + ROUND_KEYS + 0x10], xmm0	;Store On Stack
	mov [rbp + TOTAL_SIZE], rbx				;Store Total Size
	
	push rax
	
	lea rax, [rbp + ROUND_KEYS]
	call CreateSchedule

	lea rcx, [rbp + ROUND_KEYS]
	call InvMixColRounds

	pop rax
	mov rbx, [rbp + TOTAL_SIZE]				;Will only store the size
	xor rcx, rcx							;Will keep track of progress through
AESDecrypt_Loop:
	lea rdx, [rbp + ROUND_KEYS]
	movdqu xmm0, [rax + rcx]				;Initial block data
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
	movdqu xmm2, [rdx]						;Get Key Pt 1
	aesdeclast xmm0, xmm2
	pxor xmm0, xmm1
	
	lea rdx, [r8 + rcx]						;Current pos in Plaintext
	movdqu [rdx], xmm0						;Store block
	movdqu [rbp + IV], xmm8					;Overwrite IV with original state (for CBC)
	add rcx, 0x10							;Add one block to count
	cmp rcx, rbx
	jne AESDecrypt_Loop
	
	add rdx, 0x0F							;last byte of plaintext
	xor rbx, rbx
	mov bl, byte [rdx]
	mov rax, [rbp + TOTAL_SIZE]
	sub rax, rbx							;Get Size of message assuming PKCS 7
	push rax
	
	mov rax, rbp							;Position of stack vars
	mov rcx, 0x108							;Size of stack
	call Zero								;Zero it
	
	pop rax
	add rsp, 0x108							;adjust stack pointer back
	pop rbp

	ret

CreateSchedule:
	movdqu xmm1, [rax]						;Bytes 0-15 of 256bit private key
	movdqu xmm2, [rax + 0x10]				;Bytes 16-31 of 256bit private key
	
	add rax, 0x20							;Roundkeys offset, set to 32 bytes
	aeskeygenassist xmm3, xmm2, 0x01
	call KeyExpansion_1
	movdqu [rax], xmm1						;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0x10], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x02
	call KeyExpansion_1
	movdqu [rax + 0x20], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0x30], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x04
	call KeyExpansion_1
	movdqu [rax + 0x40], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0x50], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x08
	call KeyExpansion_1
	movdqu [rax + 0x60], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0x70], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x10
	call KeyExpansion_1
	movdqu [rax + 0x80], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0x90], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x20
	call KeyExpansion_1
	movdqu [rax + 0xA0], xmm1				;Store in schedule
	call KeyExpansion_2
	movdqu [rax + 0xB0], xmm2				;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x40
	call KeyExpansion_1
	movdqu [rax + 0xC0], xmm1				;Store in schedule
	ret

InvMixColRounds:
	movdqu xmm2, [rcx + 0x10]
	movdqu xmm3, [rcx + 0x20]
	movdqu xmm4, [rcx + 0x30]
	movdqu xmm5, [rcx + 0x40]
	movdqu xmm6, [rcx + 0x50]
	movdqu xmm7, [rcx + 0x60]
    aesimc xmm1, xmm2
    movdqu [rcx + 0x10], xmm1
    aesimc xmm1, xmm3
    movdqu [rcx + 0x20], xmm1
    aesimc xmm1, xmm4
    movdqu [rcx + 0x30], xmm1
    aesimc xmm1, xmm5
    movdqu [rcx + 0x40], xmm1
    aesimc xmm1, xmm6
    movdqu [rcx + 0x50], xmm1
    aesimc xmm1, xmm7
    movdqu [rcx + 0x60], xmm1
	
	movdqu xmm2, [rcx + 0x70]
	movdqu xmm3, [rcx + 0x80]
	movdqu xmm4, [rcx + 0x90]
	movdqu xmm5, [rcx + 0xA0]
	movdqu xmm6, [rcx + 0xB0]
	movdqu xmm7, [rcx + 0xC0]
    aesimc xmm1, xmm2
    movdqu [rcx + 0x70], xmm1
    aesimc xmm1, xmm3
    movdqu [rcx + 0x80], xmm1
    aesimc xmm1, xmm4
    movdqu [rcx + 0x90], xmm1
    aesimc xmm1, xmm5
    movdqu [rcx + 0xA0], xmm1
    aesimc xmm1, xmm6
    movdqu [rcx + 0xB0], xmm1
    aesimc xmm1, xmm7
    movdqu [rcx + 0xC0], xmm1
	
	movdqu xmm2, [rcx + 0xD0]
    aesimc xmm1, xmm2
    movdqu [rcx + 0xD0], xmm1
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