global EncryptWin
global DecryptWin
global EncryptNix
global DecryptNix
global AESNI

IV                  equ 0x0000
ROUND_KEYS          equ 0x0010
TOTAL_SIZE          equ 0x0100
REAL_SIZE           equ 0x0108
PADDED_BLOCK        equ 0x0110
PAD_SIZE            equ 0x0120
BOUNDARY_ALIGN_ENC  equ 0x0121
BOUNDARY_ALIGN_DEC  equ 0x0108

section .text

	;bool AESNI()
AESNI:
	xor rax, rax
	xor rcx, rcx
	push rbx
	cpuid
	cmp rax, 1
	jl AESNI_False
	mov rax, 1
	xor rcx, rcx
	cpuid
	test rcx, 0x2000000
	jz AESNI_False
AESNI_True:
	mov rax, 1
	pop rbx
	ret
AESNI_False:
	mov rax, 0
	pop rbx
	ret

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

	;void Encrypt(const uint8_t* plaintext, const unsigned int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* ciphertextOut, BOOL usePKCS7Pad /*Instead of zero-padding*/)
EncryptNix:
	push rbx                                                ;Preserve non-volatile register
	mov rbx, rsi                                            ;Get second parameter (Text Size)
	mov rax, rdi                                            ;Get first parameter (Plaintext Ptr)
	call AESEncrypt
	pop rbx
	ret
EncryptWin:
	push rbx                                                ;Preserve Windows non-volatile register
	mov rax, rcx                                            ;Get first parameter (Plaintext Ptr)
	mov rbx, rdx                                            ;Get second parameter (Text Size)
	mov rdx, r8                                             ;Get third parameter (IV Ptr)
	mov rcx, r9                                             ;Get fourth parameter (Key Ptr)
	mov r8,	[rsp+0x28]                                      ;Get fifth parameter (Buffer Ptr)
	mov r9,	[rsp+0x30]                                      ;Get sixth parameter (Use PKCS 7 Padding)

	call AESEncrypt
	pop rbx
	ret

	;rax = ptr plaintext, rbx = text size, rcx = ptr key, rdx = ptr IV, r8 = Buffer to fill, r9 = Use PKCS 7 Padding
AESEncrypt:
	push rbp

	;Stack
	;|------------------------------------------|
	;|   0x0000 |   IV                          |
	;|----------|-------------------------------|
	;|   0x0010 |   Round Keys (15 in total)    |
	;|----------|-------------------------------|
	;|   0x0100 |   Total Size (Qword)          |
	;|----------|-------------------------------|
	;|   0x0108 |   Real Size (Qword)           |
	;|----------|-------------------------------|
	;|   0x0110 |   Padded Block                |
	;|----------|-------------------------------|
	;|   0x0120 |   Pad Size (Byte)             |
	;|----------|-------------------------------|
	;|   0x0121 |   Boundary Align (Byte)       |
	;|----------|-------------------------------|

	sub rsp, 0x122                                          ;Create room on stack for local vars
	mov rbp, rsp                                            ;Get rsp after offset
	and rsp, 0xFFFFFFFFFFFFFFF0                             ;Round rsp down to nearest 16 byte boundary
	sub rbp, rsp                                            ;Determine how much the rounding offset rsp
	mov [rsp + BOUNDARY_ALIGN_ENC], bpl                     ;Store this offset
	mov rbp, rsp                                            ;Set rbp to the 16 byte boundary

	movdqu xmm0, [rdx]                                      ;Grab IV
	movdqa [rbp + IV], xmm0                                 ;Store On Stack
	movdqu xmm0, [rcx]                                      ;Grab Key Pt 1
	movdqa [rbp + ROUND_KEYS], xmm0                         ;Store On Stack
	movdqu xmm0, [rcx + 0x10]                               ;Grab Key Pt 2
	movdqa [rbp + ROUND_KEYS + 0x10], xmm0                  ;Store On Stack
	mov [rbp + REAL_SIZE], rbx                              ;Store Real Size

	push rax                                                ;Store plaintext ptr

	;Get Padding Info
	xor rdx, rdx                                            ;Clear the destination
	mov rax, rbx                                            ;Get message size
	mov rcx, 0x10                                           ;16 bytes block size
	div rcx                                                 ;Remainder stored in rdx
	xor rax, rax
	test r9, r9                                             ;Test if UsePKCS7Pad has a bit set
	jnz AESEncrypt_PadInfo_UsePKCS7
	test rdx, rdx                                           ;If its a multiple of the block size...
	jz AESEncrypt_StorePadSize                              ;...no padding needed. Else, same pad size as PKCS 7
AESEncrypt_PadInfo_UsePKCS7:
	mov al, 0x10                                            ;One block size
	sub al, dl                                              ;Get difference between remainder and size
AESEncrypt_StorePadSize:
	mov byte [rbp + PAD_SIZE], al                           ;Store
	add rax, rbx                                            ;Message length + pad size
	mov [rbp + TOTAL_SIZE], rax

	mov rax, [rsp]                                          ;Get plaintext ptr
AESEncrypt_Pad:
	add rax, [rbp + TOTAL_SIZE]                             ;Theoretical end of padded message
	sub rax, 0x10                                           ;Beginning of last block's text
	lea rbx, [rbp + PADDED_BLOCK]                           ;Point to our final (and possibly padded) block
	mov rcx, 0x10                                           ;Get block size
	sub cl, byte [rbp + PAD_SIZE]                           ;Subtract pad size to get bytes of padded block that are from original message (may be equal to zero or 16)
	call Memcpy

	mov cl, byte [rbp + PAD_SIZE]                           ;Times to write value
	test r9, r9                                             ;Test if UsePKCS7Pad has a bit set
	jnz AESEncrypt_Padding_UsePKCS7
	mov rax, 0
	test rcx, rcx
	jz AESEncrypt_Pad_LoopEnd
	jmp AESEncrypt_Padding
AESEncrypt_Padding_UsePKCS7:
	mov rax, rcx
AESEncrypt_Padding:
	add rbx, 0x10                                           ;End of padded block
	xor rdx, rdx
	mov dl, byte [rbp + PAD_SIZE]
	sub rbx, rdx                                            ;Start of where to pad in block
AESEncrypt_Pad_Loop:
	mov byte [rbx + rcx - 1], al
	loop AESEncrypt_Pad_Loop
AESEncrypt_Pad_LoopEnd:

	;Create key schedule
	lea rax, [rbp + ROUND_KEYS]
	call CreateSchedule
	pop rax                                                 ;Retrieve plaintext pointer

	xor rcx, rcx                                            ;Will keep track of progress through
AESEncrypt_Loop:
	mov rbx, [rbp + TOTAL_SIZE]                             ;Get total padded size
	cmp rcx, rbx
	je AESEncrypt_Finish                                    ;We have encrypted the last (padded) block
	sub rbx, rcx                                            ;Bytes left to encrypt
	cmp rbx, 0x10
	jnz AESEncrypt_Loop_RegBlock
	movdqa xmm0, [rbp + PADDED_BLOCK]
	jmp AESEncrypt_Loop_Enc

AESEncrypt_Loop_RegBlock:
	movdqu xmm0, [rax + rcx]                                ;Initial block data
AESEncrypt_Loop_Enc:
	lea rdx, [rbp + ROUND_KEYS]
	movdqa xmm1, [rbp + IV]                                 ;Get the IV
	movdqa xmm2, [rdx]                                      ;Get Key Pt 1
	pxor xmm0, xmm1
	pxor xmm0, xmm2

	movdqa xmm1, [rdx + 0x10]
	movdqa xmm2, [rdx + 0x20]
	movdqa xmm3, [rdx + 0x30]
	movdqa xmm4, [rdx + 0x40]
	movdqa xmm5, [rdx + 0x50]
	movdqa xmm6, [rdx + 0x60]
	movdqa xmm7, [rdx + 0x70]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7

	movdqa xmm1, [rdx + 0x80]
	movdqa xmm2, [rdx + 0x90]
	movdqa xmm3, [rdx + 0xA0]
	movdqa xmm4, [rdx + 0xB0]
	movdqa xmm5, [rdx + 0xC0]
	movdqa xmm6, [rdx + 0xD0]
	movdqa xmm7, [rdx + 0xE0]
	aesenc xmm0, xmm1
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenclast xmm0, xmm7

	lea rdx, [r8 + rcx]                                     ;Position in buffer
	movdqu [rdx], xmm0                                      ;Store block
	movdqa [rbp + IV], xmm0                                 ;Overwrite IV with State (for CBC)
	add rcx, 0x10                                           ;Add one block to count
	jmp AESEncrypt_Loop
AESEncrypt_Finish:
	mov rax, rbp                                            ;Position of variables in stack
	mov rcx, 0x121                                          ;Size of stack allocated (minus alignment)
	call Zero                                               ;Zero it!

	add rsp, 0x122                                          ;Adjust stack pointer back
	xor rbx, rbx
	mov bl, byte [rbp + BOUNDARY_ALIGN_ENC]
	add rsp, rbx                                            ;Add back boundary offset
	pop rbp                                                 ;Get original rpb

	ret

	;int Decrypt(const uint8_t* ciphertext, const unsigned int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* plaintextOut, BOOL expectPKCS7Pad /*Instead of zero-padding*/)
DecryptNix:
	push rbx
	mov rbx, rsi                                            ;Get second parameter (Text Size)
	mov rax, rdi                                            ;Get first parameter (Plaintext Ptr)
	call AESDecrypt
	pop rbx
	ret
DecryptWin:
	push rbx
	mov rax, rcx                                            ;Get first parameter (Cipher Ptr)
	mov rbx, rdx                                            ;Get second parameter (Text Size)
	mov rdx, r8                                             ;Get third parameter (IV Ptr)
	mov rcx, r9                                             ;Get fourth parameter (Key Ptr)
	mov r8,	[rsp+0x28]                                      ;Get fifth parameter (Buffer Ptr)
	mov r9,	[rsp+0x30]                                      ;Get sixth parameter (Expect PKCS7 Padding)

	call AESDecrypt
	pop rbx
	ret

	;rax = ptr cipher, rbx = size, rcx = ptr key, rdx = ptr IV, r8 = Buffer to fill, r9 = Use PKCS 7 Padding
AESDecrypt:
	push rbp

	;Stack
	;|------------------------------------------|
	;|   0x0000 |   IV                          |
	;|----------|-------------------------------|
	;|   0x0010 |   Round Keys (15 in total)    |
	;|----------|-------------------------------|
	;|   0x0100 |   Total Size (Qword)          |
	;|----------|-------------------------------|
	;|   0x0108 |   Boundary Align (Byte)       |
	;|----------|-------------------------------|

	sub rsp, 0x109                                          ;Create room on stack for local vars
	mov rbp, rsp
	and rsp, 0xFFFFFFFFFFFFFFF0                             ;Round rsp down to nearest 16 byte boundary
	sub rbp, rsp
	mov [rsp + BOUNDARY_ALIGN_DEC], bpl
	mov rbp, rsp

	movdqu xmm0, [rdx]                                      ;Grab IV
	movdqa [rbp + IV], xmm0                                 ;Store On Stack
	movdqu xmm0, [rcx]                                      ;Grab Key Pt 1
	movdqa [rbp + ROUND_KEYS], xmm0                         ;Store On Stack
	movdqu xmm0, [rcx + 0x10]                               ;Grab Key Pt 2
	movdqa [rbp + ROUND_KEYS + 0x10], xmm0                  ;Store On Stack
	mov [rbp + TOTAL_SIZE], rbx                             ;Store Total Size

	push rax

	lea rax, [rbp + ROUND_KEYS]
	call CreateSchedule

	lea rcx, [rbp + ROUND_KEYS]
	call InvMixColRounds

	pop rax
	mov rbx, [rbp + TOTAL_SIZE]                             ;Store total bytes to write
	xor rcx, rcx                                            ;Will keep track of progress through
AESDecrypt_Loop:
	lea rdx, [rbp + ROUND_KEYS]
	movdqu xmm0, [rax + rcx]                                ;Initial block data
	movdqa xmm8, xmm0                                       ;Store to be next IV

	movdqa xmm1, [rdx + 0x80]
	movdqa xmm2, [rdx + 0x90]
	movdqa xmm3, [rdx + 0xA0]
	movdqa xmm4, [rdx + 0xB0]
	movdqa xmm5, [rdx + 0xC0]
	movdqa xmm6, [rdx + 0xD0]
	movdqa xmm7, [rdx + 0xE0]
	pxor xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdec xmm0, xmm1

	movdqa xmm1, [rdx + 0x10]
	movdqa xmm2, [rdx + 0x20]
	movdqa xmm3, [rdx + 0x30]
	movdqa xmm4, [rdx + 0x40]
	movdqa xmm5, [rdx + 0x50]
	movdqa xmm6, [rdx + 0x60]
	movdqa xmm7, [rdx + 0x70]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdec xmm0, xmm1

	movdqa xmm1, [rbp]                                      ;Get IV
	movdqa xmm2, [rdx]                                      ;Get Key Pt 1
	aesdeclast xmm0, xmm2
	pxor xmm0, xmm1

	lea rdx, [r8 + rcx]                                     ;Current pos in Ciphertext
	movdqu [rdx], xmm0                                      ;Store block
	movdqa [rbp + IV], xmm8                                 ;Overwrite IV with original state (for CBC)
	add rcx, 0x10                                           ;Add one block to count
	cmp rcx, rbx
	jne AESDecrypt_Loop

	mov rax, [rbp + TOTAL_SIZE]
	test r9, r9                                             ;Check if expecting PKCS7 padding (and to check for it)
	jz AESDecrypt_Finish
	add rdx, 0x0F                                           ;Last byte of ciphertext
	xor rbx, rbx
	mov bl, byte [rdx]
	sub rax, rbx                                            ;Get Size of message assuming PKCS 7

	mov rcx, rbx                                            ;Last byte val = number to check
	lea rdx, [r8 + rax]                                     ;Start of padding
AESDecrypt_CheckPad_Loop:
	cmp byte [rdx + rcx - 1], bl
	jne AESDecrypt_BadPad
	mov byte [rdx + rcx - 1], 0x00                          ;Zero it (it's padding, we don't need it. Plus helps out good ol' c strings)
	loop AESDecrypt_CheckPad_Loop

AESDecrypt_Finish:
	push rax
	mov rax, rbp                                            ;Position of stack vars
	mov rcx, 0x108                                          ;Size of stack minus boundary
	call Zero                                               ;Zero it

	pop rax
	add rsp, 0x109                                          ;Adjust stack pointer back
	xor rbx, rbx
	mov bl, byte [rbp + BOUNDARY_ALIGN_DEC]
	add rsp, rbx                                            ;Add back boundary offset
	pop rbp

	ret
AESDecrypt_BadPad:
	mov rax, rbp                                            ;Position of stack vars
	mov rcx, 0x108                                          ;Size of stack
	call Zero                                               ;Zero it

	mov rax, -1
	add rsp, 0x109                                          ;Adjust stack pointer back
	xor rbx, rbx
	mov bl, byte [rbp + BOUNDARY_ALIGN_DEC]
	add rsp, rbx                                            ;Add back boundary offset
	pop rbp

	ret

CreateSchedule:
	movdqa xmm1, [rax]                                      ;Bytes 0-15 of 256 bit private key
	movdqa xmm2, [rax + 0x10]                               ;Bytes 16-31 of 256 bit private key

	add rax, 0x20                                           ;Roundkeys offset, set to 32 bytes
	aeskeygenassist xmm3, xmm2, 0x01
	call KeyExpansion_1
	movdqa [rax], xmm1                                      ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0x10], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x02
	call KeyExpansion_1
	movdqa [rax + 0x20], xmm1                               ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0x30], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x04
	call KeyExpansion_1
	movdqa [rax + 0x40], xmm1                               ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0x50], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x08
	call KeyExpansion_1
	movdqa [rax + 0x60], xmm1                               ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0x70], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x10
	call KeyExpansion_1
	movdqa [rax + 0x80], xmm1                               ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0x90], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x20
	call KeyExpansion_1
	movdqa [rax + 0xA0], xmm1                               ;Store in schedule
	call KeyExpansion_2
	movdqa [rax + 0xB0], xmm2                               ;Store in schedule
	aeskeygenassist xmm3, xmm2, 0x40
	call KeyExpansion_1
	movdqa [rax + 0xC0], xmm1                               ;Store in schedule
	ret

InvMixColRounds:
	movdqa xmm2, [rcx + 0x10]
	movdqa xmm3, [rcx + 0x20]
	movdqa xmm4, [rcx + 0x30]
	movdqa xmm5, [rcx + 0x40]
	movdqa xmm6, [rcx + 0x50]
	movdqa xmm7, [rcx + 0x60]
	aesimc xmm1, xmm2
	movdqa [rcx + 0x10], xmm1
	aesimc xmm1, xmm3
	movdqa [rcx + 0x20], xmm1
	aesimc xmm1, xmm4
	movdqa [rcx + 0x30], xmm1
	aesimc xmm1, xmm5
	movdqa [rcx + 0x40], xmm1
	aesimc xmm1, xmm6
	movdqa [rcx + 0x50], xmm1
	aesimc xmm1, xmm7
	movdqa [rcx + 0x60], xmm1

	movdqa xmm2, [rcx + 0x70]
	movdqa xmm3, [rcx + 0x80]
	movdqa xmm4, [rcx + 0x90]
	movdqa xmm5, [rcx + 0xA0]
	movdqa xmm6, [rcx + 0xB0]
	movdqa xmm7, [rcx + 0xC0]
	aesimc xmm1, xmm2
	movdqa [rcx + 0x70], xmm1
	aesimc xmm1, xmm3
	movdqa [rcx + 0x80], xmm1
	aesimc xmm1, xmm4
	movdqa [rcx + 0x90], xmm1
	aesimc xmm1, xmm5
	movdqa [rcx + 0xA0], xmm1
	aesimc xmm1, xmm6
	movdqa [rcx + 0xB0], xmm1
	aesimc xmm1, xmm7
	movdqa [rcx + 0xC0], xmm1

	movdqa xmm2, [rcx + 0xD0]
	aesimc xmm1, xmm2
	movdqa [rcx + 0xD0], xmm1
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
