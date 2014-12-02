test: test.o
	ld test.o -o test

test.o: AES.asm
	nasm -f elf64 AES.asm -o test.o
