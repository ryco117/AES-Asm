nix:
	nasm -f elf64 -o AES.o AES.asm
	g++ -c main.cpp -o main.o -O3
	g++ -o a.out AES.o main.o -O3
win:
	nasm -f win64 -o AES.o AES.asm
	g++ -c main.cpp -o main.o -O3 -DWINDOWS
	g++ -o a.exe AES.o main.o -O3
