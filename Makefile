test:
	nasm -f elf64 -o AES.o AES.asm
	g++ -c main.cpp -o main.o
	g++ -o a.exe AES.o main.o
win:
	nasm -f win64 -o AES.o AES.asm
	g++ -c main.cpp -o main.o -DWINDOWS
	g++ -o a.exe AES.o main.o