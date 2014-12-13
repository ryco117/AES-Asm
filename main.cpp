#include <iostream>
#include <string>

extern "C"
{
	void Encrypt(char* Text, int size, char* IV, char* Key, char* Buffer);
	int Decrypt(char* Cipher, int size, char* IV, char* Key, char* Buffer);
}

int main()
{
	char IV[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
	char Key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	std::string Message = "Hello there world! This tests aribitrarily sized plaintext! Did it work?!";
	
	char buff[81] = {0};
	Encrypt((char*)Message.c_str(), Message.size(), IV, Key, buff);
	std::cout << "Original: " << Message << std::endl;
	std::cout << "Encrypted: " << buff << std::endl;
	int len = Decrypt(buff, 80, IV, Key, buff);
	buff[len] = 0;
	std::cout << "Decrypted: " << buff << std::endl;
	return 0;
}