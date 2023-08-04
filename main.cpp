#include <iostream>
#include <string>
#include <string.h>

extern "C"
{
	bool AESNI();
	void EncryptNix(const uint8_t* Text, int size, const uint8_t IV[16], const uint8_t Key[32], uint8_t* Buffer);
	int DecryptNix(const uint8_t* Cipher, int size, const uint8_t IV[16], const uint8_t Key[32], uint8_t* Buffer);
	void EncryptWin(const uint8_t* Text, int size, const uint8_t IV[16], const uint8_t Key[32], uint8_t* Buffer);
	int DecryptWin(const uint8_t* Cipher, int size, const uint8_t IV[16], const uint8_t Key[32], uint8_t* Buffer);
}

int main()
{
	uint8_t IV[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
	uint8_t Key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	std::string Message = "Hello there world! This tests arbitrarily sized plaintext! Did it work?!?";
	char buff[81] = {"\0"};
	
	if(!AESNI())
	{
		std::cout << "AES-NI is not supported on this CPU :(\n";
		return -1;
	}
	
	bool p = true;
	if(p)
	{
		std::cout << "Original: " << Message << std::endl;
		/*std::cout << "Message Ptr: " << (unsigned long long)Message.c_str() << std::endl << "IV Ptr: " << (unsigned long long)IV << std::endl\
				  << "Key Ptr: " << (unsigned long long)Key << std::endl << "buff Ptr: " << (unsigned long long)buff << std::endl;*/
	}
	#ifdef WINDOWS
		EncryptWin((uint8_t*)Message.c_str(), Message.size(), IV, Key, (uint8_t*)buff);
	#else
		EncryptNix((uint8_t*)Message.c_str(), Message.size(), IV, Key, (uint8_t*)buff);
	#endif
	if(p)
		std::cout << "Encrypted: " << buff << std::endl;

	#ifdef WINDOWS
		int len = DecryptWin((const uint8_t*)buff, 80, IV, Key, (uint8_t*)buff);
	#else
		int len = DecryptNix((const uint8_t*)buff, 80, IV, Key, (uint8_t*)buff);
	#endif
	if(len == -1)
	{
		if(p)
			std::cout << "Was not padded correctly\n";
		return len;
	}
	if(p)
	{
		std::cout << "Decrypted: " << buff << std::endl;
		std::cout << "String Length: " << strlen(buff) << ", " << len << std::endl;
	}
	return 0;
}
