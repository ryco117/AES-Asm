#include <iostream>
#include <string>
#include <string.h>

extern "C"
{
	bool AESNI();
	void EncryptNix(const uint8_t* data, int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* buffer, bool usePKCS7Padding);
	int64_t DecryptNix(const uint8_t* Cipher, int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* buffer, bool expectPKCS7Padding);
	void EncryptWin(const uint8_t* data, int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* buffer, bool usePKCS7Padding);
	int64_t DecryptWin(const uint8_t* Cipher, int size, const uint8_t IV[16], const uint8_t key[32], uint8_t* buffer, bool expectPKCS7Padding);
}

int main()
{
	// Don't use non-random, hardcoded keys and IVs in production code. This is just for demonstration.
	uint8_t IV[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
	uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
	std::string message = "Hello there world! This tests arbitrarily sized plaintext! Did it work?!?";
	char buff[81] = {"\0"};

	// Recommended to use PKCS7 padding when the size of the source data is not known at decryption time.
	// This is common for user generated data, such as text.
	bool usePKCS7Padding = true;
	
	if(!AESNI())
	{
		std::cout << "AES-NI is not supported on this CPU :(" << std::endl;
		return -1;
	}
	
	bool print = true;
	if(print)
	{
		std::cout << "Original: " << message << std::endl;
	}
	#ifdef WINDOWS
		EncryptWin((uint8_t*)Message.c_str(), Message.size(), IV, Key, (uint8_t*)buff, usePKCS7Padding);
	#else
		EncryptNix((uint8_t*)message.c_str(), message.size(), IV, key, (uint8_t*)buff, usePKCS7Padding);
	#endif
	if(print)
	{
		std::cout << "Encrypted: " << buff << std::endl;
	}

	#ifdef WINDOWS
		int len = DecryptWin((const uint8_t*)buff, 80, IV, Key, (uint8_t*)buff, usePKCS7Padding);
	#else
		int len = DecryptNix((const uint8_t*)buff, 80, IV, key, (uint8_t*)buff, usePKCS7Padding);
	#endif
	if(len == -1)
	{
		if(print)
			std::cerr << "Was not padded correctly\n";
		return len;
	}
	if(print)
	{
		std::cout << "Decrypted: " << buff << std::endl;
		std::cout << "String Length: " << strlen(buff) << ", " << len << std::endl;
	}

	return 0;
}
