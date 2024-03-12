#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

#include "libs/nklfsr/cipher.h"

// this is the key all versions of this NK cipher use
// it seems hardcoded in their version of this library
// however in case its ever changed, I added the feature
// of specifying a custom key.
unsigned char default_key[12] =
{
	0x78, 0x56, 0xB4, 0xC2,
	0xEF, 0xCD, 0xAB, 0x90,
	0x55, 0x84, 0x26, 0xFE
};

int main(int argc, char** argv)
{
	// test case - the wallpaper from the SPE destover sample
	HANDLE hEncryptedWallpaper = CreateFileW(L"wall.bin", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(hEncryptedWallpaper == INVALID_HANDLE_VALUE)
	{
		wprintf(L"we could not open test case! - 0x%08X\n", GetLastError());
		return 1;
	}
	
	DWORD rb = 0;
	DWORD zeWallpsize = GetFileSize(hEncryptedWallpaper, NULL);
	BYTE *zeWallpaper = (BYTE*)LocalAlloc(LMEM_ZEROINIT, zeWallpsize);
	
	if(!ReadFile(hEncryptedWallpaper, zeWallpaper, zeWallpsize, &rb, NULL))
	{
		wprintf(L"we could not read test case! - 0x%08X\n", GetLastError());
		LocalFree(zeWallpaper);
		CloseHandle(hEncryptedWallpaper);
		return 1;
	}
	
	CloseHandle(hEncryptedWallpaper);
	
	/////////////////////////////////////////////////////////////////////////////////
	
	LFSR_ctx ctx;
	LFSR_init(&ctx, default_key);
	
	LFSR_encryptdecrypt(&ctx, zeWallpaper, zeWallpsize);
	
	/////////////////////////////////////////////////////////////////////////////////
	
	HANDLE hDecryptedWallpaper = CreateFileW(L"wall.bmp", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if(hDecryptedWallpaper == INVALID_HANDLE_VALUE)
	{
		wprintf(L"we could not open result case! - 0x%08X\n", GetLastError());
		return 1;
	}
	
	DWORD wb = 0;
	if(!WriteFile(hDecryptedWallpaper, zeWallpaper, zeWallpsize, &rb, NULL))
	{
		wprintf(L"we could not write result case! - 0x%08X\n", GetLastError());
		LocalFree(zeWallpaper);
		CloseHandle(hDecryptedWallpaper);
		return 1;
	}
	
	LocalFree(zeWallpaper);
	CloseHandle(hDecryptedWallpaper);
	
	/////////////////////////////////////////////////////////////////////////////////
	
	// unit testing, basic example of encrypting decrypting data.
	unsigned char test_data[] = "Hello world!";
	DWORD test_len = lstrlenA((CHAR*)test_data);
	
	for(DWORD i = 0; i < 5; i++)
	{	
		LFSR_init(&ctx, default_key);
		LFSR_encryptdecrypt(&ctx, test_data, test_len);
		
		wprintf(L"Encrypted test: ");
		for(DWORD j = 0; j < test_len; j++)
		{
			wprintf(L"%02X", test_data[j]);
		}
		wprintf(L"\r\n");
		
		LFSR_init(&ctx, default_key);
		LFSR_encryptdecrypt(&ctx, test_data, test_len);
		
		wprintf(L"Decrypted test: %s\r\n\r\n", test_data);
	}
	
	/////////////////////////////////////////////////////////////////////////////////
	
	return 0;
}