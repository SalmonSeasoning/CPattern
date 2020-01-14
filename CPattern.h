#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdlib>

class CPattern
{
public:
	CPattern(const char* szModule, const char* szSignature, const char* szMask, uintptr_t iOffset = 0)
	{
		this->m_szModule = szModule;
		this->m_szSignature = szSignature;
		this->m_szMask = szMask;
		this->m_iOffset = iOffset;
	}
	CPattern(const wchar_t* szModule, const wchar_t* szSignature, const wchar_t* szMask, uintptr_t iOffset = 0)
	{
		this->m_szuModule = szModule;
		this->m_szuSignature = szSignature;
		this->m_szuMask = szMask;
		this->m_iOffset = iOffset;
	}
	uintptr_t FindPatternA()
	{
		// Get module info
		MODULEINFO modInfo = { 0 };
		HMODULE hModule = NULL;
		if ((hModule = GetModuleHandleA(this->m_szModule)) == NULL) return NULL;
		GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
		// uintptr_t will be 4-bytes 32-bit (a.k.a. same as DWORD) and 8-bytes 64-bit (also same as DWORD)
		uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
		uintptr_t size = (uintptr_t)modInfo.SizeOfImage;

		uintptr_t sigLength = (uintptr_t)strlen(this->m_szMask);

		for (uintptr_t i = 0; i < size - sigLength; i++)
		{
			bool found = true;
			for (uintptr_t j = 0; j < sigLength; j++)
			{
				found &= this->m_szMask[j] == '?' || this->m_szSignature[j] == *(char*)(base + i + j);
			}
			if (found) return (base + i + this->m_iOffset);
		}

		return 0;
	}
	uintptr_t FindPatternW()
	{
		// Get module info
		MODULEINFO modInfo = { 0 };
		HMODULE hModule = NULL;
		if ((hModule = GetModuleHandleW(this->m_szuModule)) == NULL) return NULL;
		GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
		// uintptr_t will be 4-bytes 32-bit (a.k.a. same as DWORD) and 8-bytes 64-bit (also same as DWORD)
		uintptr_t base = (uintptr_t)modInfo.lpBaseOfDll;
		uintptr_t size = (uintptr_t)modInfo.SizeOfImage;

		uintptr_t sigLength = (uintptr_t)wcslen(this->m_szuMask);

		for (uintptr_t i = 0; i < size - sigLength; i++)
		{
			bool found = true;
			for (uintptr_t j = 0; j < sigLength; j++)
			{
				found &= this->m_szuMask[j] == '?' || this->m_szuSignature[j] == *(char*)(base + i + j);
			}
			if (found) return (base + i + this->m_iOffset);
		}

		return 0;
	}
private:
	const char* m_szSignature = nullptr;
	const char* m_szMask = nullptr;
	const char* m_szModule = nullptr;
	const wchar_t* m_szuSignature = nullptr;
	const wchar_t* m_szuMask = nullptr;
	const wchar_t* m_szuModule = nullptr;
	uintptr_t m_iOffset = 0;
};