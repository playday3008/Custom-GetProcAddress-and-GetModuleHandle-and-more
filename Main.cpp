#include <iostream>
#include <fstream>

#include <Windows.h>
#include <tchar.h>

#include "CustomWinApi.h"

#ifdef UNICODE
#define _tcout wcout
#else
#define _tcout cout
#endif

using namespace std;

//////////////////////////////////////////////////////////////////////////////////////////////////
//										Usage examples below
//////////////////////////////////////////////////////////////////////////////////////////////////
int main()
{
	auto hKernel32 = GetModule(_T("kernel32"));
	_tcout << _T("hKernel32 = 0x") << hex << hKernel32 << endl;

	auto FncDeleteFileA = reinterpret_cast<void*>(GetExportAddress(hKernel32, "DeleteFileA", TRUE));
	_tcout << _T("GetExportAddress( hKernel32, \"DeleteFileA\", TRUE ) => 0x") << hex << FncDeleteFileA << endl;

	_tcout << _T("Function offset: (FncDeleteFileA - hKernel32) => 0x") << hex <<
		reinterpret_cast<unsigned char*>(FncDeleteFileA) - reinterpret_cast<unsigned char*>(hKernel32) << endl;

	ifstream hKernel32File(_T("C:\\Windows\\System32\\kernel32.dll"), ios::binary);
	hKernel32File.seekg(0, hKernel32File.end);
	auto Kernel32FileSize = static_cast<SIZE_T>(hKernel32File.tellg());
	hKernel32File.seekg(0, hKernel32File.beg);
	auto Kernel32FileContent = VirtualAlloc(NULL, Kernel32FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Kernel32FileContent) {
		hKernel32File.close();
		return 1;
	}
	hKernel32File.read(reinterpret_cast<char*>(Kernel32FileContent), Kernel32FileSize);
	hKernel32File.close();

	_tcout << _T("Kernel32FileContent => 0x") << hex << Kernel32FileContent << endl;

	FncDeleteFileA = reinterpret_cast<void*>(GetExportAddress(reinterpret_cast<HMODULE>(Kernel32FileContent), "DeleteFileA", FALSE));

	_tcout << _T("DeleteFileA inside Kernel32FileContent => 0x") << hex << FncDeleteFileA << endl;

	auto DeleteFileA_RVA = ImageVaToRva(Kernel32FileContent, FncDeleteFileA);

	_tcout << _T("DeleteFileA_RVA => 0x") << hex << DeleteFileA_RVA << _T(" {will be same as function offset above ;)}") << endl;

	FncDeleteFileA = reinterpret_cast<void*>(reinterpret_cast<unsigned char*>(hKernel32) + DeleteFileA_RVA);
	_tcout << _T("hKernel32 + DeleteFileA_RVA => 0x") << hex << FncDeleteFileA << endl;

	VirtualFree(Kernel32FileContent, NULL, MEM_RELEASE);

	//can be used to get a function offset of a 32bit dll when currently running as 64bit ;)

	ifstream h_32Bit_Kernel32File(_T("C:\\Windows\\System32\\kernel32.dll"), ios::binary);
	h_32Bit_Kernel32File.seekg(0, h_32Bit_Kernel32File.end);
	auto _32Bit_Kernel32FileSize = static_cast<SIZE_T>(h_32Bit_Kernel32File.tellg());
	h_32Bit_Kernel32File.seekg(0, h_32Bit_Kernel32File.beg);
	auto _32Bit_Kernel32FileContent = VirtualAlloc(NULL, _32Bit_Kernel32FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!_32Bit_Kernel32FileContent) {
		h_32Bit_Kernel32File.close();
		return 1;
	}
	h_32Bit_Kernel32File.read(reinterpret_cast<char*>(_32Bit_Kernel32FileContent), _32Bit_Kernel32FileSize);
	h_32Bit_Kernel32File.close();

	auto _32Bit_FncDeleteFileA = reinterpret_cast<void*>(GetExportAddress(reinterpret_cast<HMODULE>(_32Bit_Kernel32FileContent), "DeleteFileA", FALSE));

	auto _32Bit_DeleteFileA_RVA = ImageVaToRva(_32Bit_Kernel32FileContent, _32Bit_FncDeleteFileA);
	_tcout << _T("[32Bit] DeleteFileA_RVA => 0x") << hex << _32Bit_DeleteFileA_RVA << endl;

	VirtualFree(_32Bit_Kernel32FileContent, NULL, MEM_RELEASE);

	_tsystem(_T("pause"));
}
