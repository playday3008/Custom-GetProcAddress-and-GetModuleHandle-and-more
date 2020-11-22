#include <algorithm>
#include <array>
#include <cwctype>
#include <filesystem>
#include <string>

#include <Windows.h>
#include <malloc.h>
#include "CustomWinApi.h"

//////////////////////////////////////////////////////////////////////////////////////////////////
//		Equivalent to the windows api function GetModuleHandleA and GetModuleHandleW
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleW( _In_opt_ LPCWSTR lpModuleName )
{
	struct CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	};

	//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00166
	struct TEB
	{
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		struct PEB* ProcessEnvironmentBlock;
		//...
	};

	//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
	struct PEB_LDR_DATA
	{
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	};
	//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
	struct PEB
	{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN SpareBits : 1;
			};
		};
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PEB_LDR_DATA* Ldr;
		//...
	};
	struct UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	};
	//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
	struct LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		//...
	};

	auto ProcessEnvironmentBlock = reinterpret_cast<PEB*>(reinterpret_cast<TEB*>(NtCurrentTeb())->ProcessEnvironmentBlock);
	if (lpModuleName == nullptr)
		return reinterpret_cast<HMODULE>(ProcessEnvironmentBlock->ImageBaseAddress);

	auto Ldr = ProcessEnvironmentBlock->Ldr;

	std::wstring moduleName = lpModuleName;
	std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);
	std::array<LIST_ENTRY*, 3> ModuleLists{};
	ModuleLists.at(0) = &Ldr->InLoadOrderModuleList;
	ModuleLists.at(1) = &Ldr->InMemoryOrderModuleList;
	ModuleLists.at(2) = &Ldr->InInitializationOrderModuleList;
	for (size_t j = 0; j < ModuleLists.size(); j++)
	{
		for (auto  pListEntry  = ModuleLists.at(j)->Flink;
						  pListEntry != ModuleLists.at(j);
						  pListEntry  = pListEntry->Flink)
		{
			auto pEntry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(reinterpret_cast<BYTE*>(pListEntry) - sizeof(LIST_ENTRY) * j); //= CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

			std::wstring buffer = pEntry->BaseDllName.Buffer;
			std::transform(buffer.begin(), buffer.end(), buffer.begin(), ::towlower);

			if (buffer == moduleName)
				return reinterpret_cast<HMODULE>(pEntry->DllBase);

			std::wstring FileName = std::filesystem::path(buffer).filename();

			if (FileName.empty())
				continue;

			if (FileName == moduleName)
				return reinterpret_cast<HMODULE>(pEntry->DllBase);

			std::wstring FileNameWithoutExtension = std::filesystem::path(buffer).stem();

			if (FileNameWithoutExtension == moduleName)
				return reinterpret_cast<HMODULE>(pEntry->DllBase);
		}
	}
	return nullptr;
}

/// <summary>
/// Retrieves the address of an loaded module by name
/// </summary>
/// <param name="lpModuleName">name of the module, zero for current module</param>
/// <returns>returns address of the module in memory</returns>
HMODULE WINAPI GetModuleA( _In_opt_ LPCSTR lpModuleName )
{
	if (!lpModuleName) 
		return GetModuleW( NULL );

	std::string ModuleName = lpModuleName;
	std::wstring W_ModuleName(ModuleName.begin(), ModuleName.end());

	auto hReturnModule =  GetModuleW( W_ModuleName.c_str() );

	return hReturnModule;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//					Equivalent to the windows api function GetProcAddress
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Retrieves the address of an exported function inside the specified module
/// </summary>
/// <param name="hModule">Address of the module</param>
/// <param name="lpProcName">Name of the exported procedure</param>
/// <param name="MappedAsImage">Is the module mapped or a raw file? (TRUE / FALSE)</param>
/// <returns>returns the exported procedure address inside the specified module</returns>
FARPROC WINAPI GetExportAddress( _In_ HMODULE hModule, _In_ LPCSTR lpProcName, _In_ BOOLEAN MappedAsImage )
{
	if (lpProcName == NULL)
		return nullptr;

	unsigned short ProcOrdinal = USHRT_MAX;
	if (reinterpret_cast<ULONG_PTR>(lpProcName) < USHRT_MAX)
		ProcOrdinal = reinterpret_cast<ULONG_PTR>(lpProcName) & USHRT_MAX;
	else
		//in case of "#123" resolve the ordinal to 123
		if (lpProcName[0] == '#')
		{
			DWORD OrdinalFromString = atoi(lpProcName + 1);
			if (OrdinalFromString < USHRT_MAX &&
				OrdinalFromString != 0)
			{
				ProcOrdinal = OrdinalFromString & USHRT_MAX;
				lpProcName = reinterpret_cast<LPCSTR>(ProcOrdinal);
			}
		}
	auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
	if ( !DosHeader || DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	//only OptionalHeader is different between 64bit and 32bit so try not to touch it!
	auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<DWORD_PTR>(DosHeader) + DosHeader->e_lfanew );
	if ( NtHeader->Signature != IMAGE_NT_SIGNATURE )
		return nullptr;

	ULONG ExportDirectorySize = NULL;
	auto ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(ImageDirectoryEntryToDataEx( DosHeader, MappedAsImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirectorySize ));
	if ( !ExportDirectory || !ExportDirectorySize )
		return nullptr;

	//check if any export functions are present
	if ( !ExportDirectory->NumberOfFunctions )
		return nullptr;

	//from BlackBone
	//https://github.com/DarthTon/Blackbone/blob/3dc33d815011b83855af607013d34c836b9d0877/src/BlackBone/Process/ProcessModules.cpp#L266
	// Fix invalid directory size
	if (ExportDirectorySize <= sizeof(IMAGE_EXPORT_DIRECTORY))
		// New size should take care of max number of present names (max name length is assumed to be 255 chars)
		ExportDirectorySize = static_cast<DWORD>(ExportDirectory->AddressOfNameOrdinals -
			static_cast<DWORD>(reinterpret_cast<BYTE*>(ExportDirectory) - reinterpret_cast<BYTE*>(DosHeader))
			+ max(ExportDirectory->NumberOfFunctions, ExportDirectory->NumberOfNames) * 255);

	DWORD AddressOfNamesRVA			= ExportDirectory->AddressOfNames;
	DWORD AddressOfFunctionsRVA		= ExportDirectory->AddressOfFunctions;
	DWORD AddressOfNameOrdinalsRVA	= ExportDirectory->AddressOfNameOrdinals;

	auto ExportNames = reinterpret_cast<DWORD*>( MappedAsImage ? (reinterpret_cast<BYTE*>(DosHeader) + AddressOfNamesRVA) : ImageRvaToVa( NtHeader, DosHeader, AddressOfNamesRVA));
	auto Functions = reinterpret_cast<DWORD*>( MappedAsImage ? (reinterpret_cast<BYTE*>(DosHeader) + AddressOfFunctionsRVA) : ImageRvaToVa( NtHeader, DosHeader, AddressOfFunctionsRVA));
	auto Ordinals = reinterpret_cast<WORD*>( MappedAsImage ? (reinterpret_cast<BYTE*>(DosHeader) + AddressOfNameOrdinalsRVA) : ImageRvaToVa( NtHeader, DosHeader, AddressOfNameOrdinalsRVA));
	
	for (DWORD i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		unsigned short OrdinalIndex = Ordinals[i];

		DWORD ExportFncOffset = Functions[OrdinalIndex];
		if (!ExportFncOffset)
			continue;

		auto ProcNamePtr = reinterpret_cast<char*>(MappedAsImage ? (reinterpret_cast<char*>(DosHeader) + ExportNames[i]) : ImageRvaToVa(NtHeader, DosHeader, ExportNames[i]));
		auto ExportFnc = reinterpret_cast<BYTE*>(MappedAsImage ? (reinterpret_cast<BYTE*>(DosHeader) + ExportFncOffset) : ImageRvaToVa(NtHeader, DosHeader, ExportFncOffset));

		//Forwarded exports:
		if (MappedAsImage &&	//Not supported on images that are not mapped
								//Not supported with ordinals for forwarded export by name
			//Check for forwarded export:
			ExportFnc > (reinterpret_cast<BYTE*>(ExportDirectory)) &&
			ExportFnc < (reinterpret_cast<BYTE*>(ExportDirectory) + ExportDirectorySize))
		{
			//for example inside the Kernelbase.dll's export table
			//NTDLL.RtlDecodePointer
			//It could also forward an ordinal
			//NTDLL.#123
			auto ForwardedString = reinterpret_cast<char*>(ExportFnc);
			auto ForwardedStringLen = static_cast<DWORD>(strlen(ForwardedString)) + 1;
			if (ForwardedStringLen >= 256)
				continue;
			std::array<char, 256> szForwardedLibraryName{};
			memcpy_s(szForwardedLibraryName.data(), szForwardedLibraryName.size(), ForwardedString, ForwardedStringLen);
			char* ForwardedFunctionName = NULL;
			char* ForwardedFunctionOrdinal = NULL;
			for (DWORD s = 0; s < ForwardedStringLen; s++)
				if (szForwardedLibraryName.at(s) == '.')
				{
					szForwardedLibraryName.at(s) = NULL;
					ForwardedFunctionName = &ForwardedString[s + 1];
					break;
				}

			//forwarded by ordinal
			if (ForwardedFunctionName != nullptr && ForwardedFunctionName[0] == '#')
			{
				ForwardedFunctionOrdinal = ForwardedFunctionName + 1;
				ForwardedFunctionName = NULL;
			}
			if (ForwardedFunctionName)
			{
				if (std::string(lpProcName) != std::string(ForwardedFunctionName))
					continue;

				auto hForwardedDll = LoadLibraryA(szForwardedLibraryName.data());
				if (!hForwardedDll)
					return nullptr;
				auto ForwardedFunction = reinterpret_cast<FARPROC>(GetExportAddress(hForwardedDll, ForwardedFunctionName, MappedAsImage));
				return reinterpret_cast<FARPROC>(ForwardedFunction);
			}
			else
				if (ForwardedFunctionOrdinal && ProcOrdinal < 0xFFFF)
				{
					DWORD ForwardedOrdinal = atoi(ForwardedFunctionOrdinal);
					if (ForwardedOrdinal > 0xFFFF ||
						ForwardedOrdinal == 0 ||
						ForwardedOrdinal != ProcOrdinal)
						continue;

					auto hForwardedDll = LoadLibraryA(szForwardedLibraryName.data());
					#pragma warning(suppress:4312)
					auto ForwardedFunction = reinterpret_cast<FARPROC>(GetExportAddress(hForwardedDll, reinterpret_cast<LPCSTR>(ForwardedOrdinal & 0xFFFF), MappedAsImage));
					return reinterpret_cast<FARPROC>(ForwardedFunction);
				}
				else
					continue;
		}

		if (reinterpret_cast<ULONG_PTR>(lpProcName) > 0xFFFF && std::string(lpProcName) == std::string(ProcNamePtr))
			return reinterpret_cast<FARPROC>(ExportFnc);
		else
		{
			if ((OrdinalIndex + 1) == ProcOrdinal)
				return reinterpret_cast<FARPROC>(ExportFnc);
		}
	}
	return nullptr;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageDirectoryEntryToDataEx
//////////////////////////////////////////////////////////////////////////////////////////////////
PVOID WINAPI ImageDirectoryEntryToDataInternal(PVOID Base, BOOLEAN MappedAsImage, ULONG* Size, DWORD SizeOfHeaders, IMAGE_DATA_DIRECTORY* DataDirectory, IMAGE_FILE_HEADER* ImageFileHeader, void* ImageOptionalHeader)
{
	*reinterpret_cast<ULONG*>(Size) = NULL;

	if (!DataDirectory->VirtualAddress || !DataDirectory->Size || !SizeOfHeaders)
		return nullptr;

	*reinterpret_cast<ULONG*>(Size) = DataDirectory->Size;
	if (MappedAsImage || DataDirectory->VirtualAddress < SizeOfHeaders)
		return reinterpret_cast<char*>(Base) + DataDirectory->VirtualAddress;

	auto SizeOfOptionalHeader = ImageFileHeader->SizeOfOptionalHeader;
	auto NumberOfSections = ImageFileHeader->NumberOfSections;
	if (!NumberOfSections || !SizeOfOptionalHeader)
		return nullptr;

	auto pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(ImageOptionalHeader) + SizeOfOptionalHeader);
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		auto pSectionHeader = &pSectionHeaders[i];
		if ((DataDirectory->VirtualAddress >= pSectionHeader->VirtualAddress) &&
			(DataDirectory->VirtualAddress < (pSectionHeader->SizeOfRawData + pSectionHeader->VirtualAddress)))
		{
			return reinterpret_cast<char*>(Base) + (DataDirectory->VirtualAddress - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
		}
	}
	return nullptr;
}
PVOID WINAPI ImageDirectoryEntryToData32(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER *ImageFileHeader, IMAGE_OPTIONAL_HEADER32 *ImageOptionalHeader)
{
	*reinterpret_cast<ULONG*>(Size) = NULL;

	if ( DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes )
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if ( !DataDirectory->VirtualAddress || !DataDirectory->Size )
		return nullptr;

	return ImageDirectoryEntryToDataInternal(	Base, 
												MappedAsImage, 
												Size, 
												ImageOptionalHeader->SizeOfHeaders, 
												DataDirectory, 
												ImageFileHeader, 
												ImageOptionalHeader );
}
PVOID WINAPI ImageDirectoryEntryToData64(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER *ImageFileHeader, IMAGE_OPTIONAL_HEADER64 *ImageOptionalHeader)
{
	*reinterpret_cast<ULONG*>(Size) = NULL;

	if ( DirectoryEntry >= ImageOptionalHeader->NumberOfRvaAndSizes )
		return nullptr;

	IMAGE_DATA_DIRECTORY* DataDirectory = &ImageOptionalHeader->DataDirectory[DirectoryEntry];
	if ( !DataDirectory->VirtualAddress || !DataDirectory->Size )
		return nullptr;

	return ImageDirectoryEntryToDataInternal(	Base, 
												MappedAsImage, 
												Size, 
												ImageOptionalHeader->SizeOfHeaders, 
												DataDirectory, 
												ImageFileHeader, 
												ImageOptionalHeader );
}
PVOID WINAPI ImageDirectoryEntryToDataRom(PVOID Base, WORD HeaderMagic, USHORT DirectoryEntry, ULONG* Size, IMAGE_FILE_HEADER* ImageFileHeader, IMAGE_ROM_OPTIONAL_HEADER* ImageRomHeaders)
{
	*reinterpret_cast<ULONG*>(Size) = NULL;

	if (ImageFileHeader->NumberOfSections <= 0u || !ImageFileHeader->SizeOfOptionalHeader)
		return nullptr;

	auto pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(ImageRomHeaders) + ImageFileHeader->SizeOfOptionalHeader);

	std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
	std::transform(sectionName.begin(), sectionName.end(), sectionName.begin(), ::tolower);

	WORD j = 0;
	for (; j < ImageFileHeader->NumberOfSections; j++, pSectionHeader++)
	{
		if (DirectoryEntry == 3 && sectionName == std::string(".pdata"))
			break;
		if (DirectoryEntry == 6 && sectionName == std::string(".rdata"))
		{
			*reinterpret_cast<ULONG*>(Size) = NULL;
			for (BYTE* i = reinterpret_cast<BYTE*>(Base) + pSectionHeader->PointerToRawData + 0xC; *reinterpret_cast<DWORD*>(i); i += 0x1C)
				*Size += 0x1C;
			break;
		}
	}
	if (j >= ImageFileHeader->NumberOfSections)
		return nullptr;

	return reinterpret_cast<char*>(Base) + pSectionHeader->PointerToRawData;
}

/// <summary>
/// Locates a directory entry within the image header and returns the address of the data for the directory entry
/// </summary>
/// <param name="Base">The base address of the image or data file</param>
/// <param name="MappedAsImage">If the flag is TRUE, the file is mapped by the system as an image. If this flag is FALSE, the file is mapped as a data file by the MapViewOfFile / ReadFile function</param>
/// <param name="DirectoryEntry">The directory entry to be located</param>
/// <param name="Size">A pointer to a variable that receives the size of the data for the directory entry that is located</param>
/// <returns>If the function succeeds, the return value is a pointer to the data for the directory entry</returns>
PVOID WINAPI ImageDirectoryEntryToDataEx(PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, ULONG* Size)
{
	*reinterpret_cast<ULONG*>(Size) = NULL;

	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
	if (!pDosHeader)
		return nullptr;

	IMAGE_FILE_HEADER* ImageFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* ImageOptionalHeader = nullptr;

	auto NtHeaderFileOffset = pDosHeader->e_lfanew;
	IMAGE_NT_HEADERS* ImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(pDosHeader) + NtHeaderFileOffset);

	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE
		&& NtHeaderFileOffset > 0
		&& NtHeaderFileOffset < 0x10000000u
		&& ImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		ImageFileHeader = &ImageNtHeader->FileHeader;
		ImageOptionalHeader = &ImageNtHeader->OptionalHeader;
	}
	else
	{
		ImageFileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(Base);
		ImageOptionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(reinterpret_cast<BYTE*>(Base) + 0x14);
	}

	switch (ImageOptionalHeader->Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		return ImageDirectoryEntryToData32(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(ImageOptionalHeader));
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		return ImageDirectoryEntryToData64(
			Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(ImageOptionalHeader));
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		return ImageDirectoryEntryToDataRom(
			Base,
			IMAGE_ROM_OPTIONAL_HDR_MAGIC,
			DirectoryEntry,
			Size,
			ImageFileHeader,
			reinterpret_cast<IMAGE_ROM_OPTIONAL_HEADER*>(ImageOptionalHeader));
	}
	return nullptr;
}
//////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageRvaToSection and ImageRvaToVa
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns a pointer to the section table entry for that RVA
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function.</param>
/// <param name="Base">This parameter is reserved</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_SECTION_HEADER structure</returns>
IMAGE_SECTION_HEADER* WINAPI ImageRvaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva)
{
	if (!NtHeaders)
		return nullptr;

	DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	if (!dwNumberOfSections)
		return nullptr;

	auto SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
	auto pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(&NtHeaders->OptionalHeader) + SizeOfOptionalHeader);
	for (DWORD i = 0; i < dwNumberOfSections; i++)
	{
		auto VirtualAddress = pSectionHeaders[i].VirtualAddress;
		auto SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
		if ((Rva >= VirtualAddress) && (Rva < (SizeOfRawData + VirtualAddress)))
			return &pSectionHeaders[i];
	}
	return nullptr;
}

/// <summary>
/// Locates a relative virtual address (RVA) within the image header of a file that is mapped as a file and returns the virtual address of the corresponding byte in the file.
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile / ReadFile function</param>
/// <param name="Rva">The relative virtual address to be located</param>
/// <returns>If the function succeeds, the return value is the virtual address in the mapped file</returns>
PVOID WINAPI ImageRvaToVa(PIMAGE_NT_HEADERS NtHeaders, void* Base, DWORD Rva)
{
	IMAGE_SECTION_HEADER* ResultSection = nullptr;

	ResultSection = ImageRvaToSection(NtHeaders, reinterpret_cast<PVOID>(Base), Rva);
	if (!ResultSection)
		return nullptr;

	return reinterpret_cast<char*>(Base) + (Rva - ResultSection->VirtualAddress) + ResultSection->PointerToRawData;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Opposite to the windows api function ImageRvaToSection and ImageRvaToVa
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the section header containing the virtual address (VA) in a non mapped file buffer
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function.</param>
/// <param name="Base">This parameter is reserved</param>
/// <param name="Va">Pointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_SECTION_HEADER structure</returns>
IMAGE_SECTION_HEADER* WINAPI ImageVaToSection(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, void* Va)
{
	if (!NtHeaders)
		return nullptr;

	DWORD dwNumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	if (!dwNumberOfSections)
		return nullptr;

	UINT_PTR ImageOffset = reinterpret_cast<BYTE*>(Va) - reinterpret_cast<BYTE*>(Base);

	auto SizeOfOptionalHeader = NtHeaders->FileHeader.SizeOfOptionalHeader;
	auto pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<BYTE*>(&NtHeaders->OptionalHeader) + SizeOfOptionalHeader);
	for (DWORD i = 0; i < dwNumberOfSections; i++)
	{
		auto PointerToRawData = pSectionHeaders[i].PointerToRawData;
		auto SizeOfRawData = pSectionHeaders[i].SizeOfRawData;
		#pragma warning(suppress:26451)
		if ((ImageOffset >= PointerToRawData) && (ImageOffset < (PointerToRawData + SizeOfRawData)))
			return &pSectionHeaders[i];
	}
	return nullptr;
}

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="NtHeaders">A pointer to an IMAGE_NT_HEADERS structure. This structure can be obtained by calling the ImageNtHeader function</param>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(PIMAGE_NT_HEADERS NtHeaders, void* Base, void* Va)
{
	IMAGE_SECTION_HEADER* ResultSection = nullptr;

	ResultSection = ImageVaToSection(NtHeaders, reinterpret_cast<PVOID>(Base), Va);
	if (!ResultSection)
		return NULL;

	#pragma warning(suppress:4244)
	DWORD ImageOffset = reinterpret_cast<BYTE*>(Va) - reinterpret_cast<BYTE*>(Base);

	return (ImageOffset - ResultSection->PointerToRawData) + ResultSection->VirtualAddress;
}

/// <summary>
/// Locates the relative virtual address (RVA) of a pointer into the non mapped file buffer
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory through a call to the MapViewOfFile function</param>
/// <param name="VA">ointer to data inside the Images buffer</param>
/// <returns>If the function succeeds, the return value is the relative virtual address (RVA) in the mapped file</returns>
DWORD WINAPI ImageVaToRva(void* Base, void* Va)
{
	auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
	auto ImageNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<LPBYTE>(pDosHeader) + pDosHeader->e_lfanew);

	return ImageVaToRva(ImageNtHeader, Base, Va);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//			Equivalent to the windows api function ImageNtHeader
//////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>
/// Locates the IMAGE_NT_HEADERS structure in a PE image and returns a pointer to the data
/// </summary>
/// <param name="Base">The base address of an image that is mapped into memory by a call to the MapViewOfFile function</param>
/// <returns>If the function succeeds, the return value is a pointer to an IMAGE_NT_HEADERS structure</returns>
IMAGE_NT_HEADERS* WINAPI ImageNtHeader(_In_ PVOID Base)
{
	auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(Base);
	if (DosHeader
		&& DosHeader->e_magic == IMAGE_DOS_SIGNATURE
		&& DosHeader->e_lfanew >= 0u
		&& DosHeader->e_lfanew < 0x10000000u)
	{
		auto ImageNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<BYTE*>(DosHeader) + DosHeader->e_lfanew);
		if (ImageNtHeader->Signature == IMAGE_NT_SIGNATURE)
			return ImageNtHeader;
	}
	return nullptr;
}
