#include <iostream>
#include <Windows.h>

int main(int argc, char* argv[])
{
	SetConsoleTitleW(L"ImageBaseSearcher");
	setlocale(LC_ALL,"");

	if (argc == 1) {
		std::wcout << "Bruk: ImageBaseSearcher.exe filnavn";
		return 0;
	}

	// Variabler for å lese PE data.
	PIMAGE_DOS_HEADER pDosHeader = 0;
	PIMAGE_NT_HEADERS pNtHeader = 0;
	PIMAGE_SECTION_HEADER pSectHeader = 0;

	// Åpne en handle til målfil.
	HANDLE Fil = CreateFileA(argv[1], GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (Fil == INVALID_HANDLE_VALUE) {
		std::wcout << "Kunne ikke åpne målfil.";
		return 1;
	}

	// Last fil inn til minne for behandling.
	unsigned char* FilBuf;
	unsigned long FilSize = GetFileSize(Fil,0);
	FilBuf = (unsigned char*)malloc(FilSize);
	unsigned long FilBytesLest = 0;
	if (ReadFile(Fil, FilBuf, FilSize, &FilBytesLest, 0) == 0) {
		std::wcout << "Kunne ikke lese målfil.";
		return 1;
	}

	// Sjekk DOS header.
	pDosHeader = (PIMAGE_DOS_HEADER)FilBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::wcout << "Kunne ikke verifisere PE DOS header.";
		return 1;
	}

	// Sjekk NT header.
	pNtHeader = (PIMAGE_NT_HEADERS)(FilBuf + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		std::wcout << "Kunne ikke verifisere PE NT Header.";
		return 1;
	}

	// Opprett peker til første seksjon i NT header.
	pSectHeader = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pNtHeader);
	unsigned short SectionCount = pNtHeader->FileHeader.NumberOfSections;

	//	Eksempel RVA hentet fra x64dbg .1337 fil.
	unsigned long RVA = 0x1449E;

	//
	//	Finn første seksjon som har VirtualAddress mindre enn RVA som jeg kan regne fra. Typisk .text seksjonen.
	//	VirtualAddress representerer første byte i seksjonen etter innlasting i minne i relasjon til imagebase.
	//
	for (int a=0; a<=SectionCount; a++) {
		if (pSectHeader->VirtualAddress > RVA) {
			--pSectHeader;
			break;
		}
		++pSectHeader;
	}

	//
	//	Siden VirtualAddress og PointerToRawData har et statisk rekkeviddeforhold i både rå fil og lastet program,
	//	kan jeg regne ut offset mellom disse som vil være samme offset x64dbg bruker i forhold til ASLR imagebase.
	//
	uintptr_t FilOffset = RVA - pSectHeader->VirtualAddress + pSectHeader->PointerToRawData;
	std::wcout << "\nFil offset basert på x64dbg .1337 eksportverdi: 0x" << std::hex << FilOffset << "\n";
	std::wcout << "SectionHeader->VirtualAddress: " << std::hex << pSectHeader->VirtualAddress << "\n";
	std::wcout << "SectionHeader->PointerToRawData: " << std::hex << pSectHeader->PointerToRawData << "\n";




	//
	//  Eksempel på det motsatte: Finn RVA basert på FilOffset.
	//	Finn første seksjon som har VirtualAddress mindre enn RVA som jeg kan regne fra. Typisk .text seksjonen.
	//	VirtualAddress representerer første byte i seksjonen etter innlasting i minne i relasjon til imagebase.
	//
	DWORD sectionEnd = 0;
	for (int a=0; a<=SectionCount; a++) {
		sectionEnd = pSectHeader->PointerToRawData + pSectHeader->SizeOfRawData;
		if (FilOffset >= pSectHeader->PointerToRawData && FilOffset < sectionEnd) {
			break;
		}
		++pSectHeader;
	}

	uintptr_t RVAOffset = FilOffset - pSectHeader->PointerToRawData + pSectHeader->VirtualAddress;
	std::wcout << "\nRVA offset funnet basert på FilOffset: 0x" << std::hex << RVAOffset << "\n";
	std::wcout << "SectionHeader->VirtualAddress: " << std::hex << pSectHeader->VirtualAddress << "\n";
	std::wcout << "SectionHeader->PointerToRawData: " << std::hex << pSectHeader->PointerToRawData << "\n";

	CloseHandle(Fil);
	return 0;
}