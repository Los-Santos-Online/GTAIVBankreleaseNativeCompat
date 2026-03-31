#pragma once

static void PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked) {
	if (dwDestination & 0x8000) {
		dwAddress[0] = 0x3D600000 + (((dwDestination >> 16) & 0xFFFF) + 1);
	}
	else {
		dwAddress[0] = 0x3D600000 + ((dwDestination >> 16) & 0xFFFF);
	}

	dwAddress[1] = 0x396B0000 + (dwDestination & 0xFFFF);
	dwAddress[2] = 0x7D6903A6;
	dwAddress[3] = 0x4E800420 | (bLinked ? 1 : 0);
}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY pLdrModule, CHAR* szModuleName, DWORD dwOrdinal, DWORD dwPatchAddress)
{
	if (!pLdrModule)
		return S_FALSE;

	DWORD address = (DWORD)GetProcAddress(GetModuleHandle(szModuleName), (LPCSTR)dwOrdinal);
	if (address == NULL)
		return S_FALSE;

	VOID* headerBase = pLdrModule->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR pImportDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, XEX_HEADER_IMPORTS);
	if (pImportDesc == NULL)
		return S_FALSE;


	DWORD dwResult = 0; 

	CHAR* szStringTable = (CHAR*)(pImportDesc + 1);

	XEX_IMPORT_TABLE_ORG* pImportTable = (XEX_IMPORT_TABLE_ORG*)(szStringTable + pImportDesc->NameTableSize);

	for (DWORD x = 0; x < pImportDesc->ModuleCount; x++) {

		DWORD* pdwImportAddress = (DWORD*)(pImportTable + 1);
		for (DWORD y = 0; y < pImportTable->ImportTable.ImportCount; y++) {

			DWORD value = *((DWORD*)pdwImportAddress[y]);
			if (value == address) {

				DWORD dwCode[4];
				memcpy((void*)(DWORD*)pdwImportAddress[y], &dwPatchAddress, 4);
				PatchInJump(dwCode, dwPatchAddress, FALSE);
				memcpy((void*)(DWORD*)pdwImportAddress[y + 1], dwCode, 16);

				dwResult = S_OK;
			}
		}

		pImportTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)pImportTable) + pImportTable->TableSize);
	}

	return dwResult;
}

static BYTE DetourAsm[0x3000] = { 0 };
static DWORD DetourAsmIndex;
static RTL_CRITICAL_SECTION DetourAsmSection;

static int Int24ToInt32(int Value) {
	Value &= 0x00FFFFFF;
	if (Value & 0x800000)
		Value |= 0xFF000000;
	if (Value & 1)
		Value -= 1;
	return Value;
}

static bool IsZero(PVOID Scr, DWORD Size) {

	bool result;
	byte *bZeroData = new byte[Size];
	ZeroMemory(bZeroData, Size);

	result = !memcmp(Scr, bZeroData, Size);
	delete[] bZeroData;
	return result;
}

// need to call this from the class because all the agrs are pushed up
// from r3 because it is the class pointer
static void __declspec(naked) SetupCaller()
{
	__asm
	{
		mr r3, r4
		mr r4, r5
		mr r5, r6
		mr r6, r7
		mr r7, r8
		mr r8, r9
		mr r9, r10

		fmr fr1, fr2
		fmr fr2, fr3
		fmr fr3, fr4
		fmr fr4, fr5
		fmr fr5, fr6
		fmr fr6, fr7
		fmr fr7, fr8
		fmr fr8, fr9
		fmr fr9, fr10
		blr
	}
}

static bool bCheckIfCMP(int ptr)
{
	byte b = *(byte *)ptr;
	byte b2 = *(byte *)(ptr + 1);

	if (b == 0x40 || b == 0x41)
	{
		if (b2 == 0x9A || b2 == 0x82 || b2 == 0x99
			|| b2 == 0x81 || b2 == 0x98 || b2 == 0x80)
			return true;
	}
	return false;
}

template<class _ClassType>
class Detour
{
private:
	BYTE OriginalAsm[0x10]; // 4 instructions
	DWORD DetourIndex;

	__int64 iArgs[8];
	double fArgs[8];

	// This function will get any 'b' or 'bl' and any 'cmp' function added to the stub that
	// it replaces and return the size of the stub in byte lengths
	DWORD DetourFunctionStart(DWORD dwFunctionAddress, DWORD dwStubAddress, PVOID pDestFunc)
	{
		DWORD dwLength = 0;
		DWORD dwTemp;
		DWORD dwTempFuncAddr;
		BOOL bTemp;

		for (DWORD i = 0; i < 4; i++)
		{
			dwTempFuncAddr = dwFunctionAddress + (i * 4);
			byte b = *(byte *)dwTempFuncAddr;

			// b or bl
			if (b == 0x48 || b == 0x4B)
			{
				// get the branch to address
				dwTemp = dwTempFuncAddr + Int24ToInt32(*(DWORD *)dwTempFuncAddr);
				bTemp = (*(DWORD *)dwTempFuncAddr & 1) != 0;
				PatchInJump((PDWORD)(dwStubAddress + dwLength), dwTemp, bTemp);
				dwLength += 0x10;

				// if it was a 'b loc_' call, we won't need to anything else to the stub
				if (!bTemp)
					goto DoHook;
			}

			// beq or bne, ble or bgt, bge or blt
			else if (bCheckIfCMP(dwTempFuncAddr))
			{
				dwTemp = *(DWORD *)dwTempFuncAddr & 0xFFFF;

				// if bTemp is true the op code is 'beq'
				bTemp = b == 0x41;

				// check if the branch location is within the stub
				if (dwTemp <= 0x10 && dwTemp > 0)
				{
					if (dwTemp <= (0x10 - (i * 4)))
					{
						*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
						dwLength += 4;
					}
					else
						goto branch_else;
				}
				else
				{
				branch_else:
					// make a jump past the call if the cmp != what it is checking
					*(DWORD *)(dwStubAddress + dwLength) = ((0x40000000 + (*(DWORD *)dwTempFuncAddr & 0x00FF0000) + 0x14) +
						bTemp ? 0 : 0x01000000);
					dwLength += 4;
					PatchInJump((PDWORD)(dwStubAddress + dwLength), dwTempFuncAddr + dwTemp, FALSE);
					dwLength += 0x10;
				}
			}

			// if the function op code is null it is invalid
			else if (*(DWORD *)dwTempFuncAddr == 0)
				break;

			else
			{
				*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
				dwLength += 4;
			}
		}

		// make the stub call the orig function
		PatchInJump((PDWORD)(dwStubAddress + dwLength), dwFunctionAddress + 0x10, FALSE);
		dwLength += 0x10;

	DoHook:
		// apply the hook
		PatchInJump((PDWORD)dwFunctionAddress, (DWORD)pDestFunc, FALSE);
		return dwLength;
	}

public:
	DWORD Addr;
	DWORD SaveStub;
	Detour() {};
	~Detour() {};

	void SetupDetour(DWORD Address, PVOID Destination)
	{
		if (IsZero(&DetourAsmSection, sizeof(DetourAsmSection)))
			InitializeCriticalSection(&DetourAsmSection);

		EnterCriticalSection(&DetourAsmSection);

		if (Addr != Address || SaveStub == 0) {

			DetourIndex = DetourAsmIndex;
			SaveStub = (DWORD)&DetourAsm[DetourIndex];

			// save the address incase we take-down the detour
			Addr = Address;
			// Copy the asm bytes before we replace it with the hook
			memcpy(OriginalAsm, (PVOID)Address, 0x10);

			// increment the index for the space we are using for the stub
			DetourAsmIndex += DetourFunctionStart(Address, SaveStub, Destination);
		}
		else
		{
			// if we have already got a stub and the address is the same just re use it
			DetourFunctionStart(Address, SaveStub, Destination);
		}

		LeaveCriticalSection(&DetourAsmSection);
	}

	void TakeDownDetour()
	{
		if (Addr && MmIsAddressValid((PVOID)Addr))
			memcpy((PVOID)Addr, OriginalAsm, 0x10);
	}

	_ClassType CallOriginal(...)
	{
		SetupCaller();
		return ((_ClassType(*)(...))SaveStub)();
	}

	_ClassType CallOriginalNoCallee(...)
	{
		return ((_ClassType(*)(...))SaveStub)();
	}
};