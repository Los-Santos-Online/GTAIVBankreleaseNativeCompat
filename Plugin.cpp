#include "stdafx.h"
#include "Hooking.h"

static const DWORD kTargetTitleId = 0x54540816;
static const DWORD kBankTimestamp = 0x47C7E580;
static const DWORD kBetaTimestamp = 0x47C7E9C1;

static const DWORD kBankValidateAddr = 0x823DD858;
static const DWORD kBankScrCreateThread = 0x823DDC88;
static const DWORD kBankLookupNativeAddr = 0x823DF7C8;
static const DWORD kBankInsnSizeAddr = 0x823DBA30;
static const DWORD kBankNativeTableAddr = 0x82DBAB04;

static const DWORD kBetaValidateAddr = 0x82471D18;
static const DWORD kBetaScrCreateThread = 0x824723C8;
static const DWORD kBetaLookupNativeAddr = 0x82474308;
static const DWORD kBetaInsnSizeAddr = 0x8246EA78;
static const DWORD kBetaNativeTableAddr = 0x832C0AE8;

enum ETitleType {
	RETAIL,
	BANK,
	BETA
};

ETitleType GetTitleType() {
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
	if (pLdr->TimeDateStamp == kBankTimestamp)
		return ETitleType::BANK;

	if (pLdr->TimeDateStamp == kBetaTimestamp)
		return ETitleType::BETA;

	return ETitleType::RETAIL;
}

bool IsBank() {
	if (GetTitleType() == ETitleType::BANK) return true;
	return false;
}

typedef int(__fastcall* LookupNativeFn)(int* tableRoot, DWORD hash);
typedef int(__fastcall* GetInsnSizeFn)(BYTE* insn);

// it's a bit cursed
static int g_pfnLookupNative(DWORD hash) { 
	return reinterpret_cast<LookupNativeFn>((IsBank() ? kBankLookupNativeAddr : kBetaLookupNativeAddr))(
		reinterpret_cast<int*>(IsBank() ? kBankNativeTableAddr : kBetaNativeTableAddr), 
		hash
	);
};

static int g_pfnGetInsnSize(BYTE* insn) { 
	return reinterpret_cast<GetInsnSizeFn>(IsBank() ? kBankInsnSizeAddr : kBetaInsnSizeAddr)(insn);
};

struct NativeAlias {
	DWORD dwHash;
	const char* szName;
	DWORD pfnHandler;
};

DWORD **HandlerScriptNOP(DWORD **pdwResult) { return pdwResult; }

DWORD **HandlerScriptTrue(DWORD **pdwResult) {
	if (pdwResult && *pdwResult) **pdwResult = 1;
	return pdwResult;
}

DWORD **HandlerScriptFalse(DWORD **pdwResult) {
	if (pdwResult && *pdwResult) **pdwResult = 0;
	return pdwResult;
}

static NativeAlias g_Aliases[] = {
	{0xB12B4573, "ADD_TO_PREVIOUS_BRIEF_WITH_UNDERSCORE", (DWORD)HandlerScriptNOP},
	{0x51A7743F, "ALLOW_LOCKON_TO_FRIENDLY_PLAYERS", (DWORD)HandlerScriptNOP},
	{0x6F14A1B3, "ALLOW_STUNT_JUMPS_TO_TRIGGER", (DWORD)HandlerScriptNOP},
	{0x6F76063F, "ANCHOR_OBJECT", (DWORD)HandlerScriptNOP},
	{0x02C9EE41, "CAN_START_MISSION_PASSED_TUNE", (DWORD)HandlerScriptTrue},
	{0x46788161, "CAN_START_MISSION_PASSED_TUNE", (DWORD)HandlerScriptTrue},
	{0x45D1813F, "DOES_OBJECT_HAVE_PHYSICS", (DWORD)HandlerScriptTrue},
	{0x9E53AFD9, "FLUSH_ALL_OUT_OF_DATE_RADAR_BLIPS_FROM_MISSION_CLEANUP_LIST", (DWORD)HandlerScriptNOP},
	{0x068485D6, "FORCE_FULL_VOICE", (DWORD)HandlerScriptNOP},
	{0xA4CA9C1C, "GET_MOTION_CONTROL_PREFERENCE", (DWORD)HandlerScriptFalse},
	{0xCB979EE4, "GET_TRAIN_PLAYER_WOULD_ENTER", (DWORD)HandlerScriptFalse},
	{0xA4CAD139, "GET_WIDTH_OF_LITERAL_STRING", (DWORD)HandlerScriptFalse},
	{0x06FFF399, "UNRESOLVED_CORRUPT_LABEL_06FFF399", (DWORD)HandlerScriptNOP},
	{0x6755EAED, "HAS_RESPRAY_HAPPENED", (DWORD)HandlerScriptFalse},
	{0x944BA1DC, "IS_AUSSIE_VERSION", (DWORD)HandlerScriptFalse},
	{0xB632F152, "IS_CHAR_VISIBLE", (DWORD)HandlerScriptTrue},
	{0x9A99C9C7, "IS_HUD_RETICULE_COMPLEX", (DWORD)HandlerScriptFalse},
	{0xBCE03D35, "IS_PED_CLIMBING", (DWORD)HandlerScriptFalse},
	{0x5C3BF51B, "IS_SNIPER_INVERTED", (DWORD)HandlerScriptFalse},
	{0x9C8802DA, "NETWORK_DID_INVITE_FRIEND", (DWORD)HandlerScriptFalse},
	{0x39D26713, "NETWORK_GET_NUM_PARTY_MEMBERS", (DWORD)HandlerScriptFalse},
	{0x0FF5356E, "NETWORK_GET_UNACCEPTED_INVITE_EPISODE", (DWORD)HandlerScriptFalse},
	{0xF66BCD00, "NETWORK_GET_UNACCEPTED_INVITE_GAME_MODE", (DWORD)HandlerScriptFalse},
	{0x63049363, "PRINT_HELP_FOREVER_WITH_STRING_NO_SOUND", (DWORD)HandlerScriptNOP},
	{0x2F086A44, "SET_COLLIDE_WITH_PEDS", (DWORD)HandlerScriptNOP},
	{0x3EA7FCE4, "SET_DITCH_POLICE_MODELS", (DWORD)HandlerScriptNOP},
	{0x076F4216, "SET_DRAW_PLAYER_COMPONENT", (DWORD)HandlerScriptNOP},
	{0x805814E3, "SET_ENABLE_NEAR_CLIP_SCAN", (DWORD)HandlerScriptNOP},
	{0x33BD1A80, "SET_LOCAL_PLAYER_PAIN_VOICE", (DWORD)HandlerScriptNOP},
	{0xF0D28043, "SET_LOCAL_PLAYER_VOICE", (DWORD)HandlerScriptNOP},
	{0x990085F0, "SET_MOBILE_RADIO_ENABLED_DURING_GAMEPLAY", (DWORD)HandlerScriptNOP},
	{0xE7B8A712, "SET_PLAYER_PAIN_ROOT_BANK_NAME", (DWORD)HandlerScriptNOP},
	{0x6F2626E1, "SET_RADAR_AS_INTERIOR_THIS_FRAME", (DWORD)HandlerScriptNOP},
	{0x5B01902A, "STOP_PED_DOING_FALL_OFF_TESTS_WHEN_SHOT", (DWORD)HandlerScriptNOP},
	{0x4DD46DAE, "USE_PLAYER_COLOUR_INSTEAD_OF_TEAM_COLOUR", (DWORD)HandlerScriptNOP}
};

Detour<int(__fastcall*)(BYTE* script, int size)> g_ValidateDetour;

// blame the compiler for me not using std::map or std::unordered_map and linear searching.
static const NativeAlias* FindAlias(DWORD hash) {
	for (int i = 0; i < (int)(sizeof(g_Aliases) / sizeof(g_Aliases[0])); ++i) {
		if (g_Aliases[i].dwHash == hash) {
			return &g_Aliases[i];
		}
	}

	return 0;
}

static DWORD ReadNativeHash(BYTE* bInstruction) {
	DWORD b3 = (DWORD)bInstruction[3];
	DWORD b4 = (DWORD)bInstruction[4];
	DWORD b5 = (DWORD)bInstruction[5];
	DWORD b6 = (DWORD)bInstruction[6];
	return ((b6 << 24) | (b5 << 16) | (b4 << 8) | b3);
}

static DWORD ResolveNativeHandler(DWORD dwHash) {
	int iHandler = g_pfnLookupNative(dwHash);
	if (iHandler != 0) {
		return iHandler;
	}

	const NativeAlias* pAlias = FindAlias(dwHash);
	if (!pAlias) {
		return 0;
	}

	return pAlias->pfnHandler;
}

static bool ValidatePatchedScript(BYTE* pbScript, int iSize) {
	int iRemaining = iSize;
	BYTE* pbCursor = pbScript;

	while (iRemaining > 0) {
		if (*pbCursor == 0x2D) {
			DWORD dwHash = ReadNativeHash(pbCursor);

			int iHandlerPtr = ResolveNativeHandler(dwHash);
			if (iHandlerPtr == 0) return false;
			
			pbCursor[3] = (BYTE)iHandlerPtr;
			pbCursor[4] = (BYTE)(iHandlerPtr >> 8);
			pbCursor[5] = (BYTE)(iHandlerPtr >> 16);
			pbCursor[6] = (BYTE)(iHandlerPtr >> 24);
		}

		int iStep = g_pfnGetInsnSize(pbCursor);
		if (iStep <= 0 || iStep > iRemaining) break;

		pbCursor += iStep;
		iRemaining -= iStep;
	}

	return true;
}

static int __fastcall ValidateHook(BYTE* pbScript, int iSize) {
	DbgPrint("validate enter script=%08X size=%d\n", (DWORD)pbScript, iSize);
	return ValidatePatchedScript(pbScript, iSize);
}

static void InstallHooks() {
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
	if (!pLdr) {
		DbgPrint("target title seen but executable handle unavailable");
		return;
	}

	if (GetTitleType() == ETitleType::RETAIL) {
		DbgPrint("title matched but is neithber beta nor bank", pLdr->TimeDateStamp);
		return;
	}

	DbgPrint("title is %s", IsBank() ? "BANK\n" : "BETA\n");

	// FIXME(rwf93): move to static variables?

	// rwf93: faulting on an stlw withinside the TimeCycle::QueryModifierBoxTree, so i just nop it out with ori %r0, 0, 0
	// 2lazy4me, probably broke something
	*(DWORD*)(IsBank() ? 0x825D7488 : 0x82839370) = 0x60000000;

	//rwf93: force RAG socket to use port 2001
	*(DWORD*)(IsBank() ? 0x823248B4 : 0x8232F994) = 0x38A007D1;// li r5, 0x7D1;
	
	//jorby: Prevent widget type asserts from trapping while we debug RAG translation.
	if (!IsBank()) {
		*(DWORD*)(0x82308644) = 0x60000000; // NOP twi in bkBank::RemoteHandler
		*(DWORD*)(0x823368C0) = 0x60000000; // NOP twi in bkGroup::RemoteHandler
	}

	// fix stack sizes
	// thx jason098
	*(DWORD*)(IsBank() ? 0x82852820 : 0x82BBFAF0) = 0x38600014; // li r3, 0x14
	*(DWORD*)(IsBank() ? 0x8285282C : 0x82BBFAFC) = 0x38600014; // li r3, 0x14
	*(DWORD*)(IsBank() ? 0x82852874 : 0x82BBFB44) = 0x38600003; // li r3, 3
	*(DWORD*)(IsBank() ? 0x82852888 : 0x82BBFB58) = 0x38802000; // li r4, 0x2000

	g_ValidateDetour.SetupDetour((IsBank() ? kBankValidateAddr : kBetaValidateAddr), ValidateHook);
}

static VOID CreateSystemThread(LPTHREAD_START_ROUTINE startRoutine) {
	HANDLE hHandle = 0;
	DWORD dwThreadID = 0;
	ExCreateThread(&hHandle, 0, &dwThreadID, (PVOID)XapiThreadStartup, startRoutine, 0, 0x2 | CREATE_SUSPENDED);
	XSetThreadProcessor(hHandle, 4);
	SetThreadPriority(hHandle, THREAD_PRIORITY_ABOVE_NORMAL);
	ResumeThread(hHandle);
}

static DWORD WINAPI MainLoop(LPVOID) {
	DWORD dwCurrentTitleID = XamGetCurrentTitleId();
	DWORD dwLastTitleID = 0;

	//rwf93: install if the dwCurrentTitleID has changed to kTargetTitleId
	while (true) {
		dwCurrentTitleID = XamGetCurrentTitleId();
		if (dwCurrentTitleID != dwLastTitleID) {
			dwLastTitleID = dwCurrentTitleID;
			if (dwCurrentTitleID == kTargetTitleId)
				InstallHooks();
		}

		Sleep(50);
	}

	return 0;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		CreateSystemThread((LPTHREAD_START_ROUTINE)MainLoop);
		break;
	case DLL_PROCESS_DETACH:
		//rwf93: 100kb leak of memory, kernel will handle it. fight me.
		break;
	default:
		  break;
	}

	return TRUE;
}

extern "C" int XapiInitProcess();
extern "C" int XapiCallThreadNotifyRoutines(int);
extern "C" int XapiPAL50Incompatible();
extern "C" int XamTerminateTitle();
extern "C" int _mtinit();
extern "C" int _rtinit();
extern "C" int _cinit(int);
extern "C" int _cexit(int);
extern "C" int _CRT_INIT(...);
extern "C" int __CppXcptFilter(...);

extern "C" static int __proc_attached;

// Check dllcrt0.c in the Xbox 360 SDK
// rwf93: why the do we even need this in ${currentYear}, please give me LLVM so i never have to touch MSVC. kthxbye
__declspec(noinline)
BOOL __cdecl
SecureDllMain(
	HANDLE  hDllHandle,
	DWORD   dwReason,
	LPVOID  lpreserved
)
{
	BOOL retcode = TRUE;

	/*
	 * If this is a process detach notification, check that there has
	 * has been a prior process attach notification.
	 */
	if ((dwReason == DLL_PROCESS_DETACH) && (__proc_attached == 0))
		/*
		 * no prior process attach notification. just return
		 * without doing anything.
		 */
		return FALSE;

	__try {
		if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH)
		{
			retcode = _CRT_INIT(hDllHandle, dwReason, lpreserved);

			if (!retcode)
				return FALSE;
		}

		retcode = DllMain(hDllHandle, dwReason, lpreserved);

		if ((dwReason == DLL_PROCESS_ATTACH) && !retcode)
		{
			/*
			 * The user's DllMain routine returned failure, the C runtime
			 * needs to be cleaned up. Do this by calling _CRT_INIT again,
			 * this time imitating DLL_PROCESS_DETACH. Note this will also
			 * clear the __proc_attached flag so the cleanup will not be
			 * repeated upon receiving the real process detach notification.
			 */
			DllMain(hDllHandle, DLL_PROCESS_DETACH, lpreserved);
			_CRT_INIT(hDllHandle, DLL_PROCESS_DETACH, lpreserved);
		}

		if ((dwReason == DLL_PROCESS_DETACH) ||
			(dwReason == DLL_THREAD_DETACH))
		{
			if (_CRT_INIT(hDllHandle, dwReason, lpreserved) == FALSE)
				retcode = FALSE;

		}
	}
	__except (__CppXcptFilter(GetExceptionCode(), GetExceptionInformation())) {
		return FALSE;
	}

	return retcode;
}
