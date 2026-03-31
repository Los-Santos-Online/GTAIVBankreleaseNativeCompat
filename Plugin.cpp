#include "stdafx.h"
#include "Hooking.h"

static const DWORD kTargetTitleId = 0x54540816;
static const DWORD kTargetTimestamp = 0x47C7E580;

static const DWORD kValidateAddr = 0x823DD858;
static const DWORD kScrCreateThread = 0x823DDC88;
static const DWORD kLookupNativeAddr = 0x823DF7C8;
static const DWORD kInsertNativeAddr = 0x823DC2F8;
static const DWORD kInsnSizeAddr = 0x823DBA30;
static const DWORD kNativeTableAddr = 0x82DBAB04;

enum ShimKind {
	kReturnTrue,
	kReturnZero,
	kCommandNoOp,
	kLogOnly,
};

struct NativeAlias {
	DWORD dwHash;
	const char* szName;
	ShimKind eShim;
	const char* szNote;
	int iHitCount;
};

struct MissingNativeEntry {
	DWORD dwHash;
	DWORD dwCounter;
	const char* szName;
};

static NativeAlias g_Aliases[] = {
	{0xB12B4573, "ADD_TO_PREVIOUS_BRIEF_WITH_UNDERSCORE", kCommandNoOp, "retail only", 0},
	{0x51A7743F, "ALLOW_LOCKON_TO_FRIENDLY_PLAYERS", kCommandNoOp, "retail only", 0},
	{0x6F14A1B3, "ALLOW_STUNT_JUMPS_TO_TRIGGER", kCommandNoOp, "retail only", 0},
	{0x6F76063F, "ANCHOR_OBJECT", kCommandNoOp, "retail only", 0},
	{0x02C9EE41, "CAN_START_MISSION_PASSED_TUNE", kReturnTrue, "retail only", 0},
	{0x46788161, "CAN_START_MISSION_PASSED_TUNE", kReturnTrue, "bank release hash", 0},
	{0x45D1813F, "DOES_OBJECT_HAVE_PHYSICS", kReturnTrue, "retail only", 0},
	{0x9E53AFD9, "FLUSH_ALL_OUT_OF_DATE_RADAR_BLIPS_FROM_MISSION_CLEANUP_LIST", kCommandNoOp, "retail only", 0},
	{0x068485D6, "FORCE_FULL_VOICE", kCommandNoOp, "retail only", 0},
	{0xA4CA9C1C, "GET_MOTION_CONTROL_PREFERENCE", kReturnZero, "retail only", 0},
	{0xCB979EE4, "GET_TRAIN_PLAYER_WOULD_ENTER", kReturnZero, "retail only", 0},
	{0xA4CAD139, "GET_WIDTH_OF_LITERAL_STRING", kReturnZero, "retail only", 0},
	{0x06FFF399, "UNRESOLVED_CORRUPT_LABEL_06FFF399", kLogOnly, "corrupted retail registration label", 0},
	{0x6755EAED, "HAS_RESPRAY_HAPPENED", kReturnZero, "retail only", 0},
	{0x944BA1DC, "IS_AUSSIE_VERSION", kReturnZero, "retail only", 0},
	{0xB632F152, "IS_CHAR_VISIBLE", kReturnTrue, "retail only", 0},
	{0x9A99C9C7, "IS_HUD_RETICULE_COMPLEX", kReturnZero, "retail only", 0},
	{0xBCE03D35, "IS_PED_CLIMBING", kReturnZero, "retail only", 0},
	{0x5C3BF51B, "IS_SNIPER_INVERTED", kReturnZero, "retail only", 0},
	{0x9C8802DA, "NETWORK_DID_INVITE_FRIEND", kReturnZero, "retail only", 0},
	{0x39D26713, "NETWORK_GET_NUM_PARTY_MEMBERS", kReturnZero, "retail only", 0},
	{0x0FF5356E, "NETWORK_GET_UNACCEPTED_INVITE_EPISODE", kReturnZero, "retail only", 0},
	{0xF66BCD00, "NETWORK_GET_UNACCEPTED_INVITE_GAME_MODE", kReturnZero, "retail only", 0},
	{0x63049363, "PRINT_HELP_FOREVER_WITH_STRING_NO_SOUND", kCommandNoOp, "retail only", 0},
	{0x2F086A44, "SET_COLLIDE_WITH_PEDS", kCommandNoOp, "retail only", 0},
	{0x3EA7FCE4, "SET_DITCH_POLICE_MODELS", kCommandNoOp, "retail only", 0},
	{0x076F4216, "SET_DRAW_PLAYER_COMPONENT", kCommandNoOp, "retail only", 0},
	{0x805814E3, "SET_ENABLE_NEAR_CLIP_SCAN", kCommandNoOp, "retail only", 0},
	{0x33BD1A80, "SET_LOCAL_PLAYER_PAIN_VOICE", kCommandNoOp, "retail only", 0},
	{0xF0D28043, "SET_LOCAL_PLAYER_VOICE", kCommandNoOp, "retail only", 0},
	{0x990085F0, "SET_MOBILE_RADIO_ENABLED_DURING_GAMEPLAY", kCommandNoOp, "retail only", 0},
	{0xE7B8A712, "SET_PLAYER_PAIN_ROOT_BANK_NAME", kCommandNoOp, "retail only", 0},
	{0x6F2626E1, "SET_RADAR_AS_INTERIOR_THIS_FRAME", kCommandNoOp, "retail only", 0},
	{0x5B01902A, "STOP_PED_DOING_FALL_OFF_TESTS_WHEN_SHOT", kCommandNoOp, "retail only", 0},
	{0x4DD46DAE, "USE_PLAYER_COLOUR_INSTEAD_OF_TEAM_COLOUR", kCommandNoOp, "retail only", 0},
};

Detour<int(__fastcall*)(BYTE* script, int size)> g_ValidateDetour;

typedef int(__fastcall* LookupNativeFn)(int* tableRoot, DWORD hash);
typedef int(__fastcall* InsertNativeFn)(int* tableRoot, DWORD hash, DWORD handler);
typedef int(__fastcall* GetInsnSizeFn)(BYTE* insn);

static LookupNativeFn g_lookupNative = (LookupNativeFn)kLookupNativeAddr;
static InsertNativeFn g_insertNative = (InsertNativeFn)kInsertNativeAddr;
static GetInsnSizeFn g_getInsnSize = (GetInsnSizeFn)kInsnSizeAddr;

static int* NativeTableRoot() {
	return (int*)kNativeTableAddr;
}

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

static DWORD** HandleAliasByIndex(int iIndex, DWORD** pdwResult) {
	switch (g_Aliases[iIndex].eShim) {
		case kReturnTrue:
			if (pdwResult && *pdwResult) {
				**pdwResult = 1;
			}
			break;
		case kReturnZero:
			if (pdwResult && *pdwResult) {
				**pdwResult = 0;
			}
			break;
		case kCommandNoOp:
		case kLogOnly:
		default:
			break;
	}

  return pdwResult;
}

#define DEFINE_ALIAS_WRAPPER(INDEX) \
	extern "C" DWORD** __fastcall AliasWrapper##INDEX(DWORD** result) { \
	  	return HandleAliasByIndex(INDEX, result); \
	}

DEFINE_ALIAS_WRAPPER(0)
DEFINE_ALIAS_WRAPPER(1)
DEFINE_ALIAS_WRAPPER(2)
DEFINE_ALIAS_WRAPPER(3)
DEFINE_ALIAS_WRAPPER(4)
DEFINE_ALIAS_WRAPPER(5)
DEFINE_ALIAS_WRAPPER(6)
DEFINE_ALIAS_WRAPPER(7)
DEFINE_ALIAS_WRAPPER(8)
DEFINE_ALIAS_WRAPPER(9)
DEFINE_ALIAS_WRAPPER(10)
DEFINE_ALIAS_WRAPPER(11)
DEFINE_ALIAS_WRAPPER(12)
DEFINE_ALIAS_WRAPPER(13)
DEFINE_ALIAS_WRAPPER(14)
DEFINE_ALIAS_WRAPPER(15)
DEFINE_ALIAS_WRAPPER(16)
DEFINE_ALIAS_WRAPPER(17)
DEFINE_ALIAS_WRAPPER(18)
DEFINE_ALIAS_WRAPPER(19)
DEFINE_ALIAS_WRAPPER(20)
DEFINE_ALIAS_WRAPPER(21)
DEFINE_ALIAS_WRAPPER(22)
DEFINE_ALIAS_WRAPPER(23)
DEFINE_ALIAS_WRAPPER(24)
DEFINE_ALIAS_WRAPPER(25)
DEFINE_ALIAS_WRAPPER(26)
DEFINE_ALIAS_WRAPPER(27)
DEFINE_ALIAS_WRAPPER(28)
DEFINE_ALIAS_WRAPPER(29)
DEFINE_ALIAS_WRAPPER(30)
DEFINE_ALIAS_WRAPPER(31)
DEFINE_ALIAS_WRAPPER(32)
DEFINE_ALIAS_WRAPPER(33)

typedef DWORD** (__fastcall *AliasHandlerFn)(DWORD**);

static AliasHandlerFn g_aliasHandlers[] = {
	&AliasWrapper0,  &AliasWrapper1,  &AliasWrapper2,  &AliasWrapper3,
	&AliasWrapper4,  &AliasWrapper5,  &AliasWrapper6,  &AliasWrapper7,
	&AliasWrapper8,  &AliasWrapper9,  &AliasWrapper10, &AliasWrapper11,
	&AliasWrapper12, &AliasWrapper13, &AliasWrapper14, &AliasWrapper15,
	&AliasWrapper16, &AliasWrapper17, &AliasWrapper18, &AliasWrapper19,
	&AliasWrapper20, &AliasWrapper21, &AliasWrapper22, &AliasWrapper23,
	&AliasWrapper24, &AliasWrapper25, &AliasWrapper26, &AliasWrapper27,
	&AliasWrapper28, &AliasWrapper29, &AliasWrapper30, &AliasWrapper31,
	&AliasWrapper32, &AliasWrapper33,
};

static DWORD HandlerForAlias(int index) {
	if (index < 0 || index >= (int)(sizeof(g_aliasHandlers) / sizeof(g_aliasHandlers[0]))) {
		return 0;
	}

	return (DWORD)g_aliasHandlers[index];
}

static int ResolveNativeHandler(DWORD dwHash, const char** szResolvedName) {
	int iHandler = g_lookupNative(NativeTableRoot(), dwHash);
	if (iHandler != 0) {
		if (szResolvedName) {
			*szResolvedName = 0;
		}
		return iHandler;
	}

	const NativeAlias* pAlias = FindAlias(dwHash);
	if (!pAlias || pAlias->eShim == kLogOnly) {
		if (szResolvedName) {
			*szResolvedName = pAlias ? pAlias->szName : "UNKNOWN";
		}
		return 0;
	}

	if (szResolvedName) {
		*szResolvedName = pAlias->szName;
	}

	for (int i = 0; i < (int)(sizeof(g_Aliases) / sizeof(g_Aliases[0])); ++i) {
		if (g_Aliases[i].dwHash == dwHash) {
			return (int)HandlerForAlias(i);
		}
	}

	return 0;
}

static int ValidatePatchedScript(BYTE* script, int iSize, MissingNativeEntry* pOutEntries, int iMaxEntries) {
	int iRemaining = iSize;
	BYTE* pbCursor = script;
	int iFoundIndex = 0;
	int iResult = 1;

	while (iRemaining > 0) {
		if (*pbCursor == 0x2D) {
			DWORD dwHash = ReadNativeHash(pbCursor);
			const char* szResolvedName = 0;
			int iHandlerPtr = ResolveNativeHandler(dwHash, &szResolvedName);
			if (iHandlerPtr == 0) {
				if (iFoundIndex < iMaxEntries) {
					pOutEntries[iFoundIndex].dwHash = dwHash;
					pOutEntries[iFoundIndex].dwCounter = (DWORD)(pbCursor - script);
					pOutEntries[iFoundIndex].szName = szResolvedName ? szResolvedName : "UNKNOWN";
					iFoundIndex++;
				}
				iResult = 0;
			} else {
				pbCursor[3] = (BYTE)iHandlerPtr;
				pbCursor[4] = (BYTE)(iHandlerPtr >> 8);
				pbCursor[5] = (BYTE)(iHandlerPtr >> 16);
				pbCursor[6] = (BYTE)(iHandlerPtr >> 24);
			}
		}

		int iStep = g_getInsnSize(pbCursor);
		if (iStep <= 0 || iStep > iRemaining) {
			break;
		}

		pbCursor += iStep;
		iRemaining -= iStep;
	}

	return iResult ? iFoundIndex : -iFoundIndex;
}

static int __fastcall ValidateHook(BYTE* script, int size) {
	DbgPrint("validate enter script=%08X size=%d", (DWORD)script, size);
	MissingNativeEntry missing[64] = {};
	int validateResult = ValidatePatchedScript(script, size, missing, 64);
	int result = validateResult >= 0 ? 1 : 0;
	int missingCount = validateResult >= 0 ? validateResult : -validateResult;

	return result;
}

// TODO(rwf93): fix for retail?
#if 0
int
NetDll_XNetStartupHook(
	IN		XNCALLER_TYPE xnc,
	IN		XNetStartupParams* xnsp
) {
	xnsp->cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
	return ::NetDll_XNetStartup(xnc, xnsp);
}

int NetDll_socketHook(XNCALLER_TYPE xnc, int af, int type, int protocol)
{
	if (protocol == IPPROTO_VDP) protocol = IPPROTO_UDP;

	SOCKET s = NetDll_socket(xnc, af, type, protocol);

	DbgPrint("Receiving socket of type %i, creating socket %p with protocol %i\n", xnc, socket, protocol);
	
	int b = 1;
	NetDll_setsockopt(xnc, s, SOL_SOCKET, SO_MARKINSECURE, (const char*)&b, 4);

	return s;
}
#endif

static void InstallHooks() {
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
	if (!pLdr) {
		DbgPrint("target title seen but executable handle unavailable");
		return;
	}

	if (pLdr->TimeDateStamp != kTargetTimestamp) {
		DbgPrint("title matched but timestamp mismatch: %08X", pLdr->TimeDateStamp);
		return;
	}

	// rwf93: faulting on an stlw withinside the TimeCycle::QueryModifierBoxTree, so i just nop it out with ori %r0, 0, 0
	// 2lazy4me, probably broke something
	*(DWORD*)(0x825D7488) = 0x60000000;

	//rwf93: force RAG socket to use port 2001
	*(BYTE*)(0x823248B0 + 7) = 0xD1;
	
	// fix stack sizes
	// thx jason098
	*(DWORD*)(0x82852820) = 0x38600014;
	*(DWORD*)(0x8285282C) = 0x38600014;
	*(DWORD*)(0x82852874) = 0x38600003;
	*(DWORD*)(0x82852888) = 0x38802000;

	// TODO(rwf93): fix for retail?
#if 0
	PatchModuleImport(pLdr, "xam.xex", 51, (DWORD)NetDll_XNetStartupHook);
	PatchModuleImport(pLdr, "xam.xex", 3, (DWORD)NetDll_socketHook);
#endif

	g_ValidateDetour.SetupDetour(kValidateAddr, ValidateHook);
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
