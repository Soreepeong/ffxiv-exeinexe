#include "pch.h"

#pragma comment(lib,"dbghelp.lib")

#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static HINSTANCE s_hGame;

struct IATRESULTS {
	enum class FAILUREREASON {
		SUCCESS = 0,
		OTHER = 1,
		NOTFOUND = 2,
		CANNOTPATCH = 3,
	};
	struct FUNCTIONINFO {
		std::string name;
		size_t ord = 0;
		FAILUREREASON f = FAILUREREASON::SUCCESS;
	};
	struct MODULEINFO {
		std::string name;
		HINSTANCE handle = 0;
		FAILUREREASON f = FAILUREREASON::SUCCESS;
		std::vector<FUNCTIONINFO> functions;
	};

	std::vector<MODULEINFO> modules;
};

void ParseIAT(HINSTANCE h, IATRESULTS& res) {
	// Get IAT size
	DWORD ulsize = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
	if (!pImportDesc)
		return;

	// Loop names
	for (; pImportDesc->Name; pImportDesc++) {
		PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
		if (!pszModName)
			break;

		IATRESULTS::MODULEINFO m;

		m.name = pszModName;

		HINSTANCE hImportDLL = LoadLibraryA(pszModName);
		if (!hImportDLL) {
			m.f = IATRESULTS::FAILUREREASON::NOTFOUND;
			res.modules.push_back(m);
			continue;
		}
		m.handle = hImportDLL;
		m.f = IATRESULTS::FAILUREREASON::SUCCESS;

		// Get caller's import address table (IAT) for the callee's functions
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			((PBYTE)h + pImportDesc->FirstThunk);

		// Replace current function address with new function address
		for (; pThunk->u1.Function; pThunk++) {
			IATRESULTS::FUNCTIONINFO fu;

			FARPROC pfnNew = 0;
			size_t rva = 0;
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);

				fu.ord = ord;
				m.functions.push_back(fu);
				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn) {
					fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
					m.functions.push_back(fu);
					continue;
				}
				rva = (size_t)pThunk;

				char fe[100] = { 0 };
				sprintf_s(fe, 100, "#%zu", ord);
				pfnNew = GetProcAddress(hImportDLL, (LPCSTR)ord);
				if (!pfnNew) {
					fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
					m.functions.push_back(fu);
					continue;
				}
			} else {
				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn) {
					fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
					m.functions.push_back(fu);
					continue;
				}
				rva = (size_t)pThunk;
				PSTR fName = (PSTR)h;
				fName += pThunk->u1.Function;
				fName += 2;
				if (!fName)
					break;
				fu.name = fName;
				pfnNew = GetProcAddress(hImportDLL, fName);
				if (!pfnNew) {
					fu.f = IATRESULTS::FAILUREREASON::NOTFOUND;
					m.functions.push_back(fu);
					continue;
				}
			}

			// Patch it now...
			auto hp = GetCurrentProcess();

			if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError())) {
				DWORD dwOldProtect;
				if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect)) {
					if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew,
						sizeof(pfnNew), NULL)) {
						fu.f = IATRESULTS::FAILUREREASON::CANNOTPATCH;
						continue;
					}
					if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect,
						&dwOldProtect)) {
						fu.f = IATRESULTS::FAILUREREASON::CANNOTPATCH;
						continue;
					}
				}
			}
			m.functions.push_back(fu);
		}
		res.modules.push_back(m);
	}
}

__declspec(dllexport) void my_set_thread_attach_callback(std::function<void()> cb);
__declspec(dllexport) void my_set_thread_detach_callback(std::function<void()> cb);

decltype(&OpenProcess) s_OpenProcess;
HANDLE WINAPI NewOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	if (dwProcessId == GetCurrentProcessId() && dwDesiredAccess == PROCESS_VM_WRITE) {
		SetLastError(ERROR_ACCESS_DENIED);
		return {};
	}
	return s_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

decltype(&GetModuleFileNameW) s_GetModuleFileNameW, s_K32GetModuleFileNameW;
DWORD WINAPI NewGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize) {
	if (!hModule)
		hModule = s_hGame;
	return s_GetModuleFileNameW(hModule, lpFilename, nSize);
}

decltype(&GetModuleFileNameA) s_GetModuleFileNameA, s_K32GetModuleFileNameA;
DWORD WINAPI NewGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize) {
	if (!hModule)
		hModule = s_hGame;
	return s_GetModuleFileNameA(hModule, lpFilename, nSize);
}

int __stdcall WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
	const auto gamePath = std::filesystem::path(LR"(Z:\XIV\JP\game\ffxiv_dx11.exe)");
	const auto gameDir = gamePath.parent_path();
	SetDllDirectoryW(gameDir.c_str());
	SetCurrentDirectoryW(gameDir.c_str());

	auto& peb = *NtCurrentTeb()->ProcessEnvironmentBlock;
	peb.BeingDebugged = 0;
	peb.ProcessParameters->ImagePathName.Buffer = const_cast<wchar_t*>(gamePath.c_str());
	peb.ProcessParameters->ImagePathName.Length = peb.ProcessParameters->ImagePathName.MaximumLength = static_cast<uint16_t>(wcslen(gamePath.c_str()) * 2);

	std::wstring parameterBuffer(peb.ProcessParameters->CommandLine.Buffer, peb.ProcessParameters->CommandLine.Length);
	if (parameterBuffer.starts_with(L"\""))
		parameterBuffer = std::wstring(L"\"") + gamePath.c_str() + L"\"" + parameterBuffer.substr(parameterBuffer.find('"', 1) + 1);
	else
		parameterBuffer = std::wstring(L"\"") + gamePath.c_str() + L"\"" + parameterBuffer.substr(parameterBuffer.find(' '));
	peb.ProcessParameters->CommandLine.Buffer = const_cast<wchar_t*>(parameterBuffer.c_str());
	peb.ProcessParameters->CommandLine.Length = peb.ProcessParameters->CommandLine.MaximumLength = static_cast<uint16_t>(wcslen(parameterBuffer.c_str()) * 2);

	peb.Reserved3[1] = s_hGame = LoadLibrary(gamePath.filename().c_str());
	if (!s_hGame)
		return 0;

	IATRESULTS res;
	ParseIAT(s_hGame, res); // https://www.codeproject.com/Articles/1045674/Load-EXE-as-DLL-Mission-Possible

	MH_Initialize();
	MH_CreateHook(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleFileNameA"), &NewGetModuleFileNameA, (void**)&s_GetModuleFileNameA);
	MH_CreateHook(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleFileNameW"), &NewGetModuleFileNameW, (void**)&s_GetModuleFileNameW);
	MH_CreateHook(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32GetModuleFileNameA"), &NewGetModuleFileNameA, (void**)&s_K32GetModuleFileNameA);
	MH_CreateHook(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32GetModuleFileNameW"), &NewGetModuleFileNameW, (void**)&s_K32GetModuleFileNameW);
	MH_CreateHook(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OpenProcess"), &NewOpenProcess, (void**)&s_OpenProcess);
	MH_EnableHook(MH_ALL_HOOKS);

	auto pGame = (char*)s_hGame;
	auto& gamedosh = *(IMAGE_DOS_HEADER*)&pGame[0];
	auto& gamenth64 = *(IMAGE_NT_HEADERS64*)&pGame[gamedosh.e_lfanew];
	auto& gametls = *(IMAGE_TLS_DIRECTORY64*)&pGame[gamenth64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress];

	std::mutex mtx;
	std::map<DWORD, void*> prevTlsItem;

	my_set_thread_attach_callback([&]() {
		const auto siz = 1 + gametls.EndAddressOfRawData - gametls.StartAddressOfRawData;
		const auto addr = VirtualAlloc(nullptr, siz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!addr)
			std::abort();
		memcpy(addr, (void*)gametls.StartAddressOfRawData, siz);

		const auto lock = std::lock_guard(mtx);
		auto& tlsAddr = ((void***)NtCurrentTeb())[0xB][*(DWORD*)gametls.AddressOfIndex];
		prevTlsItem.emplace(GetCurrentThreadId(), tlsAddr);
		tlsAddr = addr;
	});

	my_set_thread_detach_callback([&]() {
		const auto lock = std::lock_guard(mtx);
		auto& tlsAddr = ((void***)NtCurrentTeb())[0xB][*(DWORD*)gametls.AddressOfIndex];
		if (const auto it = prevTlsItem.find(GetCurrentThreadId()); it != prevTlsItem.end()) {
			VirtualFree(tlsAddr, 0, MEM_RELEASE);
			tlsAddr = it->second;
			prevTlsItem.erase(it);
		}
	});

	std::thread([&]() {
		((void(*)()) & pGame[gamenth64.OptionalHeader.AddressOfEntryPoint])();
	}).join();
	return 0;
}