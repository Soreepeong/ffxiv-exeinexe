#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <functional>

static std::function<void()> s_attachcallback, s_detachcallback;

__declspec(dllexport) void my_set_thread_attach_callback(std::function<void()> cb) {
	s_attachcallback = std::move(cb);
}

__declspec(dllexport) void my_set_thread_detach_callback(std::function<void()> cb) {
	s_detachcallback = std::move(cb);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			break;
		case DLL_THREAD_ATTACH:
			if (s_attachcallback)
				s_attachcallback();
			break;
		case DLL_THREAD_DETACH:
			if (s_detachcallback)
				s_detachcallback();
			break;
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

