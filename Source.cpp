#define _WIN32_DCOM
#include <iostream>
#include <windows.h>
#include <Lmcons.h>
#include <tchar.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <intrin.h>
# pragma comment(lib, "wbemuuid.lib")

using namespace std;

void username() {
	TCHAR name[UNLEN + 1];
	DWORD size = UNLEN + 1;

	if (GetUserName((TCHAR*)name, &size))
		wcout << "windows_username: " << name << endl;
}

string getOsName()
{
#ifdef _WIN32
    return "Windows 32-bit";
#elif _WIN64
    return "Windows 64-bit";
#elif __APPLE__ || __MACH__
    return "Mac OSX";
#elif __linux__
    return "Linux";
#elif __FreeBSD__
    return "FreeBSD";
#elif __unix || __unix__
    return "Unix";
#else
    return "Other";
#endif
}

void cpuID(unsigned i, unsigned regs[4]) {
#ifdef _WIN32
    __cpuid((int*)regs, (int)i);

#else
    asm volatile
        ("cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
            : "a" (i), "c" (0));
    // ECX is set to zero for CPUID function 4
#endif
}


int _tmain(int argc, _TCHAR* argv[])
{
    username();
  

    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return 0;
    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return 0;
    }
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return 0;
    }
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"root\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return 0;
    }
    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_VideoController"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }
    IWbemClassObject* pclsObj;
    ULONG uReturn = 0;
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)break;
        VARIANT vtProp;
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        wcout << "gpu_name: " << vtProp.bstrVal << endl;
        VariantClear(&vtProp);
    }

    int CPUInfo[4] = { -1 };
    __cpuid(CPUInfo, 0x80000000);
    unsigned int nExIds = CPUInfo[0];

    // Get the information associated with each extended ID.
    char CPUBrandString[0x40] = { 0 };
    for (unsigned int i = 0x80000000; i <= nExIds; ++i)
    {
        __cpuid(CPUInfo, i);

        // Interpret CPU brand string and cache information.
        if (i == 0x80000002)
        {
            memcpy(CPUBrandString,
                CPUInfo,
                sizeof(CPUInfo));
        }
        else if (i == 0x80000003)
        {
            memcpy(CPUBrandString + 16,
                CPUInfo,
                sizeof(CPUInfo));
        }
        else if (i == 0x80000004)
        {
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        }
    }

    unsigned regs[4];

    // Get vendor
    char vendor[12];
    cpuID(0, regs);
    ((unsigned*)vendor)[0] = regs[1]; // EBX
    ((unsigned*)vendor)[1] = regs[3]; // EDX
    ((unsigned*)vendor)[2] = regs[2]; // ECX
    string cpuVendor = string(vendor, 12);

    // Get CPU features
    cpuID(1, regs);
    unsigned cpuFeatures = regs[3]; // EDX

    // Logical core count per CPU
    cpuID(1, regs);
    unsigned logical = (regs[1] >> 16) & 0xff; // EBX[23:16]
    unsigned cores = logical;

    if (cpuVendor == "GenuineIntel") {
        // Get DCP cache info
        cpuID(4, regs);
        cores = ((regs[0] >> 26) & 0x3f) + 1; // EAX[31:26] + 1

    }
    else if (cpuVendor == "AuthenticAMD") {
        // Get NC: Number of CPU cores - 1
        cpuID(0x80000008, regs);
        cores = ((unsigned)(regs[2] & 0xff)) + 1; // ECX[7:0] + 1
    }



    cout << "cpu_name: " << CPUBrandString << endl;
    cout << "cpu_cores (# of threads): " << cores << endl;

    cout << "\n" << "\n";
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();

    int x;
    cin >> x;


}

