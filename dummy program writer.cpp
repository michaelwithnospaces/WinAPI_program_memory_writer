#include <iostream>
#include <Windows.h>

void getHandleFromPid();
void writeIntToAddress(LPVOID baseAddress, int dataBuffer);
void terminateProgram();


HANDLE hProcess;
SIZE_T* pNumberOfBytesWritten = NULL;

int main() {

    getHandleFromPid();

	int intToWrite = 123456;
    uintptr_t baseAddress = 0xC0454FF874;
    writeIntToAddress((LPVOID)baseAddress, intToWrite);

    terminateProgram();

	return EXIT_SUCCESS;
}

// reads PID and returns HANDLE
void getHandleFromPid() {
    DWORD pid;
    bool invalidPid = false;

    while (!invalidPid) {
        // read process ID
        std::cout << "Process ID: ";
        std::cin >> pid;

        hProcess = OpenProcess(
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION, // desired access
            FALSE, // child process' inherit handle
            pid // target PID
        );

        // handle OpenProcess errors
        if (hProcess == NULL) {
            std::cout << "OpenProcess failed. GetLastError = " << std::dec << GetLastError() << std::endl;
        }
        else {
            break;
        }
    }
}

// writes integer to address
void writeIntToAddress(LPVOID baseAddress, int dataBuffer) {
    BOOL wpmStatus = WriteProcessMemory(
        hProcess,
        baseAddress,
        &dataBuffer,
        sizeof(int),
        pNumberOfBytesWritten
    );

    if (wpmStatus == FALSE) {
        std::cout << "WriteProcessMemory failed. [GetLastError] " << std::dec << GetLastError() << std::endl;
        system("pause");
    }
    else {
        std::cout << "Overwritten successfully." << std::endl;
    }
}

// terminates program
void terminateProgram() {
    std::cout << std::endl;
    std::cout << "Press ENTER to quit." << std::endl;
    system("pause > nul");
}