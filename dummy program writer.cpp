#include <iostream>
#include <Windows.h>

void getHandleFromPid();
void writeIntToAddress(LPVOID baseAddress, int dataBuffer);
void writeCharToAddress(LPVOID baseAddress, char dataBuffer[]);
void terminateProgram();
uintptr_t getMemoryAddress();

HANDLE hProcess;
SIZE_T* pNumberOfBytesWritten = NULL;

int main() {

    getHandleFromPid();

    // write int to target address
	int intToWrite = 999999;
    uintptr_t baseAddress = getMemoryAddress();

    writeIntToAddress((LPVOID)baseAddress, intToWrite);

    // write char array to target address
    char charToWrite[128] = "This process has been hacked!";
    baseAddress = getMemoryAddress();
    writeCharToAddress((LPVOID)baseAddress, charToWrite);

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
    std::cout << "Writing int to " << baseAddress << "..." << std::endl;

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
        std::cout << "Overwritten successfully." << std::endl << std::endl;
    }
}

// writes char array to address
void writeCharToAddress(LPVOID baseAddress, char dataBuffer[]) {
    std::cout << "Writing char array to " << baseAddress << "..." << std::endl;

    BOOL wpmStatus = WriteProcessMemory(
        hProcess,
        baseAddress,
        dataBuffer,
        128,
        pNumberOfBytesWritten
    );

    if (wpmStatus == FALSE) {
        std::cout << "WriteProcessMemory failed. [GetLastError] " << std::dec << GetLastError() << std::endl;
        system("pause");
    }
    else {
        std::cout << "Overwritten successfully." << std::endl << std::endl;
    }
}

// terminates program
void terminateProgram() {
    std::cout << std::endl;
    std::cout << "Press ENTER to quit." << std::endl;
    system("pause > nul");
}

// Get the taget memory addresss
uintptr_t getMemoryAddress() {
    uintptr_t address = 0x0;

    std::cout << "Target memory address (hexadecimal): 0x";
    std::cin >> std::hex >> address;

    return address;
}