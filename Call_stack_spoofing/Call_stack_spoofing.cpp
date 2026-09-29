// Call_stack_spoofing.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

extern "C" PVOID Spoof(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, PVOID Param, HWND hwnd0, LPCTSTR lpText0, LPCTSTR lpCaption0, UINT uType0);

using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
PrototypeMessageBox originalMsgBox = MessageBoxA;

typedef struct EXCEPTION_INFO  {
    ULONG_PTR ExeptionDirectoryAdress;
    DWORD ExeptionDirectoryCount;
}*PEXCEPTION_INFO;

typedef struct Param {
    PVOID BIT_Return_adress;
    ULONG_PTR BIT_size;
    PVOID UTS_Return_adress;
    ULONG_PTR UTS_size;
    PVOID Gadget_adress;
    ULONG_PTR Gadget_size;
    PVOID ebx_save;
    PVOID Function_adress;
    PVOID Origin_ret_adress;
}*PParam;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, * PUNWIND_INFO;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

PVOID Findgadget(HMODULE Kernel32_adress, DWORD Kernel32_size) {
    \
        LPBYTE c = (LPBYTE)Kernel32_adress;
    BYTE first = 0xFF;
    BYTE Second = 0x23;
    for (DWORD x = 0; x <= Kernel32_size; x++) {
        PUCHAR temp = c + x + 1;
        CHAR d = *(c + x);
        CHAR e = *temp;
        if (first == *(c + x) && Second == *temp) {
            printf("lmao");
            return c + x;
        }

    }
    return 0;
}

PVOID FindingExeptionInfor(HMODULE ImageBase, PEXCEPTION_INFO pExcpetion_info) {
    LPVOID imageBase = ImageBase;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)imageBase + pDosHeader->e_lfanew);

    pExcpetion_info->ExeptionDirectoryAdress = pNtHeader->OptionalHeader.DataDirectory[3].VirtualAddress + (ULONG_PTR)imageBase;
    pExcpetion_info->ExeptionDirectoryCount = pNtHeader->OptionalHeader.DataDirectory[3].Size / sizeof(RUNTIME_FUNCTION);
    return pExcpetion_info;

}

DWORD CaculatingStackSize(HMODULE ImageBase, PVOID Fucntion_Adress) {
    PEXCEPTION_INFO pExcpetion_info = new EXCEPTION_INFO;
    FindingExeptionInfor(ImageBase, pExcpetion_info);

    PUNWIND_INFO pUnwind_info = new UNWIND_INFO;
    PUNWIND_CODE pUnwind_code;

    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)pExcpetion_info->ExeptionDirectoryAdress;
    
    ULONG_PTR Runtime_function_offset = (PBYTE)Fucntion_Adress - (PBYTE)ImageBase;
    for (size_t i = 0; i < pExcpetion_info->ExeptionDirectoryCount; i++)
    {
        if (Runtime_function_offset >= pRuntimeFunction->BeginAddress && Runtime_function_offset <= pRuntimeFunction->EndAddress) {
            break;
        }
        pRuntimeFunction++;
    }
    ULONG_PTR a = pRuntimeFunction->UnwindInfoAddress + (ULONG_PTR)ImageBase;
    pUnwind_info = (PUNWIND_INFO)(pRuntimeFunction->UnwindInfoAddress+ (ULONG_PTR)ImageBase);
    pUnwind_code = pUnwind_info->UnwindCode;
    DWORD Stack_size = 0;
    for (size_t i = 0; i < pUnwind_info->CountOfCodes; i++)
    {
        DWORD Unwin_Operation_Code = pUnwind_code[i].UnwindOp;
        DWORD frameOffset = pUnwind_code[i].FrameOffset;
        DWORD codeOffset = pUnwind_code[i].CodeOffset;
        DWORD opInfo = pUnwind_code[i].OpInfo;
        switch (Unwin_Operation_Code)
        {
        case UWOP_PUSH_NONVOL:
            Stack_size = Stack_size + 8;
            break;
        case UWOP_ALLOC_LARGE:
            if (pUnwind_code[i].OpInfo == 0x1)
            {
                Stack_size = Stack_size + pUnwind_code[i + 1].FrameOffset * 8;
                i++;
                break;
            }
            else
            {
                Stack_size = Stack_size + pUnwind_code[i + 1].FrameOffset + (pUnwind_code[i + 2].FrameOffset << 16);
                i += 2;
                break;
            }
        case UWOP_ALLOC_SMALL:
            Stack_size = Stack_size + pUnwind_code[i].OpInfo * 8 + 8;
            break;
        case UWOP_PUSH_MACHFRAME:
            if (pUnwind_code[i].OpInfo == 0) {
                Stack_size += 40;
                break;
            }
            else
            {
                Stack_size += 48;
                break;
            }
        case UWOP_SAVE_NONVOL:
            i = i + 1;
            break;
        case UWOP_SAVE_NONVOL_FAR:
            i += 2;
            break;
        }
    }

    return Stack_size;
}


int EvilThing(HWND hwnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    PParam param = new Param;
    LPMODULEINFO Module_info = new MODULEINFO;
    PVOID messbox_origin = originalMsgBox;
 

    HMODULE KernelDLL_adress = LoadLibraryA("kernel32.dll");
    param->BIT_Return_adress = (PBYTE)GetProcAddress(KernelDLL_adress, "BaseThreadInitThunk") + 0x24;
    param->BIT_size = CaculatingStackSize(KernelDLL_adress, param->BIT_Return_adress);

    HMODULE ntdlldll_adress = LoadLibraryA("ntdll.dll");
    param->UTS_Return_adress = (PBYTE)GetProcAddress(ntdlldll_adress, "RtlUserThreadStart") + 0x14;
    param->UTS_size = CaculatingStackSize(ntdlldll_adress, param->UTS_Return_adress);

    GetModuleHandle(NULL);
    GetModuleInformation(GetModuleHandle(NULL), KernelDLL_adress, Module_info, sizeof(MODULEINFO));

    param->Gadget_adress = Findgadget(KernelDLL_adress, Module_info->SizeOfImage);
    param->Gadget_size = CaculatingStackSize(KernelDLL_adress, param->Gadget_adress);

    param->Function_adress = messbox_origin;
    Spoof(NULL, "lmao", "lmao", 0, param, hwnd, lpText, lpCaption, uType);
    return 0;
}

int main()
{
    LPVOID imageBase = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);



    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPCSTR libraryName = NULL;
    HMODULE library = NULL;
    PIMAGE_IMPORT_BY_NAME functionName = NULL;

    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
        library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
            originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != NULL)
            {
                functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

                // find MessageBoxA address
                if (std::string(functionName->Name).compare("MessageBoxA") == 0)
                {
                    SIZE_T bytesWritten = 0;
                    DWORD oldProtect = 0;
                    VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                    firstThunk->u1.Function = (DWORD_PTR)EvilThing;

                    // swap MessageBoxA address with address of hookedMessageBox
                    //firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
                }
                ++originalFirstThunk;
                ++firstThunk;
            }
        }

        importDescriptor++;
    }
    MessageBoxA(NULL, "Check_My_Ret_Addr", "Hooked", 0);

    /*ULONG_PTR a = (ULONG_PTR)(&shellcode + 3);
    ULONG_PTR Realative_Adress_to_API = Adress_to_API_code - (shell_codes_adress + 31);
    ULONG_PTR Realative_Adress_to_API_again = Adress_to_API_code - (shell_codes_adress + 41);
    memcpy_s(shellcode + 3, sizeof(ULONG_PTR), &mess_cap_adress, sizeof(ULONG_PTR));
    memcpy_s(shellcode + 12, sizeof(ULONG_PTR), &mess_title_adress, sizeof(ULONG_PTR));
    memcpy_s(shellcode + 23, sizeof(ULONG_PTR), &Realative_Adress_to_API, sizeof(ULONG_PTR));
    memcpy_s(shellcode + 33, sizeof(ULONG_PTR), &Realative_Adress_to_API_again, sizeof(ULONG_PTR));

    WriteProcessMemory(Remote_Proc_Handle, (LPVOID)(shell_codes_adress), &shellcode, sizeof(shellcode), 0);
    */

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
