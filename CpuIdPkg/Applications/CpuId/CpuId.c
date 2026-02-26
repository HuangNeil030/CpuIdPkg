#include <Base.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Protocol/Cpu.h>

//
// ================================================
// CPU / CPUID / MSR / MTRR App (Anti-Crash Version)
// ================================================
//

#define MSR_IA32_MTRRCAP             0x000000FE
#define MSR_IA32_MTRR_DEF_TYPE       0x000002FF
#define MSR_IA32_MTRR_PHYSBASE0      0x00000200
#define MSR_IA32_MTRR_PHYSMASK0      0x00000201

#define MSR_IA32_MTRR_FIX64K_00000   0x00000250
#define MSR_IA32_MTRR_FIX16K_80000   0x00000258
#define MSR_IA32_MTRR_FIX16K_A0000   0x00000259
#define MSR_IA32_MTRR_FIX4K_C0000    0x00000268
#define MSR_IA32_MTRR_FIX4K_C8000    0x00000269
#define MSR_IA32_MTRR_FIX4K_D0000    0x0000026A
#define MSR_IA32_MTRR_FIX4K_D8000    0x0000026B
#define MSR_IA32_MTRR_FIX4K_E0000    0x0000026C
#define MSR_IA32_MTRR_FIX4K_E8000    0x0000026D
#define MSR_IA32_MTRR_FIX4K_F0000    0x0000026E
#define MSR_IA32_MTRR_FIX4K_F8000    0x0000026F

#define CPUID_FEAT_EDX_TSC           BIT4
#define CPUID_FEAT_EDX_MSR           BIT5
#define CPUID_FEAT_EDX_MTRR          BIT12

#define IA32_MTRRCAP_VCNT_MASK       0xFFu
#define IA32_MTRRCAP_FIX_BIT         BIT8
#define IA32_MTRR_DEF_TYPE_TYPE_MASK 0xFFu
#define IA32_MTRR_DEF_TYPE_FE_BIT    BIT10
#define IA32_MTRR_DEF_TYPE_E_BIT     BIT11

#define MENU_ITEMS_COUNT             6
#define INPUT_BUF_LEN                32
#define PAGE_LINES_LIMIT             18

typedef enum {
  MenuCpuId = 0,
  MenuDumpCpuId,
  MenuReadMsr,
  MenuDumpMsr,
  MenuWriteMsr,
  MenuDumpMtrr
} MENU_ACTION;

STATIC CONST CHAR16 *mMenuItems[MENU_ITEMS_COUNT] = {
  L"CPU ID",
  L"Dump CPU ID",
  L"Read MSR",
  L"Dump MSR",
  L"Write MSR",
  L"Dump MTRR"
};

//
// =====================================================
// Global Variables for MSR #GP Handler
// =====================================================
//
EFI_CPU_ARCH_PROTOCOL *mCpu = NULL;
volatile BOOLEAN      gMsrFault = FALSE;

//
// =====================================================
// Exception Handler (Intercepts #GP)
// =====================================================
//
VOID
EFIAPI
MsrFaultHandler (
  IN EFI_EXCEPTION_TYPE   InterruptType,
  IN EFI_SYSTEM_CONTEXT   SystemContext
  )
{
  UINT8 *Ip;

#if defined (MDE_CPU_X64)
  Ip = (UINT8 *)SystemContext.SystemContextX64->Rip;
#elif defined (MDE_CPU_IA32)
  Ip = (UINT8 *)SystemContext.SystemContextIa32->Eip;
#else
  return;
#endif

  // Check if instruction is rdmsr (0F 32) or wrmsr (0F 30)
  if (Ip[0] == 0x0F && (Ip[1] == 0x32 || Ip[1] == 0x30)) {
    gMsrFault = TRUE;
    
    // Skip the faulting 2-byte instruction
#if defined (MDE_CPU_X64)
    SystemContext.SystemContextX64->Rip += 2;
    if (Ip[1] == 0x32) { // rdmsr: clear return values
      SystemContext.SystemContextX64->Rax = 0;
      SystemContext.SystemContextX64->Rdx = 0;
    }
#elif defined (MDE_CPU_IA32)
    SystemContext.SystemContextIa32->Eip += 2;
    if (Ip[1] == 0x32) {
      SystemContext.SystemContextIa32->Eax = 0;
      SystemContext.SystemContextIa32->Edx = 0;
    }
#endif
  } else {
    // If it's a real crash somewhere else, halt the system
    CpuDeadLoop(); 
  }
}

STATIC BOOLEAN SafeReadMsr (IN UINT32 Index, OUT UINT64 *Value) {
  gMsrFault = FALSE;
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrFaultHandler);
  }
  *Value = AsmReadMsr64 (Index);
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
  }
  return !gMsrFault;
}

STATIC BOOLEAN SafeWriteMsr (IN UINT32 Index, IN UINT64 Value) {
  gMsrFault = FALSE;
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrFaultHandler);
  }
  AsmWriteMsr64 (Index, Value);
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
  }
  return !gMsrFault;
}

//
// =====================================================
// UI helpers
// =====================================================
//
STATIC VOID SetAttrNormal (VOID) {
  gST->ConOut->SetAttribute (gST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
}

STATIC VOID SetAttrHighlight (VOID) {
  gST->ConOut->SetAttribute (gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLUE);
}

STATIC VOID ClearScreenAndResetAttr (VOID) {
  gST->ConOut->ClearScreen (gST->ConOut);
  SetAttrNormal ();
}

STATIC BOOLEAN ReadKeyBlocking (OUT EFI_INPUT_KEY *Key) {
  EFI_STATUS Status;
  UINTN      Index;
  if (Key == NULL) return FALSE;
  Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
  if (EFI_ERROR (Status)) return FALSE;
  Status = gST->ConIn->ReadKeyStroke (gST->ConIn, Key);
  return (BOOLEAN)!EFI_ERROR (Status);
}

STATIC VOID DrainKeyBuffer (VOID) {
  EFI_INPUT_KEY Key;
  while (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key)));
}

STATIC VOID WaitAnyKey (VOID) {
  EFI_INPUT_KEY Key;
  DrainKeyBuffer ();
  SetAttrHighlight ();
  Print (L"\nPress any key to continue");
  SetAttrNormal ();
  while (TRUE) {
    if (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) break;
  }
}

STATIC BOOLEAN PagePauseOrExit (VOID) {
  EFI_INPUT_KEY Key;
  DrainKeyBuffer ();
  SetAttrHighlight ();
  Print (L"\nPress any key to continue, or 'q' to exit");
  SetAttrNormal ();
  while (TRUE) {
    if (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) {
      Print (L"\n");
      if (Key.UnicodeChar == L'q' || Key.UnicodeChar == L'Q') return TRUE;
      return FALSE;
    }
  }
}

STATIC VOID ShowHeaderAndMenu (IN UINTN HighlightIndex) {
  UINTN I;
  ClearScreenAndResetAttr ();
  SetAttrHighlight ();
  Print (L"<<Select The Action>>\n");
  SetAttrNormal ();
  for (I = 0; I < MENU_ITEMS_COUNT; I++) {
    if (I == HighlightIndex) {
      SetAttrHighlight ();
      Print (L"%s\n", mMenuItems[I]);
      SetAttrNormal ();
    } else {
      Print (L"%s\n", mMenuItems[I]);
    }
  }
}

STATIC BOOLEAN HexCharToNibble (IN CHAR16 Ch, OUT UINT8 *Nibble) {
  if (Nibble == NULL) return FALSE;
  if (Ch >= L'0' && Ch <= L'9') { *Nibble = (UINT8)(Ch - L'0'); return TRUE; }
  if (Ch >= L'a' && Ch <= L'f') { *Nibble = (UINT8)(10 + Ch - L'a'); return TRUE; }
  if (Ch >= L'A' && Ch <= L'F') { *Nibble = (UINT8)(10 + Ch - L'A'); return TRUE; }
  return FALSE;
}

STATIC BOOLEAN ParseHex16ToUint64 (IN CONST CHAR16 *Str, OUT UINT64 *Value) {
  UINTN  Index, Start = 0;
  UINT8  Nibble;
  UINT64 Result = 0;
  if (Str == NULL || Value == NULL) return FALSE;
  if (Str[0] == L'0' && (Str[1] == L'x' || Str[1] == L'X')) Start = 2;
  if (Str[Start] == L'\0') return FALSE;
  for (Index = Start; Str[Index] != L'\0'; Index++) {
    if (!HexCharToNibble (Str[Index], &Nibble)) return FALSE;
    Result = (Result << 4) | (UINT64)Nibble;
  }
  *Value = Result;
  return TRUE;
}

STATIC BOOLEAN ReadLine (OUT CHAR16 *Buffer, IN UINTN BufferChars) {
  EFI_INPUT_KEY Key;
  UINTN         Pos = 0;
  if (Buffer == NULL || BufferChars < 2) return FALSE;
  SetMem (Buffer, BufferChars * sizeof (CHAR16), 0);
  while (TRUE) {
    if (!ReadKeyBlocking (&Key)) return FALSE;
    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      Buffer[Pos] = L'\0';
      Print (L"\n");
      return TRUE;
    }
    if (Key.UnicodeChar == CHAR_BACKSPACE) {
      if (Pos > 0) {
        Pos--;
        Buffer[Pos] = L'\0';
        Print (L"\b \b");
      }
      continue;
    }
    if (Key.UnicodeChar >= 0x20 && Key.UnicodeChar <= 0x7E) {
      if (Pos < (BufferChars - 1)) {
        Buffer[Pos++] = Key.UnicodeChar;
        Buffer[Pos]   = L'\0';
        Print (L"%c", Key.UnicodeChar);
      }
    }
  }
}

STATIC BOOLEAN PromptHexUint32 (IN CONST CHAR16 *Prompt, OUT UINT32 *Value) {
  CHAR16 Buf[INPUT_BUF_LEN];
  UINT64 Temp;
  if (Value == NULL) return FALSE;
  Print (L"%s", Prompt);
  if (!ReadLine (Buf, INPUT_BUF_LEN)) return FALSE;
  if (!ParseHex16ToUint64 (Buf, &Temp)) return FALSE;
  *Value = (UINT32)Temp;
  return TRUE;
}

STATIC BOOLEAN PromptHexUint64 (IN CONST CHAR16 *Prompt, OUT UINT64 *Value) {
  CHAR16 Buf[INPUT_BUF_LEN];
  if (Value == NULL) return FALSE;
  Print (L"%s", Prompt);
  if (!ReadLine (Buf, INPUT_BUF_LEN)) return FALSE;
  return ParseHex16ToUint64 (Buf, Value);
}

STATIC BOOLEAN PageLineAccountingEx (IN OUT UINTN *LineCount, IN VOID (*ReprintHeader)(VOID), IN UINTN HeaderLines) {
  if (LineCount == NULL) return FALSE;
  (*LineCount)++;
  if (*LineCount >= PAGE_LINES_LIMIT) {
    if (PagePauseOrExit ()) return TRUE;
    if (ReprintHeader != NULL) {
      ReprintHeader ();
      *LineCount = HeaderLines;
    } else {
      *LineCount = 0;
    }
  }
  return FALSE;
}

//
// =====================================================
// CPU Feature Functions
// =====================================================
//
STATIC BOOLEAN CpuSupportsMsr (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuid (1, &Eax, &Ebx, &Ecx, &Edx);
  return (BOOLEAN)((Edx & CPUID_FEAT_EDX_MSR) != 0);
}

STATIC BOOLEAN CpuSupportsMtrr (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuid (1, &Eax, &Ebx, &Ecx, &Edx);
  return (BOOLEAN)((Edx & CPUID_FEAT_EDX_MTRR) != 0);
}

STATIC CONST CHAR16 *MtrrTypeToStr (IN UINT8 Type) {
  switch (Type) {
    case 0x00: return L"Uncacheable";
    case 0x01: return L"Write-Combining";
    case 0x04: return L"Write-Through";
    case 0x05: return L"Write-Protect";
    case 0x06: return L"Write-Back";
    default:   return L"Reserved";
  }
}

STATIC CONST CHAR16 *MtrrTypeToShortStr (IN UINT8 Type) {
  switch (Type) {
    case 0x00: return L"UC";
    case 0x01: return L"WC";
    case 0x04: return L"WT";
    case 0x05: return L"WP";
    case 0x06: return L"WB";
    default:   return L"RSV";
  }
}

STATIC UINT8 GetPhysicalAddressBits (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuid (0x80000000, &Eax, &Ebx, &Ecx, &Edx);
  if (Eax < 0x80000008) return 36;
  AsmCpuid (0x80000008, &Eax, &Ebx, &Ecx, &Edx);
  if ((Eax & 0xFF) == 0) return 36;
  return (UINT8)(Eax & 0xFF);
}

STATIC VOID PrintCpuidTableHeader (VOID) {
  Print (L"Leaf/SubLeaf    EAX       EBX       ECX       EDX\n");
  Print (L"------------------------------------------------------\n");
}

STATIC VOID PrintMsrTableHeader (VOID) {
  Print (L"MSR        Value\n");
  Print (L"------------------------------\n");
}

STATIC BOOLEAN PrintOneCpuidLeafLine (IN UINT32 Leaf, IN UINT32 SubLeaf, IN OUT UINTN *LineCount) {
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuidEx (Leaf, SubLeaf, &Eax, &Ebx, &Ecx, &Edx);
  Print (L"%08x/%08x  %08x  %08x  %08x  %08x\n", Leaf, SubLeaf, Eax, Ebx, Ecx, Edx);
  if (PageLineAccountingEx (LineCount, PrintCpuidTableHeader, 2)) return TRUE;
  return FALSE;
}

STATIC VOID PrintBrandStringIfSupported (IN UINT32 MaxExtLeaf) {
  if (MaxExtLeaf >= 0x80000004) {
    CHAR8  Brand[49];
    UINT32 *Ptr32;
    SetMem (Brand, sizeof (Brand), 0);
    Ptr32 = (UINT32 *)Brand;
    AsmCpuid (0x80000002, &Ptr32[0],  &Ptr32[1],  &Ptr32[2],  &Ptr32[3]);
    AsmCpuid (0x80000003, &Ptr32[4],  &Ptr32[5],  &Ptr32[6],  &Ptr32[7]);
    AsmCpuid (0x80000004, &Ptr32[8],  &Ptr32[9],  &Ptr32[10], &Ptr32[11]);
    Print (L"\nBrand String : %a\n", Brand);
  }
}

STATIC VOID PrintFixedMtrrDecoded8Types (IN UINT64 Val) {
  UINTN B;
  for (B = 0; B < 8; B++) {
    UINT8 Type = (UINT8)((Val >> (B * 8)) & 0xFF);
    Print (L"%s%s", MtrrTypeToShortStr (Type), (B == 7) ? L"" : L" ");
  }
}

//
// =====================================================
// Feature Implementation 
// =====================================================
//
STATIC VOID DumpMtrrUiLikePhoto_VariableRanges (VOID) {
  UINT64 MtrrCap;
  UINT8  VariableCount;
  UINTN  I;
  
  if (!SafeReadMsr (MSR_IA32_MTRRCAP, &MtrrCap)) return;
  
  VariableCount = (UINT8)(MtrrCap & IA32_MTRRCAP_VCNT_MASK);
  if (VariableCount > 10) VariableCount = 10;

  Print (L"=== [ Variable Range MTRRs ] ===\n");
  Print (L"MTRR | Idx  | PHYSBASE (Type)                  | PHYSMASK (Valid)               | Status\n");
  Print (L"-----+------+--------------------------------+--------------------------------+----------------\n");

  for (I = 0; I < 10; I++) {
    UINT64  BaseVal = 0, MaskVal = 0;
    UINT8   Type = 0;
    BOOLEAN Valid = FALSE;
    UINT32  BaseMsr, MaskMsr;

    if (I < VariableCount) {
      BaseMsr = MSR_IA32_MTRR_PHYSBASE0 + (UINT32)(I * 2);
      MaskMsr = MSR_IA32_MTRR_PHYSMASK0 + (UINT32)(I * 2);
      SafeReadMsr(BaseMsr, &BaseVal);
      SafeReadMsr(MaskMsr, &MaskVal);
      Type  = (UINT8)(BaseVal & 0xFF);
      Valid = (BOOLEAN)((MaskVal & BIT11) != 0);
    } 

    Print (L"MTRR | 0x%02x | %016lx (%-24s) | %016lx (Valid:%d) | %s\n",
           (UINT32)I, BaseVal, MtrrTypeToStr (Type), MaskVal, Valid ? 1 : 0, Valid ? L"ENABLED" : L"DISABLED");
  }
  Print (L"\n");
}

STATIC VOID DumpMtrrUiLikePhoto_FixedRanges (VOID) {
  UINT64  MtrrCap, MtrrDef;
  BOOLEAN FixSupported, MtrrEnabled, FixEnabled;
  CONST UINT32 FixedMsrList[] = {
    MSR_IA32_MTRR_FIX64K_00000, MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000,
    MSR_IA32_MTRR_FIX4K_C0000,  MSR_IA32_MTRR_FIX4K_C8000,  MSR_IA32_MTRR_FIX4K_D0000,
    MSR_IA32_MTRR_FIX4K_D8000,  MSR_IA32_MTRR_FIX4K_E0000,  MSR_IA32_MTRR_FIX4K_E8000,
    MSR_IA32_MTRR_FIX4K_F0000,  MSR_IA32_MTRR_FIX4K_F8000
  };
  UINTN I;

  if (!SafeReadMsr(MSR_IA32_MTRRCAP, &MtrrCap)) return;
  if (!SafeReadMsr(MSR_IA32_MTRR_DEF_TYPE, &MtrrDef)) return;

  FixSupported = (BOOLEAN)((MtrrCap & IA32_MTRRCAP_FIX_BIT) != 0);
  MtrrEnabled  = (BOOLEAN)((MtrrDef & IA32_MTRR_DEF_TYPE_E_BIT) != 0);
  FixEnabled   = (BOOLEAN)((MtrrDef & IA32_MTRR_DEF_TYPE_FE_BIT) != 0);

  Print (L"=== [ Fixed Range MTRRs ] ===\n");

  if (!FixSupported) {
    Print (L"Fixed MTRR not supported.\n\n");
    return;
  }

  if (!MtrrEnabled || !FixEnabled) {
    Print (L"Fixed MTRR supported but disabled (E=%d, FE=%d).\n\n", MtrrEnabled ? 1 : 0, FixEnabled ? 1 : 0);
    return;
  }

  Print (L"MSR | MSR Addr | Value (64-bit Hex)   | Decoded Memory Types (8 Bytes)\n");
  Print (L"----+----------+----------------------+----------------------------------------\n");

  for (I = 0; I < sizeof (FixedMsrList) / sizeof (FixedMsrList[0]); I++) {
    UINT64 Val = 0;
    SafeReadMsr(FixedMsrList[I], &Val);
    Print (L"MSR | 0x%03x    | %016lx | ", FixedMsrList[I], Val);
    PrintFixedMtrrDecoded8Types (Val);
    Print (L"\n");
  }
  Print (L"\n");
}

STATIC VOID DoCpuId (VOID) {
  UINT32 Leaf, Eax, Ebx, Ecx, Edx;
  ShowHeaderAndMenu (MenuCpuId);

  if (!PromptHexUint32 (L"Enter Function Number (Hex): ", &Leaf)) {
    Print (L"Invalid input.\n"); WaitAnyKey (); return;
  }
  AsmCpuid (Leaf, &Eax, &Ebx, &Ecx, &Edx);
  Print (L"RegisterEax : %08x\nRegisterEbx : %08x\nRegisterEcx : %08x\nRegisterEdx : %08x\n", Eax, Ebx, Ecx, Edx);

  if (Leaf == 0) {
    CHAR8 Vendor[13];
    *(UINT32 *)&Vendor[0] = Ebx; *(UINT32 *)&Vendor[4] = Edx; *(UINT32 *)&Vendor[8] = Ecx; Vendor[12] = '\0';
    Print (L"Vendor      : %a\n", Vendor);
  }

  if (Leaf == 1) {
    Print (L"Feature(MSR)  EDX.BIT5  : %d\n", ((Edx & CPUID_FEAT_EDX_MSR)  != 0) ? 1 : 0);
    Print (L"Feature(MTRR) EDX.BIT12 : %d\n", ((Edx & CPUID_FEAT_EDX_MTRR) != 0) ? 1 : 0);
    Print (L"Feature(TSC)  EDX.BIT4  : %d\n", ((Edx & CPUID_FEAT_EDX_TSC)  != 0) ? 1 : 0);
  }
  WaitAnyKey ();
}

STATIC VOID DoDumpCpuId (VOID) {
  UINT32 MaxBasic, MaxExt, Eax, Ebx, Ecx, Edx, Leaf;
  UINTN  LineCount;
  CHAR8  Vendor[13];
  ShowHeaderAndMenu (MenuDumpCpuId);

  AsmCpuid (0, &Eax, &Ebx, &Ecx, &Edx);
  MaxBasic = Eax;
  *(UINT32 *)&Vendor[0] = Ebx; *(UINT32 *)&Vendor[4] = Edx; *(UINT32 *)&Vendor[8] = Ecx; Vendor[12] = '\0';

  Print (L"[CPUID Basic]\nMax Basic Leaf : 0x%08x\nVendor         : %a\n\n", MaxBasic, Vendor);
  PrintCpuidTableHeader ();
  LineCount = 2;

  for (Leaf = 0; Leaf <= MaxBasic; Leaf++) {
    if (PrintOneCpuidLeafLine (Leaf, 0, &LineCount)) return;
    if (Leaf == 0xFFFFFFFFu) break;
  }

  AsmCpuid (0x80000000, &Eax, &Ebx, &Ecx, &Edx);
  MaxExt = Eax;

  Print (L"\n[CPUID Extended]\n");
  if (PageLineAccountingEx (&LineCount, PrintCpuidTableHeader, 2)) return;
  Print (L"Max Ext Leaf   : 0x%08x\n", MaxExt);
  if (PageLineAccountingEx (&LineCount, PrintCpuidTableHeader, 2)) return;
  PrintCpuidTableHeader ();
  LineCount = 2;

  if (MaxExt >= 0x80000000) {
    for (Leaf = 0x80000000; Leaf <= MaxExt; Leaf++) {
      if (PrintOneCpuidLeafLine (Leaf, 0, &LineCount)) return;
      if (Leaf == 0xFFFFFFFFu) break;
    }
  }
  PrintBrandStringIfSupported (MaxExt);
  WaitAnyKey ();
}

STATIC VOID DoReadMsr (VOID) {
  UINT32 MsrIndex;
  UINT64 MsrData;
  ShowHeaderAndMenu (MenuReadMsr);

  if (!CpuSupportsMsr ()) {
    Print (L"[ERROR] CPU does not support MSR.\n"); WaitAnyKey (); return;
  }
  if (!PromptHexUint32 (L"Enter MSR Index (Hex): ", &MsrIndex)) {
    Print (L"Invalid input.\n"); WaitAnyKey (); return;
  }
  
  if (SafeReadMsr (MsrIndex, &MsrData)) {
    Print (L"MSR_Data : %016lx\n", MsrData);
  } else {
    Print (L"[ERROR] #GP Fault! MSR 0x%08x is invalid or reserved.\n", MsrIndex);
  }
  WaitAnyKey ();
}

STATIC VOID DoDumpMsr (VOID) {
  UINT32 StartMsr, EndMsr, Msr;
  UINT64 Value;
  UINTN  LineCount;
  ShowHeaderAndMenu (MenuDumpMsr);

  if (!CpuSupportsMsr ()) {
    Print (L"[ERROR] CPU does not support MSR.\n"); WaitAnyKey (); return;
  }
  if (!PromptHexUint32 (L"Enter Start MSR Index (Hex): ", &StartMsr)) {
    Print (L"Invalid start MSR index.\n"); WaitAnyKey (); return;
  }
  if (!PromptHexUint32 (L"Enter End   MSR Index (Hex): ", &EndMsr)) {
    Print (L"Invalid end MSR index.\n"); WaitAnyKey (); return;
  }
  if (EndMsr < StartMsr) {
    Print (L"[ERROR] End MSR must be >= Start MSR.\n"); WaitAnyKey (); return;
  }

  PrintMsrTableHeader ();
  LineCount = 2;

  for (Msr = StartMsr; Msr <= EndMsr; Msr++) {
    if (SafeReadMsr (Msr, &Value)) {
      Print (L"%08x   %016lx\n", Msr, Value);
    } else {
      SetAttrHighlight();
      Print (L"%08x   [Invalid / #GP]\n", Msr);
      SetAttrNormal();
    }
    
    if (PageLineAccountingEx (&LineCount, PrintMsrTableHeader, 2)) return;
    if (Msr == 0xFFFFFFFFu) break;
  }
  WaitAnyKey ();
}

STATIC VOID DoWriteMsr (VOID) {
  UINT32        MsrIndex;
  UINT64        MsrData;
  EFI_INPUT_KEY Key;
  ShowHeaderAndMenu (MenuWriteMsr);

  if (!CpuSupportsMsr ()) {
    Print (L"[ERROR] CPU does not support MSR.\n"); WaitAnyKey (); return;
  }

  if (!PromptHexUint32 (L"Enter MSR Index (Hex): ", &MsrIndex)) {
    Print (L"Invalid MSR index.\n"); WaitAnyKey (); return;
  }
  if (!PromptHexUint64 (L"Enter MSR Data  (Hex): ", &MsrData)) {
    Print (L"Invalid MSR data.\n"); WaitAnyKey (); return;
  }

  Print (L"Confirm write MSR[0x%X] = 0x%016lx ? (Y/N): ", MsrIndex, MsrData);
  if (!ReadKeyBlocking (&Key)) return;
  Print (L"%c\n", (Key.UnicodeChar == 0) ? L'?' : Key.UnicodeChar);
  if (Key.UnicodeChar != L'Y' && Key.UnicodeChar != L'y') {
    Print (L"Canceled.\n"); WaitAnyKey (); return;
  }

  if (SafeWriteMsr (MsrIndex, MsrData)) {
    Print (L"Write executed successfully.\n");
    if (SafeReadMsr(MsrIndex, &MsrData)) {
      Print (L"ReadBack  : %016lx\n", MsrData);
    }
  } else {
    Print (L"[ERROR] #GP Fault! Cannot write to MSR 0x%08x (Reserved or Read-Only).\n", MsrIndex);
  }
  WaitAnyKey ();
}

STATIC VOID DoDumpMtrr (VOID) {
  UINT64 MtrrDefType, MtrrCap;
  UINT8  DefaultType, Vcnt, PhysAddrBits;
  ShowHeaderAndMenu (MenuDumpMtrr);

  if (!CpuSupportsMsr () || !CpuSupportsMtrr ()) {
    Print (L"[ERROR] CPU does not support MSR/MTRR.\n"); WaitAnyKey (); return;
  }

  if (!SafeReadMsr (MSR_IA32_MTRR_DEF_TYPE, &MtrrDefType) || !SafeReadMsr (MSR_IA32_MTRRCAP, &MtrrCap)) {
    Print (L"[ERROR] Failed to read base MTRR registers.\n"); WaitAnyKey (); return;
  }

  DefaultType  = (UINT8)(MtrrDefType & IA32_MTRR_DEF_TYPE_TYPE_MASK);
  Vcnt         = (UINT8)(MtrrCap & IA32_MTRRCAP_VCNT_MASK);
  PhysAddrBits = GetPhysicalAddressBits ();

  Print (L"\n=== [ MTRR Summary ] ===\n");
  Print (L"MTRRCAP   (0xFE)  : %016lx   VCNT=%d  FIX=%d\n", MtrrCap, (UINT32)Vcnt, (MtrrCap & IA32_MTRRCAP_FIX_BIT) ? 1 : 0);
  Print (L"DEF_TYPE  (0x2FF) : %016lx   E=%d  FE=%d  Default=%s\n", MtrrDefType, 
         (MtrrDefType & IA32_MTRR_DEF_TYPE_E_BIT)  ? 1 : 0, 
         (MtrrDefType & IA32_MTRR_DEF_TYPE_FE_BIT) ? 1 : 0, 
         MtrrTypeToStr (DefaultType));
  Print (L"PhysAddrBits      : %d\n\n", (UINT32)PhysAddrBits);

  DumpMtrrUiLikePhoto_VariableRanges ();
  DumpMtrrUiLikePhoto_FixedRanges ();
  WaitAnyKey ();
}

//
// =====================================================
// Menu loop
// =====================================================
//
STATIC VOID RunMainMenu (VOID) {
  EFI_INPUT_KEY Key;
  UINTN         Selected = 0;

  while (TRUE) {
    ShowHeaderAndMenu (Selected);

    if (!ReadKeyBlocking (&Key)) continue;

    if (Key.ScanCode == SCAN_UP) {
      if (Selected == 0) Selected = MENU_ITEMS_COUNT - 1;
      else Selected--;
      continue;
    }

    if (Key.ScanCode == SCAN_DOWN) {
      Selected = (Selected + 1) % MENU_ITEMS_COUNT;
      continue;
    }

    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      switch ((MENU_ACTION)Selected) {
        case MenuCpuId:      DoCpuId (); break;
        case MenuDumpCpuId:  DoDumpCpuId (); break;
        case MenuReadMsr:    DoReadMsr (); break;
        case MenuDumpMsr:    DoDumpMsr (); break;
        case MenuWriteMsr:   DoWriteMsr (); break;
        case MenuDumpMtrr:   DoDumpMtrr (); break;
        default:             break;
      }
      continue;
    }

    if (Key.ScanCode == SCAN_ESC) break;
  }
}

//
// =====================================================
// Entry point
// =====================================================
//
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  gST->ConIn->Reset (gST->ConIn, FALSE);
  
  // Locate CPU Protocol for Exception Handling
  gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);

  RunMainMenu ();

  ClearScreenAndResetAttr ();
  Print (L"CpuMsrMtrrApp exit.\n");
  return EFI_SUCCESS;
}