//
// 引入 EDK2 基礎與 UEFI 標準函式庫
//
#include <Base.h>                               // 包含基本資料型別 (如 UINT32, BOOLEAN) 與巨集
#include <Uefi.h>                               // 包含 UEFI 標準定義 (如 EFI_STATUS, EFI_HANDLE)
#include <Library/UefiLib.h>                    // 提供 Print 等高階 UEFI 輔助函式
#include <Library/UefiApplicationEntryPoint.h>  // 提供 UEFI 應用程式的進入點 (UefiMain) 定義
#include <Library/UefiBootServicesTableLib.h>   // 提供全域變數 gBS (Boot Services) 的存取
#include <Library/BaseLib.h>                    // 提供組合語言封裝函式 (如 AsmCpuid, AsmReadMsr64)
#include <Library/BaseMemoryLib.h>              // 提供記憶體操作函式 (如 SetMem, CopyMem)
#include <Library/PrintLib.h>                   // 提供字串格式化函式
#include <Protocol/Cpu.h>                       // 提供 EFI_CPU_ARCH_PROTOCOL 定義，用於中斷與例外攔截

//
// ================================================
// CPU / CPUID / MSR / MTRR 測試工具 (防當機安全版)
// ================================================
//

//
// ---------- MSR (Model-Specific Register) 暫存器位址常數定義 ----------
//
#define MSR_IA32_MTRRCAP             0x000000FE  // MTRR 能力暫存器 (唯讀)，記錄支援的 MTRR 數量與功能
#define MSR_IA32_MTRR_DEF_TYPE       0x000002FF  // MTRR 預設記憶體類型暫存器，控制全域 MTRR 啟用狀態
#define MSR_IA32_MTRR_PHYSBASE0      0x00000200  // 第 0 組變動範圍 MTRR 的基底位址暫存器 (每組佔用 2 個 MSR，Base/Mask)
#define MSR_IA32_MTRR_PHYSMASK0      0x00000201  // 第 0 組變動範圍 MTRR 的遮罩位址暫存器

// 固定範圍 (Fixed Range) MTRR 暫存器位址
#define MSR_IA32_MTRR_FIX64K_00000   0x00000250  // 控制 0x00000 ~ 0x7FFFF 的實體記憶體屬性 (64KB 為一單位)
#define MSR_IA32_MTRR_FIX16K_80000   0x00000258  // 控制 0x80000 ~ 0x9FFFF 的實體記憶體屬性 (16KB 為一單位)
#define MSR_IA32_MTRR_FIX16K_A0000   0x00000259  // 控制 0xA0000 ~ 0xBFFFF 的實體記憶體屬性
#define MSR_IA32_MTRR_FIX4K_C0000    0x00000268  // 控制 0xC0000 ~ 0xC7FFF 的實體記憶體屬性 (4KB 為一單位)
#define MSR_IA32_MTRR_FIX4K_C8000    0x00000269  // 控制 0xC8000 ~ 0xCFFFF 
#define MSR_IA32_MTRR_FIX4K_D0000    0x0000026A  // 控制 0xD0000 ~ 0xD7FFF
#define MSR_IA32_MTRR_FIX4K_D8000    0x0000026B  // 控制 0xD8000 ~ 0xDFFFF
#define MSR_IA32_MTRR_FIX4K_E0000    0x0000026C  // 控制 0xE0000 ~ 0xE7FFF
#define MSR_IA32_MTRR_FIX4K_E8000    0x0000026D  // 控制 0xE8000 ~ 0xEFFFF
#define MSR_IA32_MTRR_FIX4K_F0000    0x0000026E  // 控制 0xF0000 ~ 0xF7FFF
#define MSR_IA32_MTRR_FIX4K_F8000    0x0000026F  // 控制 0xF8000 ~ 0xFFFFF

//
// ---------- CPUID 支援特徵位元定義 (從 CPUID EAX=1, EDX 回傳) ----------
//
#define CPUID_FEAT_EDX_TSC           BIT4        // EDX 第 4 位元：是否支援 Time Stamp Counter
#define CPUID_FEAT_EDX_MSR           BIT5        // EDX 第 5 位元：是否支援 RDMSR/WRMSR 指令
#define CPUID_FEAT_EDX_MTRR          BIT12       // EDX 第 12 位元：是否支援 MTRR 記憶體類型範圍暫存器

//
// ---------- MTRRCAP (0xFE) 暫存器的位元遮罩 ----------
//
#define IA32_MTRRCAP_VCNT_MASK       0xFFu       // Bits 7:0 代表支援的變動範圍 MTRR 總數 (Variable Count)
#define IA32_MTRRCAP_FIX_BIT         BIT8        // Bit 8 代表是否支援固定範圍 (Fixed Range) MTRR

//
// ---------- MTRR_DEF_TYPE (0x2FF) 暫存器的位元遮罩 ----------
//
#define IA32_MTRR_DEF_TYPE_TYPE_MASK 0xFFu       // Bits 7:0 定義系統預設的記憶體快取屬性 (如 UC, WB)
#define IA32_MTRR_DEF_TYPE_FE_BIT    BIT10       // Bit 10：是否啟用固定範圍 MTRR (Fixed MTRR Enable)
#define IA32_MTRR_DEF_TYPE_E_BIT     BIT11       // Bit 11：是否全域啟用 MTRR 功能 (MTRR Enable)

//
// ---------- 使用者介面 (UI) 相關常數 ----------
//
#define MENU_ITEMS_COUNT             6           // 主選單的選項總數
#define INPUT_BUF_LEN                32          // 使用者輸入字串緩衝區的最大長度 (字元數)
#define PAGE_LINES_LIMIT             18          // 分頁顯示時，每幾行暫停一次等待按鍵

// 定義選單的列舉型別 (對應到 mMenuItems 陣列的索引)
typedef enum {
  MenuCpuId = 0,     // 執行單次 CPUID 查詢
  MenuDumpCpuId,     // 傾印所有 CPUID 葉節點
  MenuReadMsr,       // 讀取單一 MSR
  MenuDumpMsr,       // 傾印指定範圍的 MSR
  MenuWriteMsr,      // 寫入 MSR
  MenuDumpMtrr       // 傾印並解析 MTRR 組態
} MENU_ACTION;

// 選單字串陣列 (STATIC 代表只在此檔案內可見，CONST 避免被修改)
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
// 全域變數 (Global Variables) 區塊：用於 MSR #GP 例外處理
// =====================================================
//
// 宣告一個指向 CPU 系統架構通訊協定的指標。我們將在進入點使用 gBS->LocateProtocol 賦值。
EFI_CPU_ARCH_PROTOCOL *mCpu = NULL;

// 宣告一個標記，用於記錄剛剛執行的 MSR 操作是否引發了保護錯誤 (#GP Fault)。
// 使用 volatile 關鍵字是為了防止編譯器過度優化，確保每次都從記憶體中重新讀取此變數的真實狀態。
volatile BOOLEAN      gMsrFault = FALSE;

//
// =====================================================
// 中斷與例外處理常式 (Exception Handler for #GP Fault)
// =====================================================
//
// 當 CPU 執行到有問題的指令（例如讀取不存在的 MSR）時，硬體會觸發 Exception 13 (#GP)。
// 若我們有註冊此函式，UEFI 的 CPU Protocol 會暫停原程式，並跳轉至此處執行。
VOID
EFIAPI
MsrFaultHandler (
  IN EFI_EXCEPTION_TYPE   InterruptType,  // 觸發的中斷類型 (此處預期為 EXCEPT_IA32_GP_FAULT，即 13)
  IN EFI_SYSTEM_CONTEXT   SystemContext   // 系統上下文，包含當下所有 CPU 暫存器 (如 RAX, RIP) 的完整快照
  )
{
  UINT8 *Ip; // Instruction Pointer 指標，用來讀取引發當機的「那行組合語言指令」的二進位機器碼

  // 根據編譯架構 (X64 或是 IA32 32位元)，從上下文結構中取得當前的指令指標 (RIP 或 EIP)
#if defined (MDE_CPU_X64)
  Ip = (UINT8 *)SystemContext.SystemContextX64->Rip;
#elif defined (MDE_CPU_IA32)
  Ip = (UINT8 *)SystemContext.SystemContextIa32->Eip;
#else
  return; // 若非 x86 架構則直接返回
#endif

  // 檢查引發異常的指令機器碼。
  // 在 x86 架構中，rdmsr 指令的機器碼是 0x0F 0x32；wrmsr 指令是 0x0F 0x30。
  if (Ip[0] == 0x0F && (Ip[1] == 0x32 || Ip[1] == 0x30)) {
    // 進入此區塊代表我們確定這是一次由 MSR 讀寫引起的預期內錯誤
    gMsrFault = TRUE; // 設定全域錯誤旗標，通知主程式讀取失敗
    
    // 【拯救當機的核心邏輯】：手動將指令指標 (RIP/EIP) 往前推移 2 個 Byte。
    // 這等於告訴 CPU：「發生錯誤的指令不要再執行了，直接跳過它執行下一行程式」。
#if defined (MDE_CPU_X64)
    SystemContext.SystemContextX64->Rip += 2;
    // 如果是讀取 MSR (rdmsr)，硬體原本會把值存入 EDX:EAX。
    // 既然讀取失敗，我們主動將 RAX 與 RDX 清零，避免回傳垃圾數值。
    if (Ip[1] == 0x32) { 
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
    // 如果引發 #GP 的指令不是 rdmsr 或 wrmsr，代表是其他程式錯誤 (如指標寫壞、越界)。
    // 這種情況下我們不應該跳過，而是將系統徹底卡死，方便開發者接上 JTAG 除錯。
    CpuDeadLoop(); 
  }
}

//
// =====================================================
// 安全的 MSR 封裝函式 (Safe Wrappers)
// =====================================================
//

// 安全讀取 MSR，若 MSR 不存在會回傳 FALSE 而不是當機
STATIC BOOLEAN SafeReadMsr (IN UINT32 Index, OUT UINT64 *Value) {
  gMsrFault = FALSE; // 初始設定為無錯誤
  
  // 步驟一：向 CPU 註冊我們的攔截常式，指定攔截 EXCEPT_IA32_GP_FAULT (中斷 13)
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrFaultHandler);
  }
  
  // 步驟二：大膽地呼叫底層組合語言執行 rdmsr。
  // 如果 Index 不存在，程式流程會瞬間跳到 MsrFaultHandler，調整 RIP 後再跳回來。
  *Value = AsmReadMsr64 (Index);
  
  // 步驟三：解除註冊攔截常式 (傳入 NULL)。保持系統乾淨，避免影響 UEFI 其他程式的運作。
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
  }
  
  // 如果 gMsrFault 被 Handler 改成了 TRUE，就回傳 FALSE 表示失敗。
  return !gMsrFault;
}

// 安全寫入 MSR，若目標不可寫入或不存在會回傳 FALSE 而不是當機
STATIC BOOLEAN SafeWriteMsr (IN UINT32 Index, IN UINT64 Value) {
  gMsrFault = FALSE;
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, MsrFaultHandler);
  }
  
  // 呼叫組合語言執行 wrmsr。
  AsmWriteMsr64 (Index, Value);
  
  if (mCpu != NULL) {
    mCpu->RegisterInterruptHandler (mCpu, EXCEPT_IA32_GP_FAULT, NULL);
  }
  return !gMsrFault;
}

//
// =====================================================
// UI 介面輔助函式 (Console / Keyboard IO)
// =====================================================
//

// 將控制台文字顏色設定為預設 (黑底淺灰字)
STATIC VOID SetAttrNormal (VOID) {
  gST->ConOut->SetAttribute (gST->ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);
}

// 將控制台文字顏色設定為高亮 (藍底白字)
STATIC VOID SetAttrHighlight (VOID) {
  gST->ConOut->SetAttribute (gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLUE);
}

// 清空螢幕並將顏色重設為預設狀態
STATIC VOID ClearScreenAndResetAttr (VOID) {
  gST->ConOut->ClearScreen (gST->ConOut); // 呼叫 Simple Text Output Protocol 的 ClearScreen
  SetAttrNormal ();
}

// 阻塞式等待按鍵輸入
// 參數: Key (輸出參數，用來接收讀取到的按鍵內容)
// 回傳: BOOLEAN (TRUE 表示成功讀取，FALSE 表示發生系統錯誤)
STATIC BOOLEAN ReadKeyBlocking (OUT EFI_INPUT_KEY *Key) {
  EFI_STATUS Status;
  UINTN      Index;

  if (Key == NULL) return FALSE; // 防呆檢查，確保指標有效

  // 使用 Boot Services 的 WaitForEvent 函式。
  // 參數1 (NumberOfEvents): 1 (我們只等待一個事件)
  // 參數2 (Event): 傳入鍵盤輸入事件的陣列位址 (&gST->ConIn->WaitForKey)
  // 參數3 (Index): 傳回被觸發事件在陣列中的索引值 (在此例中必定為 0)
  // 此函式會將 CPU 掛起，直到鍵盤有輸入才會繼續執行，藉此節省 CPU 資源。
  Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
  if (EFI_ERROR (Status)) return FALSE; // 如果等待失敗 (如 EFI_INVALID_PARAMETER) 則回傳 FALSE

  // 事件觸發後，立刻呼叫 ReadKeyStroke 把按鍵的實際內容從鍵盤緩衝區中取出
  Status = gST->ConIn->ReadKeyStroke (gST->ConIn, Key);
  
  // 若 Status 是 EFI_SUCCESS (0)，回傳 TRUE。
  return (BOOLEAN)!EFI_ERROR (Status); 
}

// 清空鍵盤輸入緩衝區 (捨棄使用者之前亂按的、還沒被程式讀取的按鍵)
STATIC VOID DrainKeyBuffer (VOID) {
  EFI_INPUT_KEY Key;
  // 只要 ReadKeyStroke 回傳成功 (代表裡面還有字元)，就一直讀、一直丟掉，直到讀空為止。
  while (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key)));
}

// 暫停程式，提示「按任意鍵繼續」
STATIC VOID WaitAnyKey (VOID) {
  EFI_INPUT_KEY Key;
  DrainKeyBuffer (); // 避免被之前殘留的按鍵直接略過暫停
  
  SetAttrHighlight ();
  Print (L"\nPress any key to continue");
  SetAttrNormal ();
  
  // 無窮迴圈，直到成功讀取到任何一個按鍵為止
  while (TRUE) {
    if (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) break;
  }
}

// 分頁暫停提示。如果在傾印大量資料時，每輸出幾行就會呼叫此函式。
// 回傳 TRUE 代表使用者按下了 'q'，想要提前結束傾印；回傳 FALSE 代表繼續往下顯示。
STATIC BOOLEAN PagePauseOrExit (VOID) {
  EFI_INPUT_KEY Key;
  DrainKeyBuffer ();
  
  SetAttrHighlight ();
  Print (L"\nPress any key to continue, or 'q' to exit");
  SetAttrNormal ();
  
  while (TRUE) {
    if (!EFI_ERROR (gST->ConIn->ReadKeyStroke (gST->ConIn, &Key))) {
      Print (L"\n");
      // 判斷按鍵的 UnicodeChar 是否為大寫或小寫的 Q
      if (Key.UnicodeChar == L'q' || Key.UnicodeChar == L'Q') return TRUE;
      return FALSE; // 使用者按了其他鍵，回傳 FALSE 繼續
    }
  }
}

// 顯示主選單與標題
// 參數: HighlightIndex (目前反白選取的選項索引)
STATIC VOID ShowHeaderAndMenu (IN UINTN HighlightIndex) {
  UINTN I;
  ClearScreenAndResetAttr ();
  
  SetAttrHighlight ();
  Print (L"<<Select The Action>>\n"); // 顯示頂部標題
  SetAttrNormal ();
  
  // 迴圈印出所有選單項目
  for (I = 0; I < MENU_ITEMS_COUNT; I++) {
    if (I == HighlightIndex) {
      SetAttrHighlight (); // 被選中的項目用高亮顯示
      Print (L"%s\n", mMenuItems[I]);
      SetAttrNormal ();
    } else {
      Print (L"%s\n", mMenuItems[I]); // 一般項目正常顯示
    }
  }
}

//
// =====================================================
// 輸入字串解析輔助函式 (Input parsing)
// =====================================================
//

// 將單一十六進位字元 (如 'A', 'f', '3') 轉換為 4-bit 的數值 (Nibble)
// 參數: Ch (輸入字元), Nibble (輸出指標，存放 0~15 的結果)
STATIC BOOLEAN HexCharToNibble (IN CHAR16 Ch, OUT UINT8 *Nibble) {
  if (Nibble == NULL) return FALSE;
  
  if (Ch >= L'0' && Ch <= L'9') { *Nibble = (UINT8)(Ch - L'0'); return TRUE; }
  if (Ch >= L'a' && Ch <= L'f') { *Nibble = (UINT8)(10 + Ch - L'a'); return TRUE; }
  if (Ch >= L'A' && Ch <= L'F') { *Nibble = (UINT8)(10 + Ch - L'A'); return TRUE; }
  
  return FALSE; // 如果字元不在上述範圍 (例如輸入了 'Z' 或 '#')，回傳失敗
}

// 將 16 進位字串轉換為 64 位元無號整數 (UINT64)
// 參數: Str (輸入字串，如 "0x1A" 或 "1A"), Value (輸出指標)
STATIC BOOLEAN ParseHex16ToUint64 (IN CONST CHAR16 *Str, OUT UINT64 *Value) {
  UINTN  Index, Start = 0;
  UINT8  Nibble;
  UINT64 Result = 0;
  
  if (Str == NULL || Value == NULL) return FALSE;
  
  // 支援包含 "0x" 或 "0X" 前綴的輸入，直接略過前兩個字元
  if (Str[0] == L'0' && (Str[1] == L'x' || Str[1] == L'X')) Start = 2;
  
  if (Str[Start] == L'\0') return FALSE; // 空字串防呆
  
  // 逐字元解析
  for (Index = Start; Str[Index] != L'\0'; Index++) {
    if (!HexCharToNibble (Str[Index], &Nibble)) return FALSE; // 遇到非法字元即失敗
    // 將之前累積的結果左移 4 bit (乘以 16)，然後加上新的 Nibble
    Result = (Result << 4) | (UINT64)Nibble;
  }
  
  *Value = Result;
  return TRUE;
}

// 讀取使用者輸入的一行文字 (直到按下 Enter)
// 參數: Buffer (儲存輸入字串的陣列), BufferChars (陣列的總長度)
STATIC BOOLEAN ReadLine (OUT CHAR16 *Buffer, IN UINTN BufferChars) {
  EFI_INPUT_KEY Key;
  UINTN         Pos = 0; // 當前游標位置
  
  if (Buffer == NULL || BufferChars < 2) return FALSE;
  
  SetMem (Buffer, BufferChars * sizeof (CHAR16), 0); // 緩衝區歸零初始化
  
  while (TRUE) {
    if (!ReadKeyBlocking (&Key)) return FALSE; // 等待並讀取按鍵
    
    // 如果按下 Enter (Carriage Return)
    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      Buffer[Pos] = L'\0'; // 在字串結尾加上 NULL 終止符
      Print (L"\n");       // 換行
      return TRUE;         // 完成讀取
    }
    
    // 如果按下 Backspace (退格鍵)
    if (Key.UnicodeChar == CHAR_BACKSPACE) {
      if (Pos > 0) {
        Pos--;
        Buffer[Pos] = L'\0';
        Print (L"\b \b"); // 在螢幕上：退格 -> 印出空白覆蓋 -> 再退格，達到刪除的視覺效果
      }
      continue;
    }
    
    // 如果是可視字元 (ASCII 0x20 空白 ~ 0x7E 波浪號)
    if (Key.UnicodeChar >= 0x20 && Key.UnicodeChar <= 0x7E) {
      if (Pos < (BufferChars - 1)) { // 確保不會超出緩衝區
        Buffer[Pos++] = Key.UnicodeChar;
        Buffer[Pos]   = L'\0';
        Print (L"%c", Key.UnicodeChar); // 將輸入的字元直接回顯到螢幕上
      }
    }
  }
}

// 提示輸入一段文字，並將其解析為 32 位元的十六進位整數
STATIC BOOLEAN PromptHexUint32 (IN CONST CHAR16 *Prompt, OUT UINT32 *Value) {
  CHAR16 Buf[INPUT_BUF_LEN];
  UINT64 Temp;
  
  if (Value == NULL) return FALSE;
  
  Print (L"%s", Prompt); // 印出提示字眼 (例如 "Enter MSR Index:")
  if (!ReadLine (Buf, INPUT_BUF_LEN)) return FALSE; // 讀取一行字串
  if (!ParseHex16ToUint64 (Buf, &Temp)) return FALSE; // 將字串轉為數字
  
  *Value = (UINT32)Temp; // 強制轉型為 32 位元
  return TRUE;
}

// 提示輸入一段文字，並將其解析為 64 位元的十六進位整數
STATIC BOOLEAN PromptHexUint64 (IN CONST CHAR16 *Prompt, OUT UINT64 *Value) {
  CHAR16 Buf[INPUT_BUF_LEN];
  
  if (Value == NULL) return FALSE;
  
  Print (L"%s", Prompt);
  if (!ReadLine (Buf, INPUT_BUF_LEN)) return FALSE;
  return ParseHex16ToUint64 (Buf, Value);
}

// 處理分頁顯示的核心邏輯。
// 參數: LineCount (目前已印出的行數指標), ReprintHeader (換頁後重新印出表頭的函式), HeaderLines (表頭佔用的行數)
// 回傳: TRUE 代表使用者要求提早離開 (Exit)，FALSE 代表正常翻頁。
STATIC BOOLEAN PageLineAccountingEx (IN OUT UINTN *LineCount, IN VOID (*ReprintHeader)(VOID), IN UINTN HeaderLines) {
  if (LineCount == NULL) return FALSE;
  
  (*LineCount)++; // 每呼叫一次，行數加一
  
  // 當行數達到單頁上限 (PAGE_LINES_LIMIT) 時觸發暫停
  if (*LineCount >= PAGE_LINES_LIMIT) {
    if (PagePauseOrExit ()) return TRUE; // 如果使用者按下 'q'，中斷顯示
    
    ClearScreenAndResetAttr(); // 換頁時清空螢幕
    if (ReprintHeader != NULL) {
      ReprintHeader (); // 重新印出欄位標題 (如 MSR | Value)
      *LineCount = HeaderLines; // 重設目前的行數為表頭行數
    } else {
      *LineCount = 0; // 若無表頭，行數歸零
    }
  }
  return FALSE;
}

//
// =====================================================
// CPU 資訊解析與特徵判斷 (Feature Functions)
// =====================================================
//

// 判斷此 CPU 是否支援 MSR 架構
STATIC BOOLEAN CpuSupportsMsr (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  // 執行 CPUID (Leaf 1: 處理器特徵與版本資訊)
  AsmCpuid (1, &Eax, &Ebx, &Ecx, &Edx);
  // 檢查 EDX 的第 5 位元 (MSR 特徵位元)
  return (BOOLEAN)((Edx & CPUID_FEAT_EDX_MSR) != 0);
}

// 判斷此 CPU 是否支援 MTRR (Memory Type Range Registers)
STATIC BOOLEAN CpuSupportsMtrr (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuid (1, &Eax, &Ebx, &Ecx, &Edx);
  // 檢查 EDX 的第 12 位元
  return (BOOLEAN)((Edx & CPUID_FEAT_EDX_MTRR) != 0);
}

// 將記憶體快取類型 (Byte 數值) 轉為可讀的完整英文字串
// 參數: Type (從 MTRR 暫存器中取出的低 8 位元數值)
STATIC CONST CHAR16 *MtrrTypeToStr (IN UINT8 Type) {
  switch (Type) {
    case 0x00: return L"Uncacheable";     // 不快取 (通常用於 MMIO)
    case 0x01: return L"Write-Combining"; // 寫入合併 (通常用於顯示卡 Framebuffer)
    case 0x04: return L"Write-Through";   // 寫透 (寫入 Cache 的同時也寫入主記憶體)
    case 0x05: return L"Write-Protect";   // 防寫
    case 0x06: return L"Write-Back";      // 寫回 (一般系統記憶體最常使用的模式)
    default:   return L"Reserved";        // 保留值或未定義
  }
}

// 將記憶體快取類型轉為簡寫字串 (用於固定範圍 MTRR 的緊湊顯示)
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

// 取得 CPU 支援的「實體記憶體定址位元數」(Physical Address Bits)
// 用於計算變動範圍 MTRR (Variable MTRR) 的實際覆蓋大小
STATIC UINT8 GetPhysicalAddressBits (VOID) {
  UINT32 Eax, Ebx, Ecx, Edx;
  
  // 查詢 CPU 支援的最大擴展功能號 (Extended CPUID Leaf)
  AsmCpuid (0x80000000, &Eax, &Ebx, &Ecx, &Edx);
  
  // 如果 CPU 連 0x80000008 (Virtual/Physical Address Size) 都不支援，則預設回傳 36 bit (64GB)
  if (Eax < 0x80000008) return 36;
  
  AsmCpuid (0x80000008, &Eax, &Ebx, &Ecx, &Edx);
  if ((Eax & 0xFF) == 0) return 36; // 防呆
  
  // EAX 的低 8 位元即為硬體支援的實體位址線數量 (通常為 36, 39 或 46)
  return (UINT8)(Eax & 0xFF);
}

//
// =====================================================
// UI 繪製與表格標題函式
// =====================================================
//

STATIC VOID PrintCpuidTableHeader (VOID) {
  Print (L"Leaf/SubLeaf    EAX       EBX       ECX       EDX\n");
  Print (L"------------------------------------------------------\n");
}

STATIC VOID PrintMsrTableHeader (VOID) {
  Print (L"MSR        Value\n");
  Print (L"------------------------------\n");
}

// 傾印單一個 CPUID 葉節點/子葉節點的資料並處理分頁
STATIC BOOLEAN PrintOneCpuidLeafLine (IN UINT32 Leaf, IN UINT32 SubLeaf, IN OUT UINTN *LineCount) {
  UINT32 Eax, Ebx, Ecx, Edx;
  // 呼叫支援 SubLeaf 的 AsmCpuidEx
  AsmCpuidEx (Leaf, SubLeaf, &Eax, &Ebx, &Ecx, &Edx);
  Print (L"%08x/%08x  %08x  %08x  %08x  %08x\n", Leaf, SubLeaf, Eax, Ebx, Ecx, Edx);
  
  // 檢查是否需要換頁。如果回傳 TRUE 代表使用者按了 q 結束。
  if (PageLineAccountingEx (LineCount, PrintCpuidTableHeader, 2)) return TRUE;
  return FALSE;
}

// 若 CPU 支援，則讀取並印出 CPU 品牌字串 (Brand String，如 "Intel(R) Core(TM) i7...")
STATIC VOID PrintBrandStringIfSupported (IN UINT32 MaxExtLeaf) {
  if (MaxExtLeaf >= 0x80000004) { // 品牌字串分佈在 80000002 ~ 80000004 這三個葉節點
    CHAR8  Brand[49]; // 3次查詢 * 4暫存器 * 4Bytes = 48字元 + 結尾 '\0'
    UINT32 *Ptr32;
    
    SetMem (Brand, sizeof (Brand), 0); // 記憶體清零
    Ptr32 = (UINT32 *)Brand; // 將字元陣列強制轉型為 32 位元指標，以便每次直接塞入一個暫存器的值
    
    // 依序讀取三個 Leaf，將回傳的 ASCI 字元直接拼接到陣列中
    AsmCpuid (0x80000002, &Ptr32[0],  &Ptr32[1],  &Ptr32[2],  &Ptr32[3]);
    AsmCpuid (0x80000003, &Ptr32[4],  &Ptr32[5],  &Ptr32[6],  &Ptr32[7]);
    AsmCpuid (0x80000004, &Ptr32[8],  &Ptr32[9],  &Ptr32[10], &Ptr32[11]);
    
    Print (L"\nBrand String : %a\n", Brand); // %a 代表印出 ASCII (CHAR8) 格式的字串
  }
}

// 解析一個 64-bit 數值內所包含的 8 個固定範圍 MTRR 類型
// 一個 Fixed MSR 控制 8 個區塊，每個區塊的屬性佔 8 bit (1 Byte)
STATIC VOID PrintFixedMtrrDecoded8Types (IN UINT64 Val) {
  UINTN B;
  for (B = 0; B < 8; B++) {
    // 將數值右移對應的位數後，取出最低的 8 位元
    UINT8 Type = (UINT8)((Val >> (B * 8)) & 0xFF);
    // 印出簡寫字串 (如 WB, UC)。如果是最後一項就不印結尾的空白。
    Print (L"%s%s", MtrrTypeToShortStr (Type), (B == 7) ? L"" : L" ");
  }
}

//
// =====================================================
// 核心功能實作區塊 (Features Implementation)
// =====================================================
//

// 顯示變動範圍 (Variable Range) MTRR 資訊的 UI 函式
STATIC VOID DumpMtrrUiLikePhoto_VariableRanges (VOID) {
  UINT64 MtrrCap;
  UINT8  VariableCount;
  UINTN  I;
  
  // 嘗試讀取 MTRRCAP (0xFE) 以得知 CPU 提供幾組 Variable MTRR。若讀取失敗則直接返回。
  if (!SafeReadMsr (MSR_IA32_MTRRCAP, &MtrrCap)) return;
  
  // 取出低 8 位元得到 Variable MTRR 的總數量
  VariableCount = (UINT8)(MtrrCap & IA32_MTRRCAP_VCNT_MASK);
  if (VariableCount > 10) VariableCount = 10; // 配合 UI 設計，最多印出前 10 組

  Print (L"=== [ Variable Range MTRRs ] ===\n");
  Print (L"MTRR | Idx  | PHYSBASE (Type)                  | PHYSMASK (Valid)               | Status\n");
  Print (L"-----+------+--------------------------------+--------------------------------+----------------\n");

  for (I = 0; I < 10; I++) {
    UINT64  BaseVal = 0, MaskVal = 0;
    UINT8   Type = 0;
    BOOLEAN Valid = FALSE;
    UINT32  BaseMsr, MaskMsr;

    // 如果該組引數在 CPU 支援的數量範圍內，則進行實際讀取
    if (I < VariableCount) {
      // 每組 MTRR 佔用兩個連續的 MSR (如第 0 組是 0x200 和 0x201)
      BaseMsr = MSR_IA32_MTRR_PHYSBASE0 + (UINT32)(I * 2);
      MaskMsr = MSR_IA32_MTRR_PHYSMASK0 + (UINT32)(I * 2);
      
      SafeReadMsr(BaseMsr, &BaseVal);
      SafeReadMsr(MaskMsr, &MaskVal);
      
      // Base 暫存器的最底 8 bit 代表此區塊的快取類型
      Type  = (UINT8)(BaseVal & 0xFF);
      // Mask 暫存器的第 11 個 bit 代表此組 MTRR 是否被啟用 (Valid Bit)
      Valid = (BOOLEAN)((MaskVal & BIT11) != 0);
    } 

    Print (L"MTRR | 0x%02x | %016lx (%-24s) | %016lx (Valid:%d) | %s\n",
           (UINT32)I, BaseVal, MtrrTypeToStr (Type), MaskVal, Valid ? 1 : 0, Valid ? L"ENABLED" : L"DISABLED");
  }
  Print (L"\n");
}

// 顯示固定範圍 (Fixed Range) MTRR 資訊的 UI 函式
STATIC VOID DumpMtrrUiLikePhoto_FixedRanges (VOID) {
  UINT64  MtrrCap, MtrrDef;
  BOOLEAN FixSupported, MtrrEnabled, FixEnabled;
  
  // 宣告一個陣列儲存所有 11 個固定範圍 MTRR 的 MSR 位址
  CONST UINT32 FixedMsrList[] = {
    MSR_IA32_MTRR_FIX64K_00000, MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000,
    MSR_IA32_MTRR_FIX4K_C0000,  MSR_IA32_MTRR_FIX4K_C8000,  MSR_IA32_MTRR_FIX4K_D0000,
    MSR_IA32_MTRR_FIX4K_D8000,  MSR_IA32_MTRR_FIX4K_E0000,  MSR_IA32_MTRR_FIX4K_E8000,
    MSR_IA32_MTRR_FIX4K_F0000,  MSR_IA32_MTRR_FIX4K_F8000
  };
  UINTN I;

  // 讀取能力與全域狀態暫存器
  if (!SafeReadMsr(MSR_IA32_MTRRCAP, &MtrrCap)) return;
  if (!SafeReadMsr(MSR_IA32_MTRR_DEF_TYPE, &MtrrDef)) return;

  // 解析支援能力與啟用狀態
  FixSupported = (BOOLEAN)((MtrrCap & IA32_MTRRCAP_FIX_BIT) != 0);
  MtrrEnabled  = (BOOLEAN)((MtrrDef & IA32_MTRR_DEF_TYPE_E_BIT) != 0);
  FixEnabled   = (BOOLEAN)((MtrrDef & IA32_MTRR_DEF_TYPE_FE_BIT) != 0);

  Print (L"=== [ Fixed Range MTRRs ] ===\n");

  if (!FixSupported) {
    Print (L"Fixed MTRR not supported.\n\n");
    return;
  }

  // 如果硬體支援，但 BIOS 尚未啟用它們，則給出提示
  if (!MtrrEnabled || !FixEnabled) {
    Print (L"Fixed MTRR supported but disabled (E=%d, FE=%d).\n\n", MtrrEnabled ? 1 : 0, FixEnabled ? 1 : 0);
    return;
  }

  Print (L"MSR | MSR Addr | Value (64-bit Hex)   | Decoded Memory Types (8 Bytes)\n");
  Print (L"----+----------+----------------------+----------------------------------------\n");

  // 逐一讀取 11 個 Fixed MSR
  for (I = 0; I < sizeof (FixedMsrList) / sizeof (FixedMsrList[0]); I++) {
    UINT64 Val = 0;
    SafeReadMsr(FixedMsrList[I], &Val);
    Print (L"MSR | 0x%03x    | %016lx | ", FixedMsrList[I], Val);
    PrintFixedMtrrDecoded8Types (Val); // 呼叫解析函式將這 64-bit 值拆解成 8 個狀態印出
    Print (L"\n");
  }
  Print (L"\n");
}

// 執行選單 [0] 的動作：手動輸入 Leaf 來查詢單一 CPUID
STATIC VOID DoCpuId (VOID) {
  UINT32 Leaf, Eax, Ebx, Ecx, Edx;
  ShowHeaderAndMenu (MenuCpuId);

  // 提示輸入 Leaf (以 16 進位)
  if (!PromptHexUint32 (L"Enter Function Number (Hex): ", &Leaf)) {
    Print (L"Invalid input.\n"); WaitAnyKey (); return;
  }
  
  // 執行查詢
  AsmCpuid (Leaf, &Eax, &Ebx, &Ecx, &Edx);
  Print (L"RegisterEax : %08x\nRegisterEbx : %08x\nRegisterEcx : %08x\nRegisterEdx : %08x\n", Eax, Ebx, Ecx, Edx);

  // 針對特別常見的 Leaf，做額外解析
  if (Leaf == 0) {
    // Leaf 0 會回傳製造商字串 (如 "GenuineIntel")，它被拆分存放在 EBX, EDX, ECX 中
    CHAR8 Vendor[13];
    *(UINT32 *)&Vendor[0] = Ebx; *(UINT32 *)&Vendor[4] = Edx; *(UINT32 *)&Vendor[8] = Ecx; Vendor[12] = '\0';
    Print (L"Vendor      : %a\n", Vendor);
  }

  if (Leaf == 1) {
    // Leaf 1 包含了處理器的核心特徵位元 (Feature Flags)
    Print (L"Feature(MSR)  EDX.BIT5  : %d\n", ((Edx & CPUID_FEAT_EDX_MSR)  != 0) ? 1 : 0);
    Print (L"Feature(MTRR) EDX.BIT12 : %d\n", ((Edx & CPUID_FEAT_EDX_MTRR) != 0) ? 1 : 0);
    Print (L"Feature(TSC)  EDX.BIT4  : %d\n", ((Edx & CPUID_FEAT_EDX_TSC)  != 0) ? 1 : 0);
  }
  WaitAnyKey (); // 暫停等使用者看結果
}

// 執行選單 [1] 的動作：傾印系統上所有支援的 CPUID 資訊
STATIC VOID DoDumpCpuId (VOID) {
  UINT32 MaxBasic, MaxExt, Eax, Ebx, Ecx, Edx, Leaf;
  UINTN  LineCount;
  CHAR8  Vendor[13];
  ShowHeaderAndMenu (MenuDumpCpuId);

  // 1. 先查詢基本範圍 (Basic Range)
  AsmCpuid (0, &Eax, &Ebx, &Ecx, &Edx);
  MaxBasic = Eax; // EAX 回傳的是處理器支援的「最大基本功能號碼」
  *(UINT32 *)&Vendor[0] = Ebx; *(UINT32 *)&Vendor[4] = Edx; *(UINT32 *)&Vendor[8] = Ecx; Vendor[12] = '\0';

  Print (L"[CPUID Basic]\nMax Basic Leaf : 0x%08x\nVendor         : %a\n\n", MaxBasic, Vendor);
  PrintCpuidTableHeader ();
  LineCount = 2; // 紀錄目前螢幕已輸出的行數

  // 用迴圈一路從 0 印到最大支援的葉節點
  for (Leaf = 0; Leaf <= MaxBasic; Leaf++) {
    // PrintOneCpuidLeafLine 會處理換頁。如果回傳 TRUE，代表使用者按了 q
    if (PrintOneCpuidLeafLine (Leaf, 0, &LineCount)) return;
    if (Leaf == 0xFFFFFFFFu) break; // 防呆機制，防止無窮迴圈
  }

  // 2. 查詢擴充範圍 (Extended Range)
  AsmCpuid (0x80000000, &Eax, &Ebx, &Ecx, &Edx);
  MaxExt = Eax;

  Print (L"\n[CPUID Extended]\n");
  if (PageLineAccountingEx (&LineCount, PrintCpuidTableHeader, 2)) return;
  Print (L"Max Ext Leaf   : 0x%08x\n", MaxExt);
  if (PageLineAccountingEx (&LineCount, PrintCpuidTableHeader, 2)) return;
  
  PrintCpuidTableHeader ();
  LineCount = 2;

  // 只有當最大擴充號碼大於或等於 0x80000000 (代表有實作) 時才傾印
  if (MaxExt >= 0x80000000) {
    for (Leaf = 0x80000000; Leaf <= MaxExt; Leaf++) {
      if (PrintOneCpuidLeafLine (Leaf, 0, &LineCount)) return;
      if (Leaf == 0xFFFFFFFFu) break;
    }
  }
  
  PrintBrandStringIfSupported (MaxExt); // 最後印出完整的 CPU 名稱字串
  WaitAnyKey ();
}

// 執行選單 [2] 的動作：讀取單一個 MSR
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
  
  // 使用具備 #GP 攔截功能的安全讀取函式
  if (SafeReadMsr (MsrIndex, &MsrData)) {
    Print (L"MSR_Data : %016lx\n", MsrData); // 成功則印出數值
  } else {
    // 攔截到錯誤，優雅地印出警告而不是死機
    Print (L"[ERROR] #GP Fault! MSR 0x%08x is invalid or reserved.\n", MsrIndex);
  }
  WaitAnyKey ();
}

// 執行選單 [3] 的動作：區間傾印 MSR (從 Start 掃描到 End)
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

  // 盲掃指定範圍內的所有 MSR
  for (Msr = StartMsr; Msr <= EndMsr; Msr++) {
    // SafeReadMsr 在這裡發揮了極大作用：掃到保留空號時絕不當機
    if (SafeReadMsr (Msr, &Value)) {
      Print (L"%08x   %016lx\n", Msr, Value); // 存在則印出數值
    } else {
      SetAttrHighlight();
      Print (L"%08x   [Invalid / #GP]\n", Msr); // 不存在則印出標示
      SetAttrNormal();
    }
    
    // 每印一行檢查是否需要換頁暫停
    if (PageLineAccountingEx (&LineCount, PrintMsrTableHeader, 2)) return;
    if (Msr == 0xFFFFFFFFu) break;
  }
  WaitAnyKey ();
}

// 執行選單 [4] 的動作：寫入單一 MSR
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

  // 寫入 MSR 前必須做二次確認，因為即使是合法的 MSR，寫錯位元也可能引發重啟
  Print (L"Confirm write MSR[0x%X] = 0x%016lx ? (Y/N): ", MsrIndex, MsrData);
  if (!ReadKeyBlocking (&Key)) return;
  
  Print (L"%c\n", (Key.UnicodeChar == 0) ? L'?' : Key.UnicodeChar);
  if (Key.UnicodeChar != L'Y' && Key.UnicodeChar != L'y') {
    Print (L"Canceled.\n"); WaitAnyKey (); return; // 若不是輸入 Y 則放棄寫入
  }

  // 使用安全寫入封裝
  if (SafeWriteMsr (MsrIndex, MsrData)) {
    Print (L"Write executed successfully.\n");
    // 寫入後立即讀取回來 (Read-Back) 驗證是否寫入成功 (有些 MSR 具有 Read-Only 位元)
    if (SafeReadMsr(MsrIndex, &MsrData)) {
      Print (L"ReadBack  : %016lx\n", MsrData);
    }
  } else {
    // 若企圖寫入唯讀的 MSR，會在這裡被優雅地攔截並印出錯誤
    Print (L"[ERROR] #GP Fault! Cannot write to MSR 0x%08x (Reserved or Read-Only).\n", MsrIndex);
  }
  WaitAnyKey ();
}

// 執行選單 [5] 的動作：顯示總結性的 MTRR 架構狀態
STATIC VOID DoDumpMtrr (VOID) {
  UINT64 MtrrDefType, MtrrCap;
  UINT8  DefaultType, Vcnt, PhysAddrBits;
  ShowHeaderAndMenu (MenuDumpMtrr);

  if (!CpuSupportsMsr () || !CpuSupportsMtrr ()) {
    Print (L"[ERROR] CPU does not support MSR/MTRR.\n"); WaitAnyKey (); return;
  }

  // 讀取架構性的 MTRR 暫存器
  if (!SafeReadMsr (MSR_IA32_MTRR_DEF_TYPE, &MtrrDefType) || !SafeReadMsr (MSR_IA32_MTRRCAP, &MtrrCap)) {
    Print (L"[ERROR] Failed to read base MTRR registers.\n"); WaitAnyKey (); return;
  }

  DefaultType  = (UINT8)(MtrrDefType & IA32_MTRR_DEF_TYPE_TYPE_MASK);
  Vcnt         = (UINT8)(MtrrCap & IA32_MTRRCAP_VCNT_MASK);
  PhysAddrBits = GetPhysicalAddressBits ();

  // 印出系統總結資訊
  Print (L"\n=== [ MTRR Summary ] ===\n");
  Print (L"MTRRCAP   (0xFE)  : %016lx   VCNT=%d  FIX=%d\n", MtrrCap, (UINT32)Vcnt, (MtrrCap & IA32_MTRRCAP_FIX_BIT) ? 1 : 0);
  Print (L"DEF_TYPE  (0x2FF) : %016lx   E=%d  FE=%d  Default=%s\n", MtrrDefType, 
         (MtrrDefType & IA32_MTRR_DEF_TYPE_E_BIT)  ? 1 : 0, 
         (MtrrDefType & IA32_MTRR_DEF_TYPE_FE_BIT) ? 1 : 0, 
         MtrrTypeToStr (DefaultType));
  Print (L"PhysAddrBits      : %d\n\n", (UINT32)PhysAddrBits);

  // 分別呼叫兩個 UI 函式畫出詳細列表
  DumpMtrrUiLikePhoto_VariableRanges ();
  DumpMtrrUiLikePhoto_FixedRanges ();
  WaitAnyKey ();
}

//
// =====================================================
// 主選單迴圈控制 (Main Menu Loop)
// =====================================================
//
STATIC VOID RunMainMenu (VOID) {
  EFI_INPUT_KEY Key;
  UINTN         Selected = 0; // 紀錄目前游標所在的選項索引 (0 ~ 5)

  while (TRUE) {
    ShowHeaderAndMenu (Selected); // 重繪畫面

    if (!ReadKeyBlocking (&Key)) continue; // 讀取按鍵

    // 處理方向鍵上 (SCAN_UP)
    if (Key.ScanCode == SCAN_UP) {
      if (Selected == 0) Selected = MENU_ITEMS_COUNT - 1; // 到達頂部則跳到最底
      else Selected--;
      continue;
    }

    // 處理方向鍵下 (SCAN_DOWN)
    if (Key.ScanCode == SCAN_DOWN) {
      Selected = (Selected + 1) % MENU_ITEMS_COUNT; // 循環增加
      continue;
    }

    // 處理 Enter 鍵確認選擇
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
      continue; // 功能執行完畢後，回到迴圈頂端重繪選單
    }

    // 處理 ESC 鍵退出程式
    if (Key.ScanCode == SCAN_ESC) break;
  }
}

//
// =====================================================
// 應用程式進入點 (Application Entry Point)
// =====================================================
//
// 這是 UEFI 編譯器預設尋找的 C 語言主程式進入點，等同於標準 C 語言的 main 函式。
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,   // 系統發給這支 UEFI 程式的識別把手 (Handle)
  IN EFI_SYSTEM_TABLE  *SystemTable   // 指向 UEFI 系統服務表 (包含了 Boot Services 與 Runtime Services) 的指標
  )
{
  // 透過 ConIn 介面發送重設命令 (Reset) 來清空鍵盤緩衝區的歷史殘留資料。
  // 參數 FALSE 代表不需要進行延伸的硬體檢測。
  gST->ConIn->Reset (gST->ConIn, FALSE);
  
  // 【尋找 CPU Protocol】：我們必須使用這個 Protocol 來掛載 Exception Handler。
  // gBS->LocateProtocol 會在 UEFI 環境中搜尋指定 GUID (gEfiCpuArchProtocolGuid) 的實例，
  // 並將該實例的記憶體位址賦值給全域指標 mCpu。如果找不到，mCpu 將保持為 NULL。
  gBS->LocateProtocol (&gEfiCpuArchProtocolGuid, NULL, (VOID **)&mCpu);

  // 進入主選單的無限迴圈
  RunMainMenu ();

  // 使用者按下 ESC 退出迴圈後，清理畫面並提示結束
  ClearScreenAndResetAttr ();
  Print (L"CpuMsrMtrrApp exit.\n");
  
  // 回傳 EFI_SUCCESS (0)，告訴 UEFI Shell 此程式正常結束。
  return EFI_SUCCESS;
}