# CpuIdPkg

---

# 🛠️ CPU / MSR / MTRR 測試工具開發指南

本專案實作了一個基於 UEFI 環境的 CPU 暫存器檢測工具。為了克服傳統工具在讀取未定義 MSR (Model-Specific Register) 時會導致系統當機 (#GP Fault) 的痛點，底層實作了**硬體中斷攔截機制**，提供高度安全的 API 供開發者呼叫。

## 🛡️ 核心安全機制 (Exception Handling)

### `MsrFaultHandler`

* **用途**：註冊於 `EFI_CPU_ARCH_PROTOCOL` 的中斷處理常式。
* **原理**：當系統觸發 `EXCEPT_IA32_GP_FAULT` (中斷向量 13) 時，此函式會介入檢查引發崩潰的指令是否為 `rdmsr` 或 `wrmsr`。若是，則將指令指標 (RIP/EIP) 推進 2 個 Bytes 以跳過錯誤指令，並設定全域旗標 `gMsrFault = TRUE`，從而拯救系統免於死機。
* **注意**：這是一個內部回呼函式 (Callback)，**不應由上層應用直接呼叫**。

---

## 📖 核心 MSR 讀寫 API (Safe Wrappers)

開發者應**絕對避免**直接使用 BaseLib 的 `AsmReadMsr64` / `AsmWriteMsr64`，請全面改用以下封裝好的安全函式。

### `SafeReadMsr`

安全地讀取指定的 MSR 暫存器。若該暫存器不存在或被硬體保留，程式不會當機，而是優雅地回傳失敗。

* **函式簽名**：
```c
STATIC BOOLEAN SafeReadMsr (IN UINT32 Index, OUT UINT64 *Value);

```


* **參數**：
* `Index` (輸入)：要讀取的 MSR 暫存器位址 (例如 `0xCE`)。
* `Value` (輸出)：用來接收 64-bit 讀取結果的指標。


* **回傳值**：`TRUE` 表示讀取成功；`FALSE` 表示觸發 #GP Fault (暫存器不存在)。
* **使用範例**：
```c
UINT64 MsrData = 0;
if (SafeReadMsr(0xCE, &MsrData)) {
    Print(L"MSR 0xCE 的值為: 0x%016lx\n", MsrData);
} else {
    Print(L"該 MSR 不存在或無法讀取！\n");
}

```



### `SafeWriteMsr`

安全地將 64-bit 數值寫入指定的 MSR 暫存器。若目標為唯讀 (Read-Only) 或位址不存在，將攔截藍屏並回傳失敗。

* **函式簽名**：
```c
STATIC BOOLEAN SafeWriteMsr (IN UINT32 Index, IN UINT64 Value);

```


* **參數**：
* `Index` (輸入)：目標 MSR 位址。
* `Value` (輸入)：欲寫入的 64-bit 數值。


* **回傳值**：`TRUE` 表示寫入指令執行完畢；`FALSE` 表示寫入遭硬體拒絕 (#GP Fault)。
* **使用範例**：
```c
if (!SafeWriteMsr(0x199, 0x1000)) {
    Print(L"[警告] 寫入被拒絕，可能該暫存器為唯讀屬性。\n");
}

```



---

## 🔍 CPU 架構與特徵檢測 API

在進行任何 MSR 或 MTRR 操作前，應先使用以下函式確認當前 CPU 的硬體支援度。

### `CpuSupportsMsr` / `CpuSupportsMtrr`

透過執行 `CPUID (Leaf 1)`，檢查 EDX 暫存器中的特徵位元，判斷硬體是否支援對應功能。

* **函式簽名**：
```c
STATIC BOOLEAN CpuSupportsMsr (VOID);
STATIC BOOLEAN CpuSupportsMtrr (VOID);

```


* **回傳值**：`TRUE` (支援) / `FALSE` (不支援)。

### `GetPhysicalAddressBits`

取得 CPU 支援的「實體記憶體定址線寬度」(Physical Address Bits)，這對於計算 MTRR (特別是 Variable MTRR) 的實際覆蓋大小至關重要。

* **函式簽名**：
```c
STATIC UINT8 GetPhysicalAddressBits (VOID);

```


* **回傳值**：整數 (通常為 `36`, `39` 或 `46`)，代表位元數。底層邏輯透過 `CPUID (Leaf 0x80000008)` 取得。

---

## 🖥️ 互動與 UI 輔助 API

### `PromptHexUint32` / `PromptHexUint64`

在畫面上印出提示字眼，並等待使用者輸入一串 16 進位字串，隨後安全地將其轉換為數值。支援帶有 `0x` 前綴或純數字輸入。

* **函式簽名**：
```c
STATIC BOOLEAN PromptHexUint32 (IN CONST CHAR16 *Prompt, OUT UINT32 *Value);

```


* **參數**：
* `Prompt`：要印在螢幕上的提示字串 (例如 `L"請輸入位址: "`)。
* `Value`：接收轉換後數值的指標。


* **回傳值**：`TRUE` (解析成功) / `FALSE` (輸入包含非法字元或為空)。

### `PageLineAccountingEx`

處理終端機畫面「分頁暫停」的核心邏輯，防止連續印出大量資料時畫面瞬間洗掉。

* **函式簽名**：
```c
STATIC BOOLEAN PageLineAccountingEx (IN OUT UINTN *LineCount, IN VOID (*ReprintHeader)(VOID), IN UINTN HeaderLines);

```


* **參數**：
* `LineCount`：目前螢幕已印出的行數指標。函式內部會自動將此值 `+1`。
* `ReprintHeader`：一個函式指標。當觸發換頁清空螢幕後，會自動呼叫此函式重繪表格的標題列。
* `HeaderLines`：標題列所佔用的行數 (用於換頁後重置 `LineCount`)。


* **回傳值**：`TRUE` 表示使用者在暫停時按下了 `q` 鍵要求中斷顯示；`FALSE` 表示繼續往下印。
* **使用範例**：
```c
UINTN LineCount = 0;
for (UINT32 i = 0; i < 100; i++) {
    Print(L"Data Line %d\n", i);
    // 若印滿指定行數會自動暫停，若回傳 TRUE 則打破迴圈
    if (PageLineAccountingEx(&LineCount, PrintMyHeader, 2)) {
        break; 
    }
}

```

---

cd /d D:\BIOS\MyWorkSpace\edk2

edksetup.bat Rebuild

chcp 65001

set PYTHONUTF8=1

set PYTHONIOENCODING=utf-8

rmdir /s /q Build\CmosRwAppPkg

build -p CpuIdPkg\CpuIdPkg.dsc -a X64 -t VS2019 -b DEBUG
