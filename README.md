# CpuIdPkg

---

# 🛠️ CPU / MSR / MTRR 測試與檢測工具開發指南

本專案是一個基於 UEFI (EDK2) 環境的底層硬體檢測工具。主要功能涵蓋處理器資訊識別 (CPUID)、底層暫存器讀寫 (MSR)，以及記憶體快取屬性解析 (MTRR)。

為確保系統穩定性，本工具實作了硬體例外攔截機制 (Exception Handling)，能有效防止盲掃暫存器時引發的系統當機 (#GP Fault)。

---

## 📖 第一部分：核心基本概念 (Basic Concepts)

在操作本工具前，請先理解以下三個 x86 架構的核心組件：

### 1. CPUID (CPU Identification)

* **是什麼**：CPUID 是一個 x86 組合語言指令，用於查詢處理器的製造商、型號、架構特徵（如是否支援 VT-x、MSR、MTRR 等）。
* **運作原理**：
軟體將「功能號碼 (Leaf)」放入 `EAX` 暫存器（有時加上 `ECX` 作為 Sub-Leaf），接著呼叫 `cpuid` 指令。CPU 會將查詢結果填入 `EAX`、`EBX`、`ECX`、`EDX` 四個暫存器中回傳。
* **範圍劃分**：
* **基本範圍 (Basic Range)**：Leaf `0x00000000` ~ `0x000000XX`（包含供應商字串、最大基礎功能號、特徵位元）。
* **擴充範圍 (Extended Range)**：Leaf `0x80000000` ~ `0x800000XX`（包含處理器品牌名稱字串、實體位址大小等）。



### 2. MSR (Model-Specific Register, 特定型號暫存器)

* **是什麼**：MSR 是 CPU 內部用於控制硬體底層行為、效能監控、電源管理與除錯的特殊暫存器。
* **危險性與 #GP 異常**：
MSR 的位址（Index）是**不連續且跳躍的**，且會隨著不同型號的 CPU 而改變。如果軟體嘗試使用 `rdmsr` 或 `wrmsr` 指令去讀寫一個**該 CPU 沒有實作（或被保留）的 MSR 位址**，CPU 會立刻觸發 `#GP` (General Protection Fault，中斷向量 13)，導致系統當機或重啟。
* **常見 MSR**：
* `0x10` (TSC): Time Stamp Counter，記錄開機以來的時脈週期。
* `0xCE` (Platform Info): 包含基礎時脈比例等資訊。



### 3. MTRR (Memory Type Range Register, 記憶體類型範圍暫存器)

* **是什麼**：MTRR 是一組特殊的 MSR，負責告訴 CPU：「這段實體記憶體區間應該使用什麼樣的快取策略 (Cacheability)」。
* **常見記憶體類型**：
* **WB (Write-Back, 0x06)**：最高效能，資料先寫入 Cache，適用於一般系統主記憶體。
* **UC (Uncacheable, 0x00)**：不使用 Cache，所有讀寫直接對應到硬體，適用於 MMIO (Memory-Mapped I/O，如 PCIe 裝置的暫存器)。
* **WC (Write-Combining, 0x01)**：將多次小寫入合併成一次大寫入，適用於顯示卡的 Framebuffer。


* **架構劃分**：
* **固定範圍 (Fixed Range MTRRs)**：固定控制 `0x00000` 到 `0xFFFFF` (前 1MB) 的記憶體，切分成 64KB、16KB、4KB 等小區塊，常用於傳統 VGA 記憶體與 BIOS ROM 的定址。
* **變動範圍 (Variable Range MTRRs)**：由 Base (基底位址) 與 Mask (遮罩大小) 兩個 MSR 組成一對，用來定義 1MB 以上大容量記憶體的快取屬性。



---

## 💻 第二部分：核心函數使用方法 (API Notes)

本專案提供了一系列安全的 C 語言封裝函數，方便開發者進行硬體讀寫。

### 🛡️ 安全 MSR 讀寫 API (Exception-Safe)

底層依賴 `EFI_CPU_ARCH_PROTOCOL` 實作中斷攔截，盲掃 MSR 時絕對不會當機。

#### `SafeReadMsr`

安全地讀取 MSR，若位址不存在會優雅地回傳失敗，而非死機。

* **定義**：`STATIC BOOLEAN SafeReadMsr (IN UINT32 Index, OUT UINT64 *Value);`
* **參數**：
* `Index` (輸入)：要讀取的 MSR 16 進位位址。
* `Value` (輸出)：用來接收 64-bit 結果的指標。


* **回傳**：`TRUE` (讀取成功), `FALSE` (觸發 #GP，該 MSR 不存在)。
* **範例**：
```c
UINT64 MsrData;
if (SafeReadMsr(0x10, &MsrData)) {
    Print(L"TSC 數值: 0x%016lx\n", MsrData);
}

```



#### `SafeWriteMsr`

安全地寫入 MSR，防範寫入唯讀暫存器導致的崩潰。

* **定義**：`STATIC BOOLEAN SafeWriteMsr (IN UINT32 Index, IN UINT64 Value);`
* **參數**：
* `Index` (輸入)：目標 MSR 位址。
* `Value` (輸入)：欲寫入的 64-bit 數值。


* **回傳**：`TRUE` (寫入成功), `FALSE` (寫入遭拒絕或不存在)。

---

### 🔍 硬體特徵檢測 API

#### `CpuSupportsMsr` / `CpuSupportsMtrr`

透過解析 CPUID Leaf 1 的 EDX 暫存器，確認當前硬體是否支援對應架構。

* **定義**：
```c
STATIC BOOLEAN CpuSupportsMsr (VOID);
STATIC BOOLEAN CpuSupportsMtrr (VOID);

```


* **回傳**：`TRUE` (支援) / `FALSE` (不支援)。

#### `GetPhysicalAddressBits`

取得 CPU 硬體的實體位址線寬度 (通常為 36, 39 或 46 bits)。此數值是計算 Variable MTRR 實際涵蓋記憶體大小的關鍵。

* **定義**：`STATIC UINT8 GetPhysicalAddressBits (VOID);`
* **回傳**：位元數 (UINT8)。

---

### 🖥️ UI 與互動輔助 API

#### `PromptHexUint32` / `PromptHexUint64`

在畫面上印出提示字元，讀取使用者的鍵盤輸入，並安全地將字串解析為 16 進位數值。

* **定義**：`STATIC BOOLEAN PromptHexUint32 (IN CONST CHAR16 *Prompt, OUT UINT32 *Value);`
* **回傳**：`TRUE` (解析成功), `FALSE` (包含非法字元或為空)。

#### `PageLineAccountingEx`

處理終端機畫面的「分頁暫停」邏輯。當印出大量資料時（如 Dump 所有 CPUID），此函數會自動在達到畫面底端時暫停，並詢問是否繼續。

* **定義**：`STATIC BOOLEAN PageLineAccountingEx (IN OUT UINTN *LineCount, IN VOID (*ReprintHeader)(VOID), IN UINTN HeaderLines);`
* **參數**：
* `LineCount`：目前螢幕已印出幾行的計數器指標。
* `ReprintHeader`：換頁後重繪表格標題的函數指標 (若無可傳 `NULL`)。
* `HeaderLines`：標題佔用的行數。


* **回傳**：`TRUE` (使用者按下 'q' 要求中斷顯示), `FALSE` (正常翻頁繼續)。

---

## ⚡ 第三部分：安全測試清單 (Quick Test)

若要驗證工具是否正常運作，建議在 `Read MSR` 功能中輸入以下保證存在的安全位址進行測試：

* `10`：Time Stamp Counter (應觀察到數值不斷變大)。
* `CE`：Platform Info。
* `FE`：MTRRCAP (MTRR 能力暫存器)。
* `2FF`：MTRR_DEF_TYPE (MTRR 預設快取類型)。

*(註：若使用 `Dump MSR`，您可以大膽設定 Start 為 `0x00`，End 為 `0xFF`，觀察 `SafeReadMsr` 如何優雅地將不存在的位址標示為 `[Invalid / #GP]` 而不引發當機。)*

---

cd /d D:\BIOS\MyWorkSpace\edk2

edksetup.bat Rebuild

chcp 65001

set PYTHONUTF8=1

set PYTHONIOENCODING=utf-8

rmdir /s /q Build\CmosRwAppPkg

build -p CpuIdPkg\CpuIdPkg.dsc -a X64 -t VS2019 -b DEBUG
