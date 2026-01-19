# SimplePacker - 简单的 PE 加壳学习项目

## 项目简介
`SimplePacker` 是一个用于学习 Windows PE (Portable Executable) 文件格式及加壳技术原理的项目。

**注意：本项目仅用于教育和研究目的，旨在帮助初学者理解 PE 结构、内存权限控制以及简单的 Shellcode 注入原理。它不具备实际的软件保护强度，无法对抗专业的逆向工程分析。**

该项目实现了一个针对 **x64 (PE32+)** 可执行文件的基础加壳器，包含“加壳” (Pack) 和“脱壳” (Unpack) 两个核心功能。

---

## 核心功能
- **加壳 (Pack)**：对目标 EXE 文件的代码段进行异或加密，并注入解密 Stub。
- **脱壳 (Unpack)**：识别已加壳的文件，恢复原始代码并移除注入的 Section。
- **PE 信息展示**：内置简单的 PE 头部解析器。

---

## 关键实现技术分析

### 1. PE 结构解析与修改
项目通过 [PEHelper.h](file:///d:/project/c++/SimplePacker/PEHelper.h) 和 [PEHelper.cpp](file:///d:/project/c++/SimplePacker/PEHelper.cpp) 实现了对 PE 文件格式的底层操作：
- **头部解析**：手动解析 DOS Header、NT Headers 以及 Section Table。
- **地址转换**：实现了 RVA (Relative Virtual Address) 与 File Offset 之间的相互转换，这是在静态文件修改中定位代码的关键。
- **新增节 (Section Injection)**：实现了向现有 PE 文件添加新节的具体逻辑。包括在头部寻找空闲空间、计算对齐后的 RVA 和文件偏移，以及更新 `SizeOfImage` 等核心字段。

### 2. 代码段加密与权限调整
在 [packer.cpp](file:///d:/project/c++/SimplePacker/packer.cpp) 中，加壳过程涉及：
- **目标定位**：寻找具有执行权限的节（通常是 `.text`），并从入口点 (EntryPoint) 开始选择一定长度的代码块。
- **异或加密**：使用简单的 XOR 算法对代码进行混淆。
- **属性修改**：将目标代码段的属性修改为可写 (`IMAGE_SCN_MEM_WRITE`)。这是为了让注入的解密 Stub 在运行时能够将解密后的代码写回内存。

### 3. Shellcode Stub 注入
这是加壳技术中最核心的部分。项目预定义了一个 x64 汇编编写的模板：
- **寄存器保护**：Stub 开始时使用 `push` 保存所有关键寄存器，结束前通过 `pop` 恢复。
- **RIP 相对寻址**：使用 `LEA RBX, [RIP + offset]` 定位存储在 Stub 尾部的解密参数（如加密起始地址、大小、密钥）。这种方式使得 Stub 具有位置无关性 (PIC)。
- **运行时解密**：在程序真正运行前，Stub 循环遍历加密内存区域，执行 XOR 还原操作。
- **流程劫持**：将 PE 头的 `AddressOfEntryPoint` 修改为指向新注入的 `.pack` 节。解密完成后，通过一个相对 `JMP` 指令跳转回原始入口点 (OEP)。

---

## 使用说明

### 编译环境
- 操作系统: Windows
- 编译器: 支持 C++11 的编译器 (如 MSVC)
- 架构: 仅支持 x64 (64位)

### 命令行用法
```bash
# 加壳
SimplePacker.exe pack <input.exe> <output.exe>

# 脱壳
SimplePacker.exe unpack <packed.exe> <output.exe>
```

---

## 项目结构
- [SimplePacker.cpp](file:///d:/project/c++/SimplePacker/SimplePacker.cpp): 命令行接口与程序入口。
- [packer.cpp](file:///d:/project/c++/SimplePacker/packer.cpp): 加壳与脱壳的具体业务逻辑。
- [PEHelper.cpp](file:///d:/project/c++/SimplePacker/PEHelper.cpp): PE 文件结构操作辅助类。
- [Packer.h](file:///d:/project/c++/SimplePacker/Packer.h) / [PEHelper.h](file:///d:/project/c++/SimplePacker/PEHelper.h): 核心类定义。

---
