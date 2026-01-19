#include "Packer.h"
#include "PEHelper.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>

// 壳代码，使用相对寻址
unsigned char stub_template[] = {
    // Pushes (10 bytes)
    0x53, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x9c,

    // LEA rbx, [rip + offset] (7 bytes) -> 指向数据区 (Offset 10)
    0x48, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00,

    // mov rcx, [rbx] (3 bytes) -> TargetRelativeOffset
    0x48, 0x8b, 0x0b,

    // mov r8, [rbx+8] (4 bytes) -> Size
    0x4c, 0x8b, 0x43, 0x08,

    // mov r9, [rbx+16] (4 bytes) -> Key
    0x4c, 0x8b, 0x4b, 0x10,

    // add rcx, rbx (3 bytes) -> TargetAddr = DataAddr + RelOffset
    0x48, 0x01, 0xd9,

    // Loop Start
    // test r8, r8 (3 bytes)
    0x4d, 0x85, 0xc0,
    // je done (2 bytes) -> Jump 11 bytes forward
    0x74, 0x0b,

    // xor [rcx], r9b (3 bytes)
    0x44, 0x30, 0x09,
    // inc rcx (3 bytes)
    0x48, 0xff, 0xc1,
    // dec r8 (3 bytes)
    0x49, 0xff, 0xc8,
    // jmp loop (2 bytes) -> Jump 16 bytes back
    0xeb, 0xf0,

    // Done:
    // Pops (10 bytes)
    0x9d, 0x41, 0x59, 0x41, 0x58, 0x5f, 0x5e, 0x5a, 0x59, 0x5b,

    // JMP rel32 (5 bytes)
    0xE9, 0x00, 0x00, 0x00, 0x00
};

struct StubParams {
    long long targetRelOffset; // TargetAddr - DataAddr
    long long size;
    long long key;
};

Packer::Packer() {}
Packer::~Packer() {}

void Packer::XorData(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

bool Packer::Pack(const std::string& inputPath, const std::string& outputPath) {
    PEHelper pe;
    if (!pe.Load(inputPath)) return false;

	// 1. 加密.text 节
    PIMAGE_SECTION_HEADER pTargetSection = nullptr;
    PIMAGE_NT_HEADERS64 pNtHeaders = pe.GetNtHeaders();
    PIMAGE_SECTION_HEADER pSections = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pTargetSection = &pSections[i];
            break;
        }
    }

    if (!pTargetSection) {
        std::cerr << "未找到可执行节 (.text)" << std::endl;
        return false;
    }

    std::cout << "正在加密节: " << pTargetSection->Name << " 大小: " << pTargetSection->Misc.VirtualSize << std::endl;

    // 2. 加密数据
    unsigned char key = 0xAA; // 恢复密钥
    DWORD targetOffset = pTargetSection->PointerToRawData;

    // 为了避免破坏混在代码段中的数据（如 IAT, .xdata 等），
    // 我们只从 EntryPoint 开始加密一小段代码。

    DWORD epRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD encryptStartRVA = pTargetSection->VirtualAddress;

    // 如果 EP 在该节内，则从 EP 开始加密
    if (epRVA >= pTargetSection->VirtualAddress &&
        epRVA < pTargetSection->VirtualAddress + pTargetSection->Misc.VirtualSize) {
        encryptStartRVA = epRVA;
        DWORD offsetInSec = epRVA - pTargetSection->VirtualAddress;
        targetOffset += offsetInSec;
    }

    // 固定加密大小为 4096 字节（或者剩余大小）
    DWORD maxEncryptSize = 4096;
    DWORD remainingSize = (pTargetSection->VirtualAddress + pTargetSection->Misc.VirtualSize) - encryptStartRVA;
    DWORD encryptSize = (remainingSize < maxEncryptSize) ? remainingSize : maxEncryptSize;

    std::cout << "加密起始 RVA: 0x" << std::hex << encryptStartRVA << std::endl;
    std::cout << "加密大小: 0x" << std::hex << encryptSize << std::endl;

    // 恢复加密
    XorData(pe.GetBuffer() + targetOffset, encryptSize, key);

    // 关键修复：添加可写属性 (IMAGE_SCN_MEM_WRITE)
    pTargetSection->Characteristics |= IMAGE_SCN_MEM_WRITE;

    // 3. 准备 Stub 参数
    // 我们需要在添加节之后计算 Offset，因为 AddSection 可能会改变 buffer

    // 4. 添加 .pack 节
    DWORD stubCodeSize = sizeof(stub_template);
    DWORD stubTotalSize = stubCodeSize + sizeof(StubParams);
    PIMAGE_SECTION_HEADER pPackSection = pe.AddSection(".pack", stubTotalSize,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE);

    if (!pPackSection) {
        std::cerr << "添加节失败" << std::endl;
        return false;
    }

    // 5. 写入 Stub 代码和数据
    BYTE* buffer = pe.GetBuffer();
    DWORD packOffset = pPackSection->PointerToRawData;

    // 填充 Stub 代码
    memcpy(buffer + packOffset, stub_template, stubCodeSize);

    // 计算并填充 LEA Offset
    // LEA 指令在 offset 10, 长度 7. NextIP = 17.
    // 数据区在 StubCodeSize 处.
    // Offset = StubCodeSize - 17.
    int32_t leaOffset = stubCodeSize - 17;
    memcpy(buffer + packOffset + 13, &leaOffset, 4);

    // 计算并填充 JMP Offset
    // JMP 指令在 stubCodeSize - 5.
    // NextIP = StubStart + StubCodeSize.
    // Target = OEP.
    DWORD originalOEP = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    DWORD stubStart = pPackSection->VirtualAddress;
    DWORD nextIP = stubStart + stubCodeSize;
    int32_t jmpOffset = originalOEP - nextIP;
    memcpy(buffer + packOffset + stubCodeSize - 4, &jmpOffset, 4);

    // 准备并写入数据
    StubParams params;
    long long dataRVA = stubStart + stubCodeSize;
    // targetRVA 必须是加密起始地址
    long long targetRVA = encryptStartRVA;
    params.targetRelOffset = targetRVA - dataRVA;
    params.size = encryptSize; // 恢复全量解密，如果再次崩溃，说明是边界问题
    params.key = key;

    memcpy(buffer + packOffset + stubCodeSize, &params, sizeof(StubParams));

    // 6. 修改入口点
    pNtHeaders = pe.GetNtHeaders(); // 重新获取
    pNtHeaders->OptionalHeader.AddressOfEntryPoint = pPackSection->VirtualAddress;

    std::cout << "加壳完成。新入口点: 0x" << std::hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;

    return pe.Save(outputPath);
}


// 脱壳函数
bool Packer::Unpack(const std::string& inputPath, const std::string& outputPath) {

    PEHelper pe;
    if (!pe.Load(inputPath)) return false;

    PIMAGE_NT_HEADERS64 pNtHeaders = pe.GetNtHeaders();
    PIMAGE_SECTION_HEADER pLastSection = pe.GetLastSection();

    if (!pLastSection || strncmp((char*)pLastSection->Name, ".pack", 5) != 0) {
        std::cerr << "未找到 .pack 节" << std::endl;
        return false;
    }

    std::cout << "发现 .pack 节，正在脱壳..." << std::endl;

    // 读取 StubParams
    // 数据在 stub_template 后面
    DWORD packOffset = pLastSection->PointerToRawData;
    StubParams params;
    memcpy(&params, pe.GetBuffer() + packOffset + sizeof(stub_template), sizeof(StubParams));

    // 计算 TargetRVA
    // TargetRVA = DataRVA + RelOffset
    long long dataRVA = pLastSection->VirtualAddress + sizeof(stub_template);
    long long targetRVA = dataRVA + params.targetRelOffset;

    // 解密
    DWORD targetOffset = pe.RvaToOffset((DWORD)targetRVA);
    if (targetOffset == 0) {
        std::cerr << "无效的目标 RVA" << std::endl;
        return false;
    }

    std::cout << "解密地址: 0x" << std::hex << targetRVA << " 大小: " << params.size << std::endl;
    XorData(pe.GetBuffer() + targetOffset, (size_t)params.size, (unsigned char)params.key);

    // 恢复入口点
    // 我们需要从 JMP 指令中提取原始 OEP
    // JMP offset 在 stub_template 倒数第 4 字节
    int32_t jmpOffset;
    memcpy(&jmpOffset, pe.GetBuffer() + packOffset + sizeof(stub_template) - 4, 4);

    DWORD stubEndRVA = pLastSection->VirtualAddress + sizeof(stub_template);
    DWORD originalOEP = stubEndRVA + jmpOffset;

    pNtHeaders->OptionalHeader.AddressOfEntryPoint = originalOEP;

    // 移除 .pack 节
    pNtHeaders->FileHeader.NumberOfSections--;
    pNtHeaders->OptionalHeader.SizeOfImage = PEHelper::Align(pLastSection->VirtualAddress, pNtHeaders->OptionalHeader.SectionAlignment);
    memset(pLastSection, 0, sizeof(IMAGE_SECTION_HEADER));

    std::cout << "脱壳完成。恢复入口点: 0x" << std::hex << originalOEP << std::endl;

    return pe.Save(outputPath);
}
