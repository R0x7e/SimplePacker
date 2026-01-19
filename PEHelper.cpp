#include "PEHelper.h"
#include <iostream>
#include <cstring>

PEHelper::PEHelper() : pDosHeader(nullptr), pNtHeaders(nullptr), pSectionHeaders(nullptr), isLoaded(false) {}

PEHelper::~PEHelper() {}

DWORD PEHelper::Align(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    DWORD remainder = value % alignment;
    if (remainder == 0) return value;
    return value + (alignment - remainder);
}

bool PEHelper::Load(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "无法打开文件: " << filepath << std::endl;
        return false;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    if (size == 0) {
        std::cerr << "文件为空" << std::endl;
        return false;
    }

    buffer.resize((size_t)size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "读取文件失败" << std::endl;
        return false;
    }

    ParseHeaders();

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "无效的 DOS 签名" << std::endl;
        return false;
    }

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "无效的 PE 签名" << std::endl;
        return false;
    }

    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::cerr << "仅支持 x64 PE 文件 (PE32+)" << std::endl;
        return false;
    }

    isLoaded = true;
    return true;
}

void PEHelper::ParseHeaders() {
    if (buffer.empty()) return;
    pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + pDosHeader->e_lfanew);
    // 节表紧跟在 OptionalHeader 后面
    // 使用 IMAGE_FIRST_SECTION 宏需要做一些转换，因为它是针对当前定义的类型的
    // 这里手动计算：
    pSectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<BYTE*>(&pNtHeaders->OptionalHeader) +
        pNtHeaders->FileHeader.SizeOfOptionalHeader
        );
}

bool PEHelper::Save(const std::string& filepath) {
    if (!isLoaded) return false;
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

void PEHelper::PrintInfo() {
    if (!isLoaded) return;
    std::cout << "--- PE 信息 ---" << std::endl;
    std::cout << "入口点 (OEP): 0x" << std::hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "镜像基址: 0x" << std::hex << pNtHeaders->OptionalHeader.ImageBase << std::endl;
    std::cout << "节数量: " << std::dec << pNtHeaders->FileHeader.NumberOfSections << std::endl;

    PIMAGE_SECTION_HEADER pSection = pSectionHeaders;
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        char name[9] = { 0 };
        memcpy(name, pSection[i].Name, 8);
        std::cout << "节 [" << i << "]: " << name
            << " RVA: 0x" << std::hex << pSection[i].VirtualAddress
            << " RawSize: 0x" << std::hex << pSection[i].SizeOfRawData
            << std::endl;
    }
}

PIMAGE_SECTION_HEADER PEHelper::GetLastSection() {
    if (!isLoaded || pNtHeaders->FileHeader.NumberOfSections == 0) return nullptr;
    return &pSectionHeaders[pNtHeaders->FileHeader.NumberOfSections - 1];
}

PIMAGE_SECTION_HEADER PEHelper::AddSection(const char* name, DWORD size, DWORD characteristics) {
    if (!isLoaded) return nullptr;

    // 检查是否有足够的空间添加节表项
    // 简单的检查：最后一个节表项之后是否碰到第一个节的数据
    // 更安全的做法是检查 SizeOfHeaders

    DWORD currentHeaderEnd = pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) +
        (pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    // 还需要加上这一个新节的大小
    if (currentHeaderEnd + sizeof(IMAGE_SECTION_HEADER) > pNtHeaders->OptionalHeader.SizeOfHeaders) {
        std::cerr << "没有足够的空间添加新节表项！" << std::endl;
        return nullptr;
    }

    PIMAGE_SECTION_HEADER pLastSection = GetLastSection();
    DWORD newSectionRVA = 0;
    DWORD newSectionRawOffset = 0;

    if (pLastSection) {
        // 新节的 RVA = 最后一个节的 RVA + VirtualSize (对齐后)
        newSectionRVA = Align(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize,
            pNtHeaders->OptionalHeader.SectionAlignment);

        // 新节的文件偏移 = 最后一个节的文件偏移 + SizeOfRawData (对齐后)
        newSectionRawOffset = Align(pLastSection->PointerToRawData + pLastSection->SizeOfRawData,
            pNtHeaders->OptionalHeader.FileAlignment);
    }
    else {
        // 理论上 RVA 从 SizeOfHeaders 对齐后开始
        newSectionRVA = Align(pNtHeaders->OptionalHeader.SizeOfHeaders, pNtHeaders->OptionalHeader.SectionAlignment);
        newSectionRawOffset = Align(pNtHeaders->OptionalHeader.SizeOfHeaders, pNtHeaders->OptionalHeader.FileAlignment);
    }

    // 准备新节的数据
    DWORD alignedSize = Align(size, pNtHeaders->OptionalHeader.FileAlignment);
    DWORD newBufferSize = newSectionRawOffset + alignedSize;

    if (newBufferSize > buffer.size()) {
        buffer.resize(newBufferSize, 0); // 填充0
        // Buffer 改变，必须重新解析指针
        ParseHeaders();
    }

    // 此时 pSectionHeaders 指针已更新
    PIMAGE_SECTION_HEADER pNewSection = &pSectionHeaders[pNtHeaders->FileHeader.NumberOfSections];

    memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
    strncpy(reinterpret_cast<char*>(pNewSection->Name), name, 8);
    pNewSection->Misc.VirtualSize = size; // 实际数据大小
    pNewSection->VirtualAddress = newSectionRVA;
    pNewSection->SizeOfRawData = alignedSize; // 对齐后的大小
    pNewSection->PointerToRawData = newSectionRawOffset;
    pNewSection->Characteristics = characteristics;

    // 更新 NT Header
    pNtHeaders->FileHeader.NumberOfSections++;
    pNtHeaders->OptionalHeader.SizeOfImage = Align(newSectionRVA + size, pNtHeaders->OptionalHeader.SectionAlignment);

    return pNewSection;
}

DWORD PEHelper::RvaToOffset(DWORD rva) {
    if (!isLoaded) return 0;
    PIMAGE_SECTION_HEADER pSection = pSectionHeaders;
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= pSection[i].VirtualAddress &&
            rva < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
            return pSection[i].PointerToRawData + (rva - pSection[i].VirtualAddress);
        }
    }
    return 0;
}

DWORD PEHelper::OffsetToRva(DWORD offset) {
    if (!isLoaded) return 0;
    PIMAGE_SECTION_HEADER pSection = pSectionHeaders;
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (offset >= pSection[i].PointerToRawData &&
            offset < pSection[i].PointerToRawData + pSection[i].SizeOfRawData) {
            return pSection[i].VirtualAddress + (offset - pSection[i].PointerToRawData);
        }
    }
    return 0;
}

PIMAGE_NT_HEADERS64 PEHelper::GetNtHeaders() {
    return pNtHeaders;
}

PIMAGE_DOS_HEADER PEHelper::GetDosHeader() {
    return pDosHeader;
}
