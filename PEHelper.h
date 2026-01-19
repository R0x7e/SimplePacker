#ifndef PEHELPER_H
#define PEHELPER_H
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

/**
 * @brief PE文件操作辅助类 (仅支持 x64 PE32+)
 * 负责PE文件的加载、解析、修改节表和保存
 */
class PEHelper {
public:
    PEHelper();
    ~PEHelper();

    // 加载PE文件
    bool Load(const std::string& filepath);

    // 保存PE文件
    bool Save(const std::string& filepath);

    // 打印PE信息
    void PrintInfo();

    // 获取最后一个节的指针
    PIMAGE_SECTION_HEADER GetLastSection();

    // 添加一个新节
    // name: 节名
    // size: 节数据大小
    // characteristics: 节属性
    PIMAGE_SECTION_HEADER AddSection(const char* name, DWORD size, DWORD characteristics);

    // 获取文件缓冲区指针
    BYTE* GetBuffer() { return buffer.data(); }

    // 获取缓冲区大小
    size_t GetSize() { return buffer.size(); }

    // RVA 转 文件偏移
    DWORD RvaToOffset(DWORD rva);

    // 文件偏移 转 RVA
    DWORD OffsetToRva(DWORD offset);

    // 获取 NT 头
    PIMAGE_NT_HEADERS64 GetNtHeaders();

    // 获取 DOS 头
    PIMAGE_DOS_HEADER GetDosHeader();

    // 对齐辅助函数
    static DWORD Align(DWORD value, DWORD alignment);

private:
    std::vector<BYTE> buffer;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeaders; // 明确使用 64 位头
    PIMAGE_SECTION_HEADER pSectionHeaders;
    bool isLoaded;

    // 重新解析指针
    void ParseHeaders();
};

#endif // PEHELPER_H
