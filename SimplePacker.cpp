#include <iostream>
#include <string>
#include <windows.h>
#include "Packer.h"

void PrintUsage() {
    std::cout << "简单的 PE 加壳工具 (x64)" << std::endl;
    std::cout << "用法:" << std::endl;
    std::cout << "  SimplePacker.exe pack <input.exe> <output.exe>" << std::endl;
    std::cout << "  SimplePacker.exe unpack <packed.exe> <output.exe>" << std::endl;
}

int main(int argc, char* argv[]) {
    //SetConsoleOutputCP(65001); // 设置控制台输出编码为 UTF-8
    if (argc != 4) {
        PrintUsage();
        return 1;
    }

    std::string mode = argv[1];
    std::string inputPath = argv[2];
    std::string outputPath = argv[3];

    Packer packer;

    if (mode == "pack") {
        std::cout << "开始加壳: " << inputPath << " -> " << outputPath << std::endl;
        if (packer.Pack(inputPath, outputPath)) {
            std::cout << "加壳成功！" << std::endl;
        }
        else {
            std::cerr << "加壳失败！" << std::endl;
            return 1;
        }
    }
    else if (mode == "unpack") {
        std::cout << "开始脱壳: " << inputPath << " -> " << outputPath << std::endl;
        if (packer.Unpack(inputPath, outputPath)) {
            std::cout << "脱壳成功！" << std::endl;
        }
        else {
            std::cerr << "脱壳失败！" << std::endl;
            return 1;
        }
    }
    else {
        PrintUsage();
        return 1;
    }

    return 0;
}
