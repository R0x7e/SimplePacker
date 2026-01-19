#ifndef PACKER_H
#define PACKER_H

#include <string>
#include <vector>
#include <windows.h>

class Packer {
public:
    Packer();
    ~Packer();

    // 加壳函数
    // inputPath: 输入文件路径
    // outputPath: 输出文件路径
    bool Pack(const std::string& inputPath, const std::string& outputPath);

    // 脱壳函数
    // inputPath: 加壳后的文件路径
    // outputPath: 还原后的文件路径
    bool Unpack(const std::string& inputPath, const std::string& outputPath);

private:
    // 简单的异或加密/解密
    void XorData(unsigned char* data, size_t size, unsigned char key);
};

#endif // PACKER_H
