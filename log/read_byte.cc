#include <iostream>
#include <fstream>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: read_byte path/to/file_to_read\n";
        std::cout << "This is used to open and read a file in hex form\n";
        exit(1);
    }
    std::ifstream file1(argv[1], std::ios::binary);
    if (!file1) {
        std::cerr << "Error opening file: " << argv[1] << std::endl;
        return 1;
    }
    file1.seekg(0, std::ios::end);
    std::streampos fileSize = file1.tellg();
    std::cout << "File size: " << fileSize << " bytes" << "\n";
    file1.close();
    
    std::ifstream file2(argv[1], std::ios::binary);      
    char byte;
    while (file2.get(byte)) {
        // Process each byte
        unsigned char ub = (unsigned char)byte;
        std::cout << (ub < 16? "  0": "  ") << std::hex << (int)ub;
    }
    

    file2.close();
    return 0;
}
