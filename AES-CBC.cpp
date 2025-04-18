/*
Owen Rasor
Learning and developing AES encryption software.
CBC (Cipher Block Chaining) encryption.
XORs with previous block and key to encrypt files - text or binary.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <iomanip>

#define BLOCK_SIZE 16

// xor block previous with next block and the key
unsigned char* xorBlock (unsigned char* block1, unsigned char* block2, unsigned char* key, const size_t& size = BLOCK_SIZE) {
    unsigned char* encrypted_block = new unsigned char[size];

    for (int i = 0; i < size; i++) {
        encrypted_block[i] = block1[i] ^ block2[i] ^ key[i];
    }

    return encrypted_block;
}

// iterate through file contents encrypting each block
unsigned char* encryptData(const std::vector<unsigned char*>& blocks, unsigned char* key, unsigned char* iv, const size_t& size = BLOCK_SIZE) {
    size_t file_size = size * blocks.size();
    unsigned char* encryptedResult = new unsigned char[file_size];
    size_t pos = 0;

    // encrypt first block with initalization vector
    unsigned char* prevEncrypted = xorBlock(blocks[0], iv, key, size);
    std::memcpy(encryptedResult + pos, prevEncrypted, size);
    pos += size;

    // chain the remaining blocks
    for (size_t i = 1; i < blocks.size(); i++) {
        unsigned char* currentEncrypted = xorBlock(blocks[i], prevEncrypted, key, size);
        std::memcpy(encryptedResult + pos, currentEncrypted, size);
        pos += size;

        delete[] prevEncrypted; // free previous block
        prevEncrypted = currentEncrypted;
    }

    delete[] prevEncrypted;
    return encryptedResult;
}

// initialize the first block to allow for encryption of first section of text
unsigned char* randomInitBlock(size_t size = BLOCK_SIZE) {
    unsigned char* initBlock = new unsigned char[size + 1]();
    initBlock[size] = '\0';
     
    char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 51);
    
    for (int i = 0; i < size; i++){
        initBlock[i] = alphabet[dist(gen)];
    }

    return initBlock;
}

// adds unsigned char for to fill block size
void addPKCS7Padding (unsigned char* block, size_t actual_size, size_t block_size = BLOCK_SIZE) {
    unsigned char pad_value = static_cast<unsigned char>(block_size - actual_size);
    for (size_t  i = actual_size; i < block_size; i++) {
        block[i] = pad_value;
    }
}

// removes the padded unsigned chars
size_t removePKCS7Padding (unsigned char* data, size_t total_size, size_t block_size = BLOCK_SIZE) {
    if (total_size == 0) return 0;

    unsigned char pad_value = data[total_size - 1];
    if (pad_value > block_size) return total_size; // invalid padding

    // validate padding
    for (size_t i = 0; i < pad_value; i++) {
        if (data[total_size - 1 - i] != pad_value) {
            return total_size; // invalid padding
        }
    }

    return total_size - pad_value;
}

unsigned char* convertFileToUnsignedChar (const char* input, size_t& out_size) {
    // read file
    std::fstream file(input, std::ios::in | std::ios::binary | std::ios::ate);

    if(!file) {
        std::cerr << "Error opening file: " << input << std::endl;
        out_size = 0;
        return nullptr;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    unsigned char* result = new unsigned char[size];

    if (!file.read(reinterpret_cast<char*>(result), size)) {
        std::cerr << "Error reading file into unsigned char." << std::endl;
        delete[] result;
        out_size = 0;
        return nullptr;
    }

    out_size = static_cast<size_t>(size);
    return result;
}

// make a vector of unsigned char from file
std::vector<unsigned char*> makeBlocks (const unsigned char* input, const size_t& input_size, const size_t& block_size = BLOCK_SIZE) {
    std::vector<unsigned char*> blocks;
    
    for (size_t i = 0; i < input_size; i += block_size) {
        unsigned char* block = new unsigned char[block_size]();

        size_t remaining = input_size - i;
        size_t chunk_size = std::min(block_size, remaining);

        std::memcpy(block, input + i, chunk_size);

        if (chunk_size < block_size) {
            addPKCS7Padding(block, chunk_size, block_size);
        }

        blocks.push_back(block);
    }

    return blocks;
}

void deallocateBlocks(std::vector<unsigned char*>& blocks) {
    for (int i = 0; i < blocks.size(); i++) {
        delete[] blocks[i];
    }
}

// decrypt a unsigned char
unsigned char* decryptData(unsigned char* data, const size_t& data_size, unsigned char* iv, unsigned char* key, size_t& out_size, const size_t& block_size = BLOCK_SIZE) {
    // convert encrypted bytes to vector of blocks
    std::vector<unsigned char*> encryptedBlocks = makeBlocks(data, data_size, block_size);

    // initialize return unsigned char
    size_t file_size = encryptedBlocks.size() * block_size;
    unsigned char* decryptedResult = new unsigned char[file_size];
    size_t pos = 0;

    for (size_t i = 0; i < encryptedBlocks.size(); i++) {
        const unsigned char* prevBlock = (i == 0) ? iv : encryptedBlocks[i - 1];

        for (size_t j = 0; j < block_size; j++) {
            decryptedResult[pos + j] = encryptedBlocks[i][j] ^ prevBlock[j] ^ key[j];
        }

        pos += block_size;
    }

    size_t unpadded_size = removePKCS7Padding(decryptedResult, data_size, block_size);
    out_size = unpadded_size;

    deallocateBlocks(encryptedBlocks);

    return decryptedResult;
}

// makes the output readable as HEX(Base64)
void printHex(std::ostream& os, const unsigned char* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    os << std::dec << '\n'; // restores stream to decimal mode
}

void printOriginal(std::ostream& os, unsigned char* data, size_t size) {
    os.write(reinterpret_cast<char*>(data), size);
    os << std::flush;
}

void printDecrypted(std::ostream& os, unsigned char* data, size_t size) {
    os.write(reinterpret_cast<char*>(data), size);
    os << std::flush; 
}

int main (int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Missing file input." << std::endl;
        return -1;
    }

    // get password
    std::string password;
    std::cout << "Enter password: ";
    std::cin >> password;

    // convert password
    unsigned char key[BLOCK_SIZE] = {};
    std::memcpy(key, password.c_str(), std::min(password.size(), static_cast<size_t>(BLOCK_SIZE)));

    unsigned char* initialization_vector = randomInitBlock(BLOCK_SIZE);

    // make file data
    size_t data_size = 0;
    unsigned char* data = convertFileToUnsignedChar(argv[1], data_size);

    // print data befor decryption
    std::cout << "Orignal Data:" << std::endl;
    printOriginal(std::cout, data, data_size);
    std::cout << std::endl << std::endl;

    // make data blocks
    std::vector<unsigned char*> blocks;
    blocks = makeBlocks(data, data_size, BLOCK_SIZE);

    // encrypt data
    size_t file_size = blocks.size() * BLOCK_SIZE;
    unsigned char* encrypted_data = encryptData(blocks, key, initialization_vector, BLOCK_SIZE);

    //print the data encrypted as hex
    std::cout << "Encrypted Data:" << std::endl;
    printHex(std::cout, encrypted_data, file_size);
    std::cout << std::endl;

    // decrypt data
    size_t decrypted_size = 0;
    unsigned char* decrypted_data = decryptData(encrypted_data, data_size, initialization_vector, key, decrypted_size, BLOCK_SIZE);

    // print decrypted data
    std::cout << "Decrypted Data:" << std::endl;
    printDecrypted(std::cout, decrypted_data, decrypted_size);
    std::cout << std::endl;

    // cleanup
    delete[] encrypted_data;
    delete[] initialization_vector;
    delete[] decrypted_data;
    deallocateBlocks(blocks);

    return 0;
}