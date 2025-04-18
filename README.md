# AES_encryption
building C++ apps for encryption softwares

# AES-CBC
AES-CBC uses block chaining to encrypt data.
This is a CLI application implementation.

Plan on adding front-end in the future

How it works:
    - Upon launching the application the user is instructed to enter a password. This password is used as the key to encrypt the data.
    - The standard block size is 16 bytes. The program divides the data into 16 byte blocks.
        - If the final block size is not 16 bytes, the program pads that block using PKCS#7.
        PKCS#7:
            - uses the value of the remaining bytes needed to fill the block, and pads the rest of the block with that value.
            - this allows for easy removal of the padding when decrypting the data.

    Encryption:
        - A random block is initialized. This block will XOR with the first block of data and the key to encrypt.
        - The data is then traversed one block at a time XOR-ing itself with the previous block and the password entered.

    Decryption:
        - The data is decrpyted in the same manner. The blocks XORs with the key and the previous block until all data is decrypted.

Running the application:
    Prequisites:
        - A C++17-compatible compiler (e.g., g++, clang++, MSVC)
        - A terminal or command prompt to run the compiled program
        - Source files compiled into an executable (e.g., g++ main.cpp -o AES_CBC -std=c++17)

    Input Requirements:
        - The input file should be a plain text or binary file
        - You will need to provide:
            - A password (used to generate the AES key)
            - An IV (Initialization Vector) during decryption (shown during encryption)

    Launching:
        - Open the terminal
        - Navigate to the directory where the compiled program exists
            - AES_CBC.exe provided in repo
        - Run the application
            - ./AES_CBC
        - Choose an option:
            1 - Encrypt a file
            2 - Decrypt a file
            0 - Exit

    Encryption Flow:
        - To encrypt a file, enter "1" when prompted in the option menu
        - You will be prompted to enter a password
        - a random IV will be generated and displayed - ** SAVE FOR DECRYPTION **
        - Enter the filename to encrypt
        - The encrypted output will be saved as {filename}_encrypted.txt (in raw binary format)
    
    Decryption Flow:
        - To decrypt a file, enter "2" when prompted in the option menu
        - You will provide the encrypted file, password, and IV shown during encryption
        - If all values are correct, the file will be decrypted and saved as {filename}_decrypted.txt