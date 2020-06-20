//
// Created by Aaron Kampmeier on 6/15/20.
// Copyright © 2020 Aaron Kampmeier. All rights reserved.
// ASU ID: 1217750807
// For Class: CSE 240 with Prof. Selgrad
//

#define FILE_ERROR_EXIT 1
#define FILE_OUT_ERROR_EXIT 2
#define UNKNOWN_OPERATION_EXIT 3

// Defines how long a block should be when using BLOCKED CipherStyle
#define BLOCK_CIPHER_LENGTH 5
// Defines how many blocks are on a line when using BLOCKED
#define BLOCK_CIPHER_LINE_GROUPS 6

// For Profiling
#define PROFILING 1

#include <iostream>
#include <cstring>

using namespace std;

/**
 * Switches this program's function between enciphering and deciphering.
 * There are a few different styles for enciphering:
 * - Punctuated: Follows all original punctuation marks, only letters are enciphered.
 * - Blocked: Removes all punctuation including whitespace, letters are blocked into groups making it decently harder
 * 		to break.
 */
enum CipherOperation {ENCIPHER_PUNCTUATED, ENCIPHER_BLOCKED, DECIPHER, UNDEFINED};


bool cipher(CipherOperation operation, char *key, char *inputFile, char *outputFile);
CipherOperation convertStrToOp(const char *strOp);

#if PROFILING
void profileCipher();
#endif

/**
 * Program that en/deciphers text using a Vigenère cipher algorithm. A vigenère cipher is a poly-alphabetic cipher in
 * that we loop through the key for each character we en/decipher making it significantly more complicated to break
 * than a traditional Caesar shift.
 *
 * Takes in command line arguments, will prompt for console input if non-existent:
 * - Structure: cipher [operation [key [inFile [outFile]]]]
 * - Options:
 * 	- Operation: encipher-blocked, encipher-punctuated, decipher
 * 	- Key: Cipher key
 * 	- inFile: Input file path
 * 	- outFile: Output file path
 *
 *
 * @return Exit code
 */
int main(int argc, char** argv) {
#if PROFILING
	profileCipher();
	return 0;
#endif
	
	CipherOperation operation = UNDEFINED;
	char* inFileName = nullptr;
	char* outFileName = nullptr;
	char* key = nullptr;
	
	
	// Check each command line argument, one by one
	for(int argi = 1; argi < argc; argi++) {
		// Check this argument against our known arguments
		char* arg = argv[argi];
		switch (argi) {
			case 1:
				// Operation
				operation = convertStrToOp(arg);
				break;
			case 2:
				//Key
				key = arg;
				break;
			case 3:
				// In file
				inFileName = arg;
				break;
			case 4:
				// Out file
				outFileName = arg;
				break;
			default:
				cerr << "Unknown input at index " << argi << endl;
				break;
		}
	}
	
	// For each non-initialized variable, ask for input. If input needs to go longer than the specified sizes, you
	// must use command line args for the input
	if (operation == UNDEFINED) {
		cout << "Enter the cipher operation (encipher-blocked, encipher-punctuated, decipher): " << endl;
		char inputOprString[30];
		cin.getline(inputOprString, sizeof(inputOprString));
		operation = convertStrToOp(inputOprString);
	}
	
	if (key == nullptr) {
		cout << "Enter the cipher key: " << endl;
		key = new char[30];
		cin.getline(key, 30);
	}
	
	if (inFileName == nullptr) {
		cout << "Enter the input file path (based on working dir): " << endl;
		inFileName = new char[100];
		cin.getline(inFileName, 100);
	}
	
	if (outFileName == nullptr) {
		cout << "Enter the output file path (based on working dir): " << endl;
		outFileName = new char[100];
		cin.getline(outFileName, 100);
	}
	
 
	// Perform the operation
	bool success = cipher(operation, key, inFileName, outFileName);
	
	delete[] key;
	delete[] inFileName;
	delete[] outFileName;
	
	return !success;
}

/**
 * Converts a string to a CipherOperation
 * @param strOp Either "encipher-blocked", "encipher-punctuated", or "decipher"
 * @return The associated CipherOperation or UNDEFINED if failed
 */
CipherOperation convertStrToOp(const char *strOp) {
	if (strcmp("encipher-blocked", strOp) == 0) {
		return ENCIPHER_BLOCKED;
	} else if (strcmp("encipher-punctuated", strOp) == 0) {
		return ENCIPHER_PUNCTUATED;
	} else if (strcmp("decipher", strOp) == 0) {
		return DECIPHER;
	} else {
		// Unknown input
		cerr << "Unknown operation" << endl;
		exit(UNKNOWN_OPERATION_EXIT);
		return UNDEFINED;
	}
}

/**
 * Performs the en/decipher operation writing the output to the specified output file. Enciphering can be done in a
 * few different styles. Deciphering will always decipher letters and leave all non-letters in place.
 * @param operation The operation to perform
 * @param key The key
 * @param inputFile The file to read from
 * @param outputFile The file to write to, will overwrite current file if one exists.
 * @return Successful
 */
bool cipher(CipherOperation operation, char *key, char *inputFile, char *outputFile) {
	// Open the files to work with
	FILE* inFile = fopen(inputFile, "r");
	FILE* outFile = fopen(outputFile, "w");
	
	// Check file opened
	if (inFile == nullptr || outFile == nullptr) {
		cerr << "Error reading file. Please check name." << endl;
		return false;
//		exit(FILE_ERROR_EXIT);
	}
	
	// Set up the file buffer to pull in 4 KB
	char readBuffer[4000];
	// The write buffer will be the same as the read buffer if doing normal PUNCTUATED. BLOCKED needs to use a
	// different one with extra padding.
	char* writeBuffer;
	switch (operation) {
		case DECIPHER:
		case ENCIPHER_PUNCTUATED:
			// Write in place to the same buffer
			writeBuffer = readBuffer;
			break;
		case ENCIPHER_BLOCKED:
			// Use a different buffer to write to in order to add block spacing
			int maxSpaces = sizeof(readBuffer) / BLOCK_CIPHER_LENGTH;
			writeBuffer = new char[sizeof(readBuffer) + maxSpaces];
			break;
	}
	
	int validReadChunks;
	int validWriteChunks;
	int processedBuffers = 0;
	
	// Tracks the index of the block and line we're writing, valid values are
	// 0 up to BLOCK_CIPHER_LINE_GROUPS * BLOCK_CIPHER_LENGTH
	int blockIndex = 0;
	
	// We'll use two itrs to track through the buffer(s), one to track the current reading spot and one to track the
	// current writing spot. They are normally the same except for when we encounter a non-enciphering character. For
	// example, if we encounter a comma, read index goes up to keep reading, but write stays there to write over the
	// comma. If style is BLOCKED, then write index might pass read index in order to add spacing.
	int bufferReadIndex;
	int bufferWriteIndex;
	
	// Set up the key
	const int keySize = strlen(key);
	int keyLetterIndex = 0; // Tracks what letter of the key we are using
	// Make the key all uppercase
	for (int i=0; i < keySize; i++) {
		key[i] = toupper(key[i]);
	}
	
	// Loop through reading the file in buffers, ciphering, and writing it out
	do {
		validReadChunks = fread(readBuffer, sizeof(char), sizeof(readBuffer), inFile); //Returns how much was read
		
		
		//-----Encipher text in buffer------
		
		// Go through each char in the buffer and encipher it
		bufferWriteIndex = 0;
		for (bufferReadIndex = 0; bufferReadIndex < validReadChunks; bufferReadIndex++) {
			//1. Get key letter
			// readCount * sizeof(buffer) gives how many chars we've previously read through
			// bufferReadIndex is where we are in this buffer cycle, so add them together to get the index of the letter we're
			// at in the reading of the whole file
			// modulus all that by keySize to get what keyLetter we should encipher with this time
//			const char keyLetter = key[(readCount * sizeof(buffer) + bufferReadIndex) % keySize];
			const char keyLetter = key[keyLetterIndex];
			
			//2. Find the key letter offset from A (65)
			const short int keyOffset = keyLetter - 65;
			
			//3. If the char is alphanumeric add the key offset to the plain txt char to get the cipher txt char. This
			// comes from the trait that the alphabets in Vigenère ciphers shift by one for each key letter farther
			// from A. So the cipher alphabet for key letter A is the plain alphabet, the cipher alphabet for key B
			// is shifted by one to the left, and the cipher alphabet for Z is shifted 25 to the left i.e. one to the
			// right.
			// Next, normalize 'A' down to 0 and mod by 26 to loop any chars past Z back to the letters and
			// re-convert back to ASCII by adding 65.
			//4. Write cipher txt char back to write buffer
			if (isalpha(readBuffer[bufferReadIndex])) {
				switch (operation) {
					case ENCIPHER_BLOCKED:
					case ENCIPHER_PUNCTUATED:
						writeBuffer[bufferWriteIndex] = (toupper(readBuffer[bufferReadIndex]) + keyOffset - 65) % 26 + 65;
						break;
					case DECIPHER:
						// To decipher, just subtract the key offset from the cipher letter. However since this could
						// yield negative numbers and the mod operator won't loop negative numbers in c++, we'll go
						// around the other way by just adding the complement: (26 - keyOffset)
						// i.e. -keyOffset = (26 - keyOffset) in mod 26
						writeBuffer[bufferWriteIndex] = (toupper(readBuffer[bufferReadIndex]) + (26 - keyOffset) -
								65) % 26 + 65;
						break;
				}
				
				bufferWriteIndex++;
				
				// We used a key letter so move on to the next
				keyLetterIndex = (keyLetterIndex + 1) % keySize;
				
				
				if (operation == ENCIPHER_BLOCKED) {
					blockIndex++;
					
					if (blockIndex / BLOCK_CIPHER_LENGTH == BLOCK_CIPHER_LINE_GROUPS) {
						
						// End the line, we have the right number of groups
						writeBuffer[bufferWriteIndex] = '\n';
						bufferWriteIndex++;
						blockIndex = 0;
					} else if (blockIndex % BLOCK_CIPHER_LENGTH == 0) {
						// Add in a space after every block
						writeBuffer[bufferWriteIndex] = ' ';
						bufferWriteIndex++;
					}
				}
			} else if (operation != ENCIPHER_BLOCKED) {
				// This runs if our character is not alphabetic, so with all styles except BLOCKED, keep it in there
				bufferWriteIndex++;
			}
			
		}
		
		
		//-----Write buffer out to file-----
		validWriteChunks = fwrite(writeBuffer, sizeof(char), bufferWriteIndex, outFile);
		
		// Check that everything wrote successfully
		if (validWriteChunks != bufferWriteIndex * sizeof(char)) {
			cerr << "Error writing to ouput file." << endl;
			return false;
//			exit(FILE_OUT_ERROR_EXIT);
		}
		
		processedBuffers++;
	} while (validReadChunks == sizeof(readBuffer)); //Once valid read chunks is less than the whole buffer, we've
	// reached the end of the file
	
	if (operation == ENCIPHER_BLOCKED) {
		delete[] writeBuffer;
	}
	
	
	fclose(inFile);
	fclose(outFile);
	
	return true;
}

#if PROFILING
void profileCipher() {

}
#endif

