//
// Created by Aaron Kampmeier on 6/15/20.
// Copyright © 2020 Aaron Kampmeier. All rights reserved.
// ASU ID: 1217750807
// For Class: CSE 240 with Prof. Selgrad
//

#define FILE_ERROR_EXIT 1
#define FILE_OUT_ERROR_EXIT 2

// Defines how long a block should be when using BLOCKED CipherStyle
#define BLOCK_CIPHER_LENGTH 5
// Defines how many blocks are on a line when using BLOCKED
#define BLOCK_CIPHER_LINE_GROUPS 6

#include <iostream>
#include <cstdio>
#include <cstring>

using namespace std;

/**
 * The different styles for enciphering.
 * Punctuated: Follows all original punctuation marks, only letters are enciphered.
 * Blocked: Removes all punctuation including spaces, letters are blocked into groups making it harder to break.
 */
enum CipherStyle {PUNCTUATED, BLOCKED};

/**
 * Switches this program's function.
 */
enum CipherOperation {ENCIPHER, DECIPHER};

bool cipher(CipherOperation operation, CipherStyle cipherStyle, char *key, char *inputFile, char *outputFile);

/**
 * Program that en/deciphers text using a Vigenère cipher algorithm. A vigenère cipher is a poly-alphabetic cipher in
 * that we loop through the key for each character we en/decipher making it significantly more complicated to break
 * than a traditional Caesar shift.
 *
 * Enciphering can be done in a few different styles specified by CipherStyle. Deciphering will always decipher
 * letters and leave all non-letters in place.
 *
 * @return Exit code
 */
int main(int argc, char** argv) {
	// User inputted data
	CipherOperation operation = ENCIPHER;
	CipherStyle cipherStyle = BLOCKED;
	char inFileName[] = "../War and Peace.txt";
	char outFileName[] = "../War and Peace Enciphered.txt";
	char key[] = "python";
	
	cipher(operation, cipherStyle, key, inFileName, outFileName);
	
	return 0;
}

/**
 * Performs the en/decipher operation
 * @param operation
 * @param cipherStyle
 * @param key
 * @param inputFile
 * @param outputFile
 * @return
 */
bool cipher(CipherOperation operation, CipherStyle cipherStyle, char *key, char *inputFile, char *outputFile) {
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
	switch (cipherStyle) {
		case PUNCTUATED:
			// Write in place to the same buffer
			writeBuffer = readBuffer;
			break;
		case BLOCKED:
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
				writeBuffer[bufferWriteIndex] = (toupper(readBuffer[bufferReadIndex]) + keyOffset - 65) % 26 + 65;
				
				// We used a key letter so move on to the next
				keyLetterIndex = (keyLetterIndex + 1) % keySize;
				
				bufferWriteIndex++;
//				lineIndex++;
				
				if (cipherStyle == BLOCKED) {
					blockIndex++;
					
//					if (lineIndex > 35) {
//						cout << "hmm" << endl;
//					}
					
					if (blockIndex / BLOCK_CIPHER_LENGTH == BLOCK_CIPHER_LINE_GROUPS) {
//						cout << lineIndex << endl;
						
						// End the line, we have the right number of groups
						writeBuffer[bufferWriteIndex] = '\n';
//						lineIndex = 0;
						bufferWriteIndex++;
						blockIndex = 0;
					} else if (blockIndex % BLOCK_CIPHER_LENGTH == 0) {
						// Add in a space after every block
						writeBuffer[bufferWriteIndex] = ' ';
						bufferWriteIndex++;
//						lineIndex++;
					}
				}
			} else if (cipherStyle == PUNCTUATED) {
				// A punctuation char and PUNCTUATED cipherStyle, so keep it in there
				bufferWriteIndex++;
			}
			
		}
		
		
		//-----Write buffer out to file-----
		validWriteChunks = fwrite(writeBuffer, sizeof(char), bufferWriteIndex, outFile);
		
		// Check that everything wrote successfully
		if (validWriteChunks != bufferWriteIndex * sizeof(char)) {
			cerr << "Error writing to enciphered file." << endl;
			return false;
		}
		
		processedBuffers++;
	} while (validReadChunks == sizeof(readBuffer)); //Once valid read chunks is less than the whole buffer, we've
	// reached the end of the file
	
	if (cipherStyle == BLOCKED) {
		delete[] writeBuffer;
	}
	
	
	fclose(inFile);
	fclose(outFile);
	
	return true;
}


