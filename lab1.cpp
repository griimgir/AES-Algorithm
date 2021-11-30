/*
Alberc Ej Salcedo 
Network Security Class
Lab 01
*/

/*
**********Recources used*************
https://en.wikipedia.org/wiki/Rijndael_S-box
https://cryptography.fandom.com/wiki/Rijndael_key_schedule
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#/media/File:AES_(Rijndael)_Round_Function.png
https://en.wikipedia.org/wiki/Lookup_table
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
*/

#include <iostream>
#include <cstring> //keeps character data in a CStringData object
#include <sstream> //allows a string object to be treated as a stream
#include <fstream> //this is used to open files to write.

/*
these headers are important as it contains the lookup tables and the key expansions. 
this is how I will be able to manipulate the 128 bit block. The headers are
the encryption is using Rijndael S-box
*/
#include "tables.h" 
#include "keyExpansions.h"

using namespace std;

/************************************************************************************************************************/
/*                                               Encryption setup                                                       */
/************************************************************************************************************************/

// first step in the round, it simply recieves the plain text message
string PlaintText(){
    string input;
    getline (cin, input);
    return input;
}

//initialize round where it xor
void addRoundKey(unsigned char * block, unsigned char * roundKey){
    for(int i = 0; i < 16; i++){
        block[i] ^= roundKey[i];
    }
}

//substitution step
void subBytes(unsigned char * block){
    for(int i = 0; i < 16; i++){
		block[i] = s[block[i]];
	}
}

// Permutation step starts shifts row left and adds diffusion
void shiftRow(unsigned char * block){
	unsigned char temp[16];

	//column 1
	temp[0] = block[0];
	temp[1] = block[5];
	temp[2] = block[10];
	temp[3] = block[15];
	
	//column 2
	temp[4] = block[4];
	temp[5] = block[9];
	temp[6] = block[14];
	temp[7] = block[3];

	//column 3
	temp[8] = block[8];
	temp[9] = block[13];
	temp[10] = block[2];
	temp[11] = block[7];
	
	//coulmun 4
	temp[12] = block[12];
	temp[13] = block[1];
	temp[14] = block[6];
	temp[15] = block[11];

	for(int i = 0; i < 16; i++){
		block[i] = temp[i];
	}
}

void mixColumn(unsigned char * block){
	unsigned char temp[16];

	temp[0] = (unsigned char) mul2[block[0]] ^ mul3[block[1]] ^ block[2] ^ block[3];
	temp[1] = (unsigned char) block[0] ^ mul2[block[1]] ^ mul3[block[2]] ^ block[3];
	temp[2] = (unsigned char) block[0] ^ block[1] ^ mul2[block[2]] ^ mul3[block[3]];
	temp[3] = (unsigned char) mul3[block[0]] ^ block[1] ^ block[2] ^ mul2[block[3]];

	temp[4] = (unsigned char)mul2[block[4]] ^ mul3[block[5]] ^ block[6] ^ block[7];
	temp[5] = (unsigned char)block[4] ^ mul2[block[5]] ^ mul3[block[6]] ^ block[7];
	temp[6] = (unsigned char)block[4] ^ block[5] ^ mul2[block[6]] ^ mul3[block[7]];
	temp[7] = (unsigned char)mul3[block[4]] ^ block[5] ^ block[6] ^ mul2[block[7]];

	temp[8] = (unsigned char)mul2[block[8]] ^ mul3[block[9]] ^ block[10] ^ block[11];
	temp[9] = (unsigned char)block[8] ^ mul2[block[9]] ^ mul3[block[10]] ^ block[11];
	temp[10] = (unsigned char)block[8] ^ block[9] ^ mul2[block[10]] ^ mul3[block[11]];
	temp[11] = (unsigned char)mul3[block[8]] ^ block[9] ^ block[10] ^ mul2[block[11]];

	temp[12] = (unsigned char)mul2[block[12]] ^ mul3[block[13]] ^ block[14] ^ block[15];
	temp[13] = (unsigned char)block[12] ^ mul2[block[13]] ^ mul3[block[14]] ^ block[15];
	temp[14] = (unsigned char)block[12] ^ block[13] ^ mul2[block[14]] ^ mul3[block[15]];
	temp[15] = (unsigned char)mul3[block[12]] ^ block[13] ^ block[14] ^ mul2[block[15]];

	for(int i = 0; i < 16; i++){
		block[i] = temp[i];
	}
}

//as stated in documentation steps are
/*
1) plain text
2) xor
3) substitute
4) shift rows
5) mix columns
6) add rounds
steps 4 and 5 are permutation steps
*/
void Round(unsigned char * block, unsigned char * key) {
	subBytes(block); 
	shiftRow(block);
	mixColumn(block);
	addRoundKey(block, key);
}

//last round does not require to mix column 
void lastRound(unsigned char * block, unsigned char * key) {
	subBytes(block);
	shiftRow(block);
	addRoundKey(block, key);
}

//AES algorithm commence
void AESEncryption(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char block[16];
	for(int i = 0; i < 16; i++) {
		block[i] = message[i];
	}

	addRoundKey(block, expandedKey);

    int rounds = 9;
	for(int i = 0; i < rounds; i++) {
		Round(block, expandedKey + ((i+1) * 16));
	}

	lastRound(block, expandedKey + 160);

	// buffers encrypted block
	for(int i = 0; i < 16; i++) {
		encryptedMessage[i] = block[i];
	}
}

/************************************************************************************************************************/
/*                                        End of Encryption setup                                                       */
/************************************************************************************************************************/

/************************************************************************************************************************/
/*                                           Decryption setup                                                           */
/************************************************************************************************************************/

/************************************************************************************************************************/
/*                                        End of Decryption setup                                                       */
/************************************************************************************************************************/

int main(){
    char message[1024];
    cout << "Enter a message: ";
    string input = PlaintText();

    strcpy(message, input.c_str());
    cout << message << endl;

    //pad message to 16bytes
    int newMessage = strlen((const char *)message);
    int paddedMessageLength = newMessage;
    if ((paddedMessageLength % 16) != 0) {
		paddedMessageLength = 16 * (paddedMessageLength / 16 + 1);
	}

    unsigned char * paddedMessage = new unsigned char[paddedMessageLength];
	for (int i = 0; i < paddedMessageLength; i++){
		if (i >= newMessage){
			paddedMessage[i] = 0;
		}
		else {
			paddedMessage[i] = message[i];
		}
	}

    //this is just to grab the key
    string str;
	ifstream infile;
	infile.open("key", ios::in | ios::binary);
	if(infile.is_open()){
		getline(infile, str);
		infile.close();
	}
	else{
        cout << "Error: Cannot open key" << endl;
    }

    //creating hex
	istringstream hex_chars_stream(str);
    //this is for the matrix
	unsigned char key[16];
	int i = 0;
	unsigned int data;
    //reference from https://stackoverflow.com/questions/3221170/how-to-turn-a-hex-string-into-an-unsigned-char-array
	while (hex_chars_stream >> hex >> data){
		key[i] = data;
		i++;
	}

    unsigned char * encrypted = new unsigned char[paddedMessageLength];
    unsigned char expandedKey[176];
    keyExpansion(key, expandedKey);
    for (int i = 0; i < paddedMessageLength; i += 16) {
		AESEncryption(paddedMessage + i, expandedKey, encrypted + i);
	}

    //TODO this is only to view hex
    cout << "Encrypted message in hex:" << endl;
	for (int i = 0; i < paddedMessageLength; i++) {
		cout << hex << (int) encrypted[i];
		cout << " ";
	} cout << endl;

    // Write the encrypted string out to file "message.aes"
	ofstream outfile;
	outfile.open("message.aes", ios::out | ios::binary);
	if (outfile.is_open())
	{
		outfile << encrypted;
		outfile.close();
		cout << "Wrote encrypted message to file message.aes" << endl;
	}

	else cout << "Unable to open file";

/************************************************************************************************************************/
/*                                                 Decryption                                                           */
/************************************************************************************************************************/



    // Free memory
	delete[] paddedMessage;
	delete[] encrypted;

    return 0;
}