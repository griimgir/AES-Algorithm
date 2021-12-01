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

    //column 1
	temp[0] = (unsigned char) lt2[block[0]] ^ lt3[block[1]] ^ block[2] ^ block[3];
	temp[1] = (unsigned char) block[0] ^ lt2[block[1]] ^ lt3[block[2]] ^ block[3];
	temp[2] = (unsigned char) block[0] ^ block[1] ^ lt2[block[2]] ^ lt3[block[3]];
	temp[3] = (unsigned char) lt3[block[0]] ^ block[1] ^ block[2] ^ lt2[block[3]];

    //column 2
	temp[4] = (unsigned char)lt2[block[4]] ^ lt3[block[5]] ^ block[6] ^ block[7];
	temp[5] = (unsigned char)block[4] ^ lt2[block[5]] ^ lt3[block[6]] ^ block[7];
	temp[6] = (unsigned char)block[4] ^ block[5] ^ lt2[block[6]] ^ lt3[block[7]];
	temp[7] = (unsigned char)lt3[block[4]] ^ block[5] ^ block[6] ^ lt2[block[7]];

    //column 3
	temp[8] = (unsigned char)lt2[block[8]] ^ lt3[block[9]] ^ block[10] ^ block[11];
	temp[9] = (unsigned char)block[8] ^ lt2[block[9]] ^ lt3[block[10]] ^ block[11];
	temp[10] = (unsigned char)block[8] ^ block[9] ^ lt2[block[10]] ^ lt3[block[11]];
	temp[11] = (unsigned char)lt3[block[8]] ^ block[9] ^ block[10] ^ lt2[block[11]];

    //column 4
	temp[12] = (unsigned char)lt2[block[12]] ^ lt3[block[13]] ^ block[14] ^ block[15];
	temp[13] = (unsigned char)block[12] ^ lt2[block[13]] ^ lt3[block[14]] ^ block[15];
	temp[14] = (unsigned char)block[12] ^ block[13] ^ lt2[block[14]] ^ lt3[block[15]];
	temp[15] = (unsigned char)lt3[block[12]] ^ block[13] ^ block[14] ^ lt2[block[15]];

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
void AESEncryption(unsigned char * message, unsigned char * expandedKey, unsigned char * encrypted) {
	unsigned char block[16];
	for(int i = 0; i < 16; i++) {
		block[i] = message[i];
	}   addRoundKey(block, expandedKey);

    int rounds = 9;
	for(int i = 0; i < rounds; i++) {
		Round(block, expandedKey + ((i+1) * 16));
	}   lastRound(block, expandedKey + 160);

	//buffers encrypted block
	for(int i = 0; i < 16; i++) {
		encrypted[i] = block[i];
	}
}

/************************************************************************************************************************/
/*                                        End of Encryption setup                                                       */
/************************************************************************************************************************/

/************************************************************************************************************************/
/*                                           Decryption setup                                                           */
/************************************************************************************************************************/

void addRoundKey_de(unsigned char * block, unsigned char * roundKey){
	for (int i = 0; i < 16; i++) {
		block[i] ^= roundKey[i];
	}
}

//unmix the columns from encryption
void inverseMixColumns(unsigned char * block){
	unsigned char temp[16];

    //column 1
	temp[0] = (unsigned char)lt14[block[0]] ^ lt11[block[1]] ^ lt13[block[2]] ^ lt9[block[3]];
	temp[1] = (unsigned char)lt9[block[0]] ^ lt14[block[1]] ^ lt11[block[2]] ^ lt13[block[3]];
	temp[2] = (unsigned char)lt13[block[0]] ^ lt9[block[1]] ^ lt14[block[2]] ^ lt11[block[3]];
	temp[3] = (unsigned char)lt11[block[0]] ^ lt13[block[1]] ^ lt9[block[2]] ^ lt14[block[3]];
	
    //column 2
    temp[4] = (unsigned char)lt14[block[4]] ^ lt11[block[5]] ^ lt13[block[6]] ^ lt9[block[7]];
	temp[5] = (unsigned char)lt9[block[4]] ^ lt14[block[5]] ^ lt11[block[6]] ^ lt13[block[7]];
	temp[6] = (unsigned char)lt13[block[4]] ^ lt9[block[5]] ^ lt14[block[6]] ^ lt11[block[7]];
	temp[7] = (unsigned char)lt11[block[4]] ^ lt13[block[5]] ^ lt9[block[6]] ^ lt14[block[7]];

    //column 3
    temp[8] = (unsigned char)lt14[block[8]] ^ lt11[block[9]] ^ lt13[block[10]] ^ lt9[block[11]];
	temp[9] = (unsigned char)lt9[block[8]] ^ lt14[block[9]] ^ lt11[block[10]] ^ lt13[block[11]];
	temp[10] = (unsigned char)lt13[block[8]] ^ lt9[block[9]] ^ lt14[block[10]] ^ lt11[block[11]];
	temp[11] = (unsigned char)lt11[block[8]] ^ lt13[block[9]] ^ lt9[block[10]] ^ lt14[block[11]];
	
    //column 4
    temp[12] = (unsigned char)lt14[block[12]] ^ lt11[block[13]] ^ lt13[block[14]] ^ lt9[block[15]];
	temp[13] = (unsigned char)lt9[block[12]] ^ lt14[block[13]] ^ lt11[block[14]] ^ lt13[block[15]];
	temp[14] = (unsigned char)lt13[block[12]] ^ lt9[block[13]] ^ lt14[block[14]] ^ lt11[block[15]];
	temp[15] = (unsigned char)lt11[block[12]] ^ lt13[block[13]] ^ lt9[block[14]] ^ lt14[block[15]];

	for (int i = 0; i < 16; i++) {
		block[i] = temp[i];
	}
}

//undo the permutation step starts shifts row to the right
void shiftRow_de(unsigned char * block){
	unsigned char temp[16];

	//column 1
	temp[0] = block[0];
	temp[1] = block[13];
	temp[2] = block[10];
	temp[3] = block[7];

	//column 2
	temp[4] = block[4];
	temp[5] = block[1];
	temp[6] = block[14];
	temp[7] = block[11];

	//column 3
	temp[8] = block[8];
	temp[9] = block[5];
	temp[10] = block[2];
	temp[11] = block[15];

	//column 4
	temp[12] = block[12];
	temp[13] = block[9];
	temp[14] = block[6];
	temp[15] = block[3];

	for (int i = 0; i < 16; i++){
		block[i] = temp[i];
	}
}

//same as subbytes but for decryption we are now using the inverse s-box
void subBytes_de(unsigned char * block){
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		block[i] = inv_s[block[i]];
	}
}

//all this does is reverse the encryption
void de_round(unsigned char * block, unsigned char * key){
	addRoundKey_de(block, key);
	inverseMixColumns(block);
	shiftRow_de(block);
	subBytes_de(block);
}

void lastRound_de(unsigned char * block, unsigned char * key){
	addRoundKey_de(block, key);
	shiftRow_de(block);
	subBytes_de(block);
}

void AESDecrypt(unsigned char * encrypted, unsigned char * expandedKey, unsigned char * decrypted){
	unsigned char block[16]; 
	for (int i = 0; i < 16; i++) {
		block[i] = encrypted[i];
	}   lastRound_de(block, expandedKey+160);

	for (int i = 8; i >= 0; i--) {
		de_round(block, expandedKey + ((i + 1) * 16));
	}   addRoundKey_de(block, expandedKey);

	//buffers decrypted block
	for (int i = 0; i < 16; i++) {
		decrypted[i] = block[i];
	}
}

/************************************************************************************************************************/
/*                                        End of Decryption setup                                                       */
/************************************************************************************************************************/

int main(){
    char message[1024];
    cout << "Enter a message: ";
    string input = PlaintText();

    strcpy(message, input.c_str());
    cout << "Message you wrote down: ";
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

    cout << "The key we will use: ";
    cout << str << endl;

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
    cout << endl;
    cout << "----The message is now enrypted!----" << endl;

    //TODO this is only to view hex
    cout << "Message in hex: ";
	for (int i = 0; i < paddedMessageLength; i++) {
		cout << hex << (int) encrypted[i];
		cout << " ";
	} cout << endl;

    cout << "Encrypted message: ";
    cout << encrypted << endl;
    cout << endl;cout << endl;

    // cout << encrypted << endl;

/************************************************************************************************************************/
/*                                                 Decryption                                                           */
/************************************************************************************************************************/
    
    cout << "Decrypting message" << endl;

    int msgLength = strlen((const char *)encrypted);
    unsigned char * decrypt = new unsigned char[msgLength];

    cout << "dycrypting: ";
    cout << decrypt << endl;
    // cout << "Message length: ";
    // cout << msgLength << endl;

    for (int i = 0; i < msgLength; i += 16) {
		AESDecrypt(encrypted + i, expandedKey, decrypt + i);
	}

    cout << "Decrypted message: ";
    for (int i = 0; i < msgLength; i++) {
		cout << decrypt[i];
	}   cout << endl;


    // Free memory
	delete[] paddedMessage;
	delete[] encrypted;

    return 0;
}