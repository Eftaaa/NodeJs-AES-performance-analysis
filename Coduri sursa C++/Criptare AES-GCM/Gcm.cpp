
#include "Gcm.h"

using namespace std;



/*Let n and u denote the unique pair of positive integers such that the total number of bits in the
plaintext is (n − 1)128 + u, where 1 ≤ u ≤ 128. The plaintext consists of a sequence of n bit
strings, in which the bit length of the last bit string is u, and the bit length of the other bit strings
is 128.*/

int n = 0; // Number of 128-bit lines
int u = 0; // Number of bits in the last line



/* m and v denote the unique pair of positive integers such that the
total number of bits in A is (m − 1)128 + v and 1 ≤ v ≤ 128. */
int m = 0;
int v = 0;




void xor_bytes(uint8_t* a, const uint8_t* b, int len = 16) {
	for (int i = 0; i < len; ++i) {
		a[i] ^= b[i];
	}
}

void shift_right(uint8_t* a) {
	uint8_t carry = 0;
	for (int i = 0; i <= 15; ++i) {
		uint8_t next_carry = a[i] & 1;
		a[i] >>= 1;
		if (carry) {
			a[i] |= 0x80;
		}
		carry = next_carry;
	}
}

void multiply_GF128(uint8_t* a, const uint8_t* b) {
	uint8_t result[16] = { 0 };
	uint8_t a_copy[16];
	std::memcpy(a_copy, a, 16);

	for (int i = 0; i < 128; ++i) {
		// Verificare daca bit-ul b este setat
		if (b[i / 8] & (1 << (7 - (i % 8)))) {
			xor_bytes(result, a_copy);
		}
		// Shiftare a_copy la dreapta
		uint8_t msb = a_copy[15] & 1; // Salvare MSB inainte de shiftare

		shift_right(a_copy);
		// Daca MSB (Most Significant Bit) este 1, se face XOR cu reducerea polinomiala
		if (msb) {
			a_copy[0] ^= 0xE1; // Reducerea polinimiala in spatiul GF(2^128) pentru GCM
		}
	}
	std::memcpy(a, result, 16);
}


std::vector<std::vector<uint8_t>> ghash(const uint8_t* H, const std::vector<std::vector<uint8_t>>& A, int m, int v, const std::vector<std::vector<uint8_t>>& C, int n, int u)
{
	std::vector<std::vector<uint8_t>> X;
	X.reserve(m + n + 2);
	long long int lenA;
	long long int lenC;
	if (m == 0)
	{
		lenA = 0;
	}
	else
	{
		lenA = ((long long int)(m - 1)) * 128 + v;
	}
	if (n == 0)
	{
		lenC = 0;
	}
	else
	{
		lenC = ((long long int)(n - 1)) * 128 + u;
	}

	uint8_t divLenA[8];
	uint8_t divLenC[8];

	for (int i = 0; i < 8; ++i)
	{
		divLenA[i] = (lenA >> 8 * (7 - i)) & 0xFF;
		divLenC[i] = (lenC >> 8 * (7 - i)) & 0xFF;
	}

	X.push_back(std::vector<uint8_t>(16, 0x00));
	for (int i = 1; i <= m + n + 1; ++i)
	{
		X.push_back(std::vector<uint8_t>());
		if ((i >= 1) && (i <= m - 1) && (m != 0))
		{
			for (int j = 0; j < 16; ++j)
			{
				X[i].push_back(X[i - 1][j] ^ A[i - 1][j]);
			}
			multiply_GF128(X[i].data(), H);
		}
		if ((i == m) && (m != 0))
		{
			for (int j = 0; j < v / 8; ++j)
			{
				X[i].push_back(X[m - 1][j] ^ (A[m - 1][j]));
			}
			for (int j = v / 8; j < 16; ++j)
			{
				X[i].push_back(X[m - 1][j] ^ (0x00));
			}
			multiply_GF128(X[i].data(), H);
		}
		if ((i > m) && (i <= m + n - 1))
		{
			for (int j = 0; j < 16; ++j)
			{
				X[i].push_back(X[i - 1][j] ^ C[i - (m + 1)][j]);
			}
			multiply_GF128(X[i].data(), H);
		}

		if (i == (m + n))
		{
			for (int j = 0; j < u / 8; ++j)
			{

				X[i].push_back(X[m + n - 1][j] ^ C[n - 1][j]);
			}
			for (int j = u / 8; j < 16; ++j)
			{
				X[i].push_back(X[m + n - 1][j] ^ 0x00);
			}
			multiply_GF128(X[i].data(), H);
		}
		if (i == (m + n + 1))
		{
			if (m != 0) {
				for (int j = 0; j < 8; ++j)
				{
					X[i].push_back((X[m + n][j] ^ (divLenA[j])));
				}
			}
			else
			{
				for (int j = 0; j < 8; ++j)
				{
					X[i].push_back((X[m + n][j] ^ 0x00));
				}
			}
			if (n != 0)
			{
				for (int j = 8; j < 16; ++j)
				{
					X[i].push_back((X[m + n][j] ^ (divLenC[j - 8])));
				}
			}
			else
			{
				for (int j = 8; j < 16; ++j)
				{
					X[i].push_back((X[m + n][j] ^ 0x00));
				}
			}
			multiply_GF128(X[i].data(), H);

		}
	}
	return X;
}


std::vector<uint8_t> ghash(const uint8_t* H, const std::vector<std::vector<uint8_t>>& A, int m, int v, const std::vector<uint8_t>& C, int n, int u)
{
	std::vector<std::vector<uint8_t>> X;
	X.reserve(m + n + 2);
	long long int lenA;
	long long int lenC;
	if (m == 0)
	{
		lenA = 0;

	}
	else
	{
		lenA = ((long long int)(m - 1)) * 128 + v;
	}
	if (n == 0)
	{
		lenC = 0;
	}
	else
	{
		lenC = ((long long int)(n - 1)) * 128 + u;
	}

	uint8_t divLenA[8];
	uint8_t divLenC[8];

	for (int i = 0; i < 8; ++i)
	{
		divLenA[i] = (lenA >> 8 * (7 - i)) & 0xFF;
		divLenC[i] = (lenC >> 8 * (7 - i)) & 0xFF;
	}
	// InitializareX[0]
	X.push_back(std::vector<uint8_t>(16, 0x00));

	// Procesare variabila A
	for (int i = 1; i <= m; ++i)
	{
		X.push_back(std::vector<uint8_t>(16, 0x00));
		if (i == m && v % 128 != 0) {
			for (int j = 0; j < v / 8; ++j) {
				X[i][j] = X[i - 1][j] ^ A[i - 1][j];
			}
		}
		else {
			for (int j = 0; j < v / 8; ++j) {
				X[i][j] = X[i - 1][j] ^ A[i - 1][j];
			}
		}
		multiply_GF128(X[i].data(), H);
	}

	// Procesare varianbila C
	for (int i = 1; i <= n; ++i)
	{
		X.push_back(std::vector<uint8_t>(16, 0x00));
		int idxC = (i - 1) * 16;
		for (int j = 0; j < 16; ++j) {
			if (idxC + j < C.size()) {
				X[m + i][j] = X[m + i - 1][j] ^ C[idxC + j];
			}
			else {
				X[m + i][j] = X[m + i - 1][j];
			}
		}
		multiply_GF128(X[m + i].data(), H);
	}

	// Procesare bloc cu lungimi
	X.push_back(std::vector<uint8_t>(16, 0x00));
	for (int j = 0; j < 8; ++j) {
		X[m + n + 1][j] = X[m + n][j] ^ divLenA[j];
	}
	for (int j = 8; j < 16; ++j) {
		X[m + n + 1][j] = X[m + n][j] ^ divLenC[j - 8];
	}
	multiply_GF128(X[m + n + 1].data(), H);
	return X.back();
}
vector<uint8_t> incr(const vector<uint8_t> ina) {

	vector<uint8_t> result;
	for (int i = 0; i < ina.size(); ++i)
	{
		result.push_back(ina[i]);
	}
	//Incrementeaza ultimii 32 de biti ai vecorului
	uint32_t value = 0;
	for (int i = 12; i < 16; ++i)
	{
		value = (value << 8) + ina[i];

	}
	value = (value + 1) % UINT32_MAX; // increment modulo 2^32
	for (int i = 12; i < 16; ++i)
	{
		result[i] = ((value >> 8 * (15 - i)) & 0xFF);

	}
	return result;
}




void GCMCRypt(string& inputFile, string& keyFile, string& AAD, string& Iv)
{



	vector<uint8_t> iv;
	iv.reserve(Iv.length());

	for (size_t i = 0; i < Iv.length(); i += 2) {
		std::string byteString = Iv.substr(i, 2);
		iv.push_back((uint8_t)std::stoi(byteString, nullptr, 16));
	}

	
	std::string keyfile = keyFile;



	uint8_t* K = new uint8_t[keyfile.length()]; //A secret key K, whose length is appropriate for the underlying block cipher.

	for (size_t i = 0; i < keyfile.length(); i += 2) {
		std::string byteString = keyfile.substr(i, 2);
		K[i / 2] = (uint8_t)std::stoi(byteString, nullptr, 16);
	}



	//inputs

	/*vector<uint8_t> Iv = vector < uint8_t>(12, 0x00);*/
	/* An initialization vector IV, that can have any number of bits between 1 and 2^64. For a fixed
value of the key, each IV value must be distinct, but need not have equal lengths. 96 - bit
	IV values can be processed more efficiently, so that length is recommended for situations in
	which efficiency is critical.*/




	vector<vector<uint8_t>> P; // A plaintext P, which can have any number of bits between 0 and 2^39 − 256.

	int fileSize = inputFile.size();
	size_t estimatedLines = static_cast<size_t>(fileSize / 16);
	P.reserve(estimatedLines);

	size_t rowSize = 16;
	for (size_t i = 0; i < inputFile.size(); ++i) {
		if (P.empty() || P.back().size() == rowSize) {
			P.push_back(vector<uint8_t>());
			n++;
		}
		P.back().push_back(inputFile[i]);
	}
	if (!P.empty() && P.back().empty()) {
		P.pop_back();
		n--;
	}
	u = P.empty() ? 0 : P.back().size() * 8;


	vector<vector<uint8_t>> A; /* Additional authenticated data (AAD), which is denoted as A. This data is authenticated, but
	not encrypted, and can have any number of bits between 0 and 264.*/


	int AADfileSize = AAD.size();
	size_t estimatedAADLines = static_cast<size_t>(AADfileSize / 16);
	A.reserve(estimatedAADLines);
	for (size_t i = 0; i < AAD.size(); ++i) {
		if (A.empty() || A.back().size() == rowSize) {
			A.push_back(vector<uint8_t>());
			m++;
		}
		A.back().push_back(AAD[i]);

	}
	if (!A.empty() && A.back().empty()) {
		A.pop_back();
		m--;
	}
	v = A.empty() ? 0 : A.back().size() * 8;


	//outputs

	vector<vector<uint8_t>> C;// A ciphertext C whose length is exactly that of the plaintext P
	vector<uint8_t> T;//An authentication tag T, whose length can be any value between 0 and 128. The length of the tag is denoted as t.
	int t = 128;//length of T
	auto start = std::chrono::high_resolution_clock::now();
	uint8_t* H = new uint8_t[16];
	for (int i = 0; i < 16; ++i)
	{
		H[i] = 0x00;
	}
	H = Cipher(H, keyfile.length() / 2, K);
	
	vector<vector<uint8_t>>Y;
	for (int i = 0; i <= n; ++i) {
		Y.push_back(vector<uint8_t>());
	}

	if (iv.size() == 12) {
		for (int i = 0; i < 16; ++i)
		{
			if (i < 12)
			{
				Y[0].push_back(iv[i]);
			}
			else if (i != 15)
				Y[0].push_back(0x00);
			else
				if (i == 15)
				{
					Y[0].push_back(0x01);
				}
		}
	}
	else
	{
		Y[0] = ghash(H, {}, 0, 0, iv, 1, iv.size()*8);
	}

	for (int i = 1; i <= n; ++i) {
		Y[i] = incr(Y[i - 1]);
	}






	vector<uint8_t*> KY;
	uint8_t* tempY = new uint8_t[16];

	for (int i = 0; i <= n; ++i)
	{
		for (int j = 0; j < 16; j++)
		{
			tempY[j] = Y[i][j];
		}
		KY.push_back(Cipher(tempY, keyfile.length() / 2, K));
	}
	delete[]tempY;


	for (int i = 0; i < n - 1; ++i)
	{
		C.push_back(vector<uint8_t>());
		for (int j = 0; j < 16; ++j)
		{
			C[i].push_back((P[i][j] ^ KY[i + 1][j]));
		}
	}

	C.push_back(vector<uint8_t>());

	for (int j = 0; j < u / 8; ++j)
	{
		C[n - 1].push_back(P[n - 1][j] ^ KY[n][j]);
	}
	std::vector<std::vector<uint8_t>> X;

	cout << "C: ";

	for (int i = 0; i < C.size()-1; ++i)
	{
		for (int j = 0; j < 16;j++)
		{
			if (C[i][j] < 16) {
				std::cout << 0;
			}
			cout << hex << (int) C[i][j];
		}
		cout << endl;
	}
	
	for (int j = 0; j <u/8; j++)
	{
		if (C[n - 1][j] < 16) {
			std::cout << 0;
		}
		cout << hex << (int) C[n-1][j];
	}
	cout << endl;

	X = ghash(H, A, m, v, C, n, u);


	for (int i = 0; i < t / 8; ++i) {
		T.push_back((X.back()[i]) ^ (KY[0][i]));
	}

	cout << "Tag from the c++ program: ";
	for (int i = 0; i < T.size(); ++i)
	{
		if (T[i] < 16) {
			std::cout << 0;
		}
		cout << hex << (int)T[i] << " ";
	}
	cout << endl;
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double, std::milli> encryptionTime = end - start;

	double timeInMs = encryptionTime.count();
	std::cout << "Encryption time: " << timeInMs << " ms" << std::endl;



	for (int i = 0; i < n; ++i)
	{
		delete KY[i];
	}
	delete[] K;
}

std::string decode_base64(const std::string& encoded_string) {
	std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::string decoded_string;
	int val = 0;
	int bits = -8;
	for (const char& c : encoded_string) {
		if (base64_chars.find(c) == std::string::npos) {
			break;
		}
		val = (val << 6) + base64_chars.find(c);
		bits += 6;

		if (bits >= 0) {
			decoded_string.push_back(char((val >> bits) & 0xFF));
			bits -= 8;
		}
	}
	return decoded_string;
}


int main(int argc, char* argv[])
{


	std::string dataBase64;
	std::getline(std::cin, dataBase64);
	std::string keyBase64;
	std::getline(std::cin, keyBase64);
	

	if (keyBase64.empty()) {
		cerr << "Error: key.\n";
		return 1;
	}


	

	std::string aedBase64;
	std::getline(std::cin, aedBase64);
	std::string ivBase64;
	std::getline(std::cin, ivBase64);

	if (ivBase64.empty()) {
		cerr << "Error: Iv.\n";
		return 1;
	}

	// Decodarea din Base64 a datelor de intrare
	std::string data = decode_base64(dataBase64);
	std::string key = decode_base64(keyBase64);
	std::string aed = decode_base64(aedBase64);
	std::string Iv = decode_base64(ivBase64);


	GCMCRypt(data, key, aed, Iv);




	return 0;
}