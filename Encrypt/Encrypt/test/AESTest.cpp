#include "stdafx.h"
#include <string.h>
#include "../AESAlgorithm.h"

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AES;

static std::string GenerateIV()
{
	AutoSeededRandomPool prng;
	unsigned char iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	std::string strIv;
	strIv.assign(iv, iv + sizeof(iv));

	return strIv;
}

class AESAlgorithmTest : public ::testing::Test 
{
public:
	void SetUp()
	{
		strKey = "1234567890123456";
		strToEncrypt = "Hello AesAlgorithm";
		aesOperator.setKey(strKey);
	}

	void TearDown()
	{

	}

public:
	std::string strKey;
	std::string strToEncrypt;
	CAESAlgorithm aesOperator;
};

TEST_F(AESAlgorithmTest, CBCEncryptAndDecrypt)
{
	std::string strEncrypted;	
	aesOperator.setMode(AES_MODE_CBC);

	std::string strIV = GenerateIV();
	aesOperator.setIV(strIV);
	bool bRet = aesOperator.Encrypt(strToEncrypt, strEncrypted);
	EXPECT_TRUE(bRet);

	std::string strDecrypt;
	bRet = aesOperator.Decrypt(strEncrypted, strDecrypt);
	EXPECT_TRUE(bRet);
	EXPECT_STREQ(strToEncrypt.c_str(), strDecrypt.c_str());
}


TEST_F(AESAlgorithmTest, ECBEncryptAndDecrypt)
{
	std::string strEncrypted;
	aesOperator.setMode(AES_MODE_ECB);
	
	bool bRet = aesOperator.Encrypt(strToEncrypt, strEncrypted);
	EXPECT_TRUE(bRet);

	std::string strDecrypt;
	bRet = aesOperator.Decrypt(strEncrypted, strDecrypt);
	EXPECT_TRUE(bRet);
	EXPECT_STREQ(strToEncrypt.c_str(), strDecrypt.c_str());
}

TEST_F(AESAlgorithmTest, OFBEncryptAndDecrypt)
{
	std::string strEncrypted;
	aesOperator.setMode(AES_MODE_OFB);

	std::string strIV = GenerateIV();
	aesOperator.setIV(strIV);
	bool bRet = aesOperator.Encrypt(strToEncrypt, strEncrypted);
	EXPECT_TRUE(bRet);

	std::string strDecrypt;
	bRet = aesOperator.Decrypt(strEncrypted, strDecrypt);
	EXPECT_TRUE(bRet);
	EXPECT_STREQ(strToEncrypt.c_str(), strDecrypt.c_str());
}

TEST_F(AESAlgorithmTest, CFBEncryptAndDecrypt)
{
	std::string strEncrypted;
	aesOperator.setMode(AES_MODE_CFB);

	std::string strIV = GenerateIV();
	aesOperator.setIV(strIV);
	bool bRet = aesOperator.Encrypt(strToEncrypt, strEncrypted);
	EXPECT_TRUE(bRet);

	std::string strDecrypt;
	bRet = aesOperator.Decrypt(strEncrypted, strDecrypt);
	EXPECT_TRUE(bRet);
	EXPECT_STREQ(strToEncrypt.c_str(), strDecrypt.c_str());
}

TEST_F(AESAlgorithmTest, CRTEncryptAndDecrypt)
{
	std::string strEncrypted;
	aesOperator.setMode(AES_MODE_CRT);

	std::string strIV = GenerateIV();
	aesOperator.setIV(strIV);
	bool bRet = aesOperator.Encrypt(strToEncrypt, strEncrypted);
	EXPECT_TRUE(bRet);

	std::string strDecrypt;
	bRet = aesOperator.Decrypt(strEncrypted, strDecrypt);
	EXPECT_TRUE(bRet);
	EXPECT_STREQ(strToEncrypt.c_str(), strDecrypt.c_str());
}