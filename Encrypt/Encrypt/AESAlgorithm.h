#pragma once
#include "ISecureAlgorithm.h"

enum EM_AES_MODE
{
	AES_MODE_ECB = 0,
	AES_MODE_CBC,	
	AES_MODE_CRT,
	AES_MODE_OFB,
	AES_MODE_CFB,
};

class CAESAlgorithm :
	public ISecureAlgorithm
{
public:
	CAESAlgorithm();
	explicit CAESAlgorithm(const std::string& strKey, EM_AES_MODE aesMode);
	virtual ~CAESAlgorithm();
	
public:
	bool Encrypt(const std::string& strIn, std::string& strOut);
	bool Decrypt(const std::string& strIn, std::string& strOut);

	void setKey(const std::string& strKey);
	void setIV(const std::string& strIV);
	std::string getKey();
	void setMode(EM_AES_MODE aesMode);

private:
	// CBC Mode
	bool CBCModeEncrypt(const std::string& strIn, std::string& strOut);
	bool CBCModeDecrypt(const std::string& strIn, std::string& strOut);

	// ECB Mode
	bool ECBModeEncrypt(const std::string& strIn, std::string& strOut);
	bool ECBModeDecrypt(const std::string& strIn, std::string& strOut);

	// CFB Mode
	bool CFBModeEncrypt(const std::string& strIn, std::string& strOut);
	bool CFBModeDecrypt(const std::string& strIn, std::string& strOut);

	// OFB Mode
	bool OFBModeEncrypt(const std::string& strIn, std::string& strOut);
	bool OFBModeDecrypt(const std::string& strIn, std::string& strOut);

	// CRT Mode
	bool CRTModeEncrypt(const std::string& strIn, std::string& strOut);
	bool CRTModeDecrypt(const std::string& strIn, std::string& strOut);

private:
	std::string m_strKey;
	std::string m_strIV;
	EM_AES_MODE m_emMode;
};

