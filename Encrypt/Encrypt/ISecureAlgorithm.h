#pragma once
#include <string>

class ISecureAlgorithm
{
public:
	ISecureAlgorithm();
	virtual ~ISecureAlgorithm();

public:
	virtual bool Encrypt(const std::string& strIn, std::string& strOut) = 0;
	virtual bool Decrypt(const std::string& strIn, std::string& strOut) = 0;
};

