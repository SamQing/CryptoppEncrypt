#include "stdafx.h"
#include "AESAlgorithm.h"
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::CFB_Mode;

#include "assert.h"



CAESAlgorithm::CAESAlgorithm()
	: m_strKey("")
	, m_strIV("")
	, m_emMode(AES_MODE_ECB)
{
}


CAESAlgorithm::CAESAlgorithm(const std::string& strKey, EM_AES_MODE aesMode)
	: m_strKey(strKey)
	, m_strIV("")
	, m_emMode(aesMode)
{

}

CAESAlgorithm::~CAESAlgorithm()
{
}


bool CAESAlgorithm::Encrypt(const std::string& strIn, std::string& strOut)
{	
	bool bRet = false;
	switch (m_emMode)
	{
	case AES_MODE_CBC:
		bRet = CBCModeEncrypt(strIn, strOut);
		break;
	case AES_MODE_ECB:
		bRet = ECBModeEncrypt(strIn, strOut);
		break;
	case AES_MODE_OFB:
		bRet = OFBModeEncrypt(strIn, strOut);
		break;
	case AES_MODE_CFB:
		bRet = CFBModeEncrypt(strIn, strOut);
		break;
	case AES_MODE_CRT:
		bRet = CRTModeEncrypt(strIn, strOut);
		break;
	default:
		break;
	}
	return bRet;
}


bool CAESAlgorithm::Decrypt(const std::string& strIn, std::string& strOut)
{
	bool bRet = false;
	switch (m_emMode)
	{
	case AES_MODE_CBC:
		bRet = CBCModeDecrypt(strIn, strOut);
		break;
	case AES_MODE_ECB:
		bRet = ECBModeDecrypt(strIn, strOut);
		break;
	case AES_MODE_OFB:
		bRet = OFBModeDecrypt(strIn, strOut);
		break;
	case AES_MODE_CFB:
		bRet = CFBModeDecrypt(strIn, strOut);
		break;
	case AES_MODE_CRT:
		bRet = CRTModeDecrypt(strIn, strOut);
		break;
	default:
		break;
	}
	return bRet;	
}

void CAESAlgorithm::setKey(const std::string & strKey)
{
	m_strKey = strKey;
}

void CAESAlgorithm::setIV(const std::string & strIV)
{
	m_strIV = strIV;
}

std::string CAESAlgorithm::getKey()
{
	return m_strKey;
}

void CAESAlgorithm::setMode(EM_AES_MODE aesMode)
{
	m_emMode = aesMode;
}

bool CAESAlgorithm::CBCModeEncrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		cout << "plain text: " << strIn << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(e,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::CBCModeDecrypt(const std::string & strIn, std::string & strOut)
{	
	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(d,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << strOut << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;	
	}

	return true;
}

bool CAESAlgorithm::ECBModeEncrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		cout << "plain text: " << strIn << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey((const unsigned char*)m_strKey.c_str(), m_strKey.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(strIn, true,
			new StreamTransformationFilter(e,
				new StringSink(strOut)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::ECBModeDecrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey((const unsigned char*)m_strKey.c_str(), m_strKey.size());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(d,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << strOut << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::CFBModeEncrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		cout << "plain text: " << strIn << endl;

		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(strIn, true,
			new StreamTransformationFilter(e,
				new StringSink(strOut)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}

	return true;
}

bool CAESAlgorithm::CFBModeDecrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(d,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << strOut << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::OFBModeEncrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		cout << "plain text: " << strIn << endl;

		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// OFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(strIn, true,
			new StreamTransformationFilter(e,
				new StringSink(strOut)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;		
	}

	return true;
}

bool CAESAlgorithm::OFBModeDecrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(d,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << strOut << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::CRTModeEncrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		cout << "plain text: " << strIn << endl;

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(strIn, true,
			new StreamTransformationFilter(e,
				new StringSink(strOut)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}

bool CAESAlgorithm::CRTModeDecrypt(const std::string & strIn, std::string & strOut)
{
	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV((const unsigned char*)m_strKey.c_str(), m_strKey.size(), (const unsigned char*)m_strIV.c_str());

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(strIn, true,
			new StreamTransformationFilter(d,
				new StringSink(strOut)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << strOut << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return false;
	}
	return true;
}
