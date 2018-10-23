#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <sstream>
#include <windows.h>
#include <cstdlib>
#include <ctime>
#include <random>
#include <string>
#include <cassert>
#include "STUN Client.h"

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned char uchar;
typedef unsigned long long ulonglong;

#define WIN32_SOCK_MAJ_VER 2
#define WIN32_SOCK_MIN_VER 2
#define TARGET_PORT 3478
#define MAGIC_COOKIE 0x2112A442

#pragma comment(lib, "Ws2_32.lib")

static WSADATA wsaData;
static const char strUsage[] = "Usage: stunclient <server name or ip> [server port]\n";
static addrinfo aiHints, *aiResult, *aiSelected;
static SOCKET theSocket;
static bool bWSAInited = false;
static bool bAddrInfoCalled = false;
static bool bSocketCreated = false;
static sockaddr_in localAddress;
static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_int_distribution<uint> dist(0, ((uint)(0) - 1));

static enum MessageMethod {
	Binding
};

static enum MessageClass {
	Request,
	Response
};

void cleanup();

static BOOL WINAPI closeHandler(DWORD dwCtrlType) {
	cleanup();

	return true;
}

static bool decodePaket(uchar *paketData, uint sizePaket, __out MessageClass &messageClass, __out MessageMethod &messageMethod) {
	ushort messageMethodEncoded;
	ushort messageClassEncoded;
	ushort messageLengthEncoded;
	uint magicCookieCO;
	uint transactionID[3];

	if (sizePaket < 20 && sizePaket & 4 != 0)
		return false;

	if ((paketData[0] & 0b11000000) != '\0')
		return false;

	WSAHtonl(theSocket, MAGIC_COOKIE, (u_long*)&magicCookieCO);

	if (*(reinterpret_cast<uint*>(paketData + 4)) != magicCookieCO)
		return false;

	messageMethodEncoded = (*(reinterpret_cast<ushort*>(paketData))) & 0b0011111011101111;
	messageClassEncoded = (*(reinterpret_cast<ushort*>(paketData))) & 0b0000000100010000;


	return true;
}

static uint encodePaket(MessageClass messageClass, MessageMethod messageMethod, __out unsigned char *pdu) {

	ushort messageTypeAndLZ = 0;
	ushort messageLength = 0;
	uint magicCookieCO;
	uint transactionID[3];

	transactionID[0] = dist(gen);
	transactionID[1] = dist(gen);
	transactionID[2] = dist(gen);

	WSAHtonl(theSocket, MAGIC_COOKIE, (u_long*)&magicCookieCO);

	switch (messageMethod) {
	case  MessageMethod::Binding:
		switch (messageClass) {
		case MessageClass::Request:
			WSAHtons(theSocket, 0x0001, (u_short*)&messageTypeAndLZ);
			break;
		default:
			return -1;
		}
		break;
	default:
		return -1;
	}

	pdu[0] = ((unsigned char*)&messageTypeAndLZ)[0];
	pdu[1] = ((unsigned char*)&messageTypeAndLZ)[1];

	pdu[2] = ((unsigned char*)&messageLength)[0];
	pdu[3] = ((unsigned char*)&messageLength)[1];

	pdu[4] = ((unsigned char*)&magicCookieCO)[0];
	pdu[5] = ((unsigned char*)&magicCookieCO)[1];
	pdu[6] = ((unsigned char*)&magicCookieCO)[2];
	pdu[7] = ((unsigned char*)&magicCookieCO)[3];

	pdu[8] = ((unsigned char*)&transactionID + 0)[0];
	pdu[9] = ((unsigned char*)&transactionID + 0)[1];
	pdu[10] = ((unsigned char*)&transactionID + 0)[2];
	pdu[11] = ((unsigned char*)&transactionID + 0)[3];

	pdu[12] = ((unsigned char*)&transactionID + 1)[0];
	pdu[13] = ((unsigned char*)&transactionID + 1)[1];
	pdu[14] = ((unsigned char*)&transactionID + 1)[2];
	pdu[15] = ((unsigned char*)&transactionID + 1)[3];

	pdu[16] = ((unsigned char*)&transactionID + 2)[0];
	pdu[17] = ((unsigned char*)&transactionID + 2)[1];
	pdu[18] = ((unsigned char*)&transactionID + 2)[2];
	pdu[19] = ((unsigned char*)&transactionID + 2)[3];

	return 20;
}

static void cleanup() {
	if (bAddrInfoCalled) freeaddrinfo(aiSelected);
	if (bSocketCreated) closesocket(theSocket);
	if (bWSAInited) WSACleanup();
}

static inline char toHex(char byte)
{
	static char hex[] = { '0','1','2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	return hex[byte];
}


int main(int argc, char **argv)
{
	SetConsoleCtrlHandler(closeHandler, true);

	int iResult;
	bool isIP;

	if (argc != 3 && argc != 2) {
		std::cerr << "Invalid usage.\n";
		std::cout << strUsage;

		return EXIT_FAILURE;
	}

	iResult = WSAStartup(MAKEWORD(WIN32_SOCK_MAJ_VER, WIN32_SOCK_MIN_VER), &wsaData);

	bWSAInited = true;

	if (iResult != 0) {
		std::cerr << "WSAStartup failed: " << iResult << std::endl;

		cleanup();

		return EXIT_FAILURE;
	}

	char strTargetPort[6];

	_itoa_s(TARGET_PORT, strTargetPort, 10);

	memset(&aiHints, 0, sizeof(aiHints));

	aiHints.ai_family = AF_INET;
	aiHints.ai_socktype = SOCK_DGRAM;
	aiHints.ai_protocol = IPPROTO_UDP;

	iResult = getaddrinfo(argv[1], (argc == 2) ? (strTargetPort) : (argv[2]), &aiHints, &aiResult);

	bAddrInfoCalled = true;

	if (iResult != 0) {
		std::cerr << "Address resolution failed: " << iResult << std::endl;

		cleanup();

		return EXIT_FAILURE;
	}


	theSocket = socket(aiResult->ai_family, aiResult->ai_socktype, aiResult->ai_protocol);

	bSocketCreated = true;

	if (iResult != 0) {
		std::cerr << "Couldn't get local socket name (address): " << WSAGetLastError() << std::endl;

		cleanup();

		return EXIT_FAILURE;
	}

	if (theSocket == INVALID_SOCKET) {
		std::cerr << "Couldn't create socket: " << WSAGetLastError() << std::endl;

		cleanup();

		return EXIT_FAILURE;
	}

	unsigned char pdu[20];

	ushort sizePDU = encodePaket(MessageClass::Request, MessageMethod::Binding, pdu);

	/*for (int i = 0; i < 20; i++)
	{
		char ch = pdu[i];
		std::cout << toHex((ch & 0xf0) >> 4) << toHex(ch & 0x0f);
	}

	std::cout << std::endl;*/

	if (sendto(theSocket, (const char*)pdu, 20, 0, aiResult->ai_addr, sizeof(*aiResult->ai_addr)) == SOCKET_ERROR) {
		std::cerr << "UDP send failed: " << WSAGetLastError() << std::endl;
	}

	const ushort sizeReceiveBuffer = 1024;

	unsigned char bufferReceive[sizeReceiveBuffer];

	int sizeLocalAddress = sizeof(localAddress);

	iResult = getsockname(theSocket, (sockaddr*)&localAddress, &sizeLocalAddress);

	uint sizeReceived = 0;

	MessageClass messageClass;
	MessageMethod messageMethod;

	while (true) {

		if ((sizeReceived = recvfrom(theSocket, (char*)bufferReceive, sizeReceiveBuffer, 0, (sockaddr*)&localAddress, &sizeLocalAddress)) == SOCKET_ERROR) {
			std::cerr << "UDP receive failed: " << WSAGetLastError() << std::endl;
		}
		else {
			if (sizeReceived == 0)
				continue;

			decodePaket(bufferReceive, sizeReceived, messageClass, messageMethod);
		}
	}

	cleanup();

	return EXIT_SUCCESS;
}