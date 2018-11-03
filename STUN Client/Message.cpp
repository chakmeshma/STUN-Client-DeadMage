#include "Message.h"

const uint32 Message::magic_cookie = 0x2112A442;
static std::random_device rd;
static std::mt19937 gen(rd());
static std::uniform_int_distribution<uint32> dist(0, ((uint32)(0) - 1));

Message::Message(MessageMethod method, MessageClass messageClass, std::vector<Attribute> attributes)
{
	transactionID[0] = dist(gen);
	transactionID[1] = dist(gen);
	transactionID[2] = dist(gen);
	this->method = method;
	this->messageClass = messageClass;
	this->attributes = attributes;
}

Message::Message(MessageMethod method, MessageClass messageClass, uint32 transactionID[3], std::vector<Attribute> attributes) {
	memcpy(this->transactionID, transactionID, sizeof(uint32) * 3);
	this->method = method;
	this->messageClass = messageClass;
	this->attributes = attributes;
}

//TODO: check for unknown attributes or unexpected attributes that might cause the decodation to fail
Message Message::fromPacket(uint8 *pdu, unsigned int packetSize) {
	uint16 messageMethodEncoded;
	uint16 messageClassEncoded;
	uint16 messageLength;
	uint32 magicCookieCO;
	uint32 transactionID[3];
	MessageMethod messageMethod;
	MessageClass messageClass;
	std::vector<Attribute> attributes;

	if (packetSize < 20 && packetSize & 4 != 0)
		throw ProcessingException(ProcessingExceptionType::InvalidPacket);

	if ((pdu[0] & 0b11000000) != '\0')
		throw ProcessingException(ProcessingExceptionType::InvalidPacket);

	magicCookieCO = htonl(magic_cookie);

	if (*(reinterpret_cast<uint32*>(pdu + 4)) != magicCookieCO)
		throw ProcessingException(ProcessingExceptionType::InvalidPacket);

	messageMethodEncoded = (*(reinterpret_cast<uint16*>(pdu))) & 0b0011111011101111;
	messageLength = htons(*reinterpret_cast<uint16*>(pdu + 2));
	messageClassEncoded = (*(reinterpret_cast<uint16*>(pdu))) & 0b0000000100010000;

	if (messageLength % 4 != 0)
		throw ProcessingException(ProcessingExceptionType::InvalidPacket);

	transactionID[0] = *(reinterpret_cast<uint32*>(pdu + 8));
	transactionID[1] = *(reinterpret_cast<uint32*>(pdu + 12));
	transactionID[2] = *(reinterpret_cast<uint32*>(pdu + 16));

	switch (messageMethodEncoded) {
	case 0x0001: //Binding
		messageMethod = MessageMethod::Binding;
		break;
	default:
		messageMethod = MessageMethod::Unknown;
	}

	switch (messageClassEncoded) {
	case 0x0100: //Success Response
		messageClass = MessageClass::SuccessResponse;
		break;
	default:
		messageClass = MessageClass::Unknown;
	}

	//printHex((char*)(pdu + 20), messageLength);

	//Parsing Attributes START

	uint8 *pAttributes = pdu + 20;
	bool isDifferentByteOrder = isHostNetworkDifferentEndianness();

	do {
		uint16 attributeType;
		uint16 attributeLength;

		attributeType = ntohs(*reinterpret_cast<uint16*>(pAttributes));
		pAttributes += 2;
		attributeLength = ntohs(*reinterpret_cast<uint16*>(pAttributes));
		pAttributes += 2;

		Attribute attribute(attributeLength);
		attribute.type = static_cast<AttributeType>(attributeType);

		memcpy(attribute.data.get(), pAttributes, attributeLength);

		pAttributes += (attributeLength % 4 == 0) ? (attributeLength) : (attributeLength + (4 - (attributeLength % 4)));  //Skip over attribute value padding due to 4-byte alignment

		attributes.push_back(attribute);

	} while (pAttributes < pdu + 20 + messageLength);

	//Parsing Attributes END

	Message message = Message(messageMethod, messageClass, transactionID, attributes);

	return message;
}

uint32 Message::encodePacket(uint8 *pdu) {
	MessageTypeLZ messageTypeLZ;
	uint16 encodedMessageTypeLZ = 0;
	uint16 encodedMessageLength = 0;
	uint32 encodedMagicCookie;

	encodedMagicCookie = htonl(magic_cookie);

	switch (this->method) {
	case  MessageMethod::Binding:
		switch (messageClass) {
		case MessageClass::Request:
			messageTypeLZ = MessageTypeLZ::Binding_Request;
			break;
		case MessageClass::SuccessResponse:
			break;
		default:
			throw ProcessingException(ProcessingExceptionType::InvalidPacketParam);
		}
		break;
	default:
		throw ProcessingException(ProcessingExceptionType::InvalidPacketParam);
	}

	encodedMessageTypeLZ = htons(static_cast<uint16>(messageTypeLZ));

	memcpy(((uint16*)pdu) + 0, &encodedMessageTypeLZ, sizeof(uint16));
	memcpy(((uint16*)pdu) + 1, &encodedMessageLength, sizeof(uint16));
	memcpy(((uint32*)pdu) + 1, &encodedMagicCookie, sizeof(uint32));
	memcpy(((uint8*)pdu) + 8, transactionID, sizeof(uint32) * 3);

	return 20;
}

void Message::getMappedAddress(uint32 targetIPv4, uint16 targetPort, uint32 *ipv4, uint16 *port)
{
	for (auto attribute : attributes) {
		if (attribute.type == AttributeType::XOR_MAPPED_ADDRESS && attribute.length == 8 && reinterpret_cast<uint8*>(attribute.data.get())[1] == 1) {

			uint16 encodedPort = *reinterpret_cast<uint16*>(attribute.data.get() + 2);
			uint32 encodedIP = *reinterpret_cast<uint32*>(attribute.data.get() + 4);

			encodedPort = ntohs(encodedPort);
			encodedIP = ntohl(encodedIP);

			*port = encodedPort ^ static_cast<const uint16>(magic_cookie >> 16);
			*ipv4 = encodedIP ^ magic_cookie;

			return;
		}
	}

	throw ProcessingException(ProcessingExceptionType::NAMappedAddress);
}

bool Message::isHostNetworkDifferentEndianness()
{
	uint16 testValue = 0x0FF0;
	uint16 resultValue;

	resultValue = htons(testValue);

	return (testValue != resultValue);
}

bool Message::isHostBigEndian()
{
	uint16 testValue = 0x01FF;

	return (reinterpret_cast<uint8*>(&testValue)[0] == 0x01);
}

void Message::getTransactionID(uint32 transactionID[3]) {
	transactionID[0] = this->transactionID[0];
	transactionID[1] = this->transactionID[1];
	transactionID[2] = this->transactionID[2];
}

std::vector<Attribute>& Message::getAttributes() {
	return this->attributes;
}