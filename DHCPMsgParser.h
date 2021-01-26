#pragma once
#include <memory>
#include <vector>

// #include <Windows.h> // 
#include <wtypes.h>


// Maximum size of a UDP datagram (see RFC 768)
#define MAX_UDP_MESSAGE_SIZE ((65536)-8)
// DHCP constants (see RFC 2131 section 4.1)
#define DHCP_SERVER_PORT (67)
#define DHCP_CLIENT_PORT (68)
// Broadcast bit for flags field (RFC 2131 section 2)
#define BROADCAST_FLAG (0x80)
// For display of host name information
#define MAX_HOSTNAME_LENGTH (256)
// RFC 2131 section 2

const char pcsServerName[] = "DHCPLite DHCP server";
enum op_values
{
    op_BOOTREQUEST = 1,
    op_BOOTREPLY = 2,
};
// RFC 2132 section 9.6
enum option_values
{
    option_PAD = 0,
    option_SUBNETMASK = 1,
    option_HOSTNAME = 12,
    option_REQUESTEDIPADDRESS = 50,
    option_IPADDRESSLEASETIME = 51,
    option_DHCPMESSAGETYPE = 53,
    option_SERVERIDENTIFIER = 54,
    option_CLIENTIDENTIFIER = 61,
    option_NTPServer = 42,
    option_END = 255,
};
enum DHCPMessageTypes
{
    DHCPMessageType_DISCOVER = 1,
    DHCPMessageType_OFFER = 2,
    DHCPMessageType_REQUEST = 3,
    DHCPMessageType_DECLINE = 4,
    DHCPMessageType_ACK = 5,
    DHCPMessageType_NAK = 6,
    DHCPMessageType_RELEASE = 7,
    DHCPMessageType_INFORM = 8,
};

// DHCP magic cookie values
const BYTE pbDHCPMagicCookie[] = { 99, 130, 83, 99 };

class DHCPMsgParser
{
public:

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma pack(push, 1)

    struct DHCPMsg
    {
        BYTE op;
        BYTE htype;
        BYTE hlen;
        BYTE hops;
        DWORD xid;
        WORD secs;
        WORD flags;
        DWORD ciaddr;		// Client IP
        DWORD yiaddr;		// Your client IP Address
        DWORD siaddr;		// Next Server IP
        DWORD giaddr;		// Relay agent IP
        BYTE chaddr[16];	// Client MAC Address and Padding
        BYTE sname[64];		// Server hostname
        BYTE file[128];
        BYTE options[1];
    };

    struct DHCPServerOptions
    {
        BYTE pbMagicCookie[4];
        BYTE pbMessageType[3];
        BYTE pbLeaseTime[6];
        BYTE pbSubnetMask[6];
        BYTE pbServerID[6];
        BYTE NTPServer[6];
        BYTE bEND;
    };


    enum MsgType : uint8_t
    {
        DHCPDISCOVER = 1,
        DHCPOFFER = 2,
        DHCPREQUEST = 3,
        DHCPDECLINE = 4,
        DHCPACK = 5,
        DHCPNAK = 6,
        DHCPRELEASE = 7,
        DHCPINFORM = 8,
    };

    enum Options : uint8_t
    {
        PAD = 0,
        SUBNETMASK = 1,
        HOSTNAME = 12,
        REQUESTEDIPADDRESS = 50,
        IPADDRESSLEASETIME = 51,
        DHCPMESSAGETYPE = 53,
        SERVERIDENTIFIER = 54,
        CLIENTIDENTIFIER = 61,
        NTPServer = 42,
        END = 255,
    };

    // TODO this could be a problem considering the alignment?
    struct DHCPMsgOption
    {
        BYTE option;
        BYTE size;
        BYTE data[1];
    };

#pragma pack(pop)
#pragma warning(pop)

    DHCPMsgParser(DHCPMsg* pMsg, DWORD sizeIn) : mMsg(pMsg), mSize(sizeIn)
    {}

    bool isValid() const
    {
        MsgType type = DHCPACK;

        if (mSize < sizeof(DHCPMsg) + sizeof(pbDHCPMagicCookie)) { return false; }
        if (op_BOOTREQUEST != mMsg->op) { return false; }
        if (0 != memcmp(pbDHCPMagicCookie, mMsg->options, sizeof(pbDHCPMagicCookie))) { return false; }
        if (!msgType(type)) { return false; }
        if (type == DHCPOFFER || type == DHCPACK || type == DHCPNAK) { return false; }

        return true;
    }

    u_long updateAndgetClientAddr(const DHCPMsg* msgReq)
    {
        if (0 != msgReq->giaddr) { mMsg->flags |= BROADCAST_FLAG; return msgReq->giaddr; }

        MsgType type = DHCPACK;
        if (!msgType(type)) { throw "Invalid msg type"; }

        if (type == MsgType::DHCPNAK) { return INADDR_BROADCAST; }
        if (0 != msgReq->ciaddr) { return msgReq->ciaddr; }

        if (0 != (BROADCAST_FLAG & msgReq->flags)) { return INADDR_BROADCAST; }

        if (0 == msgReq->yiaddr) { return INADDR_BROADCAST; }

        return  msgReq->yiaddr;
    }

    bool msgType(MsgType& type) const
    {
        auto option = getOption(Options::DHCPMESSAGETYPE);
        if (nullptr == option) { return false; }

        type = static_cast<MsgType>(option->data[0]);
        return true;
    }

    DHCPMsgOption* getOption(Options option) const
    {
        if (option == Options::END || option == Options::PAD) { return nullptr; }

        const BYTE* pbCurrentOption = mMsg->options + sizeof(pbDHCPMagicCookie);
        const BYTE* pEnd = mMsg->options + (mSize - sizeof(DHCPMsg));
        DHCPMsgOption* requestedOption = nullptr;

        while (pbCurrentOption < pEnd)
        {
            if (option_PAD == (*pbCurrentOption)) { pbCurrentOption++;					continue; }
            if (option_END == (*pbCurrentOption)) { break; }

            if (option == (*pbCurrentOption)) { requestedOption = (DHCPMsgOption*)pbCurrentOption;	break; }

            pbCurrentOption += (2 + (*(pbCurrentOption + 1)));
        }

        if (pbCurrentOption >= pEnd) { return nullptr; }
        // TODO if(requestedOption >= pEnd) success case size check

        return requestedOption;
    }

    std::string hostName() const
    {
        auto option = getOption(Options::HOSTNAME);
        if (nullptr == option) { return std::string(); }

        auto buff = std::make_unique<char[]>(option->size + 1);
        ZeroMemory(&(buff[0]), option->size + 1);
        memcpy(&(buff[0]), option->data, option->size);
        std::string clientHostName(&(buff[0]));
        return clientHostName;
    }

    UINT32 requestedIP() const
    {
        auto option = getOption(Options::REQUESTEDIPADDRESS);
        if (nullptr == option) { return 0; }

        if (sizeof(UINT32) != option->size) { return 0; }

        return *((UINT32*)&(option->data[0]));
    }

    std::vector<BYTE> createResponse() const
    {
        std::vector<BYTE> response(sizeof(DHCPMsg) + sizeof(DHCPServerOptions));
        ZeroMemory(&response[0], response.size() * sizeof(response[0]));

        DHCPMsg* newMsg = reinterpret_cast<DHCPMsg*>(&response[0]);
        newMsg->op = op_BOOTREPLY;
        newMsg->htype = mMsg->htype;
        newMsg->hlen = mMsg->hlen;
        // pdhcpmReply->hops = 0;
        newMsg->xid = mMsg->xid;
        // pdhcpmReply->ciaddr = 0;
        // pdhcpmReply->yiaddr = 0;  Or changed below
        // pdhcpmReply->siaddr = 0;
        newMsg->flags = mMsg->flags;
        newMsg->giaddr = mMsg->giaddr;
        CopyMemory(newMsg->chaddr, mMsg->chaddr, sizeof(newMsg->chaddr));
        const char* pServiceName = "VolcanoDHCPServer";
        strncpy_s((char*)(newMsg->sname), sizeof(newMsg->sname), pcsServerName, _TRUNCATE);

        DHCPServerOptions* const pdhcpsoServerOptions = (DHCPServerOptions*)(newMsg->options);
        CopyMemory(pdhcpsoServerOptions->pbMagicCookie, pbDHCPMagicCookie, sizeof(pdhcpsoServerOptions->pbMagicCookie));

        pdhcpsoServerOptions->pbMessageType[0] = Options::DHCPMESSAGETYPE;
        pdhcpsoServerOptions->pbMessageType[1] = 1;

        pdhcpsoServerOptions->pbLeaseTime[0] = Options::IPADDRESSLEASETIME;
        pdhcpsoServerOptions->pbLeaseTime[1] = 4;

        pdhcpsoServerOptions->pbSubnetMask[0] = Options::SUBNETMASK;
        pdhcpsoServerOptions->pbSubnetMask[1] = 4;

        pdhcpsoServerOptions->pbServerID[0] = Options::SERVERIDENTIFIER;
        pdhcpsoServerOptions->pbServerID[1] = 4;

        pdhcpsoServerOptions->NTPServer[0] = Options::NTPServer;
        pdhcpsoServerOptions->NTPServer[1] = 4;

        pdhcpsoServerOptions->bEND = Options::END;
        return std::move(response);
    }


    bool setMsgType(MsgType type)
    {
        auto option = getOption(Options::DHCPMESSAGETYPE);
        if (nullptr == option) { return false; }

        option->data[0] = static_cast<BYTE>(type);
        type = static_cast<MsgType>(option->data[0]);
        return true;
    }

    bool setNTPServer(UINT32 NTPServerInNWOrder)
    {
        auto option = getOption(Options::NTPServer);
        if (nullptr == option) { return false; }

        *(UINT32*)(option->data) = NTPServerInNWOrder;
        return true;
    }

    bool setLeaseTime(UINT32 leaseTimeInSeconds)
    {
        auto option = getOption(Options::IPADDRESSLEASETIME);
        if (nullptr == option) { return false; }
        *(UINT32*)(option->data) = htonl(leaseTimeInSeconds);
        return true;
    }

    bool setSubnetMask(UINT32 subnetMaskInNWOrder)
    {
        auto option = getOption(Options::SUBNETMASK);
        if (nullptr == option) { return false; }

        *(UINT32*)(option->data) = subnetMaskInNWOrder;
        return true;
    }

    bool setServerIP(UINT32 serverIPInNWOrder)
    {
        auto option = getOption(Options::SERVERIDENTIFIER);
        if (nullptr == option) { return false; }

        *(UINT32*)(option->data) = serverIPInNWOrder;
        return true;
    }

private:

    DHCPMsg* mMsg = nullptr;
    DWORD mSize = 0;
};
