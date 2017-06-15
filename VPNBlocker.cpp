/*
Copyright (C) 2017 Vladimir "allejo" Jimenez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <cstdarg>
#include <json/json.h>
#include <queue>

#include "bzfsAPI.h"
#include "plugin_config.h"
#include "bztoolkit/bzToolkitAPI.h"
#include "JsonObject/JsonObject.h"

static std::string CONFIG_EMAIL;
static std::string CONFIG_URL;

// Define plug-in name
const std::string PLUGIN_NAME = "VPN Blocker";

// Define plug-in version numbering
const int MAJOR = 1;
const int MINOR = 0;
const int REV = 1;
const int BUILD = 1;

// Logging helper functions
static void logMessage(const char *type, int level, const char *message, va_list args)
{
    char buffer[4096];
    vsnprintf(buffer, 4096, message, args);

    bz_debugMessagef(level, "%s :: %s :: %s", bz_toupper(type), PLUGIN_NAME.c_str(), buffer);
}

static void errorMessage(int level, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    logMessage("error", level, message, args);
    va_end(args);
}

static void warnMessage(int level, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    logMessage("warning", level, message, args);
    va_end(args);
}

static void debugMessage(int level, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    logMessage("debug", level, message, args);
    va_end(args);
}

class VPNBlocker : public bz_Plugin, public bz_CustomSlashCommandHandler, public bz_BaseURLHandler
{
public:
    virtual const char* Name ();
    virtual void Init (const char* config);
    virtual void Cleanup ();
    virtual void Event (bz_EventData* eventData);
    virtual bool SlashCommand (int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params);

    virtual void URLDone (const char* URL, const void* data, unsigned int size, bool complete);
    virtual void URLTimeout (const char* URL, int errorCode);
    virtual void URLError (const char* URL, int errorCode, const char *errorString);

private:
    virtual void loadConfiguration(const char *filePath);
    virtual void nextQuery();
    virtual bool allowedToUseVPN(int playerID);

    bool webBusy;

    struct WebQuery
    {
        int playerID;
        std::string callsign;
        std::string ipAddress;

        std::string getURLCall()
        {
            bz_ApiString url;
            url.format("%s?showtype=4&email=%s&ip=%s", CONFIG_URL.c_str(), CONFIG_EMAIL.c_str(), ipAddress.c_str());

            debugMessage(2, "Executing the following URL job...");
            debugMessage(2, "    %s", url.c_str());

            return url;
        }
    };

    struct WhiteListEntry
    {
        bool isProxy;
        std::string callsign;
        std::string ipAddress;
    };

    std::map<std::string, WhiteListEntry> whiteList;
    std::queue<WebQuery> queryQueue;

    WebQuery currentQuery;

    // Configuration settings
    enum VpnAllowance
    {
        vNone = 0,
        vVerified,
        vAdmins,
        vPermission
    };

    VpnAllowance
        ALLOW_VPN;

    std::string
        VPN_BLOCKLIST_URL,
        VPN_REPORT_URL;

    int
        MAX_BZID;
};

BZ_PLUGIN(VPNBlocker)

const char* VPNBlocker::Name()
{
    static std::string pluginName;

    if (pluginName.empty())
        pluginName = bztk_pluginName(PLUGIN_NAME, MAJOR, MINOR, REV, BUILD);

    return pluginName.c_str();
}

void VPNBlocker::Init(const char* config)
{
    Register(bz_eAllowPlayer);
    Register(bz_ePlayerJoinEvent);

    loadConfiguration(config);

    bz_registerCustomSlashCommand("vpnblocklist", this);
}

void VPNBlocker::Cleanup()
{
    Flush();

    bz_removeCustomSlashCommand("vpnblocklist");
}

void VPNBlocker::Event(bz_EventData* eventData)
{
    switch (eventData->eventType)
    {
        case bz_eAllowPlayer:
        {
            bz_AllowPlayerEventData_V1 *data = (bz_AllowPlayerEventData_V1*)eventData;

            if (whiteList.find(data->ipAddress) != whiteList.end())
            {
                if (whiteList[data->ipAddress].isProxy && !allowedToUseVPN(data->playerID))
                {
                    data->reason = "Your host has been detected as a VPN. Please do not use a VPN while playing on this server.";
                    data->allow = false;
                }
            }
        }
        break;

        case bz_ePlayerJoinEvent:
        {
            bz_PlayerJoinPartEventData_V1 *data = (bz_PlayerJoinPartEventData_V1*)eventData;

            if (whiteList.find(data->record->ipAddress) != whiteList.end() && !allowedToUseVPN(data->playerID))
            {
                WebQuery query;
                query.playerID = data->playerID;
                query.callsign = data->record->callsign;
                query.ipAddress = data->record->ipAddress;

                queryQueue.push(query);
                nextQuery();
            }
        }
        break;

        default:
            break;
    }
}

bool VPNBlocker::SlashCommand(int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params)
{
    if (!bz_hasPerm(playerID, "playerList"))
    {
        bz_sendTextMessagef(BZ_SERVER, playerID, "You do not have permission to run the /%s command", command.c_str());
        return true;
    }

    if (command == "vpnblocklist")
    {
        bz_sendTextMessagef(BZ_SERVER, playerID, "Currently blocked VPN IPs:");

        for (auto entry : whiteList)
        {
            WhiteListEntry &e = entry.second;

            if (!e.isProxy) { continue; }

            bz_sendTextMessagef(BZ_SERVER, playerID, "    %s", e.ipAddress.c_str());
        }

        return true;
    }

    return false;
}

void VPNBlocker::URLDone(const char* /*URL*/, const void *data, unsigned int /*size*/, bool complete)
{
    std::string webData = (const char*)data;

    if (complete)
    {
        webBusy = false;
        json_object *config = json_tokener_parse(webData.c_str());

        JsonObject root;
        JsonObject::buildObject(root, config);

        WhiteListEntry entry;
        entry.ipAddress = currentQuery.ipAddress;
        entry.callsign = currentQuery.callsign;
        entry.isProxy = root.getChild("proxy").getInt();

        whiteList[entry.ipAddress] = entry;

        if (entry.isProxy)
        {
            bz_sendTextMessagef(BZ_SERVER, currentQuery.playerID, "Your host has been detected as a VPN. Please use refrain from using a VPN while playing.");
            bz_sendTextMessagef(BZ_SERVER, currentQuery.playerID, "If you believe this to be a mistake, please contact %s", bz_getServerOwner());
            bz_kickUser(currentQuery.playerID, "Your host has been detected as a VPN.", true);
        }

        nextQuery();
    }
}

void VPNBlocker::URLTimeout(const char* /*URL*/, int /* errorCode*/)
{
    webBusy = false;
    nextQuery();
}

void VPNBlocker::URLError(const char* /*URL*/, int /*errorCode*/, const char * /*errorString*/)
{
    webBusy = false;
    nextQuery();
}

void VPNBlocker::nextQuery()
{
    if (!queryQueue.empty() && !webBusy)
    {
        webBusy = true;
        currentQuery = queryQueue.front();

        bz_addURLJob(currentQuery.getURLCall().c_str(), this, NULL);

        queryQueue.pop();
    }
}

bool VPNBlocker::allowedToUseVPN(int playerID)
{
    switch (ALLOW_VPN)
    {
        case vVerified:
        {
            int bzID = 0;
            bool allowed = false;
            bz_BasePlayerRecord *pr = bz_getPlayerByIndex(playerID);

            try
            {
                bzID = std::stoi(pr->bzID.c_str());
            }
            catch (std::exception &e) {}

            if (pr->verified)
            {
                allowed = (MAX_BZID == 0 || bzID <= MAX_BZID);
            }

            bz_freePlayerRecord(pr);

            return allowed;
        }

        case vAdmins:
        {
            return bz_getAdmin(playerID);
        }

        case vPermission:
        {
            return bz_hasPerm(playerID, "ALLOWVPN");
        }

        default:
            return false;
    }
}

void VPNBlocker::loadConfiguration(const char* filePath)
{
    PluginConfig config = PluginConfig(filePath);
    std::string section = "vpnblocker";

    if (config.errors)
    {
        errorMessage(0, "Your configuration file contains errors. Shutting down...");
        bz_shutdown();
    }

    CONFIG_EMAIL = config.item(section, "API_EMAIL");
    CONFIG_URL = config.item(section, "API_URL");

    // Read settings for ALLOW_VPN
    std::string _allowVPN = bz_toupper(config.item(section, "ALLOW_VPN").c_str());

    if      (_allowVPN == "NONE")       { ALLOW_VPN = vNone; }
    else if (_allowVPN == "VERIFIED")   { ALLOW_VPN = vVerified; }
    else if (_allowVPN == "ADMINS")     { ALLOW_VPN = vAdmins; }
    else if (_allowVPN == "PERMISSION") { ALLOW_VPN = vPermission; }
    else
    {
        ALLOW_VPN = vNone;
        errorMessage(0, "An invalid setting was found for ALLOW_VPN, defaulting to: NONE");
    }

    // Read settings for MAX_BZID
    MAX_BZID = 0;

    try
    {
        MAX_BZID = std::stoi(config.item(section, "MAX_BZID"));
    }
    catch (std::exception &e) {}

    debugMessage(3, "MAX_BZID has been set to %d", MAX_BZID);

    // Read settings for VPN_BLOCKLIST_URL and VPN_REPORT_URL
    VPN_BLOCKLIST_URL = config.item(section, "VPN_BLOCKLIST_URL");
    VPN_REPORT_URL = config.item(section, "VPN_REPORT_URL");
}
