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

#include <json/json.h>
#include <queue>

#include "bzfsAPI.h"
#include "plugin_utils.h"
#include "JsonObject.h"

static std::string CONFIG_EMAIL;
static std::string CONFIG_URL;

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

    virtual void loadConfiguration(const char* filePath);

private:
    virtual void nextQuery();

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
};

BZ_PLUGIN(VPNBlocker)

const char* VPNBlocker::Name ()
{
    return "VPN Blocker";
}

void VPNBlocker::Init (const char* config)
{
    Register(bz_eAllowPlayer);

    loadConfiguration(config);

    bz_registerCustomSlashCommand("vpnblocklist", this);
}

void VPNBlocker::Cleanup ()
{
    Flush();

    bz_removeCustomSlashCommand("vpnblocklist");
}

void VPNBlocker::Event (bz_EventData* eventData)
{
    switch (eventData->eventType)
    {
        case bz_eAllowPlayer:
        {
            bz_AllowPlayerEventData_V1 *data = (bz_AllowPlayerEventData_V1*)eventData;

            if (whiteList.find(data->ipAddress) != whiteList.end())
            {
                if (whiteList[data->ipAddress].isProxy)
                {
                    data->reason = "Your host has been detected as a VPN. Please do not use a VPN while playing on this server.";
                    data->allow = false;
                }
            }
            else
            {
                WebQuery query;
                query.playerID = data->playerID;
                query.callsign = data->callsign;
                query.ipAddress = data->ipAddress;

                queryQueue.push(query);
                nextQuery();
            }
        }
        break;

        default: break;
    }
}

bool VPNBlocker::SlashCommand (int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params)
{
    if (command == "vpnblocklist")
    {

        return true;
    }

    return false;
}

void VPNBlocker::URLDone(const char* /*URL*/, const void *data, unsigned int size, bool complete)
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
            bz_sendTextMessage(BZ_SERVER, currentQuery.playerID, "Your host has been detected as a VPN. Please use refrain from using a VPN while playing.");
            bz_sendTextMessage(BZ_SERVER, currentQuery.playerID, "If you believe this to be a mistake, please contact the server owner.");
            bz_kickUser(currentQuery.playerID, "Your host has been detected as VPN.", true);
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

        bz_debugMessagef(2, "DEBUG :: VPNBlocker :: Executing the following URL job...");
        bz_debugMessagef(2, "DEBUG :: VPNBlocker ::    %s", currentQuery.getURLCall().c_str());
        bz_addURLJob(currentQuery.getURLCall().c_str(), this, NULL);

        queryQueue.pop();
    }
}

void VPNBlocker::loadConfiguration (const char* filePath)
{
    PluginConfig config = PluginConfig(filePath);
    std::string section = "vpnblocker";

    CONFIG_EMAIL = config.item(section, "API_EMAIL");
    CONFIG_URL = config.item(section, "API_URL");
}
