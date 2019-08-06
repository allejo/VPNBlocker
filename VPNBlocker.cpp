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
#include <map>
#include <queue>

#include "bzfsAPI.h"
#include "plugin_config.h"
#include "plugin_files.h"

#include "nlohmann/json.hpp"

using json = nlohmann::json;

static std::string CONFIG_API_KEY;
static std::string CONFIG_URL;

// Define plug-in name
const std::string PLUGIN_NAME = "VPN Blocker";

// Define plug-in version numbering
const int MAJOR = 2;
const int MINOR = 0;
const int REV = 0;
const int BUILD = 30;

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

static void noticeMessage(int level, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    logMessage("notice", level, message, args);
    va_end(args);
}

static void debugMessage(int level, const char *message, ...)
{
    va_list args;
    va_start(args, message);
    logMessage("debug", level, message, args);
    va_end(args);
}

enum ServiceType {
    IPHub = 0,
    Custom,
};

enum VpnAllowanceBehavior {
    None = 0,
    Verified,
};

struct BlockDefinition {
    std::string key;
    std::string value;
};

struct ApiResponse {
    std::vector<std::string> fieldsToReport;
    BlockDefinition blockDefinition;
};

struct Service {
    ServiceType type;
    std::string url;
    std::unordered_map<std::string, std::string> queryParams;
    std::unordered_map<std::string, std::string> headers;
    ApiResponse response;
};

struct Configuration {
    VpnAllowanceBehavior behavior = None;
    int maxBZID;
    std::vector<Service> services;
    std::string blockListUrl;
    std::string reportUrl;
};

NLOHMANN_JSON_SERIALIZE_ENUM(ServiceType, {
    {IPHub, "iphub"},
    {Custom, "custom"},
})

NLOHMANN_JSON_SERIALIZE_ENUM(VpnAllowanceBehavior, {
    {None, "none"},
    {Verified, "verified"},
})

void to_json(json &j, const BlockDefinition &b)
{
    j = json{
        {"key", b.key},
        {"value", b.value},
    };
}

void to_json(json &j, const ApiResponse &a)
{
    j = json{
        {"report", json(a.fieldsToReport)},
        {"disallow", a.blockDefinition},
    };
}

void to_json(json &j, const Service &s)
{
    j = json{
        {"type", s.type},
        {"url", s.url},
        {"query_params", json(s.queryParams)},
        {"headers", json(s.headers)},
        {"response", s.response},
    };
}

void to_json(json &j, const Configuration &c)
{
    j = json{
        {"allow_vpn", c.behavior},
        {"max_bzid", c.maxBZID},
        {"services", c.services},
        {"block_list_url", c.blockListUrl},
        {"report_url", c.reportUrl},
    };
}

void from_json(const json &j, BlockDefinition &b)
{
    j.at("key").get_to(b.key);
    j.at("value").get_to(b.value);
}

void from_json(const json &j, ApiResponse &a)
{
    j.at("report").get_to(a.fieldsToReport);
    j.at("disallow").get_to(a.blockDefinition);
}

void from_json(const json &j, Service &s)
{
    j.at("type").get_to(s.type);
    j.at("url").get_to(s.url);

    if (s.type == IPHub)
    {
        s.headers["X-Key"] = j.at("key").get<std::string>();
    }
    else if (s.type == Custom)
    {
        j.at("query_params").get_to(s.queryParams);
        j.at("headers").get_to(s.headers);
        j.at("response").get_to(s.response);
    }
}

void from_json(const json &j, Configuration &c)
{
    j.at("allow_vpn").get_to(c.behavior);
    j.at("max_bzid").get_to(c.maxBZID);
    j.at("services").get_to(c.services);
    j.at("block_list_url").get_to(c.blockListUrl);
    j.at("report_url").get_to(c.reportUrl);
}

class VPNBlocker : public bz_Plugin, public bz_CustomSlashCommandHandler, public bz_URLHandler_V2
{
public:
    const char* Name ();
    void Init (const char* config);
    void Cleanup ();
    void Event (bz_EventData* eventData);
    bool SlashCommand (int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params);

    void URLDone (const char* URL, const void* data, unsigned int size, bool complete);
    void URLTimeout (const char* URL, int errorCode);
    void URLError (const char* URL, int errorCode, const char *errorString);

private:
    bool loadJsonConfiguration(const char *filePath);
    bool allowedToUseVPN(int playerID);
    void nextQuery();

    bool loadSuccessful;
    bool webBusy;

    enum QueryType
    {
        qApiCheck = 0,
        qReportVpn,
        qFetchVpnList
    };

    struct WebQuery
    {
        QueryType type;
        int playerID;
        std::string callsign;
        std::string ipAddress;

        std::string getURLCall()
        {
            bz_ApiString url;
            url.format("%s%s", CONFIG_URL.c_str(), ipAddress.c_str());

            debugMessage(3, "Executing the following URL job...");
            debugMessage(3, "    %s", url.c_str());

            return url;
        }
    };

    struct CachedAddressEntry
    {
        bool isProxy;
        std::string callsign;
        std::string ipAddress;
    };

    std::map<std::string, CachedAddressEntry> whiteList;
    std::queue<WebQuery> queryQueue;

    Configuration conf;
    WebQuery currentQuery;

    // Configuration settings

    std::string
        VPN_BLOCKLIST_URL,
        VPN_REPORT_URL;

    bz_APIStringList *curlHeaders;
};

BZ_PLUGIN(VPNBlocker)

const char* VPNBlocker::Name()
{
    static const char* pluginBuild;

    if (!pluginBuild)
    {
        pluginBuild = bz_format("%s %d.%d.%d (%d)", PLUGIN_NAME.c_str(), MAJOR, MINOR, REV, BUILD);
    }

    return pluginBuild;
}

void VPNBlocker::Init(const char* config)
{
    loadSuccessful = loadJsonConfiguration(config);
    webBusy = false;

    Register(bz_eAllowPlayer);
    Register(bz_ePlayerJoinEvent);

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

            if (whiteList.find(data->record->ipAddress) == whiteList.end() && !allowedToUseVPN(data->playerID))
            {
                WebQuery query;
                query.type = qApiCheck;
                query.playerID = data->playerID;
                query.callsign = data->record->callsign;
                query.ipAddress = data->record->ipAddress;

                queryQueue.push(query);

                debugMessage(3, "Queueing IP check for [#%d] %s (%s)", query.playerID, query.callsign.c_str(), query.ipAddress.c_str());

                nextQuery();
            }
        }
        break;

        default:
            break;
    }
}

bool VPNBlocker::SlashCommand(int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList* /*params*/)
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
            CachedAddressEntry &e = entry.second;

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

    debugMessage(3, "Incoming URL job response was completed %ssuccessfully", complete ? "" : "un");

    if (complete)
    {
        bz_deleteStringList(curlHeaders);

        webBusy = false;
        json response = json::parse(webData.c_str());

        switch (currentQuery.type)
        {
            case qApiCheck:
            {
                CachedAddressEntry entry;
                entry.ipAddress = currentQuery.ipAddress;
                entry.callsign = currentQuery.callsign;

                // See special value 1: https://iphub.info/api
                entry.isProxy = (response["block"] == 1);

                whiteList[entry.ipAddress] = entry;

                if (entry.isProxy)
                {
                    debugMessage(3, "IP %s has been detected as a VPN", entry.ipAddress.c_str());

                    const char* currentIP = bz_getPlayerIPAddress(currentQuery.playerID);

                    if (!currentIP)
                    {
                        noticeMessage(0, "IP %s blocked as VPN, but no player found with this IP.", entry.ipAddress.c_str());
                        return;
                    }

                    // Only kick the user if it's the same IP, otherwise another player might have joined with the same ID
                    if (strcmp(currentIP, currentQuery.ipAddress.c_str()) == 0)
                    {
                        bz_kickUser(currentQuery.playerID, "Your host has been detected as a VPN.", true);
                    }

                    bz_sendTextMessagef(BZ_SERVER, eAdministrators, "%s [%s] has been blocked as a VPN.", entry.callsign.c_str(), entry.ipAddress.c_str());
                    noticeMessage(0, "Player %s (%s) removed for VPN usage", entry.callsign.c_str(), entry.ipAddress.c_str());

                    if (VPN_REPORT_URL != "0")
                    {
                        bz_ApiString query;
                        query.format("query=%s&callsign=%s&ipAddress=%s&host=%s&country=%s&asn=%s",
                                     "reportVPN", entry.callsign.c_str(), entry.ipAddress.c_str(), response["hostname"].get<std::string>().c_str(),
                                     response["countryName"].get<std::string>().c_str(), response["asn"].get<std::string>().c_str());

                        bz_addURLJob(VPN_REPORT_URL.c_str(), NULL, query.c_str());
                    }
                }
                else
                {
                    debugMessage(4, "Connection from %s not detected as a VPN", entry.ipAddress.c_str());
                }
            }
            break;

            case qFetchVpnList:
            {
                for (auto item : response)
                {
                    CachedAddressEntry entry;
                    entry.ipAddress = item["ipAddress"];
                    entry.isProxy = true;

                    whiteList[entry.ipAddress] = entry;
                }
            }
            break;

            default:
            {
                warnMessage(0, "An unknown query type was made to URL: %s", currentQuery.getURLCall().c_str());
            }
            break;
        }

        nextQuery();
    }
}

void VPNBlocker::URLTimeout(const char* URL, int /*errorCode*/)
{
    errorMessage(0, "Query timed out to %s", URL);

    webBusy = false;
    nextQuery();
}

void VPNBlocker::URLError(const char* URL, int /*errorCode*/, const char* errorString)
{
    errorMessage(0, "Query error to %s", URL);
    errorMessage(0, "  error message: %s", errorString);

    webBusy = false;
    nextQuery();
}

void VPNBlocker::nextQuery()
{
    if (CONFIG_API_KEY.empty() || CONFIG_URL.empty())
    {
        errorMessage(0, "Either `API_KEY` or `API_URL` has not been configured correctly; no URL call can be made.");
        return;
    }

    debugMessage(3, "Preparing to send next queued IP check");

    if (!queryQueue.empty() && !webBusy)
    {
        webBusy = true;
        currentQuery = queryQueue.front();

        curlHeaders = bz_newStringList();
        curlHeaders->push_back("X-Key: " + CONFIG_API_KEY);

        bool urlJobSent = bz_addURLJob(currentQuery.getURLCall().c_str(), this, NULL, NULL, curlHeaders);

        debugMessage(3, "IP check %s", urlJobSent ? "sent successfully" : "failed to send");

        queryQueue.pop();
    }
    else
    {
        if (webBusy)
        {
            debugMessage(3, "Web jobs are currently busy");
        }

        if (queryQueue.empty())
        {
            debugMessage(3, "nextQuery() was called but the queue was empty");
        }
    }
}

bool VPNBlocker::allowedToUseVPN(int playerID)
{
    if (bz_hasPerm(playerID, "ALLOWVPN"))
    {
        return true;
    }

    switch (conf.behavior)
    {
        case Verified:
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
                allowed = (conf.maxBZID == 0 || bzID <= conf.maxBZID);
            }

            bz_freePlayerRecord(pr);

            return allowed;
        }

        default:
            return false;
    }
}

bool VPNBlocker::loadJsonConfiguration(const char *filePath)
{
    std::string content = getFileText(filePath);

    if (content.empty())
    {
        errorMessage(0, "The configuration file could not be loaded: %s", filePath);
        return false;
    }

    json raw_conf = json::parse(content.c_str(), NULL, false);

    if (raw_conf.is_discarded())
    {
        errorMessage(0, "Configuration file failed to load due to containing invalid JSON.");
        return false;
    }

    conf = raw_conf.get<Configuration>();

    return true;
}
