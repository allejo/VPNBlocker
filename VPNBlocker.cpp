/*
Copyright (C) 2017 Vladimir "allejo" Jimenez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <algorithm>
#include <cstdarg>
#include <map>
#include <queue>

#include "bzfsAPI.h"
#include "plugin_files.h"

#include "nlohmann/json.hpp"

using json = nlohmann::json;

// Define plug-in name
const std::string PLUGIN_NAME = "VPN Blocker";

// Define plug-in version numbering
const int MAJOR = 2;
const int MINOR = 0;
const int REV = 1;
const int BUILD = 65;
const std::string SUFFIX = "";

// Define build settings
const int VERBOSITY_LEVEL = 4;

namespace logging
{
    static void logMessage(const char *type, int level, const char *message, va_list args)
    {
        char buffer[4096];
        vsnprintf(buffer, 4096, message, args);

        bz_debugMessagef(std::min(VERBOSITY_LEVEL, level), "%s :: %s :: %s", bz_toupper(type), PLUGIN_NAME.c_str(), buffer);
    }

    static void debug(int level, const char *message, ...)
    {
        va_list args;
        va_start(args, message);
        logMessage("debug", level, message, args);
        va_end(args);
    }

    static void notice(int level, const char *message, ...)
    {
        va_list args;
        va_start(args, message);
        logMessage("notice", level, message, args);
        va_end(args);
    }

    static void warn(int level, const char *message, ...)
    {
        va_list args;
        va_start(args, message);
        logMessage("warning", level, message, args);
        va_end(args);
    }

    static void error(int level, const char *message, ...)
    {
        va_list args;
        va_start(args, message);
        logMessage("error", level, message, args);
        va_end(args);
    }
}

namespace config
{
    enum ServiceType
    {
        IPHub = 0,
        Custom,
    };

    enum VpnWhitelist
    {
        None = 0,
        Verified,
    };

    struct BlockDefinition
    {
        std::string key;
        std::string value;
    };

    struct ApiResponse
    {
        std::vector<std::string> fieldsToReport;
        BlockDefinition blockDefinition;
    };

    struct Service
    {
        ServiceType type;
        std::string url;
        std::unordered_map<std::string, std::string> queryParams;
        std::unordered_map<std::string, std::string> headers;
        ApiResponse response;

        bz_APIStringList *urlHeaders;

        Service()
        {
            ipAddress = "";
            initialized = false;
        }

        std::string sendRequestForIP(std::string ip, bz_URLHandler_V2 *handler)
        {
            init();

            ipAddress = ip;
            std::string fullUrl = getURL();

            bool urlJobSent = bz_addURLJob(fullUrl.c_str(), handler, (void *) this, NULL, urlHeaders);

            logging::debug(3, "IP check %s", urlJobSent ? "sent successfully" : "failed to send");
            logging::debug(3, "  Sending to: %s", url.c_str());

            return fullUrl;
        }

        bool shouldBlock(std::string returnResponse)
        {
            json data = json::parse(returnResponse, NULL, false);

            if (data.is_discarded())
            {
                return false;
            }

            std::string keyToBlock = response.blockDefinition.key;
            std::string valueToBlock = response.blockDefinition.value;

            if (!data.count(keyToBlock))
            {
                logging::warn(0, "The '%s' key was not found in the following JSON: %s", keyToBlock.c_str(), returnResponse.c_str());

                return false;
            }

            json value = data[keyToBlock];

            if (value.is_boolean())
            {
                return value;
            }
            else if (value.is_number())
            {
                return std::to_string((int) value) == valueToBlock;
            }
            else if (value.is_string())
            {
                return value == valueToBlock;
            }

            return false;
        }

    protected:
        std::string ipAddress;
        bool initialized;

        void init()
        {
            if (initialized)
            {
                return;
            }

            for (auto &header : headers)
            {
                bz_ApiString header_raw = bz_format("%s: %s", header.first.c_str(), header.second.c_str());
                urlHeaders->push_back(header_raw);
            }

            initialized = true;
        }

        std::string getURL()
        {
            return setPlaceholderValues(url) + getQueryParameters();
        }

        std::string getQueryParameters()
        {
            bz_APIStringList parameters;

            for (auto &param : queryParams)
            {
                parameters.push_back(param.first + "=" + bz_urlEncode(setPlaceholderValues(param.second).c_str()));
            }

            return bz_format("?%s", parameters.join("&"));
        }

        std::string setPlaceholderValues(std::string str)
        {
            bz_ApiString msg = str;

            msg.replaceAll("{ip}", ipAddress.c_str());

            return msg;
        }
    };

    struct Settings
    {
        VpnWhitelist behavior = None;
        int maxBZID;
        std::vector<Service> services;
        std::string blockListUrl;
        std::string reportUrl;

        void reportVPN(std::string ipAddress, json body, Service *srv)
        {
            if (reportUrl.empty() || !srv)
            {
                return;
            }

            bz_ApiString query = "query=reportVPN";
            bz_ApiString ip = "ip=" + ipAddress;
            bz_APIStringList parameters;

            parameters.push_back(query);
            parameters.push_back(ip);

            auto &reporting = srv->response.fieldsToReport;

            for (auto &field : reporting)
            {
                if (!body.count(field))
                {
                    continue;
                }

                json value = body[field];
                std::string value_str;

                if (value.is_number_integer())
                {
                    value_str = std::to_string((int) value);
                }
                else if (value.is_number_float())
                {
                    value_str = std::to_string((float) value);
                }
                else if (value.is_boolean())
                {
                    value_str = value ? "true" : "false";
                }
                else if (value.is_string())
                {
                    value_str = value;
                }

                bz_ApiString curr = bz_format("%s=%s", field.c_str(), bz_urlEncode(value_str.c_str()));
                parameters.push_back(curr);
            }

            bz_addURLJob(reportUrl.c_str(), NULL, parameters.join("&"));
        }
    };

    NLOHMANN_JSON_SERIALIZE_ENUM(ServiceType, {
        {IPHub, "iphub"},
        {Custom, "custom"},
    })

    NLOHMANN_JSON_SERIALIZE_ENUM(VpnWhitelist, {
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

    void to_json(json &j, const Settings &c)
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

        if (s.type == IPHub)
        {
            s.url = "http://v2.api.iphub.info/ip/{ip}";

            s.headers["X-Key"] = j.at("key").get<std::string>();

            s.response = ApiResponse();
            s.response.fieldsToReport = {"ip"};
            s.response.blockDefinition = BlockDefinition();
            s.response.blockDefinition.key = "block";
            s.response.blockDefinition.value = "1";
        }
        else if (s.type == Custom)
        {
            j.at("url").get_to(s.url);
            j.at("query_params").get_to(s.queryParams);
            j.at("headers").get_to(s.headers);
            j.at("response").get_to(s.response);
        }
    }

    void from_json(const json &j, Settings &c)
    {
        j.at("allow_vpn").get_to(c.behavior);
        j.at("max_bzid").get_to(c.maxBZID);
        j.at("services").get_to(c.services);
        j.at("block_list_url").get_to(c.blockListUrl);
        j.at("report_url").get_to(c.reportUrl);
    }
}

class VPNBlocker : public bz_Plugin, public bz_CustomSlashCommandHandler, public bz_URLHandler_V2
{
public:
    const char *Name();
    void Init(const char *config);
    void Cleanup();
    void Event(bz_EventData *eventData);

    bool SlashCommand(int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params);

    void URLDone(const char *URL, const void *data, unsigned int size, bool complete);
    void URLTimeout(const char *URL, int errorCode);
    void URLError(const char *URL, int errorCode, const char *errorString);

private:
    bool allowedToUseVPN(int playerID);

    void kickPlayersByIP(std::string ip);
    void cleanServicesMemory();
    void reloadSettings();
    void queryTick();

    std::string CONFIG_PATH;
    bool loadSuccessful;

    enum QueryType
    {
        qApiCheck = 0,
        qReportVpn,
        qFetchVpnList
    };

    struct VPNCheckRequest
    {
        QueryType type;
        int playerID;
        std::string callsign;
        std::string ipAddress;
    };

    struct VPNStatusResult
    {
        bool isProxy;
        std::string callsign;
        std::string ipAddress;
    };

    std::map<std::string, VPNStatusResult> cachedIPs;
    std::map<std::string, std::queue<std::string>> playerApiQueries;
    std::queue<VPNCheckRequest> queryQueue;

    config::Settings conf;
    VPNCheckRequest currentQuery;
};

BZ_PLUGIN(VPNBlocker)

const char *VPNBlocker::Name()
{
    static const char *pluginBuild;

    if (!pluginBuild)
    {
        pluginBuild = bz_format("%s %d.%d.%d (%d)", PLUGIN_NAME.c_str(), MAJOR, MINOR, REV, BUILD);

        if (!SUFFIX.empty())
        {
            pluginBuild = bz_format("%s - %s", pluginBuild, SUFFIX.c_str());
        }
    }

    return pluginBuild;
}

void VPNBlocker::Init(const char *config)
{
    CONFIG_PATH = config;

    reloadSettings();

    Register(bz_eAllowPlayer);
    Register(bz_ePlayerJoinEvent);

    bz_registerCustomSlashCommand("reload", this);
    bz_registerCustomSlashCommand("vpnblocker", this);
    bz_registerCustomSlashCommand("vpnblocklist", this);
    bz_registerCustomSlashCommand("vpnunblock", this);
}

void VPNBlocker::Cleanup()
{
    cleanServicesMemory();

    Flush();

    bz_removeCustomSlashCommand("reload");
    bz_removeCustomSlashCommand("vpnblocker");
    bz_removeCustomSlashCommand("vpnblocklist");
    bz_removeCustomSlashCommand("vpnunblock");
}

void VPNBlocker::Event(bz_EventData *eventData)
{
    // If the plug-in didn't load successfully, don't bother handling any events
    if (!loadSuccessful)
    {
        return;
    }

    switch (eventData->eventType)
    {
        case bz_eAllowPlayer:
        {
            bz_AllowPlayerEventData_V1 *data = (bz_AllowPlayerEventData_V1*)eventData;

            if (cachedIPs.find(data->ipAddress) != cachedIPs.end())
            {
                if (cachedIPs[data->ipAddress].isProxy && !allowedToUseVPN(data->playerID))
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

            if (cachedIPs.find(data->record->ipAddress) == cachedIPs.end() && !allowedToUseVPN(data->playerID))
            {
                VPNCheckRequest request;
                request.type = qApiCheck;
                request.playerID = data->playerID;
                request.callsign = data->record->callsign;
                request.ipAddress = data->record->ipAddress;

                queryQueue.push(request);

                logging::debug(3, "Queueing IP check for [#%d] %s (%s)", request.playerID, request.callsign.c_str(), request.ipAddress.c_str());

                queryTick();
            }
        }
        break;

        default:
            break;
    }
}

bool VPNBlocker::SlashCommand(int playerID, bz_ApiString command, bz_ApiString /*message*/, bz_APIStringList *params)
{
    if (command == "reload" && bz_hasPerm(playerID, "setAll"))
    {
        if (params->size() == 0)
        {
            reloadSettings();
        }
        else if (params->get(0) == "vpnblocker")
        {
            reloadSettings();
            return true;
        }
    }
    else if (command == "vpnblocker")
    {
        if (!bz_hasPerm(playerID, "shutdownserver"))
        {
            bz_sendTextMessagef(BZ_SERVER, playerID, "You do not have permission to run the /%s command", command.c_str());
            return true;
        }

        bz_sendTextMessagef(BZ_SERVER, playerID, "VPNBlocker Status");
        bz_sendTextMessagef(BZ_SERVER, playerID, "-----------------");
        bz_sendTextMessagef(BZ_SERVER, playerID, "Status: %s", loadSuccessful ? "Running" : "ERROR");
        bz_sendTextMessagef(BZ_SERVER, playerID, "Services: %d", conf.services.size());

        return true;
    }
    else if (command == "vpnblocklist")
    {
        if (!bz_hasPerm(playerID, "playerList"))
        {
            bz_sendTextMessagef(BZ_SERVER, playerID, "You do not have permission to run the /%s command", command.c_str());
            return true;
        }

        bz_sendTextMessagef(BZ_SERVER, playerID, "Currently blocked VPN IPs:");

        for (auto entry : cachedIPs)
        {
            VPNStatusResult &e = entry.second;

            if (!e.isProxy)
            {
                continue;
            }

            bz_sendTextMessagef(BZ_SERVER, playerID, "    %s", e.ipAddress.c_str());
        }

        return true;
    }
    else if (command == "vpnunblock")
    {
        if (!bz_hasPerm(playerID, "unban"))
        {
            bz_sendTextMessagef(BZ_SERVER, playerID, "You do not have permission to run the /%s command", command.c_str());
            return true;
        }

        if (params->size() != 1)
        {
            bz_sendTextMessagef(BZ_SERVER, playerID, "Syntax: /%s <ip>", command.c_str());
        }
        else
        {
            std::string ip = params->get(0);

            if (cachedIPs.find(ip) == cachedIPs.end() || !cachedIPs[ip].isProxy)
            {
                bz_sendTextMessagef(BZ_SERVER, playerID, "%s was not found on the VPN block list", ip.c_str());
            }
            else
            {
                cachedIPs[ip].isProxy = false;

                bz_sendTextMessagef(BZ_SERVER, eAdministrators, "%s removed %s from the VPN block list", bz_getPlayerCallsign(playerID), ip.c_str());
                bz_sendTextMessagef(BZ_SERVER, playerID, "%s removed from the VPN block list", ip.c_str());
            }
        }

        return true;
    }

    return false;
}

void VPNBlocker::URLDone(const char *URL, const void *data, unsigned int /*size*/, bool complete)
{
    std::string webData = (const char*)data;

    logging::debug(3, "Incoming URL job response was completed %ssuccessfully", complete ? "" : "un");

    if (!complete)
    {
        return;
    }

    json response = json::parse(webData, NULL, false);

    if (response.is_discarded())
    {
        logging::error(0, "Response from API query could not be parsed as JSON (%s)", URL);
        logging::error(0, "  => %s", webData.c_str());

        return;
    }

    switch (currentQuery.type)
    {
        case qApiCheck:
        {
            VPNStatusResult result;
            result.ipAddress = currentQuery.ipAddress;
            result.callsign = currentQuery.callsign;

            config::Service *srvHandler = (config::Service *) token;

            if (!srvHandler)
            {
                return;
            }

            result.isProxy = srvHandler->shouldBlock(webData);

            cachedIPs[result.ipAddress] = result;
            auto &apiQueue = playerApiQueries[currentQuery.ipAddress];

            apiQueue.pop();

            if (result.isProxy)
            {
                logging::debug(3, "IP %s has been detected as a VPN", result.ipAddress.c_str());

                if (playerApiQueries.count(currentQuery.ipAddress))
                {
                    logging::debug(VERBOSITY_LEVEL, "Clearing queued API queries for %s...", result.ipAddress.c_str());

                    while (!apiQueue.empty())
                    {
                        std::string q = apiQueue.front();

                        logging::debug(VERBOSITY_LEVEL, "Removed URL job for: %s", q.c_str());

                        bz_removeURLJob(q.c_str());
                        apiQueue.pop();
                    }
                }

                kickPlayersByIP(currentQuery.ipAddress);

                conf.reportVPN(result.ipAddress, response, srvHandler);
            }
            else
            {
                logging::debug(4, "Connection from %s not detected as a VPN", result.ipAddress.c_str());
            }
        }
        break;

        case qFetchVpnList:
        {
            for (auto &item : response)
            {
                VPNStatusResult entry;
                entry.ipAddress = item["ipAddress"];
                entry.isProxy = true;

                cachedIPs[entry.ipAddress] = entry;
            }
        }
        break;

        default:
        {
            logging::warn(0, "An unknown query type was made to URL: %s", URL);
        }
        break;
    }

    queryTick();
}

void VPNBlocker::URLTimeout(const char *URL, int /*errorCode*/)
{
    playerApiQueries[currentQuery.ipAddress].pop();

    logging::error(0, "Query timed out to %s", URL);

    queryTick();
}

void VPNBlocker::URLError(const char *URL, int /*errorCode*/, const char *errorString)
{
    playerApiQueries[currentQuery.ipAddress].pop();

    logging::error(0, "Query error to %s", URL);
    logging::error(0, "  error message: %s", errorString);

    queryTick();
}

/**
 * A query is defined a dynamic number of API calls to Services that will be made per player.
 */
void VPNBlocker::queryTick()
{
    logging::debug(3, "Preparing to send next queued IP check");

    if (queryQueue.empty())
    {
        logging::debug(4, "queryTick() was called but queue was empty");

        return;
    }

    currentQuery = queryQueue.front();

    for (auto &service : conf.services)
    {
        playerApiQueries[currentQuery.ipAddress].push(service.sendRequestForIP(currentQuery.ipAddress, this));
    }

    queryQueue.pop();

    queryTick();
}

/**
 * Check whether or not a given player ID is allowed to use a VPN based on the `allow_vpn` behavior.
 *
 * The "ALLOWVPN" permission will always supersede any settings.
 *
 * @param playerID The ID of the player to check
 *
 * @return True if the player is allowed to use a VPN.
 */
bool VPNBlocker::allowedToUseVPN(int playerID)
{
    if (bz_hasPerm(playerID, "ALLOWVPN"))
    {
        return true;
    }

    switch (conf.behavior)
    {
        case config::Verified:
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

/**
 * Load the Settings file from the same path that was stored since the plug-in was first loaded.
 */
void VPNBlocker::reloadSettings()
{
    logging::debug(VERBOSITY_LEVEL, "Loading configuration file...");

    cleanServicesMemory();

    std::string content = getFileText(CONFIG_PATH);

    if (content.empty())
    {
        loadSuccessful = false;
        logging::error(0, "The Settings file could not be loaded: %s", CONFIG_PATH.c_str());

        return;
    }

    json raw_conf = json::parse(content.c_str(), NULL, false);

    if (raw_conf.is_discarded())
    {
        loadSuccessful = false;
        logging::error(0, "Settings file failed to load due to containing invalid JSON.");

        return;
    }

    conf = raw_conf.get<config::Settings>();
    loadSuccessful = true;

    for (auto &service : conf.services)
    {
        service.urlHeaders = bz_newStringList();
    }

    logging::debug(VERBOSITY_LEVEL, "Configuration file loaded successfully with %d services", conf.services.size());
}

/**
 * Clean up the memory we've allocated for our Services.
 */
void VPNBlocker::cleanServicesMemory()
{
    logging::debug(VERBOSITY_LEVEL, "Freeing of memory has been triggered.");

    for (auto &service : conf.services)
    {
        bz_deleteStringList(service.urlHeaders);
    }
}

void VPNBlocker::kickPlayersByIP(std::string ip)
{
    bz_APIIntList *players = bz_getPlayerIndexList();

    for (unsigned int i = 0; i < players->size(); ++i)
    {
        int playerID = players->get(i);
        bz_BasePlayerRecord *pr = bz_getPlayerByIndex(playerID);

        if (pr->ipAddress == ip)
        {
            bz_kickUser(playerID, "Your host has been detected as a VPN.", true);

            bz_sendTextMessagef(BZ_SERVER, eAdministrators, "%s [%s] has been blocked as a VPN.", pr->callsign.c_str(), pr->ipAddress.c_str());
            logging::notice(0, "Player %s (%s) removed for VPN usage", pr->callsign.c_str(), pr->ipAddress.c_str());
        }

        bz_freePlayerRecord(pr);
    }

    bz_deleteIntList(players);
}
