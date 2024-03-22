/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "network_security_config.h"

#include <sys/stat.h>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#include <dlfcn.h>
#include <regex>
#include <sstream>
#include <securec.h>

#include "openssl/evp.h"
#include "net_mgr_log_wrapper.h"
#include "net_manager_constants.h"
#include "netmanager_base_common_utils.h"
#include "net_bundle.h"

namespace OHOS {
namespace NetManagerStandard {

const std::string TAG_NETWORK_SECURITY_CONFIG("network-security-config");
const std::string TAG_BASE_CONFIG("base-config");
const std::string TAG_DOMAIN_CONFIG("domain-config");
const std::string TAG_TRUST_ANCHORS("trust-anchors");
const std::string TAG_CERTIFICATES("certificates");
const std::string TAG_DOMAINS("domains");
const std::string TAG_INCLUDE_SUBDOMAINS("include-subdomains");
const std::string TAG_NAME("name");
const std::string TAG_PIN_SET("pin-set");
const std::string TAG_EXPIRATION("expiration");
const std::string TAG_PIN("pin");
const std::string TAG_DIGEST_ALGORITHM("digest-algorithm");
const std::string TAG_DIGEST("digest");

const std::string REHASHD_CA_CERTS_DIR("/data/storage/el2/base/files/rehashed_ca_certs");
#ifdef WINDOWS_PLATFORM
const char OS_PATH_SEPARATOR = '\\';
#else
const char OS_PATH_SEPARATOR = '/';
#endif

#ifdef __LP64__
const std::string LIB_LOAD_PATH = "/system/lib64/platformsdk/libnet_bundle_utils.z.so";
#else
const std::string LIB_LOAD_PATH = "/system/lib/platformsdk/libnet_bundle_utils.z.so";
#endif

using GetNetBundleClass = INetBundle *(*)();

NetworkSecurityConfig::NetworkSecurityConfig()
{
    if (GetConfig() != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Fail to get NetworkSecurityConfig");
    } else {
        NETMGR_LOG_D("Succeed to get NetworkSecurityConfig");
    }
}

NetworkSecurityConfig::~NetworkSecurityConfig() {}

NetworkSecurityConfig &NetworkSecurityConfig::GetInstance()
{
    static NetworkSecurityConfig gInstance;
    return gInstance;
}

bool NetworkSecurityConfig::IsCACertFileName(const char *fileName)
{
    std::string str;
    auto ext = strrchr(fileName, '.');
    if (ext != nullptr) {
        str = ext + 1;
    }

    for (auto &c : str) {
        c = tolower(c);
    }

    return (str == "pem" || str == "crt");
}

void NetworkSecurityConfig::GetCAFilesFromPath(const std::string caPath, std::vector<std::string> &caFiles)
{
    DIR *dir = opendir(caPath.c_str());
    if (dir == nullptr) {
        NETMGR_LOG_E("open CA path[%{public}s] fail. [%{public}d]", caPath.c_str(), errno);
        return;
    }

    struct dirent *entry = readdir(dir);
    while (entry != nullptr) {
        if (IsCACertFileName(entry->d_name)) {
            if (caPath.back() != OS_PATH_SEPARATOR) {
                caFiles.push_back(caPath + OS_PATH_SEPARATOR + entry->d_name);
            } else {
                caFiles.push_back(caPath + entry->d_name);
            }
            NETMGR_LOG_D("Read CA File [%{public}s] from CA Path", entry->d_name);
        }
        entry = readdir(dir);
    }

    closedir(dir);
}

void NetworkSecurityConfig::AddSurfixToCACertFileName(const std::string &caPath, std::set<std::string> &allFileNames,
                                                      std::string &caFile)
{
    uint32_t count = 0;
    for (auto &fileName : allFileNames) {
        if (fileName.find(caFile) != std::string::npos) {
            count++;
        }
    }

    caFile = caFile + '.' + std::to_string(count);
    allFileNames.insert(caFile);
}

X509 *NetworkSecurityConfig::ReadCertFile(const std::string &fileName)
{
    std::ifstream certFile(fileName.c_str());
    if (!certFile.is_open()) {
        NETMGR_LOG_E("Fail to read cert fail [%{public}s]", fileName.c_str());
        return nullptr;
    }

    std::stringstream certStream;
    certStream << certFile.rdbuf();

    const std::string &certData = certStream.str();
    BIO *bio = BIO_new_mem_buf(certData.c_str(), -1);
    if (bio == nullptr) {
        NETMGR_LOG_E("Fail to call BIO_new_mem_buf");
        return nullptr;
    }

    X509 *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (x509 == nullptr) {
        NETMGR_LOG_E("Fail to call PEM_read_bio_X509.");
    }

    BIO_free(bio);
    return x509;
}

std::string NetworkSecurityConfig::GetRehashedCADirName(const std::string &caPath)
{
    unsigned char hashedHex[EVP_MAX_MD_SIZE];
    auto ret = EVP_Digest(reinterpret_cast<const unsigned char *>(caPath.c_str()), caPath.size(), hashedHex, nullptr,
                          EVP_sha256(), nullptr);
    if (ret != 1) {
        return "";
    }

    /* Encode the hashed string by base16 */
    constexpr unsigned int HASHED_DIR_NAME_LEN = 32;
    constexpr unsigned int BASE16_ELE_SIZE = 2;
    char hashedStr[HASHED_DIR_NAME_LEN + 1] = {0};
    for (unsigned int i = 0; i < HASHED_DIR_NAME_LEN / BASE16_ELE_SIZE; i++) {
        if (sprintf_s(&hashedStr[BASE16_ELE_SIZE * i], sizeof(hashedStr) - BASE16_ELE_SIZE * i, "%02x", hashedHex[i]) <
            0) {
            return "";
        }
    }

    return hashedStr;
}

std::string NetworkSecurityConfig::BuildRehasedCAPath(const std::string &caPath)
{
    if (access(REHASHD_CA_CERTS_DIR.c_str(), F_OK) == -1) {
        if (mkdir(REHASHD_CA_CERTS_DIR.c_str(), S_IRWXU | S_IRWXG) == -1) {
            NETMGR_LOG_E("Fail to make a rehased caCerts dir [%{public}d]", errno);
            return "";
        }
    }

    auto dirName = GetRehashedCADirName(caPath);
    if (dirName.empty()) {
        NETMGR_LOG_E("Fail to make a rehased caCerts dir for [%{public}s]", caPath.c_str());
        return "";
    }

    auto rehashedCertpath = REHASHD_CA_CERTS_DIR + OS_PATH_SEPARATOR + dirName;
    if (access(rehashedCertpath.c_str(), F_OK) == -1) {
        if (mkdir(rehashedCertpath.c_str(), S_IRWXU | S_IRWXG) == -1) {
            NETMGR_LOG_E("Fail to make a rehased caCerts dir [%{public}d]", errno);
            return "";
        }
    }

    NETMGR_LOG_D("Build dir [%{public}s]", rehashedCertpath.c_str());
    return rehashedCertpath;
}

std::string NetworkSecurityConfig::GetRehasedCAPath(const std::string &caPath)
{
    if (access(REHASHD_CA_CERTS_DIR.c_str(), F_OK) == -1) {
        return "";
    }

    auto dirName = GetRehashedCADirName(caPath);
    if (dirName.empty()) {
        return "";
    }

    auto rehashedCertpath = REHASHD_CA_CERTS_DIR + OS_PATH_SEPARATOR + dirName;
    if (access(rehashedCertpath.c_str(), F_OK) == -1) {
        return "";
    }

    return rehashedCertpath;
}

std::string NetworkSecurityConfig::ReHashCAPathForX509(const std::string &caPath)
{
    std::set<std::string> allFiles;
    std::vector<std::string> caFiles;

    GetCAFilesFromPath(caPath, caFiles);
    if (caFiles.empty()) {
        NETMGR_LOG_D("No customized CA certs.");
        return "";
    }

    auto rehashedCertpath = BuildRehasedCAPath(caPath);
    if (rehashedCertpath.empty()) {
        return rehashedCertpath;
    }

    for (auto &caFile : caFiles) {
        auto x509 = ReadCertFile(caFile);
        if (x509 == nullptr) {
            continue;
        }

        constexpr int X509_HASH_LEN = 16;
        char buf[X509_HASH_LEN] = {0};
        if (sprintf_s(buf, sizeof(buf), "%08lx", X509_subject_name_hash(x509)) < 0) {
            return "";
        }
        X509_free(x509);
        x509 = nullptr;

        std::string hashName(buf);
        AddSurfixToCACertFileName(rehashedCertpath, allFiles, hashName);

        std::string rehashedCaFile = rehashedCertpath + OS_PATH_SEPARATOR + hashName;
        if (access(rehashedCaFile.c_str(), F_OK) == 0) {
            NETMGR_LOG_D("File [%{public}s] exists.", rehashedCaFile.c_str());
            continue;
        }

        std::ifstream src(caFile);
        std::ofstream dst(rehashedCaFile);
        if (!src.is_open() || !dst.is_open()) {
            NETMGR_LOG_E("fail to open cert file.");
            continue;
        }
        dst << src.rdbuf();
        NETMGR_LOG_D("Rehased cert generated. [%{public}s]", rehashedCaFile.c_str());
    }

    return rehashedCertpath;
}

int32_t NetworkSecurityConfig::CreateRehashedCertFiles()
{
    for (auto &cert : baseConfig_.trustAnchors_.certs_) {
        ReHashCAPathForX509(cert);
    }
    for (auto &domainConfig : domainConfigs_) {
        for (auto &cert : domainConfig.trustAnchors_.certs_) {
            ReHashCAPathForX509(cert);
        }
    }

    return NETMANAGER_SUCCESS;
}

bool NetworkSecurityConfig::ValidateDate(const std::string &dateStr)
{
    return true;
}

int32_t NetworkSecurityConfig::GetConfig()
{
    std::string json;
    auto ret = GetJsonFromBundle(json);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("Failed to get json from bundler manager.");
        return ret;
    }

    ret = ParseJsonConfig(json);
    if (ret != NETMANAGER_SUCCESS) {
        return ret;
    }

    ret = CreateRehashedCertFiles();
    if (ret != NETMANAGER_SUCCESS) {
        return ret;
    }

    NETMGR_LOG_D("NetworkSecurityConfig Cached.");
    return NETMANAGER_SUCCESS;
}

__attribute__((no_sanitize("cfi"))) std::string NetworkSecurityConfig::GetJsonProfile()
{
    void *handler = dlopen(LIB_LOAD_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (handler == nullptr) {
        NETMGR_LOG_E("load failed, failed reason : %{public}s", dlerror());
        return "";
    }
    GetNetBundleClass getNetBundle = (GetNetBundleClass)dlsym(handler, "GetNetBundle");
    if (getNetBundle == nullptr) {
        NETMGR_LOG_E("GetNetBundle faild, failed reason : %{public}s", dlerror());
        dlclose(handler);
        return "";
    }
    auto netBundle = getNetBundle();
    if (netBundle == nullptr) {
        NETMGR_LOG_E("netBundle is nullptr");
        dlclose(handler);
        return "";
    }
    std::string jsonProfile;
    auto ret = netBundle->GetJsonFromBundle(jsonProfile);
    if (ret != NETMANAGER_SUCCESS) {
        NETMGR_LOG_E("get profile failed");
        dlclose(handler);
        return "";
    }
    NETMGR_LOG_D("get profile success");
    dlclose(handler);
    return jsonProfile;
}

int32_t NetworkSecurityConfig::GetJsonFromBundle(std::string &jsonProfile)
{
    static std::string json = GetJsonProfile();
    if (json.empty()) {
		NETMGR_LOG_E("json is nullptr");
        return NETMANAGER_ERR_INTERNAL;
    }
    jsonProfile = json;
    return NETMANAGER_SUCCESS;
}

void NetworkSecurityConfig::ParseJsonTrustAnchors(const Json::Value &root, const cJSON* const object,
                                                  TrustAnchors &trustAnchors)
{
    if (!root.isArray()) {
        return;
    }

    uint32_t sizeTd = cJSON_GetArraySize(object);
    for (uint32_t j = 0; j < sizeTd; j++) {
        cJSON *trustAnchorsItem = cJSON_GetArrayItem(object, j);
        cJSON *certificates = cJSON_GetObjectItem(trustAnchorsItem, TAG_CERTIFICATES.c_str());
        std::string cert = cJSON_GetStringValue(certificates);
        NETMGR_LOG_E("ParseJsonTrustAnchors certificates: %{public}s", cert.c_str());
    }

    auto size = root.size();
    for (uint32_t i = 0; i < size; i++) {
        if (root[i].isMember(TAG_CERTIFICATES.c_str()) && root[i][TAG_CERTIFICATES.c_str()].isString()) {
            auto cert_path = root[i][TAG_CERTIFICATES.c_str()].asString();
            NETMGR_LOG_E("ParseJsonTrustAnchors cert_path: %{public}s", cert_path.c_str());
            trustAnchors.certs_.push_back(cert_path);
        }
    }

    return;
}

void NetworkSecurityConfig::ParseJsonDomains(const Json::Value &root, const cJSON* const object,
                                             std::vector<Domain> &domains)
{
    if (!root.isArray()) {
        return;
    }

    uint32_t sizeTd = cJSON_GetArraySize(object);
    for (uint32_t j = 0; j < sizeTd; j++) {
        Domain domainTs;
        cJSON *domainItem = cJSON_GetArrayItem(object, j);
        cJSON *name = cJSON_GetObjectItem(domainItem, TAG_NAME.c_str());
        if (cJSON_IsNull(name) && !cJSON_IsString(name)) {
            continue;
        }
        domainTs.domainName_ = cJSON_GetStringValue(name);
        NETMGR_LOG_E("ParseJsonDomains name: %{public}s", domainTs.domainName_.c_str());
        cJSON *subDomains = cJSON_GetObjectItem(domainItem, TAG_INCLUDE_SUBDOMAINS.c_str());
        if (!cJSON_IsNull(subDomains) && cJSON_IsBool(subDomains)) {
            domainTs.includeSubDomains_ = cJSON_IsTrue(subDomains) ? true : false;
            NETMGR_LOG_E("ParseJsonDomains subDomains: %{public}d", domainTs.includeSubDomains_);
        } else {
            domainTs.includeSubDomains_ = true;
        }
    }

    auto size = root.size();
    for (uint32_t i = 0; i < size; i++) {
        Domain domain;
        if (!root[i].isMember(TAG_NAME.c_str()) || !root[i][TAG_NAME.c_str()].isString()) {
            continue;
        }
        domain.domainName_ = root[i][TAG_NAME.c_str()].asString();
        NETMGR_LOG_E("ParseJsonDomains domainName_: %{public}s", domain.domainName_.c_str());
        if (root[i].isMember(TAG_INCLUDE_SUBDOMAINS.c_str()) && root[i][TAG_INCLUDE_SUBDOMAINS.c_str()].isBool()) {
            domain.includeSubDomains_ = root[i][TAG_INCLUDE_SUBDOMAINS.c_str()].asBool();
            NETMGR_LOG_E("ParseJsonDomains subDomains: %{public}d", domain.includeSubDomains_);
        } else {
            domain.includeSubDomains_ = true;
        }

        domains.push_back(domain);
    }

    return;
}

void NetworkSecurityConfig::ParseJsonPinSet(const Json::Value &root, const cJSON* const object, PinSet &pinSet)
{
    if (root.isNull()) {
        return;
    }
    cJSON *expiration = cJSON_GetObjectItem(object, TAG_EXPIRATION.c_str());
    if (!cJSON_IsNull(expiration) && cJSON_IsString(expiration)) {
        NETMGR_LOG_E("ParseJsonPinSet expiration: %{public}s", expiration->valuestring);
    }
    cJSON *pins = cJSON_GetObjectItem(object, TAG_PIN.c_str());
    if (cJSON_IsNull(pins) || !cJSON_IsArray(pins)) {
        return;
    }
    uint32_t sizeTd = cJSON_GetArraySize(pins);
    for (uint32_t j = 0; j < sizeTd; j++) {
        cJSON *pinsItem = cJSON_GetArrayItem(pins, j);
        cJSON *digestAlgorithm = cJSON_GetObjectItem(pinsItem, TAG_DIGEST_ALGORITHM.c_str());
        if (cJSON_IsNull(digestAlgorithm) || !cJSON_IsString(digestAlgorithm)) {
            continue;
        }
        NETMGR_LOG_E("ParseJsonPinSet digestAlgorithm: %{public}s", digestAlgorithm->valuestring);
        cJSON *digest = cJSON_GetObjectItem(pinsItem, TAG_DIGEST.c_str());
        if (cJSON_IsNull(digest) || !cJSON_IsString(digest)) {
            continue;
        }
        NETMGR_LOG_E("ParseJsonPinSet digest: %{public}s", digest->valuestring);
    }
    if (root.isMember(TAG_EXPIRATION.c_str()) && root[TAG_EXPIRATION.c_str()].isString()) {
        pinSet.expiration_ = root[TAG_EXPIRATION.c_str()].asString();
        NETMGR_LOG_E("ParseJsonPinSet pinSet.expiration_: %{public}s", pinSet.expiration_.c_str());
    }
    if (!root.isMember(TAG_PIN.c_str()) || !root[TAG_PIN.c_str()].isArray()) {
        return;
    }
    auto pinRoot = root[TAG_PIN.c_str()];
    auto size = pinRoot.size();
    for (uint32_t i = 0; i < size; i++) {
        if (pinRoot[i].isMember(TAG_DIGEST_ALGORITHM.c_str()) && pinRoot[i][TAG_DIGEST_ALGORITHM.c_str()].isString() &&
            pinRoot[i].isMember(TAG_DIGEST.c_str()) && pinRoot[i][TAG_DIGEST.c_str()].isString()) {
            Pin pin;
            pin.digestAlgorithm_ = pinRoot[i][TAG_DIGEST_ALGORITHM.c_str()].asString();
            NETMGR_LOG_E("ParseJsonPinSet pin.digestAlgorithm_: %{public}s", pin.digestAlgorithm_.c_str());
            pin.digest_ = pinRoot[i][TAG_DIGEST.c_str()].asString();
            NETMGR_LOG_E("ParseJsonPinSet pin.digest_: %{public}s", pin.digest_.c_str());
            pinSet.pins_.push_back(pin);
        }
    }
    return;
}

void NetworkSecurityConfig::ParseJsonBaseConfig(const Json::Value &root, const cJSON* const object,
                                                BaseConfig &baseConfig)
{
    if (root.isNull()) {
        return;
    }

    cJSON *trustAnchors = cJSON_GetObjectItem(object, TAG_TRUST_ANCHORS.c_str());
    if (trustAnchors == nullptr) {
        return;
    }

    ParseJsonTrustAnchors(root[TAG_TRUST_ANCHORS.c_str()], trustAnchors, baseConfig.trustAnchors_);
}

void NetworkSecurityConfig::ParseJsonDomainConfigs(const Json::Value &root, const cJSON* const object,
                                                   std::vector<DomainConfig> &domainConfigs)
{
    if (!root.isArray()) {
        return;
    }
    uint32_t sizeTd = cJSON_GetArraySize(object);
    NETMGR_LOG_E("ParseJsonDomainConfigs sizeTd: %{public}u", sizeTd);
    auto size = root.size();
    NETMGR_LOG_E("ParseJsonDomainConfigs size: %{public}u", size);
    for (uint32_t i = 0; i < size; i++) {
        cJSON *domainConfigItem = cJSON_GetArrayItem(object, i);
        DomainConfig domainConfig;
        cJSON *domains = cJSON_GetObjectItem(domainConfigItem, TAG_DOMAINS.c_str());
        ParseJsonDomains(root[i][TAG_DOMAINS.c_str()], domains, domainConfig.domains_);
        cJSON *trustAnchors = cJSON_GetObjectItem(domainConfigItem, TAG_TRUST_ANCHORS.c_str());
        ParseJsonTrustAnchors(root[i][TAG_TRUST_ANCHORS.c_str()], trustAnchors, domainConfig.trustAnchors_);
        cJSON *pinSet = cJSON_GetObjectItem(domainConfigItem, TAG_PIN_SET.c_str());
        ParseJsonPinSet(root[i][TAG_PIN_SET.c_str()], pinSet, domainConfig.pinSet_);

        domainConfigs.push_back(domainConfig);
    }

    return;
}

int32_t NetworkSecurityConfig::ParseJsonConfig(const std::string &content)
{
    if (content.empty()) {
        return NETMANAGER_SUCCESS;
    }

    cJSON *json = cJSON_Parse(content.c_str());
    if (json == nullptr) {
        NETMGR_LOG_E("Failed to parse network json profile.");
        return NETMANAGER_ERR_INTERNAL;
    }
    NETMGR_LOG_E("ParseJsonConfig : %{public}s", cJSON_Print(json));

    cJSON *networkSecurityConfig = cJSON_GetObjectItem(json, TAG_NETWORK_SECURITY_CONFIG.c_str());
    if (networkSecurityConfig == nullptr) {
        NETMGR_LOG_E("networkSecurityConfig is null");
        return NETMANAGER_SUCCESS;
    }
    cJSON *baseConfig = cJSON_GetObjectItem(networkSecurityConfig, TAG_BASE_CONFIG.c_str());
    if (baseConfig == nullptr) {
        NETMGR_LOG_E("baseConfig is null");
        return NETMANAGER_SUCCESS;
    }
    cJSON *domainConfig = cJSON_GetObjectItem(networkSecurityConfig, TAG_DOMAIN_CONFIG.c_str());
    if (domainConfig != nullptr) {
        NETMGR_LOG_E("domainConfig is null");
        return NETMANAGER_SUCCESS;
    }

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    JSONCPP_STRING errs;

    bool isSuccess = reader->parse(content.c_str(), content.c_str() + content.length(), &root, &errs);
    if (!isSuccess) {
        NETMGR_LOG_E("Failed to parse network json profile.");
        return NETMANAGER_ERR_INTERNAL;
    }

    if (root.isNull() || !root.isMember(TAG_NETWORK_SECURITY_CONFIG.c_str())) {
        return NETMANAGER_SUCCESS;
    }

    Json::StyledWriter styled_writer;
    std::string json_str = styled_writer.write(root);
    NETMGR_LOG_E("ParseJsonConfig root: %{public}s", json_str.c_str());

    ParseJsonBaseConfig(root[TAG_NETWORK_SECURITY_CONFIG.c_str()][TAG_BASE_CONFIG.c_str()], baseConfig, baseConfig_);

    ParseJsonDomainConfigs(root[TAG_NETWORK_SECURITY_CONFIG.c_str()][TAG_DOMAIN_CONFIG.c_str()],
                           domainConfig, domainConfigs_);
    cJSON_Delete(json);
    return NETMANAGER_SUCCESS;
}

int32_t NetworkSecurityConfig::GetPinSetForHostName(const std::string &hostname, std::string &pins)
{
    if (hostname.empty()) {
        NETMGR_LOG_E("Failed to get pinset, hostname is empty.");
        return NETMANAGER_SUCCESS;
    }

    PinSet *pPinSet = nullptr;
    for (auto &domainConfig : domainConfigs_) {
        for (const auto &domain : domainConfig.domains_) {
            if (hostname == domain.domainName_) {
                pPinSet = &domainConfig.pinSet_;
                break;
            } else if (domain.includeSubDomains_ && CommonUtils::UrlRegexParse(hostname, domain.domainName_)) {
                pPinSet = &domainConfig.pinSet_;
                break;
            }
        }
        if (pPinSet != nullptr) {
            break;
        }
    }

    if (pPinSet == nullptr) {
        NETMGR_LOG_D("No pinned pubkey configured.");
        return NETMANAGER_SUCCESS;
    }

    if (!ValidateDate(pPinSet->expiration_)) {
        return NETMANAGER_ERR_PERMISSION_DENIED;
    }

    std::stringstream ss;
    for (const auto &pin : pPinSet->pins_) {
        NETMGR_LOG_D("Got pinnned pubkey %{public}s", pin.digest_.c_str());
        ss << pin.digestAlgorithm_ << "//" << pin.digest_ << ";";
    }

    pins = ss.str();
    if (!pins.empty()) {
        pins.pop_back();
    }

    return NETMANAGER_SUCCESS;
}

int32_t NetworkSecurityConfig::GetTrustAnchorsForHostName(const std::string &hostname, std::vector<std::string> &certs)
{
    if (hostname.empty()) {
        NETMGR_LOG_E("Failed to get trust anchors, hostname is empty.");
        return NETMANAGER_SUCCESS;
    }

    TrustAnchors *pTrustAnchors = nullptr;
    for (auto &domainConfig: domainConfigs_) {
        for (const auto &domain: domainConfig.domains_) {
            if (hostname == domain.domainName_) {
                pTrustAnchors = &domainConfig.trustAnchors_;
                break;
            } else if (domain.includeSubDomains_ && CommonUtils::UrlRegexParse(hostname, domain.domainName_)) {
                pTrustAnchors = &domainConfig.trustAnchors_;
                break;
            }
        }
        if (pTrustAnchors != nullptr) {
            break;
        }
    }

    if (pTrustAnchors == nullptr) {
        pTrustAnchors = &baseConfig_.trustAnchors_;
    }

    for (auto &certPath : pTrustAnchors->certs_) {
        auto rehashedCertpath = GetRehasedCAPath(certPath);
        if (!rehashedCertpath.empty()) {
            certs.push_back(rehashedCertpath);
        }
        NETMGR_LOG_D("Got cert [%{public}s] [%{public}s]", certPath.c_str(), rehashedCertpath.c_str());
    }

    if (certs.empty()) {
        NETMGR_LOG_D("No customized CA certs configured.");
    }

    return NETMANAGER_SUCCESS;
}

void NetworkSecurityConfig::DumpConfigs()
{
    NETMGR_LOG_I("DumpConfigs:baseConfig_.trustAnchors_.certs");
    for (auto &cert : baseConfig_.trustAnchors_.certs_) {
        NETMGR_LOG_I("[%{public}s]", cert.c_str());
    }

    NETMGR_LOG_I("DumpConfigs:domainConfigs_");
    for (auto &domainConfig : domainConfigs_) {
        NETMGR_LOG_I("=======================");
        for (auto &domain : domainConfig.domains_) {
            NETMGR_LOG_I("domainConfigs_.domains_[%{public}s][%{public}s]", domain.domainName_.c_str(),
                         domain.includeSubDomains_ ? "include_subDomain" : "not_include_subDomain");
        }
        NETMGR_LOG_I("domainConfigs_.domains_.pinSet_.expiration_[%{public}s]",
                     domainConfig.pinSet_.expiration_.c_str());
        for (auto &pin : domainConfig.pinSet_.pins_) {
            NETMGR_LOG_I("domainConfigs_.domains_.pinSet_.pins[%{public}s][%{public}s]", pin.digestAlgorithm_.c_str(),
                         pin.digest_.c_str());
        }
        for (auto &cert : domainConfig.trustAnchors_.certs_) {
            NETMGR_LOG_I("domainConfigs_.domains_.trustAnchors_.certs_[%{public}s]", cert.c_str());
        }
    }
}

} // namespace NetManagerStandard
} // namespace OHOS
