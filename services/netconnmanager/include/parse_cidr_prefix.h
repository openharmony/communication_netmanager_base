#ifndef NETMANAGER_PARSE_CIDR_PREFIX_H
#define NETMANAGER_PARSE_CIDR_PREFIX_H

#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>

namespace OHOS {
namespace NetManagerStandard {
inline bool ParseCidrPrefixLen(const std::string &text, int32_t &out)
{
    if (text.empty()) {
        return false;
    }
    int32_t value = 0;
    const char *first = text.data();
    const char *last = first + text.size();
    auto result = std::from_chars(first, last, value);
    if (result.ec != std::errc() || result.ptr != last) {
        return false;
    }
    out = value;
    return true;
}
} // namespace NetManagerStandard
} // namespace OHOS
#endif
