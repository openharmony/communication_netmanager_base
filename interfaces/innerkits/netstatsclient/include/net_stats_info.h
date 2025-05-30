/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef NET_STATS_INFO_H
#define NET_STATS_INFO_H

#include "parcel.h"

namespace OHOS {
namespace NetManagerStandard {
#define NET_SYMBOL_VISIBLE __attribute__ ((visibility("default")))
struct NET_SYMBOL_VISIBLE NetStatsInfo final : public Parcelable {
    uint32_t uid_ = 0;
    std::string iface_;
    std::string ident_;
    uint64_t date_ = 0;
    uint64_t rxBytes_ = 0;
    uint64_t txBytes_ = 0;
    uint64_t rxPackets_ = 0;
    uint64_t txPackets_ = 0;
    uint32_t flag_ = 0;
    int32_t userId_ = 0;

    inline const std::string UidData() const
    {
        return std::to_string(uid_) + "," + ident_ + "," + iface_ + "," + std::to_string(date_) + "," +
               std::to_string(rxBytes_) + "," + std::to_string(rxPackets_) + "," + std::to_string(txBytes_) + "," +
               std::to_string(txPackets_) + "," + std::to_string(flag_) + "," + std::to_string(userId_);
    }

    inline const std::string IfaceData() const
    {
        return "'" + iface_ + "'," + std::to_string(date_) + "," + std::to_string(rxBytes_) + "," +
               std::to_string(rxPackets_) + "," + std::to_string(txBytes_) + "," + std::to_string(txPackets_);
    }

    inline uint64_t GetStats() const
    {
        return rxBytes_ + txBytes_;
    }

    inline bool Equals(const NetStatsInfo &info) const
    {
        return info.uid_ == uid_ && info.iface_ == iface_;
    }

    inline bool HasNoData() const
    {
        return rxBytes_ == 0 && rxPackets_ == 0 && txBytes_ == 0 && txPackets_ == 0;
    }

    const NetStatsInfo operator-(const NetStatsInfo &other) const
    {
        NetStatsInfo info;
        info.uid_ = other.uid_;
        info.iface_ = other.iface_;
        info.ident_ = ident_;
        info.rxPackets_ = (rxPackets_ > other.rxPackets_) ? rxPackets_ - other.rxPackets_ : 0;
        info.rxBytes_ = (rxBytes_ > other.rxBytes_) ? rxBytes_ - other.rxBytes_ : 0;
        info.txPackets_ = (txPackets_ > other.txPackets_) ? txPackets_ - other.txPackets_ : 0;
        info.txBytes_ = (txBytes_ > other.txBytes_) ? txBytes_ - other.txBytes_ : 0;
        info.flag_ = flag_;
        info.userId_ = userId_;
        return info;
    }

    NetStatsInfo &operator+=(const NetStatsInfo &other)
    {
        rxPackets_ += other.rxPackets_;
        rxBytes_ += other.rxBytes_;
        txPackets_ += other.txPackets_;
        txBytes_ += other.txBytes_;
        return *this;
    }

    bool Marshalling(Parcel &parcel) const override;
    static bool Marshalling(Parcel &parcel, const NetStatsInfo &stats);
    static bool Marshalling(Parcel &parcel, const std::vector<NetStatsInfo> &statsInfos);
    static bool Marshalling(Parcel &parcel, const std::unordered_map<uint32_t, NetStatsInfo> &statsInfos);
    static NetStatsInfo* Unmarshalling(Parcel &parcel);
    static bool Unmarshalling(Parcel &parcel, NetStatsInfo &stats);
    static bool Unmarshalling(Parcel &parcel, std::vector<NetStatsInfo> &statsInfos);
    static bool Unmarshalling(Parcel &parcel, std::unordered_map<uint32_t, NetStatsInfo> &statsInfos);
};
} // namespace NetManagerStandard
} // namespace OHOS
#endif // NET_STATS_INFO_H
