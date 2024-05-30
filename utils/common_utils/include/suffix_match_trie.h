/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETMANAGER_BASE_SUFFIX_MATCH_TRIE_H
#define NETMANAGER_BASE_SUFFIX_MATCH_TRIE_H

#include <string>

#include <securec.h>

namespace OHOS::NetManagerStandard {
static constexpr const char VISIBLE_CHAR_START = 0x21; // SPACE
static constexpr const char VISIBLE_CHAR_END = 0x7f;   // DEL
static constexpr const int VISIBLE_CHAR_RANGE = VISIBLE_CHAR_END - VISIBLE_CHAR_START;

/**
 * @brief Longest suffix match trie
 *
 * @tparam T trie node value type
 */
template <class T> class SuffixMatchTrie {
private:
    /**
     * @brief TrieNode define
     */
    struct TrieNode {
        // suffix terminal flag
        bool terminal;
        // children pointers
        struct TrieNode *children[VISIBLE_CHAR_RANGE];
        // node value
        T val;
    };

public:
    SuffixMatchTrie()
    {
        root_ = CreateNode();
    }

    ~SuffixMatchTrie()
    {
        FreeTrie(root_);
    }

    /**
     * @brief Check trie is empty or not
     *
     * @return true if empty, otherwise false
     */
    bool Empty()
    {
        return (size_ == 0);
    }

    /**
     * @brief Insert a node to trie
     *
     * @param key tire node key
     * @param val tire node value
     */
    void Insert(const std::string &key, const T &val)
    {
        if (key.empty()) {
            return;
        }
        TrieNode *pCrawl = root_;
        for (auto it = key.rbegin(); it != key.rend(); it++) {
            char ch = *it;
            int i = ch - VISIBLE_CHAR_START;
            if (!pCrawl->children[i])
                pCrawl->children[i] = CreateNode();
            pCrawl = pCrawl->children[i];
        }
        pCrawl->terminal = true;
        pCrawl->val = val;
        size_++;
    }

    /**
     * @brief Update trie node
     *
     * @param key tire node key
     * @param val tire node value to be update
     */
    bool Update(const std::string &key, const T &val)
    {
        if (key.empty()) {
            return false;
        }
        TrieNode *pCrawl = root_;
        TrieNode *found = nullptr;
        for (auto it = key.rbegin(); pCrawl && it != key.rend(); it++) {
            char ch = *it;
            int i = ch - VISIBLE_CHAR_START;
            pCrawl = pCrawl->children[i];
            if (pCrawl && pCrawl->terminal) {
                found = pCrawl;
            }
        }
        if (found) {
            found->val = val;
            return true;
        }
        return false;
    }

    /**
     * @brief match key with longest suffix
     *
     * @param key tire node key
     * @param out tire node value
     */
    int LongestSuffixMatch(const std::string &key, T &out)
    {
        if (key.empty()) {
            return 0;
        }
        TrieNode *pCrawl = root_;
        TrieNode *found = nullptr;
        int index = 0;
        int matchLen = 0;
        for (auto it = key.rbegin(); pCrawl && it != key.rend(); it++) {
            char ch = *it;
            int i = ch - VISIBLE_CHAR_START;
            pCrawl = pCrawl->children[i];
            index++;

            if (pCrawl && pCrawl->terminal) {
                found = pCrawl;
                matchLen = index;
            }
        }
        if (found) {
            out = found->val;
        }
        return matchLen;
    }

private:
    TrieNode *root_;
    uint32_t size_ = 0;
    TrieNode *CreateNode()
    {
        TrieNode *node = new TrieNode;
        memset_s(node, sizeof(TrieNode), 0, sizeof(TrieNode));
        return node;
    }
    void FreeTrie(TrieNode *root)
    {
        if (root) {
            for (int i = 0; i < VISIBLE_CHAR_RANGE; i++) {
                FreeTrie(root->children[i]);
            }

            delete root;
            root = nullptr;
        }
    }
};
} // namespace OHOS::NetManagerStandard
#endif // NETMANAGER_BASE_SUFFIX_MATCH_TRIE_H