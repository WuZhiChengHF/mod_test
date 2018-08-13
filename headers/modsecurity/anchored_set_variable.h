/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifdef __cplusplus
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <sstream>
#include <string>
#include <cstring>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>
#include <memory>
#endif

#include "modsecurity/variable_value.h"

#ifndef HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_H_
#define HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_H_

#ifdef __cplusplus

namespace modsecurity
{
class Transaction;
namespace Utils
{
class Regex;
}


struct MyEqual
{
    bool operator()(const std::string& Left, const std::string& Right) const
    {
       const unsigned char* pLeft = (const unsigned char*) Left.c_str(); 
       const unsigned char* pRight = (const unsigned char*) Right.c_str(); 
       int nLSize = Left.size();
       int nRSize = Right.size();
       if (nLSize != nRight) return false; 
       if (memcmp(pLeft, pRight, nLSize)) return false;

       return true;
    }
};

struct MyHash
{
    size_t operator()(const std::string& Keyval) const
    {
        unsigned int uRet = 0; 
        const unsigned char* pKeyCurrent = (const unsigned char*)Keyval.c_str();
        unsigned int uTmp = 0;

        int nSize = Keyval.size();

        for (int i=0; i<nSize; i++)
        {
            uTmp = pKeyCurrent[i];
            uTmp <<= ((i%sizeof(int))*8);
            uRet ^= uTmp;
        }

        return uRet;
    }
};


class AnchoredSetVariable : public std::unordered_multimap<std::string,
    VariableValue *, MyHash, MyEqual>
{
public:
    AnchoredSetVariable(Transaction *t, std::string name);
    ~AnchoredSetVariable();

    void unset();

    void set(const std::string &key, const std::string &value,
             size_t offset);

    void set(const std::string &key, const std::string &value,
             size_t offset, size_t len);

    void setCopy(std::string key, std::string value, size_t offset);

    void resolve(std::vector<const VariableValue *> *l);

    void resolve(const std::string &key,
                 std::vector<const VariableValue *> *l);

    void resolveRegularExpression(Utils::Regex *r,
                                  std::vector<const VariableValue *> *l);

    std::unique_ptr<std::string> resolveFirst(const std::string &key);

    Transaction *m_transaction;
    std::string m_name;
};

}  // namespace modsecurity

#endif


#endif  // HEADERS_MODSECURITY_ANCHORED_SET_VARIABLE_H_

