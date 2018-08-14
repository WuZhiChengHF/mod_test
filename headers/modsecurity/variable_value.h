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
#include <string>
#include <iostream>
#include <memory>
#include <list>
#include <utility>
#endif

#include "modsecurity/variable_origin.h"

#ifndef HEADERS_MODSECURITY_VARIABLE_H_
#define HEADERS_MODSECURITY_VARIABLE_H_

#ifndef __cplusplus
typedef struct Variable_t VariableValue;
#endif

#ifdef __cplusplus

void* operator new(size_t size);
void* operator new[](size_t size);
void  operator delete(void* p);
void  operator delete[](void* p);

namespace modsecurity
{

#include<list>
using std::list;
template<typename T>
class CacheList
{
protected:
    list<T*> clist;
public:
    CacheList() {}
    ~CacheList()
    {
        while (!clist.empty())
        {
            T* p = clist.front();
            delete p;
            clist.pop_front();
        }
    }

    T* pop_one(const T* o)
    {
        if (clist.size() == 0)
        {
            return (T*) new T(o);
        }
        T* p = clist.front();
        p->init(o);
        clist.pop_front();
        return p;
    }

    VariableOrigin* pop_one(void)
    {
        if (clist.size() == 0)
        {
            return new VariableOrigin();
        }

        VariableOrigin* p = clist.front();
        clist.pop_front();

        return p;
    }

    void push_one(T* t)
    {
        t->clear();
        clist.push_back(t);
    }

    //void push_one(VariableOrigin* t)
    //{
    //    clist.push_back(t);
    //}

    int get_conut()
    {
        return clist.size();
    }
};

//template <>
//VariableOrigin* CacheList<VariableOrigin>::pop_one();
//{
//    if (clist.size() == 0)
//    {
//        return new VariableOrigin();
//    }
//
//    VariableOrigin* p = clist.front();
//    clist.pop_front();
//
//    return p;
//}

template <>
void CacheList<VariableOrigin>::push_one(VariableOrigin* t);
//{
//    clist.push_back(t);
//}

class Collection;
class VariableValue
{
public:
    explicit VariableValue(const std::string *key) :
        m_key(""),
        m_value("")
    {
        m_key.assign(*key);
        m_keyWithCollection = std::make_shared<std::string>(*key);
        m_from_pool = false;
    }

    VariableValue(const std::string *key, const std::string *value) :
        m_key(""),
        m_value("")
    {
        m_key.assign(*key);
        m_value.assign(*value);
        m_keyWithCollection = std::make_shared<std::string>(*key);
        m_from_pool = false;
    }

    VariableValue() :
        m_key(""),
        m_value("")
    {
        m_keyWithCollection = std::make_shared<std::string>(m_key);
        m_from_pool = false;
    }

    VariableValue(const std::string *a, const std::string *b, const std::string *c) :
        m_key(*a + ":" + *b),
        m_value(*c)
    {
        m_keyWithCollection = std::make_shared<std::string>(*a + ":" + *b);
        m_from_pool = false;
    }

    VariableValue(std::shared_ptr<std::string> fullName) :
        m_key(""),
        m_value("")
    {
        m_keyWithCollection = fullName;
        m_key.assign(*fullName.get());
        m_from_pool = false;
    }

    VariableValue(std::shared_ptr<std::string> fullName, const std::string *value) :
        m_key(""),
        m_value("")
    {
        m_value.assign(*value);
        m_keyWithCollection = fullName;
        m_key.assign(*fullName.get());
        m_from_pool = false;
    }


    explicit VariableValue(const VariableValue *o) :
        m_key(""),
        m_value("")
    {
        m_key.assign(o->m_key);
        m_value.assign(o->m_value);
        m_col.assign(o->m_col);
        m_keyWithCollection = o->m_keyWithCollection;

        for (auto &i : o->m_orign)
        {
            std::unique_ptr<VariableOrigin> origin(new VariableOrigin());
            origin->m_offset = i->m_offset;
            origin->m_length = i->m_length;
            m_orign.push_back(std::move(origin));
        }
        m_from_pool = false;
    }

    inline void init(const VariableValue* o)
    {
        m_key.assign(o->m_key);
        m_value.assign(o->m_value);
        m_col.assign(o->m_col);
        m_keyWithCollection = o->m_keyWithCollection;

        for (auto &i:o->m_orign)
        {
            VariableOrigin* p = clist_value_orig.pop_one();
            std::unique_ptr<VariableOrigin> origin(p);
            origin->m_offset = i->m_offset;
            origin->m_length = i->m_length;
            m_orign.push_back(std::move(origin));
        }

        m_from_pool = true;
    }
    
    inline void clear()
    {
        for (auto &i: this->m_orign)
        {
            clist_value_orig.push_one(i.release());
        }
    }

    static bool free_value(const VariableValue* v)
    {
        if (v == 0) return false;

        if (v->m_from_pool)
        {
            clist_value.push_one((VariableValue*)v);
        }
        else delete v;

        return true;
    }

    static CacheList<VariableValue> clist_value;
    static CacheList<VariableOrigin> clist_value_orig;
    bool m_from_pool;
    std::string m_key;
    std::string m_value;
    std::string m_col;
    std::shared_ptr<std::string> m_keyWithCollection;
    std::list<std::unique_ptr<VariableOrigin>> m_orign;
};

}  // namespace modsecurity
#endif

#endif  // HEADERS_MODSECURITY_VARIABLE_H_
