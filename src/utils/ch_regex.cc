#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string>
#include<list>
#include<fstream>
#include<iostream>
#include"src/utils/geo_lookup.h"
#include"src/utils/ch_regex.h"
#include<ch.h>

namespace modsecurity
{
namespace Utils
{
using std::list;
using std::string;

ChRegex::ChRegex(const string& pattern_):pattern(pattern_),ch_compile_flag(true)
{
    ch_compile_error_t* compile_err = NULL;
    m_database = NULL;
    m_scratch = NULL;

    std::string sRegStr(pattern);
    unsigned int ch_flag = CH_FLAG_DOTALL|CH_FLAG_MULTILINE;
    if (ch_compile(sRegStr.c_str(), ch_flag, CH_MODE_GROUPS, NULL, &m_database, &compile_err) != CH_SUCCESS)
    {
        ch_free_compile_error(compile_err);
        ch_compile_flag = false;
    }

    if (ch_alloc_scratch(m_database, &m_scratch) != CH_SUCCESS)
    {
        ch_free_database(m_database);
        m_database = NULL;
        ch_compile_flag = false;
    }

    //如果ch_regex不能编译通过,仍使用pcre
    if (!ch_compile_flag)
    {
        m_pre = new Regex(pattern);
    }
}

ChRegex::~ChRegex()
{
    if (m_database != NULL)
    {
        ch_free_database(m_database);
        m_database = NULL;
    }
    if (m_scratch != NULL)
    {
        ch_free_scratch(m_scratch);
        m_scratch = NULL;
    }
    if (NULL != m_pre)
    {
        delete m_pre;
    }
}

list<SMatch> ChRegex::searchAll(const std::string& s)
{
    const char* subject = s.c_str();
    const string tmpString = string(s.c_str(), s.size());
    ChList<SMatch> ChList(s);
    if (!ch_compile_flag)
    {
        return m_pre->searchAll(s);
    }
    ch_scan(m_database, tmpString.c_str(), tmpString.size(), 0, m_scratch, ch_match_callback, 0, &ChList);
    return ChList.MatchList;
}

int ch_match_callback(unsigned int id, unsigned long long from, unsigned long long to,
                      unsigned int flags, unsigned int size, const ch_capture_t* captured, void* context)
{
    if (NULL == context)
    {
        return 0;
    }
    ChList<SMatch>* pChList = (ChList<SMatch>*)context;
    SMatch smatch;
    if (size > 1)
    {
        for (int i=1; i<size; i++)
        {
            if (captured[i].flags == 1)
            {
                smatch.m_offset = (int)from;
                smatch.m_length = (int)(to-from);
                if (smatch.m_length < pChList->sOrig.size())
                {
                    smatch.match = string(pChList->sOrig, captured[i].from, (captured[i].to-captured[i].from));
                    pChList->MatchList.push_front(smatch);
                }
            }
        }
    }

    return 0;
}

int ch_regex_search(const string& s, SMatch* match, const ChRegex& regex)
{
    const char* subject = s.c_str();
    const std::string tmpString = std::string(s.c_str(), s.size());

    ChList<SMatch> ChList(s);

    if (!regex.ch_compile_flag)
    {
        return regex_search(s, match, *regex.m_pre);
    }

    ch_scan(regex.m_database, tmpString.c_str(), tmpString.size(),
            CH_MODE_GROUPS, regex.m_scratch, ch_match_callback, 0, &ChList);

    if (ChList.MatchList.size() > 0)
    {
        SMatch match_temp = ChList.MatchList.front();
        match->m_offset = match_temp.m_offset;
        match->m_length  = match_temp.m_length;
        match->match  = match_temp.match;
        match->size  = ChList.MatchList.size();
    }

    return ChList.MatchList.size();
}


int ch_regex_search(const std::string& s, const ChRegex& regex)
{
    const std::string tmpString = std::string(s.c_str(), s.size());
    ChList<SMatch> ChList(s);

    if (!regex.ch_compile_flag)
    {
        return regex_search(s, *regex.m_pre);
    }

    ch_scan(regex.m_database, s.c_str(), s.size(), CH_MODE_GROUPS, regex.m_scratch, ch_match_callback, 0, &ChList);

    return ChList.MatchList.size();
}
} // namespace Utils
} // namespace modsecurity
