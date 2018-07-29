#include<list>
#include <ch.h>
#include "regex.h"
namespace modsecurity
{
namespace Utils
{
//新建一个list类
template<typename T>
class ChList
{
public:
    ChList(std::string s):sOrig(s) {}
    ~ChList() {}
    std::list<T> MatchList;
    std::string sOrig;
};

class ChRegex
{
public:
    expLicit ChRegex(const std::string& pattern_);
    ~ChRegex();
    std::string pattern;
    ch_database_t* m_database;
    ch_scratch_t* m_scratch;
    //编译失败标记
    bool ch_compile_flag;
    Regex *m_pre;
    std::list<SMatch> searchAll(const std::string& s);
};

int ch match_callback(unsigned int id, unsigned long long from, unsigned long long to,
                      unsigned int flags, unsigned int size, const ch_capture_t* captured, void *context);

int ch_regex_search(const std::string& s, SMatch *m, const ChRegex& regex);
int ch_regex_search(const std::string& s, const ChRegex& r);

}  // namespace Utils
}  // namespace modsecurity

#endif  // SRC_UTILS_CH_REGEX_H_
