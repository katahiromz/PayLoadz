#include <windows.h>
#include <windowsx.h>
#include <strsafe.h>
#include <time.h>
#include <assert.h>
#include <string>

template <typename T_CHAR>
inline void mstr_trim_right(std::basic_string<T_CHAR>& str, const T_CHAR *spaces)
{
    typedef std::basic_string<T_CHAR> string_type;
    size_t j = str.find_last_not_of(spaces);
    if (j == string_type::npos)
    {
        str.clear();
    }
    else
    {
        str = str.substr(0, j + 1);
    }
}

int main(int argc, char **argv)
{
    for (;;)
    {
        time_t t = time(NULL);
        struct tm tmLocal = *localtime(&t);
        struct tm tmGlobal = *gmtime(&t);
        std::string local = asctime(&tmLocal);
        std::string global = asctime(&tmGlobal);
        mstr_trim_right(local, " \t\r\n");
        mstr_trim_right(global, " \t\r\n");
        printf("localtime: %s, gmtime: %s\r", local.c_str(), global.c_str());
        Sleep(333);
    }
    return 0;
}
