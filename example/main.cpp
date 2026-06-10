#include <iostream>
#include <string>
#include "../src/autocrypt.hpp"

int main() {    // default usage via flag AUTOSTR
    std::cout << AUTOSTR("enter key: ");
    std::string input;
    std::cin >> input;

    if (input == AUTOSTR("super_secret")) {
        std::wcout << AUTOSTR(L"done") << std::endl;         // output encrypted wide string
    } else {
        std::wcout << AUTOSTR(L"denied") << std::endl;
    }

    return 0;
}