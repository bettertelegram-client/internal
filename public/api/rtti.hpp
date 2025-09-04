#ifndef RTTI_HPP
#define RTTI_HPP

#include <Windows.h>

#include <iostream>
#include <functional>
#include <map>
#include <any>

namespace rtti {

    template<typename T>
    T _cast(const std::any& arg, int which = 0) {
        try { return std::any_cast<T>(arg); }
        catch (const std::bad_any_cast& e) {}
    }

    using some_func = std::function<std::any(std::vector<std::any>)>;
    struct func_entry {
        std::string class_name;
        std::string func_name;
        some_func func_ptr;

        func_entry(std::string c, std::string f, some_func p) : class_name(c), func_name(f), func_ptr(p) {}
    };

    extern std::vector<func_entry> func_registry;

    class my_rtti {

    public:

        template<typename datatype>
        static datatype call_func(const std::string& class_name, const std::string& func_name, std::vector<std::any> args) {
            for (const auto& entry : func_registry) if (entry.class_name == class_name && entry.func_name == func_name) {
                return std::any_cast<datatype>(entry.func_ptr(args));
            }
        }

        template<>
        inline void call_func<void>(const std::string& class_name, const std::string& func_name, std::vector<std::any> args) {
            for (const auto& entry : func_registry) {
                if (entry.class_name == class_name && entry.func_name == func_name) {
                    entry.func_ptr(args);
                    return;
                }
            }
        }

        static void register_func(const std::string& class_name, const std::string& func_name, some_func func_ptr);

    };

}

#endif // RTTI_HPP