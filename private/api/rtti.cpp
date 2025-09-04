#include <nlohmann/json.hpp>
#include <api/licence.hpp>
#include <../thirdparty/crypto/otrv3.hpp>
#include <api/rtti.hpp>

std::vector<rtti::func_entry> rtti::func_registry;

void rtti::my_rtti::register_func(const std::string& class_name, const std::string& func_name, some_func func_ptr) {
    func_registry.push_back({ class_name, func_name, func_ptr });
}