#include "pdb.hpp"

#include <print>
#include <vector>
#include <filesystem>
#include <atlbase.h>
#include <dia2.h>

namespace {
	std::string to_utf8(const std::wstring& value) {
		if (value.empty()) {
			return {};
		}
		const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
			static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
		if (size <= 0) {
			return {};
		}
		std::string out(static_cast<size_t>(size), '\0');
		WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
			out.data(), size, nullptr, nullptr);
		return out;
	}
}

pdb_parser::pdb_parser(std::string path) : pdb_path(path) {}

void pdb_parser::parse() {
	{
		if (FAILED(CoInitialize(NULL))) {
			std::println("[-] Failed to initialize COM library.");
			return;
		}

		CComPtr<IDiaDataSource> source;
		if (FAILED(source.CoCreateInstance(CLSID_DiaSource))) {
			std::println("{}", source.CoCreateInstance(CLSID_DiaSource));
			std::println("[-] Failed to create IDiaDataSource instance.");
			return;
		}

		std::wstring pdb_wpath = std::filesystem::path(pdb_path).wstring();
		if (FAILED(source->loadDataFromPdb(pdb_wpath.c_str()))) {
			std::println("[-] Failed to load PDB file: {}", pdb_path);
			return;
		}

		CComPtr<IDiaSession> session;
		if (FAILED(source->openSession(&session))) {
			std::println("[-] Failed to open PDB session.");
			return;
		}

		CComPtr<IDiaSymbol> global;
		session->get_globalScope(&global);

		CComPtr<IDiaEnumSymbols> symbols;
		if (FAILED(global->findChildren(SymTagFunction, nullptr, nsNone, &symbols))) {
			std::println("[-] No functions found in PDB.");
			return;
		}

		CComPtr<IDiaSymbol> function;
		ULONG fetched = 0;
		while (SUCCEEDED(symbols->Next(1, &function, &fetched)) && fetched == 1) {
			BSTR decorated = nullptr;
			BSTR undecorated = nullptr;
			DWORD rva = 0;
			std::uintptr_t length = 0;

			function->get_name(&decorated);
			function->get_undecoratedName(&undecorated);
			function->get_relativeVirtualAddress(&rva);

			symbol_info function_info;

			if (decorated) {
				function_info.decorated_name = std::wstring(decorated);
			}
			if (undecorated) {
				function_info.undecorated_name = std::wstring(undecorated);
			}
			if (SUCCEEDED(function->get_length(&length))) {
				function_info.start_rva = rva;
				function_info.end_rva = rva + static_cast<DWORD>(length);
			}
			else {
				function_info.end_rva = 0;
			}

			info.push_back(function_info);

			if (decorated) SysFreeString(decorated);
			if (undecorated) SysFreeString(undecorated);

			function.Release();
		}
	}
	CoUninitialize();
}

void pdb_parser::print_info() {
	for (int i = 0; i < info.size(); i++) {
		std::println("Function: {}", to_utf8(info[i].decorated_name));
		std::println("Undecorated: {}", to_utf8(info[i].undecorated_name));
		std::println("Start RVA: 0x{:X}", info[i].start_rva);
		std::println("End RVA: 0x{:X}\n", info[i].end_rva);
	}
}
