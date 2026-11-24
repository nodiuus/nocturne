#include "pdb.hpp"

#include <print>
#include <vector>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <atlbase.h>
#include <dia2.h>

pdb_parser::pdb_parser(std::string path) : pdb_path(path) {
	if (FAILED(CoInitialize(NULL))) {
		throw std::runtime_error("Failed to initialize COM library");
	}

	try {
		CComPtr<IDiaDataSource> source;
		if (FAILED(source.CoCreateInstance(CLSID_DiaSource))) {
			throw std::runtime_error("Failed to create IDiaDataSource instance");
		}

		std::wstring pdb_wpath = std::filesystem::path(pdb_path).wstring();
		if (FAILED(source->loadDataFromPdb(pdb_wpath.c_str()))) {
			throw std::runtime_error("Failed to load PDB file: " + pdb_path);
		}

		CComPtr<IDiaSession> session;
		if (FAILED(source->openSession(&session))) {
			throw std::runtime_error("Failed to open PDB session");
		}

		CComPtr<IDiaSymbol> global;
		if (FAILED(session->get_globalScope(&global)) || !global) {
			throw std::runtime_error("Failed to get PDB global scope");
		}

		CComPtr<IDiaEnumSymbols> symbols;
		if (FAILED(global->findChildren(SymTagFunction, nullptr, nsNone, &symbols)) || !symbols) {
			throw std::runtime_error("Failed to enumerate PDB functions");
		}

		CComPtr<IDiaSymbol> function;
		ULONG fetched = 0;
		HRESULT result;
		while (SUCCEEDED(result = symbols->Next(1, &function, &fetched)) && fetched == 1) {
			DWORD rva = 0;
			ULONGLONG length = 0;
			if (function->get_relativeVirtualAddress(&rva) != S_OK ||
				function->get_length(&length) != S_OK || rva == 0 || length == 0 ||
				length > (std::numeric_limits<DWORD>::max)() - rva) {
				function.Release();
				continue;
			}

			BSTR decorated = nullptr;
			BSTR undecorated = nullptr;

			function->get_name(&decorated);
			function->get_undecoratedName(&undecorated);

			symbol_info function_info;
			function_info.start_rva = rva;
			function_info.end_rva = rva + static_cast<DWORD>(length);

			if (decorated) {
				function_info.decorated_name = std::wstring(decorated);
			}
			if (undecorated) {
				function_info.undecorated_name = std::wstring(undecorated);
			}
			info.push_back(function_info);

			if (decorated) SysFreeString(decorated);
			if (undecorated) SysFreeString(undecorated);

			function.Release();
		}
		if (FAILED(result)) {
			throw std::runtime_error("Failed to read PDB functions");
		}
	}
	catch (...) {
		CoUninitialize();
		throw;
	}
	CoUninitialize();
}

std::string pdb_parser::to_utf8(const std::wstring& value) {
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

void pdb_parser::print_undecorated_names() {
	for (int i = 0; i < info.size(); i++) {
		std::println("[{}]\tName: {}\n\tStart RVA: 0x{:X}\n\tEnd RVA: 0x{:X}\n", i, to_utf8(info[i].undecorated_name), info[i].start_rva, info[i].end_rva); //eugh
	}
}

void pdb_parser::print_info() {
	for (int i = 0; i < info.size(); i++) {
		std::println("Function: {}", to_utf8(info[i].decorated_name));
		std::println("Undecorated: {}", to_utf8(info[i].undecorated_name));
		std::println("Start RVA: 0x{:X}", info[i].start_rva);
		std::println("End RVA: 0x{:X}\n", info[i].end_rva);
	}
}

std::vector<symbol_info> pdb_parser::get_symbols() const {
	return info;
}
