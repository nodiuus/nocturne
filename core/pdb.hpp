#pragma once

/*
	old pdb parsing util
	TODO: implement support for virtualzing functions by name
*/

#include <string>
#include <vector>

struct symbol_info {
	std::wstring decorated_name;
	std::wstring undecorated_name;
	uintptr_t start_rva;
	uintptr_t end_rva;
};

class pdb_parser {
public:
	pdb_parser(std::string path);
	std::string to_utf8(const std::wstring& value);
	void print_info();
	void print_undecorated_names();

	std::vector<symbol_info> get_symbols() const;
private:
	std::string pdb_path;
	std::vector<symbol_info> info;
};