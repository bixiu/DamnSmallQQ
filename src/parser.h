/*
 * parser.h
 *
 *  Created on: Mar 17, 2009
 *  	Author: Phoebus Veiz <phoebusveiz@gmail.com>
 */

#ifndef PARSER_H_
#define PARSER_H_

#include <vector>
using namespace std;

class parser
{
public:
	parser();
	~parser();
	static int parse_xml(const char* xml_file, vector<string>& vec);
	static int parse_xml_group(const vector<string>& urls, vector<string>& vec);
private:
};

#endif /* PARSER_H_ */

