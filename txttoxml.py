#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  txttoxml.py
#  
#  Copyright 2017 Emese Szabó <emese@Elitke>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  
import xml.etree.ElementTree as ET
import re
from optparse import OptionParser
import argparse


def main(args):
	r = re.compile(r'''(?P<title>Date|Time|User|Ip\s+address|Public\s+Ip\s+address|HW\s+address|operating-system|processor|kernel-release|kernel-version)\s*:?\s*(?P<value>.*)''', re.VERBOSE)
	
	#args
	parser = argparse.ArgumentParser()
	parser.add_argument('-t','--inputtxt', help='Input txtfile name',required=True)
	parser.add_argument('-x','--inputxml', help='Input xmlfile name',required=True)
	parser.add_argument('-o','--output', help='Output file name',required=True)
	args = parser.parse_args()

	#xml
	with open(args.inputtxt) as f:
		tt = ET.parse(args.inputxml)
		root=tt.getroot()
		root.text='\n'
		celldata = ET.SubElement(root, 'local')
		celldata.text ='\n'
		celldata.tail='\n'
		for line in f:
			m = r.search(line)
			if m:
				title = m.group('title')
				title = title.replace(' ','')
				title = title.replace('-','')
				en = ET.SubElement(celldata, title.lower())
				en.text = m.group('value')
				en.tail = '\n'
	#ET.dump(root)
	tree = ET.ElementTree(root)
	tree.write(args.output, encoding='utf-8', xml_declaration=True)

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
