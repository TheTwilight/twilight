#!/usr/bin/env python

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

from elasticsearch import Elasticsearch
import getopt
import sys

def main():
	
	letters = 'e:u:p:h' #username, password
	keywords = ['username=', 'password=']
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		sys.exit()
	username = ''
	password = ''
	es_ip=''
        static_fields = dict()
	print(opts)
	for o,p in opts:
		if o in ['-u', '--username=']:
			username=p
			if not username:
				print "Please specify a username after -u "
				sys.exit()
		elif o in ['-e', '--es_ip=']:
			es_ip=p
			if not es_ip:
				print "Please specify an IP after -e "
				sys.exit()
		elif o in ['-p', '--password=']:
			password=p
			if not password:
				print "Please specify a password after -p "
				sys.exit()
	  

	if (len(sys.argv) < 1):
		usage()
		sys.exit()
		
	es = Elasticsearch([{'host':es_ip}],
		http_auth=(username,password),
		port=9200,
		use_ssl=True,
		verify_certs=False)
	
	if not es.ping():
		raise ValueError("Connection failed")

if __name__ == "__main__":
	main()
