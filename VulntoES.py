#!/usr/bin/env python

#  This file is based on VulntoES. The original program can be found
#  here: https://github.com/ChrisRimondi/VulntoES

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


from datetime import datetime
from elasticsearch import Elasticsearch
import json
import time
import codecs
import struct
import locale
import glob
import sys
import getopt
import xml.etree.ElementTree as xml
import re
import copy
#import certifi
#import socket
#import pprint
import urllib3


class NmapES:
	"This class will parse an Nmap XML file and send data to Elasticsearch"

	def __init__(self, input_file,es_ip,index_name,username,password):
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.es = Elasticsearch([{'host':es_ip}],
		http_auth=(username,password),
		port=9200,
		use_ssl=True,
		verify_certs=False)
		self.index_name = index_name

	def displayInputFileName(self):
		print self.input_file

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)
		
	def extend_stuff(self, title, data, datatype):
		extend_mapping = {
								title: {
									"type": datatype
								}
							
						}
		
		extend_doc = {title: data }
		return [extend_mapping, extend_doc]

	def toES(self):
		"Returns a list of dictionaries (only for open ports) for each host in the report"
		
		mapping = {
                    "timestamp": {
                        "type": "date"
                    },
                    "location": {
                        "type": "geo_point"
                    },	
		}
		doc = {
				'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
		}
		for ru in self.root.iter('nmaprun'):
			if ru.tag == "nmaprun":
				if ru.attrib["version"]:
					extendarray = self.extend_stuff("version",ru.attrib["version"],"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				if ru.attrib["args"]:
					extendarray = self.extend_stuff("args",ru.attrib["args"],"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
		for mesi in self.root.iter('local'):
			for datas in mesi:
				if datas.tag == 'user':
					extendarray = self.extend_stuff('local_user',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				elif datas.tag == 'ipaddress':
					if ' ' in datas.text:
						splitstr = datas.text.split(' ')
						for idx, item in enumerate(splitstr):
							extendarray = self.extend_stuff('local_ip_private_'+str(idx+1),item,"ip")
							mapping.update(extendarray[0])
							doc.update(extendarray[1])
					else:
						extendarray = self.extend_stuff('local_ip_private',datas.text,"ip")
						mapping.update(extendarray[0])
						doc.update(extendarray[1])
				elif datas.tag == 'publicipaddress':
					if ' ' in datas.text:
						splitstr = datas.text.split(' ')
						for idx, item in enumerate(splitstr):
							extendarray = self.extend_stuff('local_ip_public'+str(idx+1),item,"ip")
							mapping.update(extendarray[0])
							doc.update(extendarray[1])
					else:
						extendarray = self.extend_stuff('local_ip_public',datas.text,"ip")
						mapping.update(extendarray[0])
						doc.update(extendarray[1])
				elif datas.tag == 'hwaddress':
					extendarray = self.extend_stuff('local_hwaddress',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				elif datas.tag == 'operatingsystem':
					extendarray = self.extend_stuff('local_os',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				elif datas.tag == 'processor':
					extendarray = self.extend_stuff('local_processor',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				elif datas.tag == 'kernelrelease':
					extendarray = self.extend_stuff('local_kernelrelease',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
				elif datas.tag == 'kernelversion':
					extendarray = self.extend_stuff('local_kernelversion',datas.text,"keyword")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
		permanent_doc = copy.deepcopy(doc)
		permanent_mapping = copy.deepcopy(mapping)
		for h in self.root.iter('host'):
			doc = copy.deepcopy(permanent_doc)
			mapping = copy.deepcopy(permanent_mapping)
			check_endtime = 0
			if h.tag == 'host':
				if h.attrib['endtime']:
					extendarray = self.extend_stuff("time",time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(h.attrib['endtime']))),"date")
					mapping.update(extendarray[0])
					doc.update(extendarray[1])
					check_endtime =  h.attrib["endtime"]
			for loc in self.root.iter('host'):
				check_endtime_counterpart = 0
				if loc.tag == 'host':
					if loc.attrib['endtime']:
						check_endtime_counterpart = loc.attrib['endtime']
				if (check_endtime == check_endtime_counterpart) & (check_endtime != 0):
					for c in loc:
						if c.tag == 'hostscript':
							for s in c:
								if (s.tag == 'script') & (s.attrib['id'] == "traceroute-geolocation"):
									lat = 0
									lon = 0
									for ta in s:
										for ele in ta:
											if ele.attrib['key'] == "lat":
												lat = ele.text
											if ele.attrib['key'] == "lon":
												lon = ele.text
									if (lat != 0) & (lon != 0) & ('location' not in doc):
										joint_location = lat +","+ lon
										extend_doc = {
											"location": joint_location
										}
										doc.update(extend_doc)
			extendarray = self.extend_stuff("scanner",'nmap',"keyword")
			mapping.update(extendarray[0])
			doc.update(extendarray[1])
			for c in h:
				if c.tag == 'address':
					if c.attrib['addr']:
						extendarray = self.extend_stuff('ip',c.attrib['addr'],"ip")
						mapping.update(extendarray[0])
						doc.update(extendarray[1])
				elif c.tag == 'hostnames':
					for names in c.getchildren():
						if names.attrib['name']:
							extendarray = self.extend_stuff('hostname',names.attrib['name'],"keyword")
							mapping.update(extendarray[0])
							doc.update(extendarray[1])
				elif c.tag == 'mesi':
					if c.attrib['titkosnev']:
						#dict_item['secretstuff'] = c.attrib['titkosnev']
						print("Bent hagytad a Mesi-taget")
				elif c.tag == 'ports':
					for port in c.getchildren():
						portstate = "closed"
						if port.tag == 'port':
							extendarray = self.extend_stuff('port',port.attrib['portid'],"keyword")
							mapping.update(extendarray[0])
							doc.update(extendarray[1])
							extendarray = self.extend_stuff('protocol',port.attrib['protocol'],"keyword")
							mapping.update(extendarray[0])
							doc.update(extendarray[1])
							for p in port.getchildren():
								if p.tag == 'state':
									portstate = p.attrib['state']
									extendarray = self.extend_stuff('state',p.attrib['state'],"keyword")
									mapping.update(extendarray[0])
									doc.update(extendarray[1])
								elif p.tag == 'service':
									extendarray = self.extend_stuff('service',p.attrib['name'],"keyword")
									mapping.update(extendarray[0])
									doc.update(extendarray[1])
								elif p.tag == 'script':
									if p.attrib['id']:
										if p.attrib['output']:
											extendarray = self.extend_stuff(p.attrib['id'],p.attrib['output'],"keyword")
											mapping.update(extendarray[0])
											doc.update(extendarray[1])									
							if portstate == 'open':
								#Only sends document to ES if the port is open
								mappings = { "mappings": { "vuln": { "properties": mapping } } }
								try:    # try to create index
									self.es.indices.create(index=self.index_name, body=mappings)
								except: # if index exists: ensure mapping is created
									self.es.indices.put_mapping(index=self.index_name, doc_type="vuln", body={ "properties": mapping })
								self.es.index(index=self.index_name,doc_type="vuln", body=doc)
								with open('kibana_json.txt', 'w') as outfile:
									json.dump(doc, outfile)

def usage():
		print "Usage: VulntoES.py [-i input_file | input_file=input_file] [-e elasticsearch_ip | es_ip=es_ip_address] [-I index_name] [-r report_type | --report_type=type] [-s name=value] [-h | --help]"
def main():

        letters = 'i:I:e:r:s:u:p:h' #input_file, index_name es_ip_address, report_type, create_sql, create_xml, username, password, help
	keywords = ['input-file=', 'index_name=', 'es_ip=','report_type=', 'static=', 'username=', 'password=', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = ''
	es_ip = ''
	report_type = ''
	index_name = ''
	username = ''
	password = ''
        static_fields = dict()

	for o,p in opts:
	  if o in ['-i','--input-file=']:
		in_file = p
	  elif o in ['-r', '--report_type=']:
	  	report_type = p
	  elif o in ['-e', '--es_ip=']:
	  	es_ip=p
	  elif o in ['-u', '--es_ip=']:
	  	username=p
	  	if not username:
			print "Please specify a username after -u "
			sys.exit()
	  elif o in ['-p', '--es_ip=']:
	  	password=p
	  	if not password:
			print "Please specify a password after -p "
			sys.exit()
	  elif o in ['-I', '--index_name=']:
		index_name=p
          elif o in ['-s', '--static']:
                name, value = p.split("=", 1)
                static_fields[name] = value
	  elif o in ['-h', '--help']:
		 usage()
		 sys.exit()


	if (len(sys.argv) < 1):
		usage()
		sys.exit()

	try:
		with open(in_file) as f: pass
	except IOError as e:
		print "Input file does not exist. Exiting."
		sys.exit()

	if report_type.lower() == 'nmap':
		print "This software is based on VulntoES but modified so use it with nmap only!"
		print "Sending Nmap data to Elasticsearch"
		np = NmapES(in_file,es_ip,index_name,username,password)
		np.toES()
	else:
		print "Error: Invalid report type specified. Available options: nmap"
		sys.exit()

if __name__ == "__main__":
	main()
