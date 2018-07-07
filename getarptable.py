#!/usr/bin/python
import subprocess
import os
import sys
import re
import argparse
import time
import datetime
import csv
import urllib2
import json


#Create the argument parser
parser = argparse.ArgumentParser(description='Retrieves the ARP table from network devices and lists the MAC addresses in multiple formats')

#use subparsers to make arguments mutually exclussive
subparsers = parser.add_subparsers(help="Choose between walking a list of IP addresses from a config file, or extracing a list of addresses from a previous results file")

#Command options for walking
parser_walk = subparsers.add_parser('walk', help='Use the command to walk target IP addresses and retrieve their ARP tables.')
parser_walk.add_argument('in_file', help="Specify the IN file containing addresses to walk.  \
	The file should have one entery per line containing comma delimited IP address and building number.", type=argparse.FileType('r'))
parser_walk.add_argument('-c', '--community', help="Specify the SNMP community string")

#Command options for extracting data from old results files
parser_extract = subparsers.add_parser('extract', help='Use the command to extract specific IP addresses from a previous results file.')
parser_extract.add_argument('results_file', help='Specify a previous results file from which you wish to extract ARP data based on IP address', type=argparse.FileType('r'))

#Parse some args
args = parser.parse_args()
oui_file = 'oui.dict'
oui_dict = {}

# The walk function is called from main() if the args.in_file is set.  It reads the config file,
# calls the snmpbulkwalk function for each device in the config file, and then takes the retuned
# results and writes them to a csv file names with the date and time. ie. 2015-04-07-17-50.csv
# That file would indicate that script that pulled the data started at 5:50 PM on Apr. 7, 2015.
# The date is listed backwards so that it an alphabetical sort in the OS also sorts chronologically.
def walk():
	out_file = timeStamp()['DateTime'] + '.csv'
	config = args.in_file.read().splitlines()
	devices = []
	targets = []
	arp_data = [['Date', 'Building','Router IP','Host IP', 'Dot Notation','Colon Notation','No Notation','OUI','Company']]
	errors = []
	# Look for the #Devices section.  If it's not there, print out a sample config file.
	# If it is there, parse the config, and walk the identified devices.
	if (config.count('#Devices')) == 0:
			print """
ERROR: Invalid configuration file.  The file does not have a #Devices section.
Valid Example Config:

#The '#' lets you comment lines out.
#Do not remove the '#Devices' line.  It designates the devices to walk.
#
#Devices
#List the network devices you want to walk below, one per line, in the follwoing format:
# x.x.x.x,Location
10.0.0.1,Bldg 1
10.1.0.1,Bldg 2
10.2.0.1,Bldg 3
"""
	else:
		for device in range(config.index('#Devices'), len(config)):
			if config[device][0] != '#':
				devices.append(config[device].strip().split(','))
		for index, device in enumerate(devices):
			# If the file has IP addresses, but not buildings, add an 'N/A' to the location field.
			if len(device) != 2:
				device.append('N/A')
			ip,building = device
			device_data = snmpbulkwalk(ip, building, args.community)
			if len(device_data) == 4:
				errors.extend(device_data)
			else:
				arp_data.extend(device_data)
		if len(errors) > 0:
			arp_data.extend(errors)
		csvWriter(out_file, arp_data)

# The program calls extract() from main() if args.results_file is set.  You provide it a previous results file, 
# and it then takes a list of IP addresses from stdin to extract from the results file.  It appends the 'Extract'
# to the reults file name, and writes the data to a new CSV file with 'Extract' appended to the end of the file name
# before the extension. 
def extract():
	buff = []
	extract = [['Date', 'Building','Router IP','Host IP', 'Dot Notation','Colon Notation','No Notation','OUI','Company']]
	out_file =(args.results_file.name)[:-4] + '-Extract.csv'
	run = True
	print ''
	print 'Enter the IP addresses, one per line, that you would like to extract from %s' % (args.results_file.name) 
	print ''
	while run:
	    line = sys.stdin.readline().rstrip('\n')
	    if len(line) < 1:
	        run = False
	    else:
	        buff.append(line)
	results = csv.reader(args.results_file, delimiter=',', quotechar='"')
	for line in results:
		for ip in buff:
			if line.count(ip) > 0:
				extract.append(line)
				#for l in line:
					#print l,
	for e in extract:
		print ', '.join(e)
	csvWriter(out_file, extract)

# Calls the snmpbulkwalk program on unix like operating systems.
# The bulk version pulls an entire tree at a time instead of making
# individual requests for the next item.  This provides dramatic speed
# improvements when there is latency between you and the network device.
def snmpbulkwalk(ip, location, community):
    print '%s - Walking %s...' % (timeStamp()['time'], ip)
    dt =  timeStamp()['DateTime']
    proc = subprocess.Popen('snmpbulkwalk -v 2c -c %s %s .1.3.6.1.2.1.4.22.1.2' % (community,ip), \
     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout_value = proc.communicate()[0]
    if len(stdout_value) == 0:
    	print 'Error: Validate the IP address and community string are correct, and that remote system ' \
    	+ 'is running an SNMP daemon. IP: %s Community: %s' % (ip,community)
    	return [dt, location, ip, 'ERROR']
    else:
    	print "%s - Finished %s." % (timeStamp()['time'], ip)
        data_extract = extractData(stdout_value.split('\n'))
        for index, row in enumerate(data_extract):
        	data_extract[index] = formatData(ip, row, dt, location)
        print str(index + 1) + ' ARP Entries Found.\n' 
        return data_extract

# # The remote device will return SNMP data in a new line delimited format.
# Sample data: 
# From snmpbulkwalk in Macintosh, Cygwin, and %NagiosOS%:
# IP-MIB::ipNetToMediaPhysAddress.124.10.149.70.97 = STRING: 5c:26:a:2f:1b:28
# From snmpbulkwalk in Debian Linux:
# iso.3.6.1.2.1.4.22.1.2.200.10.149.70.97 = Hex-STRING: 5C 26 0A 2F 1B 28
# In the sample, the IP address is 10.149.70.97, and the MAC is 5c:26:a:2f:1b:28.
# The regex below will pull out the IP address and MAC address regardless of 
# the returned format.
def extractData(raw_snmpdata):
	extracted_data = []
	for data in raw_snmpdata:
		# I love and hate regex at the same time.
		match = re.search(\
			'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))' \
			+ '(?:\s.+\:\s)((?:(([0-9a-fA-F]){1,2}[\:\s]){5}(([0-9a-fA-F]){1,2})))', data)
		if match:
			row = [match.group(1), match.group(2)]
			extracted_data.append(row)
	return extracted_data

# The data from SNMP on Macintoshes and Cygwin elimnates leading 0's in 
# the MAC address hex pairs. This function pads the macs with 0's, 
# and then creates a version of the MAC with all of the desired delimeters
# data_source is the IP address of the network device that was walked.
# raw_data is provided in the following formats:
# Macs and Cygwin: ['10.149.70.97', '5c:26:a:2f:1b:28']
# Debian Linux: ['10.149.70.97', '5C 26 0A 2F 1B 28']
def formatData(data_source, raw_data, timestamp, location):
	if raw_data[1].count(':') == 0:
		mac = raw_data[1].split()
	else:
		mac = raw_data[1].split(':')
	for index, group in enumerate(mac):
		if len(group) == 1:
			mac[index] = ''.join(['0', group])
	new_row = [timestamp, location, data_source, raw_data[0]]
	new_row.append('.'.join([''.join(mac[:2]), ''.join(mac[2:4]), ''.join(mac[4:6])]))
	new_row.append(':'.join(mac))
	new_row.append(''.join(mac))
	new_row.append((''.join(mac)[:6]))
	org_id = ouiQuery(new_row[-1])
	new_row.append(org_id)
	return new_row

# Used to crate time stamps.  It returnes a dictionary of the date, time, and DateTime.
# Usage Date: timeStamp()['date']
# Usage Time: timeStamp()['time']
# Usage Date and Time: timeStamp()['DateTime']
def timeStamp():
    now = time.time()
    d = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d')
    t = datetime.datetime.fromtimestamp(now).strftime('%H:%M:%S')
    dt = datetime.datetime.fromtimestamp(now).strftime('%Y-%m-%d-%H-%M')
    return {'date': d, 'time': t, 'DateTime': dt}

def csvWriter(csv_file, data):
	with open(csv_file, 'wb') as csvfile:
		file_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
		file_writer.writerows(data)
		csvfile.close()
		print """
Complete!
The results has been written to %s""" % (csv_file)

# Takes an OUI of a MAC address, checks the local dictionary, and if it's not present,
# it queries this API to get the company name of the vendor, and returns it.
def ouiQuery(oui):
	global oui_dict
	if oui_dict.has_key(oui):
		return oui_dict[oui]
	else:
		api_url = 'http://www.macvendorlookup.com/api/v2/%s/' % (oui)
		api_response=urllib2.urlopen(api_url)
		api_data = api_response.read()
		if len(api_data) > 0:
			parsed_data = json.loads(api_data)
			company = str(parsed_data[0]['company'])
		else: 
			company = 'UNKNOWN'
		oui_dict[oui] =  company
		return company


# main() runs by default.  Because the 'walk' and 'extract' commands are mutually exclusive,
# it makes a decision about which function to run besed on whether 'args' has the exptected
# attribute for either the config file, or results file.  If it finds the config file,
# it runs the 'walk' function.  If it finds the results file attribute, it runs the extract
# funtion. 
def main():
	
	global oui_dict
	global oui_file

	# Load the OUI dictionary
	if os.path.isfile(oui_file):
	    with open(oui_file, 'r') as f:
	    	oui_dict = json.load(f) #f.readlines()
	oui_count = len(oui_dict)    	
	if hasattr(args,'in_file'):
		walk()

	elif hasattr(args,'results_file'):
		extract()
	# If the OUI dictionary has new items, write a new dictionary file.
	if len(oui_dict) > oui_count:
	    with open(oui_file, 'w') as f:
	        json.dump(oui_dict, f) #f.writelines(oui_dict)
	        f.close()

if __name__ == '__main__':
    main()