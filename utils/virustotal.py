# Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
# please don't share this file with anyone else. PRIVATE_API_KEY 
# is approved by virustotal and can only be used under certain conditions.
# Disclosing this key is not allowed.
#for the search modifier, please see https://www.virustotal.com/intelligence/help/file-search/#search-
#to use this lib, you need to install the Python Requests Library which you can find at 
#http://docs.python-requests.org/

import requests
import json
import argparse
import sys
import os
import time
PRIVATE_API_KEY = ""
TOTAL = 0
TAG_COUNT = 0
SAMPLE_FOLDER = "./SAMPLE/"
#TAG_LIST = {"CVE-2003-0344","CVE-2005-1790","CVE-2005-4560",
#		"CVE-2006-1359","CVE-2006-4868","CVE-2006-3730","CVE-2006-4777",
#		"CVE-2006-5745","CVE-2007-0038","CVE-2008-2463","CVE-2008-3008",
#		"CVE-2008-3704","CVE-2008-4844","CVE-2009-0075","CVE-2009-1534",
#		"CVE-2009-3672","CVE-2010-0249","CVE-2010-0248","CVE-2010-0806",
#		"CVE-2010-0805","CVE-2010-0483","CVE-2010-0480","CVE-2010-1885",
#		"CVE-2010-2568","CVE-2010-3962","CVE-2010-3971","CVE-2011-1260",
#		"CVE-2011-1996","CVE-2011-3400","CVE-2012-0003","CVE-2012-1876",
#		"CVE-2012-1875","CVE-2013-0025","CVE-2013-0074","CVE-2013-3896",
#		"CVE-2013-2551","CVE-2013-3163","CVE-2013-3184","CVE-2013-3205",
#		"CVE-2013-3893","CVE-2013-3897","CVE-2013-3918","CVE-2014-0307",
#		"CVE-2012-4792","CVE-2013-1347","CVE-2006-0003","CVE-2006-4704",
#		"CVE-2012-4969","CVE-2006-1016","CVE-2013-3893"}

TAG_LIST = {
	"CVE-2012-2546","CVE-2012-2523","CVE-2012-2522","CVE-2012-2521","CVE-2012-1539","CVE-2012-1538","CVE-2012-1529","CVE-2012-1526","CVE-2012-1524","CVE-2012-1522","CVE-2010-1118","CVE-2010-0249",
"CVE-2009-3672","CVE-2009-3126","CVE-2009-3019","CVE-2009-3003","CVE-2009-2954","CVE-2009-2764","CVE-2009-2668","CVE-2009-2655","CVE-2009-2536","CVE-2009-2531","CVE-2009-2530",
"CVE-2009-2529","CVE-2009-2528","CVE-2009-2518","CVE-2009-2504","CVE-2009-2503","CVE-2009-2502","CVE-2009-2501","CVE-2009-2500","CVE-2009-2350","CVE-2009-2064","CVE-2009-1547",
"CVE-2009-1530","CVE-2009-0554","CVE-2009-0553","CVE-2009-0551","CVE-2009-0550","CVE-2009-0369","CVE-2009-0341","CVE-2009-0076","CVE-2009-0075","CVE-2009-0072","CVE-2008-5912",
"CVE-2008-5750","CVE-2008-5556","CVE-2008-5555","CVE-2008-5554","CVE-2008-5553","CVE-2014-0277","CVE-2014-0276","CVE-2014-0275","CVE-2014-0274","CVE-2014-0273","CVE-2014-0272",
"CVE-2014-0271","CVE-2014-0270","CVE-2014-0269","CVE-2014-0268","CVE-2014-0267","CVE-2014-0235","CVE-2013-7331","CVE-2013-5052","CVE-2013-5051","CVE-2013-5049","CVE-2013-5048",
"CVE-2013-5047","CVE-2013-5046","CVE-2013-5045","CVE-2013-4015","CVE-2013-3918","CVE-2013-3917","CVE-2013-3916","CVE-2013-3915","CVE-2013-3914","CVE-2013-3912","CVE-2013-3911",
"CVE-2013-3910","CVE-2013-3909","CVE-2013-3908","CVE-2013-3897","CVE-2013-3893","CVE-2013-3886","CVE-2013-3885","CVE-2013-3882","CVE-2013-3875","CVE-2013-3874","CVE-2013-3873",
"CVE-2013-3872","CVE-2013-3871","CVE-2013-3846","CVE-2013-3845","CVE-2013-3209","CVE-2013-3208","CVE-2013-3207","CVE-2013-3206","CVE-2013-3205","CVE-2013-3204","CVE-2013-3203",
"CVE-2014-2782","CVE-2014-2777","CVE-2014-2776","CVE-2014-2775","CVE-2014-2773","CVE-2014-2772","CVE-2014-2771","CVE-2014-2770","CVE-2014-2769","CVE-2014-2768","CVE-2014-2767",
"CVE-2014-2766","CVE-2014-2765","CVE-2014-2764","CVE-2014-2763","CVE-2014-2761","CVE-2014-2760","CVE-2014-2759","CVE-2014-2758","CVE-2014-2757","CVE-2014-2756","CVE-2014-2755",
"CVE-2014-2754","CVE-2014-2753","CVE-2014-1815","CVE-2014-1805","CVE-2014-1804","CVE-2014-1803","CVE-2014-1802","CVE-2014-1800","CVE-2014-1799","CVE-2014-1797","CVE-2014-1796",
"CVE-2014-1795","CVE-2014-1794","CVE-2014-1792","CVE-2014-1791","CVE-2014-1790","CVE-2014-1789","CVE-2014-1788","CVE-2014-1786","CVE-2014-1785","CVE-2014-1784","CVE-2014-1783",
"CVE-2014-1782","CVE-2014-1781","CVE-2014-1780","CVE-2014-1779","CVE-2014-1778","CVE-2014-1777","CVE-2013-2557","CVE-2013-2552","CVE-2013-2551","CVE-2013-1451","CVE-2013-1450",
"CVE-2013-1347","CVE-2013-1338","CVE-2013-1312","CVE-2013-1311","CVE-2013-1310","CVE-2013-1309","CVE-2013-1308","CVE-2013-1307","CVE-2013-1306","CVE-2013-1304","CVE-2013-1303",
"CVE-2013-1297","CVE-2013-1288","CVE-2013-0811","CVE-2013-0094","CVE-2013-0093","CVE-2013-0092","CVE-2013-0091","CVE-2013-0090","CVE-2013-0089","CVE-2013-0088","CVE-2013-0087",
"CVE-2013-0030","CVE-2013-0029","CVE-2013-0028","CVE-2013-0027","CVE-2013-0026","CVE-2013-0025","CVE-2013-0024","CVE-2013-0023","CVE-2013-0022","CVE-2013-0021","CVE-2013-0020",
"CVE-2013-0019","CVE-2013-0018","CVE-2013-0015","CVE-2012-6502","CVE-2012-4969","CVE-2012-4792","CVE-2012-4787","CVE-2012-4782","CVE-2012-4781","CVE-2012-4775","CVE-2012-2557",
"CVE-2012-2548","CVE-2008-5552","CVE-2008-5551","CVE-2008-4844","CVE-2008-4788","CVE-2008-4787","CVE-2008-4381","CVE-2008-4261","CVE-2008-4260","CVE-2008-4259","CVE-2008-4258",
"CVE-2008-4029","CVE-2008-3477","CVE-2008-3476","CVE-2008-3475","CVE-2008-3474","CVE-2008-3473","CVE-2008-3472","CVE-2008-3014","CVE-2008-3012","CVE-2008-2948","CVE-2008-2259",
"CVE-2008-2258","CVE-2008-2257","CVE-2008-2256","CVE-2008-2255","CVE-2008-2254","CVE-2008-1544","CVE-2008-1442","CVE-2008-1085","CVE-2008-0078","CVE-2008-0076","CVE-2007-5348",
"CVE-2007-4790","CVE-2007-0099","CVE-2014-1776","CVE-2014-1775","CVE-2014-1774","CVE-2014-1773","CVE-2014-1772","CVE-2014-1771","CVE-2014-1770","CVE-2014-1769","CVE-2014-1765",
"CVE-2014-1764","CVE-2014-1763","CVE-2014-1762","CVE-2014-1760","CVE-2014-1755","CVE-2014-1753","CVE-2014-1752","CVE-2014-1751","CVE-2014-0324","CVE-2014-0322","CVE-2014-0321",
"CVE-2014-0314","CVE-2014-0313","CVE-2014-0312","CVE-2014-0311","CVE-2014-0310","CVE-2014-0309","CVE-2014-0308","CVE-2014-0307","CVE-2014-0306","CVE-2014-0305","CVE-2014-0304",
"CVE-2014-0303","CVE-2014-0302","CVE-2014-0299","CVE-2014-0298","CVE-2014-0297","CVE-2014-0293","CVE-2014-0290","CVE-2014-0289","CVE-2014-0288","CVE-2014-0287","CVE-2014-0286",
"CVE-2014-0285","CVE-2014-0284","CVE-2014-0283","CVE-2014-0282","CVE-2014-0281","CVE-2014-0280","CVE-2014-0279","CVE-2014-0278","CVE-2013-3202","CVE-2013-3201","CVE-2013-3199",
"CVE-2013-3194","CVE-2013-3193","CVE-2013-3192","CVE-2013-3191","CVE-2013-3190","CVE-2013-3189","CVE-2013-3188","CVE-2013-3187","CVE-2013-3186","CVE-2013-3184","CVE-2013-3166",
"CVE-2013-3164","CVE-2013-3163","CVE-2013-3162","CVE-2013-3161","CVE-2013-3153","CVE-2013-3152","CVE-2013-3151","CVE-2013-3150","CVE-2013-3149","CVE-2013-3148","CVE-2013-3147",
"CVE-2013-3146","CVE-2013-3145","CVE-2013-3144","CVE-2013-3143","CVE-2013-3142","CVE-2013-3141","CVE-2013-3140","CVE-2013-3139","CVE-2013-3126","CVE-2013-3125","CVE-2013-3124",
"CVE-2013-3123","CVE-2013-3122","CVE-2013-3121","CVE-2013-3120","CVE-2013-3119","CVE-2013-3118","CVE-2013-3117","CVE-2013-3116","CVE-2013-3115","CVE-2013-3114","CVE-2013-3113",
"CVE-2013-3112","CVE-2013-3111","CVE-2013-3110"}
def getComments(hash):
	params = {'apikey': PRIVATE_API_KEY, 'resource': hash}
	response = requests.get('https://www.virustotal.com/vtapi/v2/comments/get', params=params)
	json_response = response.json()
	print json_response

def getReport(hash):
	params = {'apikey': PRIVATE_API_KEY, 'resource': hash, 'allinfo':True}
	response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
	json_response = response.json()
	print json_response

def query( query_key, offset):
	params = {'apikey':PRIVATE_API_KEY , 'query':query_key, 'offset':offset}
	print "querying ....\n" +query_key
	response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params= params)
	print response
	res_json = response.json()
	print "abc"
	return res_json


def download( hash ):
	params = {'apikey':PRIVATE_API_KEY, 'hash': hash}
	response = requests.get('https://www.virustotal.com/vtapi/v2/file/download', params = params)
	downloaded_file = response.content
	return downloaded_file

def download_list(hash_list,tag):
	global TAG_COUNT, TOTAL
	if(not os.path.exists(SAMPLE_FOLDER+tag)):
		os.mkdir(SAMPLE_FOLDER+tag)
	for it in hash_list:
		if os.path.exists(SAMPLE_FOLDER+tag+"/"+it+".html"):
			continue
		df = download(it)
		f = open(SAMPLE_FOLDER+tag+"/"+it+".html", "w")
		f.write(df)
		f.close()
		TAG_COUNT = TAG_COUNT+1
		TOTAL = TOTAL+1
		print "downloaded "+tag+" "+str(TAG_COUNT)+" total "+str(TOTAL)
		time.sleep(0.5)

def search(tag):
	print "downloading samples of"+tag
	query_key = tag +" type:html"
	global TAG_COUNT
	TAG_COUNT = 0
	ret_json = query( query_key, "")
	while True:
		if( "hashes" not in str(ret_json)):
			log(tag +" not exists on virustotal")
			break
		hash_list = ret_json["hashes"]
		download_list(hash_list,tag)
		if("offset" in str(ret_json)):
			offset = ret_json["offset"]
			print "offset "
			ret_json= query(query_key, offset)
		else:
			break
	
	log("samples "+tag+" "+str(TAG_COUNT)+"\n")
def search_exploit(tag, loc):
	print "downlading samples of " + tag
	query_key = tag +" type:html"
	global TAG_COUNT
	TAG_COUNT = 0
	ret_json = query( query_key, "")
	while True:
		if( "hashes" not in str(ret_json)):
			log(tag +" not exists on virustotal")
			break
		hash_list = ret_json["hashes"]
		download_list(hash_list,loc)
		if("offset" in str(ret_json)):
			offset = ret_json["offset"]
			ret_json= query(query_key, offset)
		else:
			break
	
	log("samples "+tag+" "+str(TAG_COUNT)+"\n")

def log(message):
	f = open("./log.txt","a")
	f.write(message)
	f.close()

def downloadFromCVE():
	f = open("./cvelist.txt")
	line = f.readline()
	while 1:
		if not line:
			break
		if len(line) <3:
			line = f.readline()
			continue
		search(line.rstrip())
		line = f.readline()

def downloadFromVT():
	search("CVE")

def downloadFromExploit():
	search_exploit("exploit positives:1+ ls:2014-07-09+ ls:2014-07-11-", "exploit")

def main():
	#getComments('08e59d6876c4fa5925445b626502b28e84bd23c8e335dbfc415a81bef2025e91')
	#getReport("08e59d6876c4fa5925445b626502b28e84bd23c8e335dbfc415a81bef2025e91")
	#for tag in TAG_LIST:
	#	search(tag)
	#downloadFromCVE()
	#downloadFromVT()
	downloadFromExploit()
	global TOTAL
	log("Total samples "+str(TOTAL)+"\n")
	
	

if __name__ == '__main__':
	main()
