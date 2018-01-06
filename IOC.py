#!/usr/bin/python3
import argparse
import requests
import uuid
import xml.etree.cElementTree as ET
import requests
from pprint import pprint

parser = argparse.ArgumentParser()
parser.add_argument("prov_hash", help="Enter the hash to retrieve details from Virustotal")
args = parser.parse_args()
prov_hash = args.prov_hash

params = {'apikey': '345b1725730d11661043a070b763b89e5f5c4340e3d72cae2bc210bfac3edc0f', 'resource': prov_hash}

headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  VirusTotal"
  }
response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
  params=params, headers=headers)
json_response = response.json()
#Prints Json Response from VirusTotal
pprint(json_response) 

#Retrieve values used in IOC from Json
md5 = json_response['md5']
sha1 = json_response['sha1']
sha256 = json_response['sha256']

#Hybrid Analysis
KEY_Hybrid = 'duhb3r6b02gcg8wg8kcwwwswc'
SECRET_Hybrid = 'f7c072deec549790e52a7dc058fc7830fc99688b4a0d5575'

headers_Hybrid = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  Falcon"
  }

url = "https://www.hybrid-analysis.com/api/scan/" + str(prov_hash)
params_Hybrid = {"apikey":KEY_Hybrid,"secret":SECRET_Hybrid,"type":"json"}
response_Hybrid = requests.get(url, params=params_Hybrid, headers=headers_Hybrid)
json_Hybrid = response_Hybrid.json()
pprint(json_Hybrid) #Prints Json Response from Hybrid Analysis

size = (response['response'][0]['size']) #File Size 
domains = (response['response'][0]['domains']) #Domains
compro_hosts = (response['response'][0]['compromised_hosts']) #Compromised IP's (Hosts)
hosts = (response['response'][0]['hosts']) #IP Addresses
file_name = (response['response'][0]['submitname']) #File Name

def indent(elem, level=0):
  i = "\n" + level*"  "
  if len(elem):
    if not elem.text or not elem.text.strip():
      elem.text = i + "  "
    if not elem.tail or not elem.tail.strip():
      elem.tail = i
    for elem in elem:
      indent(elem, level+1)
    if not elem.tail or not elem.tail.strip():
      elem.tail = i
  else:
    if level and (not elem.tail or not elem.tail.strip()):
      elem.tail = i

def buildTree():
	from datetime import datetime
	time = datetime.now().replace(microsecond=0).isoformat()
	short_desc = input("What is the name of the IoC? ")
	desc = input("What is the description of the IoC? ")
	author = input("Who is the author of the IoC? ")
	
	ioc = ET.Element("ioc")
	ioc.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	ioc.set("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
	ioc.set("xmlns", "http://schemas.mandiant.com/2010/ioc")
	ioc.set("id", str(uuid.uuid4()))
	ioc.set("last-modified", time)
	
	ET.SubElement(ioc, "short_description").text = short_desc
	ET.SubElement(ioc, "description").text = desc
	ET.SubElement(ioc, "keywords")
	ET.SubElement(ioc, "authored_by").text = author
	ET.SubElement(ioc, "authored_date").text = time
	ET.SubElement(ioc, "links")
	definition = ET.SubElement(ioc, "definition")
	#md5sum	
	indicator = ET.SubElement(definition, "Indicator")
	indicator.set("operator", "OR")
	indicator.set("id", str(uuid.uuid4()))

	indicatorItem = ET.SubElement(indicator, "IndicatorItem")
	indicatorItem.set("id", str(uuid.uuid4()))
	indicatorItem.set("condition", "is")
	
	context = ET.SubElement(indicatorItem, "Context")
	context.set("document", "FileItem")
	context.set("search", "FileItem/Md5sum")
	context.set("type", "mir")
	
	content = ET.SubElement(indicatorItem, "Content")
	content.text = md5
	content.set("type", "md5")
	#sha1
	indicator1 = ET.SubElement(definition, "Indicator")
	indicator1.set("operator", "OR")
	indicator1.set("id", str(uuid.uuid4()))

	indicatorItem1 = ET.SubElement(indicator1, "IndicatorItem")
	indicatorItem1.set("id", str(uuid.uuid4()))
	indicatorItem1.set("condition", "is")
	
	context1 = ET.SubElement(indicatorItem1, "Context")
	context1.set("document", "FileItem")
	context1.set("search", "FileItem/Sha1sum")
	context1.set("type", "mir")
	
	content1 = ET.SubElement(indicatorItem1, "Content")
	content1.text = sha1
	content1.set("type", "sha1")
	#sha256
	indicator2 = ET.SubElement(definition, "Indicator")
	indicator2.set("operator", "OR")
	indicator2.set("id", str(uuid.uuid4()))

	indicatorItem2 = ET.SubElement(indicator2, "IndicatorItem")
	indicatorItem2.set("id", str(uuid.uuid4()))
	indicatorItem2.set("condition", "is")
	
	context2 = ET.SubElement(indicatorItem2, "Context")
	context2.set("document", "FileItem")
	context2.set("search", "FileItem/Sha256sum")
	context2.set("type", "mir")
	
	content2 = ET.SubElement(indicatorItem2, "Content")
	content2.text = sha256
	content2.set("type", "sha256")

	tree = ET.ElementTree(ioc)
	tree.write("AutoGen.ioc", xml_declaration=True, encoding="us-ascii")

if __name__ == "__main__":
  buildTree()
