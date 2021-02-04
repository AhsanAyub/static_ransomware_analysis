#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"

# Import libraries
import csv
import json

''' Utility function to access VirusTotal report based on the MD5
hash of the ransomware sample. Store the report information in a
dictionary as per requirement of the AVClass labelling tool. '''
def VT_scan(api_key, resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    data = {}
    try:
        response_json = requests.get(url, params=params)
        response = response_json.json()
        data["sha1"] = response["sha1"]
        data["av_labels"] = []
        for av_engine in response["scans"]:
            temp = []
            temp.append(str(av_engine))
            temp.append(str(response["scans"][av_engine]["result"]))
            data["av_labels"].append(temp)
        data["scan_date"] = response["scan_date"]
        data["sha256"] = response["sha256"]
        data["md5"] = response["md5"]
    
    except:
        print("Something went wrong during VT scan")
        return {}

    return data

# Driver program
if __name__ == '__main__':
    api_key = "...put api key here..."

    ''' Read the JSON file that contains all the hash codes of ransomware
    used in the research (734) '''
    with open('./knowledge_extractor_set_dump.json') as f:
        ransomware_samples_fingerprint = json.loads(f.read())

    ''' Using VirusTotal engine to scan every sample
    Dumping the report to a json file '''
    with open('./vt_api2_report_734_ransomware_samples.json', 'w') as f:
        for item in ransomware_samples_fingerprint:
            temp = {}
            temp = VT_scan(api_key, ransomware_samples_fingerprint[item]['fingerprint']['md5'])
            temp = str(temp)
            temp = temp.replace("'", "\"")
            f.write("%s\n" % temp)