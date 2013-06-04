#!/usr/bin/python
#Written by Jeremy 'germ' Galloway JeremyNGalloway@gmail.com
#This module submits a user-defined URL to the VirusTotal scanning engine, and displays the results
import sys
import simplejson
import urllib
import urllib2
import re
from time import sleep 

if len(sys.argv) <= 1:  #get the target domain to scan
  target = raw_input('Target domain to scan -->')  
else: target = sys.argv[1]

url = "https://www.virustotal.com/vtapi/v2/url/scan" #vt submission url
apikey = "your VT api key here" 
parameters = {"url": target,
              "apikey": apikey }
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
json = response.read()  #response from vt


if re.search(r'Scan request successfully queued', json): #if submission succeeds or fails, let the user know
  print "Scan request successfully queued... \n"
else: 
  print "URL submission failed" 
  exit()
#Submission complete, the below code retrieves the results

del parameters["url"] #change the key value for target from 'url' to 'resource' (per vt api)
parameters ["resource"] = target
parameters ["scan"] = 1 #add 'scan' to force submission if url is unknown
url = "https://www.virustotal.com/vtapi/v2/url/report" #redefine url to reflect retreval url
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
json = response.read()
response_dict = simplejson.loads(json) #add the response to a dict that we can parse through

while re.search(r'queued', response_dict.get('verbose_msg')): #check the response to see if we're waiting in queue
  print "Waiting in queue...\n"
  sleep(10)                               #if so, sleep and then retry
  try:
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
  except:
  	print "Error while retrieving report, retrying"
  	
print "Permalink: " + response_dict.get('permalink') + "\n"  #printing info about response
print "Scan date: " + response_dict.get('scan_date') + " (re-run if results are stale) \n"  #printing info about response

results = response_dict.get('scans') #make dictionary for the scan results

for key, value in results.iteritems(): #print the scan results with formatted output
  print str(key).ljust(22) + '*',
  if hasattr(value, 'items'): #parsing through the nested dictionary
    for subkey, subvalue in value.items():
      print str(subkey).capitalize()+":", str(subvalue).capitalize()+"  ",
    else:
      print
  else:
      print str(value)
      
print "\n" + str(response_dict.get('positives')) + " positives out of " + str(response_dict.get('total')) + " total. \n" #printing info about response

