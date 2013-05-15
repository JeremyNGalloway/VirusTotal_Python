#!/usr/bin/python
#Written by Jeremy 'germ' Galloway
#This module submits a user-defined URL to the VirusTotal scanning engine, and displays the results
import simplejson
import urllib
import urllib2
import re
from time import sleep 
target = raw_input('Target domain to scan -->') #get the target domain to scan from the user's keyboard
url = "https://www.virustotal.com/vtapi/v2/url/scan" #vt submission url
apikey = "YourApiKeyHere" 
parameters = {"url": target,
              "apikey": apikey }
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
try:                                 #if the user cannot contact vt, an exception will be raised
	response = urllib2.urlopen(req)
except:
	print "URL submission failed"
	exit()
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
  print "Waiting in queue...\n"                               #if so, sleep and then retry
  sleep(10)
  try:
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    response_dict = simplejson.loads(json)
  except:
  	print "URL submission failed"
  	
print "Permalink: " + response_dict.get('permalink') + "\n"  #printing info about response
print "Scan date: " + response_dict.get('scan_date') + "\n"  #printing info about response

results = response_dict.get('scans') #make dictionary for the scan results

for key, value in results.iteritems(): #print the scan results with formatted output
    print str(key).ljust(22) + '*',
    if hasattr(value, 'items'):
        for subkey, subvalue in value.items():
            print str(subkey).capitalize()+":", str(subvalue).capitalize()+"  ",
        else:
            print
    else:
        print str(value)
      
print "\n" + str(response_dict.get('positives')) + " positives out of " + str(response_dict.get('total')) + " total. \n" #printing info about response

