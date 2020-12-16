#!/usr/bin/env python3

### This script is used to query MISP for new events containing attributes of type sigma.
### These attributes should contain only signatures written in the sigma format.
### Signatures can then currently be converted and imported to either ElastAlert or Elastic SIEM rules using the Sigmac converter.
### Converter must be obtained from https://github.com/Neo23x0/sigma 
### Script is used as part of project at EAAA.

import requests
import json
import sys
import subprocess
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

### FILE AND FOLDERS
ALERT_FOLDER = './alerts/'				    
SIGNATURE_FOLDER = './sigma_signatures/'		   
CONFIG_FOLDER = './sigma_configs/'	

### INSERT SIEM CONFIGS	    
CONFIG_FILE = ''                     
BACKEND_CONFIG_FILE = ''   

### PROJECT REQUIRES THE SIGMAC CONVERTER AVAILABLE
### INSERT PATH TO SIGMAC CONVERTER
SIGMAC = ''

### INSERT TARGET OUTPUT
TARGET = ''

### INSERT KIBANA SETTINGS
KIBANA_URL = '/api/detection_engine/rules/_import'
KIBANA_USER = ''
KIBANA_AUTH = ''

### INSERT MISP SETTINGS
MISP_URL = '/attributes/restSearch'
MISP_API_KEY = ''

### Queries MISP for new attributes of type sigma within the last X minutes (default 5)
### Expected result is JSON format 
def mispQuery():
    headers={'Authorization':MISP_API_KEY,'Accept':'application/json','Content-type':'application/json'}
    data=json.dumps({"returnFormat":"json","type":"sigma","last":"5m"})
    response = requests.post(MISP_URL,headers=headers,data=data,verify=False)
    return response
    
### Reads converted file from alert folder request POST for rule to Kibana as an imported file
def pushToKibana(elasticRule):
    auth = (KIBANA_USER, KIBANA_AUTH)
    files = {'file': open(ALERT_FOLDER + elasticRule, 'rb')}
    headers = {'kbn-xsrf' : 'true'}
    requests.post(KIBANA_URL, headers=headers, files=files, auth=auth)

### Write signatures and rules to disk
def fileWriter(directory, content, filename):
    try:
        with open(directory + filename, 'w') as file:
            file.write(content)
            file.close()
    except IOError as error:
        print(error)

### Decode bytearray
def decodeBytes(output_bytes):
    output_str = output_bytes.decode("utf-8")
    return output_str

### Runs Sigmac converter according to global variables and a few static settings
def convertAndApply(sigma_filename):
    if (TARGET == 'es-rule'):
        run = subprocess.Popen([SIGMAC, '-t', TARGET, '-c', CONFIG_FILE, '--backend-option', 'keyword_field=''', SIGNATURE_FOLDER + sigma_filename], stdout=subprocess.PIPE)
        rule = decodeBytes(run.communicate()[0])
        ruleName = sigma_filename + '.ndjson'
        fileWriter(ALERT_FOLDER, rule, ruleName)
        pushToKibana(ruleName)
        print("Sigmac converter called for: " + sigma_filename) 
    
    elif (TARGET == 'elastalert'):
        run = subprocess.Popen([SIGMAC, '-t', TARGET, '-c', CONFIG_FILE, '--backend-config', BACKEND_CONFIG_FILE, SIGNATURE_FOLDER + sigma_filename], stdout=subprocess.PIPE)
        rule = decodeBytes(run.communicate()[0])
        ruleName = sigma_filename
        fileWriter(ALERT_FOLDER, rule, ruleName)
        print("Sigmac converter called for: " + sigma_filename) 
    
### Main loop
### For each attribute in MISP response, write signature to disk
### Notify Sigmac to convert to rule
### Sleep accoring to time set in MISP (default 5m)
try:
    while True:
        response = mispQuery()
        events = response.json()
        if events['response']['Attribute'] != []:
            for attribute in events['response']['Attribute']:
                sigmaFileName = 'Sigma' + '_' + attribute['id'] + '.yml'
                attr_value = attribute['value']
                fileWriter(SIGNATURE_FOLDER, attr_value, sigmaFileName)
                convertAndApply(sigmaFileName)
        else:
            print("No new events")
        time.sleep(300)
except KeyboardInterrupt:
    sys.exit
