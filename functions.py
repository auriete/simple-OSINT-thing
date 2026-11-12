import requests
import vt
from ipwhois import *
import dns.resolver
import json
import time



def whois_query(addr):
    try:
        stripped = addr.replace('.','')
        # add regex later
        if stripped.isnumeric():
            ipwhois = IPWhois()
            data = ipwhois.lookup(addr)
            return json.dumps(data)
        else:
            return "Please enter a valid IP address. (e.g. 8.8.8.8)"
            
    
    except ConnectionError:
        print("Something went wrong!")

def shodan_query(IP,time=10):
    try:
        results = requests.get(f'https://internetdb.shodan.io/{IP}',timeout=time)
        data = results.json()
        return data
    
    except requests.exceptions.ConnectionError:
        print("Something went wrong! Please check your connection and try again.")
    except requests.exceptions.Timeout:
        print("Took too long to get a response! Please try again, or adjust your timeout value.")

def domain_query(domain: str):

    record_types = ['A','AAAA','MX','CNAME','NS','SOA','TXT']
    result = {}
    indv_records = []
    for indv_type in record_types:
        try:
            response = dns.resolver.resolve(domain,indv_type)
            for record in response:
                indv_records.append(record.to_text())
            result.update({indv_type: indv_records})
            indv_records = []
            

        except dns.resolver.NoAnswer:
            result.update({indv_type: "None"})
        except dns.resolver.NXDOMAIN:
            print("Results not found")

    return json.dumps(result)

def malware_scan(target: str):
    try:
        VT_KEY = "[REMOVED KEY]"
        c = vt.Client(VT_KEY)

        analysis = c.scan_url(url=target)
        while True:
            analysis = c.get_object("/analyses/{}", analysis.id)
            print(analysis.status)
            if analysis.status == "completed":
                break
            time.sleep(5)
        results_dict = analysis.to_dict()
        #results = analysis.results
        #results = str(results)
        return results_dict["attributes"]["results"]
        
    except:
        return "Error"
    finally:
        c.close()
