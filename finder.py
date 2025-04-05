#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tool Name: BYOVDFinder
# Description: Checks which drivers from loldrivers.io are NOT blocked by the current HVCI blocklist.
# Usage: python3 finder.py driversipolicy.xml
#
# Author: Nikhil John Thomas (@ghostbyt3)
# Contributors: Robin (@D4mianWayne)
# License: Apache License 2.0
# URL: https://github.com/ghostbyt3/BYOVDFinder

import argparse
import requests
from colorama import init, Fore, Back, Style
import xml.etree.ElementTree as ET

init(autoreset=True)

LOLDIVERS_URL = "https://www.loldrivers.io/api/drivers.json"

def load_loldrivers():
    response = requests.get(LOLDIVERS_URL)
    data = response.json()
    driver_info = {}
    known_vulnerable_samples = []
    
    for entry in data:
        if "KnownVulnerableSamples" in entry:
            for sample in entry["KnownVulnerableSamples"]:
                sample['_parent_driver'] = {
                    'Id': entry.get('Id'),
                    'Tags': entry.get('Tags', []),
                    'Category': entry.get('Category'),
                    'MitreID': entry.get('MitreID')
                }
                known_vulnerable_samples.append(sample)
    
    return known_vulnerable_samples

def load_policy(xml_path):
    namespaces = {'ns': 'urn:schemas-microsoft-com:sipolicy'}
    tree = ET.parse(xml_path)
    root = tree.getroot()

    file_rules = root.find("ns:FileRules", namespaces)
    signers = root.find("ns:Signers", namespaces)

    deny_rules = []
    if file_rules is not None:
        for rule in file_rules.findall("ns:Deny", namespaces):
            hash_value = rule.get("Hash", "").lower()
            if hash_value:
                deny_rules.append(hash_value)

    cert_roots = []
    if signers is not None:
        for signer in signers.findall("ns:Signer", namespaces):
            for cert in signer.findall("ns:CertRoot", namespaces):
                cert_value = cert.get("Value", "").lower()
                if cert_value:
                    cert_roots.append(cert_value)

    return deny_rules, cert_roots

def has_blocked_hash(driver, deny_rules):
    # Check if any of the driver's hash match blocked hash
    hashes_to_check = [
        driver.get("MD5", "").lower(),
        driver.get("SHA1", "").lower(),
        driver.get("SHA256", "").lower(),
    ]
    
    if "Authentihash" in driver:
        auth_hash = driver["Authentihash"]
        hashes_to_check.extend([
            auth_hash.get("MD5", "").lower(),
            auth_hash.get("SHA1", "").lower(),
            auth_hash.get("SHA256", "").lower(),
        ])
    
    for h in hashes_to_check:
        if h and h in deny_rules:
            return True
    return False

def has_blocked_signer(driver, cert_roots):
    # Check if any of the driver's signatures match blocked cert roots
    if "Signatures" not in driver:
        return False
        
    for sig in driver["Signatures"]:
        if "Certificates" in sig:
            for cert in sig["Certificates"]:
                if "TBS" in cert:
                    tbs = cert["TBS"]
                    for hash_type in ["MD5", "SHA1", "SHA256", "SHA384"]:
                        if hash_type in tbs and tbs[hash_type].lower() in cert_roots:
                            return True
    return False

def print_driver(driver):
    parent_info = driver.get('_parent_driver', {})
    driver_id = parent_info.get('Id', '')
    driver_link = f"https://www.loldrivers.io/drivers/{driver_id}" if driver_id else "N/A"
    
    filename = driver.get('Filename') or ''.join(parent_info.get('Tags', []))
    print(Fore.RED + Style.BRIGHT + f"DRIVER: {filename if filename else 'Unknown'}")
    print(Fore.GREEN + f"  Link: {driver_link}")
    
    md5 = driver.get('MD5')
    sha1 = driver.get('SHA1')
    sha256 = driver.get('SHA256')

    if md5:
        print(f"  MD5: {md5}")
    if sha1:
        print(f"  SHA1: {sha1}")
    if sha256:
        print(f"  SHA256: {sha256}")
    if any([md5, sha1, sha256]):
        print("-"*80)

def main(xml_path):

    print(Fore.CYAN + r"""
      _____   _______   _____  ___ _         _         
     | _ ) \ / / _ \ \ / /   \| __(_)_ _  __| |___ _ _ 
     | _ \\ V / (_) \ V /| |) | _|| | ' \/ _` / -_) '_|
     |___/ |_| \___/ \_/ |___/|_| |_|_||_\__,_\___|_|  
                                                       """
    )

    loldrivers = load_loldrivers()
    deny_rules, cert_roots = load_policy(xml_path)
    blocked_count = 0
    allowed_count = 0
    
    for driver in loldrivers:
        if has_blocked_hash(driver, deny_rules) or has_blocked_signer(driver, cert_roots):
            blocked_count += 1
        else:
            allowed_count += 1
            print_driver(driver)
    
    print()
    print(Fore.MAGENTA + f"[+] Number of Blocked Drivers: {blocked_count}")
    print(Fore.MAGENTA + f"[+] Number of Allowed Drivers: {allowed_count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check allowed drivers against the HVCI block list.")
    parser.add_argument("xml_path", help="Path to the HVCI policy XML file.")
    args = parser.parse_args()
    
    main(args.xml_path)