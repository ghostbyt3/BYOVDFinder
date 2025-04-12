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
from packaging import version

init(autoreset=True)

LOLDIVERS_URL = "https://www.loldrivers.io/api/drivers.json"

def load_loldrivers():
    response = requests.get(LOLDIVERS_URL)
    data = response.json()
    known_vulnerable_samples = []
    
    for entry in data:
        if "KnownVulnerableSamples" in entry:
            for sample in entry["KnownVulnerableSamples"]:
                sample['_parent_driver'] = {
                    'Id': entry.get('Id'),
                    'Tags': entry.get('Tags', [])
                }
                known_vulnerable_samples.append(sample)
    
    return known_vulnerable_samples

def load_policy(xml_path):
    namespaces = {'ns': 'urn:schemas-microsoft-com:sipolicy'}
    tree = ET.parse(xml_path)
    root = tree.getroot()

    file_rules = root.find("ns:FileRules", namespaces)
    signers = root.find("ns:Signers", namespaces)

    # Collect deny rules (hash and file version based)
    deny_hashes = set()
    deny_file_versions = {}
    if file_rules is not None:
        for rule in file_rules.findall("ns:Deny", namespaces):
            hash_value = rule.get("Hash", "").lower()
            if hash_value:
                deny_hashes.add(hash_value)
            
            file_name = rule.get("FileName", "")
            max_version = rule.get("MaximumFileVersion", "")
            if file_name and max_version:
                deny_file_versions[file_name.lower()] = max_version

    # Collect signer information with file attrib refs
    signer_info = []
    if signers is not None:
        for signer in signers.findall("ns:Signer", namespaces):
            cert_roots = []
            for cert in signer.findall("ns:CertRoot", namespaces):
                cert_value = cert.get("Value", "").lower()
                if cert_value:
                    cert_roots.append(cert_value)
            
            file_attrib_refs = []
            for ref in signer.findall("ns:FileAttribRef", namespaces):
                rule_id = ref.get("RuleID", "")
                if rule_id:
                    file_attrib_refs.append(rule_id)
            
            if cert_roots:
                signer_info.append({
                    'cert_roots': cert_roots,
                    'file_attrib_refs': file_attrib_refs
                })

    # Collect file attribute rules
    file_attribs = {}
    if file_rules is not None:
        for attrib in file_rules.findall("ns:FileAttrib", namespaces):
            file_name = attrib.get("FileName", "").lower()
            rule_id = attrib.get("ID", "")
            if file_name and rule_id:
                file_attribs[file_name] = rule_id

    return deny_hashes, deny_file_versions, signer_info, file_attribs

def has_blocked_hash(driver, deny_hashes):
    hashes_to_check = set()
    
    # Add direct hashes
    for hash_type in ['MD5', 'SHA1', 'SHA256']:
        h = driver.get(hash_type, "").lower()
        if h:
            hashes_to_check.add(h)
    
    # Add authenticode hashes
    if "Authentihash" in driver:
        auth_hash = driver["Authentihash"]
        for hash_type in ['MD5', 'SHA1', 'SHA256']:
            h = auth_hash.get(hash_type, "").lower()
            if h:
                hashes_to_check.add(h)
    
    return len(hashes_to_check & deny_hashes) > 0

def has_blocked_version(driver, deny_file_versions, file_attribs):
    original_filename = driver.get("OriginalFilename", "").lower()
    if not original_filename:
        return False
    
    max_version = deny_file_versions.get(original_filename)
    if not max_version:
        return False
    
    driver_version = driver.get("FileVersion", "")
    if not driver_version:
        return False
    
    try:
        version_parts = driver_version.replace(',', '.').split()
        clean_version = version_parts[0] if version_parts else ""
        
        if clean_version and version.parse(clean_version) <= version.parse(max_version):
            return True
    except version.InvalidVersion:
        pass
    
    return False

def has_blocked_signer(driver, signer_info, file_attribs):
    if "Signatures" not in driver:
        return False
    
    original_filename = driver.get("OriginalFilename", "").lower()
    file_attrib_id = file_attribs.get(original_filename) if original_filename else None
    
    for sig in driver["Signatures"]:
        if "Certificates" not in sig:
            continue
            
        for cert in sig["Certificates"]:
            if "TBS" not in cert:
                continue
                
            tbs = cert["TBS"]
            for hash_type in ["MD5", "SHA1", "SHA256", "SHA384"]:
                if hash_type not in tbs:
                    continue
                    
                cert_hash = tbs[hash_type].lower()
                for signer in signer_info:
                    if cert_hash in signer['cert_roots']:
                        if (not signer['file_attrib_refs'] or 
                            (file_attrib_id and file_attrib_id in signer['file_attrib_refs'])):
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
    deny_hashes, deny_file_versions, signer_info, file_attribs = load_policy(xml_path)
    blocked_count = 0
    allowed_count = 0
    for driver in loldrivers:
        if (has_blocked_hash(driver, deny_hashes) or 
            has_blocked_version(driver, deny_file_versions, file_attribs) or 
            has_blocked_signer(driver, signer_info, file_attribs)):
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