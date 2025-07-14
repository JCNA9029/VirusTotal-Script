import hashlib
import requests
import pickle
import numpy as np
import socket
import sys
from pathlib import Path
import os

def check_internet_connection(host="8.8.8.8", port=53, timeout=3):
    try:
        # Try to create a socket connection to the host
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False

#VirusTotal API 
headers = {
        "accept": "application/json",
        "x-apikey": "acf09e97046fd748b4cdc5a9cd2a53d6da2ca56d57eb8602f9e0374146ad78a3"
    }
BASE_URL = 'https://www.virustotal.com/api/v3/files/'

#file extension to number for easier model training
extension_map = {
    'dll': 1,
    'exe': 2,
    '2exe': 3,
    'doc': 4,
    'docx': 4,
    'xlsx': 5,
    'xls': 5,
    '4x': 6
 }  

#sending the number to the machine model
def map_extension_to_number(parameter):
    return extension_map.get(parameter, -1)  

#conversion of the file to SHA256
def sha256_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        #Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

#Start of the program
def start():
    while True:
            choice = int(input("Do you want to use your SHA (1) or upload a file (2) or Exit (3)?"))
            if choice == 2: #Upload a file
                antivirus_drag()
                end()
                break
            elif choice == 1: #Use a SHA256 Key
                antivirus_SHA()
                end()
                break
            elif choice == 3: #Exit
                print("Thank you for using the app!")
                raise SystemExit
            else: print("invalid answer")

#Dragging option
def antivirus_drag():
    while True:
        decision = input("Do you want to upload a list of SHA (.txt) for multiple quick scan (1) or a single scan(2)? Press 3 to return. ")
        if decision == '1': #.txt multiple Hash Scanning
            file_path = input("Drag the .txt file that has list of SHA256 that you want to scan: ")
            if file_path == '':
                print("Please upload a file")
            else:
                process_hashes_from_file(file_path)
                end()
                break
        elif decision == '2': #Single File Scanning
            file_path = input("Drag the file you want to scan: ")
            SHA=None
            if file_path == '':
                print("Please upload a file")
            else:
                asd(SHA=SHA, file_path=file_path)
                end()
                break
        elif decision == '3': #Return to Start
            start()
            raise SystemExit
        else:
            print("invalid answer")
            decision

#SHA256 Option
def antivirus_SHA():
    SHA = input("Input the SHA that you want to scan, press '1' to go back:")
    if SHA == '1':
        start()
    else:
        file_path = None
        asd(SHA=SHA, file_path=file_path)
        
#Antivirus Function
def asd(SHA, file_path):
    path = SHA or file_path #Choose if the program would use user SHA or filepath
    if path is file_path:
        sha_path = sha256_file(file_path)
    else:
        sha_path = SHA       
        print("SHA256 of the file:" +  sha_path)
    url2 = BASE_URL + sha_path
     
    response = requests.get(url2, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        
        #Extracting relevant information
        attributes = json_response.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        #Extract values with defaults
        analysis_id = json_response.get('data', {}).get('id', 'Not Available')
        scan_results = attributes.get('last_analysis_results', {})
        malicious = stats.get('malicious', 0)
        harmless = stats.get('harmless', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        timeout = stats.get('timeout', 0)
        confirmedtimeout = stats.get('confirmed-timeout', 0)
        failure = stats.get('failure', 0)
        unsupported = stats.get('type-unsupported', 0)
        names = [attributes.get('names', 'Not Available')]

        #Calculate total engines
        total_engines = sum([malicious, harmless, suspicious, undetected, timeout, confirmedtimeout, failure, unsupported])

        print(f"\nAnalysis ID: {analysis_id}")
        print(f"Total Scan Engines: {total_engines}")
        print(f"Malicious Detections: {malicious}")
        print(f"Harmless Results: {harmless}")
        print(f"Suspicious Results: {suspicious}")
        print(f"Undetected Results: {undetected}")
        print(f"Unsupported Results: {unsupported}")
        print(f"Failure Results: {failure}")
        
        print("\nDetection Results:")
        #Displaying results
        for engine, result in scan_results.items():
            if result['category'] == 'malicious':
                print(f"{engine}: {result['category']} - {result['result']}")
            else:
                print(f"{engine}: {result['category']}")
                
        #For printing common names 
        print("\nItem commonly known as: ")
        for name in names:
            print(name)   
            
     #If SHA256 is not yet on the database of VirusTotal API       
    elif file_path == None:
        print(f"Error: {response.status_code} - {response.text} \n The file is not yet on the database. Please try again after a few minutes")
    else:
        error(file_path, response)

def get_file_info(file_hash):
    
    url = BASE_URL + file_hash
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        file_info = data['data']['attributes']
        stats = file_info.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        harmless = stats.get('harmless', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        failure = stats.get('failure', 0)
        unsupported = stats.get('type-unsupported', 0)
        
        print(f"Malicious Detections: {malicious}")
        print(f"Harmless Results: {harmless}")
        print(f"Suspicious Results: {suspicious}")
        print(f"Undetected Results: {undetected}")
        print(f"Unsupported Results: {unsupported}")
        print(f"Failure Results: {failure}")
        
        return {
            "malicious": malicious,
            "harmless": harmless,
            "suspicious": suspicious,
            "undetected": undetected,
            "unsupported": unsupported,
            "failure": failure,
        }       
    else:
        return f"Error {response.status_code}: {response.text}"
    
import os

def process_hashes_from_file(file_path):
    output = input("Name the file you want to save the results (type 'none' if you don't want): ").strip()
    if output != '':
        if file_path.lower().endswith('.txt'):  #Check if the file is a .txt file
            try:
                if os.path.isfile(file_path):  #Check if the file exists
                    if isinstance(output, str) and output.lower() != "none":  #If the user wants to save results
                        with open(file_path, 'r') as f, open(output + '.txt', 'w') as output_file:
                            for line in f:
                                file_hash = line.strip()
                                if file_hash:  #Skip empty lines
                                    print(f"\nChecking hash: {file_hash}")
                                    result = get_file_info(file_hash)
                                    if isinstance(result, dict):  #If the result is a dictionary
                                        output_file.write(f"Hash: {file_hash}\n")
                                        for key, value in result.items():
                                            output_file.write(f"{key.capitalize()}: {value}\n")
                                        output_file.write("\n")
                                    else:  # If the result is not a dictionary, write the error
                                        output_file.write(f"Hash: {file_hash}\nError: {result}\n\n")
                                else:
                                    print("Skipping empty line.")
                    else:  #If the user doesn't want to save results
                        with open(file_path, 'r') as f:
                            for line in f:
                                file_hash = line.strip()
                                if file_hash:  #Skip empty lines
                                    print(f"\nChecking hash: {file_hash}")
                                    result = get_file_info(file_hash)
                                    if isinstance(result, dict):
                                        for key, value in result.items():
                                            print(f"{key.capitalize()}: {value}")
                                    else:
                                        print(f"Error: {result}")
                else:
                    print("The file does not exist. Please try again.")
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print("\nThe file is not a .txt file. Please try again with a valid .txt file.")
    else:
        print("Please insert name")
        process_hashes_from_file(file_path)

#When uploading the file but not on database, transitions to Machine Learning
def error(file_path, response):
    print(f"Error: {response.status_code} - {response.text} \n The file is not yet on the database. Please try again after a few minutes \n Scanning using Machine Learning (available to scan: .dll, .exe, .docx, .xls files).")
    parameter = Path(file_path).suffix[1:]
    numeric_value = map_extension_to_number(parameter)
    if parameter not in extension_map:
            print(f"Unknown file extension: {parameter}")
            return -1
    numeric_value_reshaped = np.array([[numeric_value]])
    prediction(numeric_value_reshaped) 

#Machine Learning Prediction
def prediction(numeric_value_reshaped):
    with open('antivirus3', 'rb') as file:
        clf = pickle.load(file)
        pred = clf.predict(numeric_value_reshaped)
        print("\n The prediction are as follows: \n\n   Malice      Generic    Trojan   Ransomware    Worm     Backdoor")
        np.set_printoptions(suppress=True)
        print(pred)
        print("  Spyware     Rootkit    Encrypter Downloader")

#End Function       
def end():
    while True:
        answer = input("\nDo you want to scan another file, Yes (Y) or No (N)? Or return to the Menu (M)?").lower()
        if answer == 'y':
            start()
            break
        elif answer == 'n':
            print("Thank you for using the app!")
            raise SystemExit
        elif answer == 'm':
            start()
        else: 
            print("Invalid Answer")
            answer

if check_internet_connection():
        print("Connected to the internet. Proceeding...")
        start()
else:
        print("No internet connection. Exiting...")
        sys.exit()



                




