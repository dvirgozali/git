import os
import requests
def check_file_or_folder(path):
    if os.path.isfile(path):
        return "File"
    elif os.path.isdir(path):
        return "Folder"
    else:
        return "Unknown"
def open_file(file):
    try:
        with open(file,'r') as file:
            content=file.read()
        print(f"Contents of '{file}':\n{content}")
        check_file_virustotal(api_key,file)
    except FileNotFoundError:
        print(f"File '{file}' not found.")
    except PermissionError:
        print(f"Permission denied to open file '{file}'.")
    except Exception as e:
        print(f"Error opening file '{file}': {e}")
def open_folder(folder_path):
    try:
       os.path.exists(folder_path)
       print("opening folder"+'{folder_path}')
       files = os.listdir(folder_path)
       for i in range(len(files)):
           type=check_file_or_folder(files[i])
           if type=='File':
               open_file(files[i])
           elif type=='Folder':
               open_folder(files[i])
           else:
               print("the type is unknown")
    except Exception as e:
        print("this folder did not found")

def check_file_virustotal(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': file_path}
    
    try:
        response = requests.get(url, params=params)
        json_response = response.json()
        
        if response.status_code == 200:
            if json_response['response_code'] == 1:
                positives = json_response['positives']
                total = json_response['total']
                print(f"Scan results for file: {file_path}")
                print(f"Detections: {positives}/{total}")
                if positives > 0:
                    print("The file is detected as malicious by some antivirus engines.")
                else:
                    print("The file is not detected as malicious by any antivirus engine.")
            else:
                print("File not found in VirusTotal database.")
        else:
            print(f"Error: {response.status_code}, {json_response.get('verbose_msg')}")
    
    except Exception as e:
        print(f"Exception occurred: {e}")

api_key = os.getenv('VIRUSTOTAL_API_KEY')

