#/usr/share/python3
#**************************************
#Name :  Mr Whitehat
#Created : 21-04-2024
#Last Modified : 21-04-24
#**************************************


# Antivirus System Using VirusTotal Api
import os
import time
import sys
import hashlib
from colorama import init,Fore
import win32api
import socket
import requests

#Color Scheme
#Add Api Key Here !
ApiKey = ""
B = Fore.BLUE
Y = Fore.YELLOW
R = Fore.RED
C = Fore.CYAN
G = Fore.GREEN
W = Fore.WHITE

#HashCompute
def ComputeHash(data):
    global sig
    sig = hashlib.sha256(data)

    return sig.hexdigest()

#Scan File
def Filescan():

    cls()

    print(G+"\t\t\t\t\t\t"+"*****[Single File Scan]*****"+"\t\t\t\t\t\t\t")
    time.sleep(.7)
    print(Y+"[+]Checking For File")
    time.sleep(.7)
    if not sys.argv[2]:

        print(R+"File Not Supplied!")

    else:
        print()

        print(Y+"[+]Reading File !")

        if os.path.exists(sys.argv[2]):

            print(G+"\t\t\t\t\t\t"+"*****[File Info]*****"+"\t\t\t\t\t\t\t")
            time.sleep(.7)
            print(C+"\nFile Name:",sys.argv[2].split(".")[0])
            time.sleep(.7)
            print("File Extension:.",sys.argv[2].split(".")[-1])
            time.sleep(.7)
            with open(sys.argv[2],"rb") as File:

                Cont = File.read()
                File.close()

            digisig = ComputeHash(Cont)
            print(B+"\n[+]Hash Found [Sha256]:",digisig)
            time.sleep(.7)
            print(Y+"\n[+]File Size :",int(os.path.getsize(sys.argv[2]))/1024,"KB")
            print(G+"\t\t\t\t\t\t"+"*****[Api Interaction]*****"+"\t\t\t\t\t\t\t")
            if IsComputerOnline():
                print(Y+"[+]System Is Online !")
                #Request Api
                ApiRequest(digisig,sys.argv[2])
            
            else:
                print(R+"[!]Computer Is Offline Plz Connect To the Internet")
        else:
            #No FileFound
            print(R+"\n[-]File Not Found !")
            print(G)
#Extension
def FilterExt():
    Ext = sys.argv[2].split(".")[-1]
    print("\n [*]Found Ext :",Ext)
    if Ext == "jpeg" or "jpg":
        return "image/jpeg"
    elif Ext=="exe":
        return "application/x-msdownload"
    elif Ext == "txt":
        return "text/plain"
    elif Ext == "pdf":
        return "application/pdf"
    elif Ext == "ps1" or "bat":
        return "application/octet-stream"
    elif Ext == "py":
        return "text/x-python"
    elif Ext == "png":
        return "image/png"
    else:
        print("Ext Found:",Ext)
        return "application/octet-stream"

#Driver List
def DriveList():
    Drive = win32api.GetLogicalDriveStrings().split("\00")
    for i in range(len(Drive)):
        if Drive[i] == "":
            Drive.pop(i)
    return Drive

#Only Filter Ext
def Ext():
    try:
        cls()
        time.sleep(.5)
        print(G+"\t\t\t\t\t\t"+"*****[Extention Scan]*****"+"\t\t\t\t\t\t\t")
        Extention = sys.argv[2]
        Filelst=[]
        time.sleep(.5)
        print(C+"\n[+]Filtering Extention :",Extention)
        lst = DriveList()
        time.sleep(.5)
        print(Y+"\nEnumerating Drives In The System !")
        for c,el in enumerate(lst):
            if el !="":
                print(G+f"[{c+1}]{el}")
        time.sleep(.5)
        print(Y+"\nTraversing Through The Drive !")
        for i in lst:
            print(C+f"[+]{i}")
            print(G+"[*]Scanning File !")
            Counter=0
            for root,dirs,files in os.walk(i):
                for file in files:
                    if file.endswith(Extention):
                        Counter +=1
                        print(f"[{Counter}].{root}\\{file}")
                        Filelst.append(f"{root}\\{file}")
                        
        time.sleep(.5)
        if not len(Filelst)==0:
            print(Y+"File Count:",len(Filelst))
            for i in Filelst:
                print("[!]File :",i)
                time.sleep(10)
                try:
                    with open(i,"rb") as File:
                        r = File.read()
                        File.close()
                    H = ComputeHash(r)
                    ApiRequest(H,i)
                except:
                    print(R+"File Access Not Allowed [!] Or Request Error")
                    continue
        else:
            print(R+"[*]Extention Not Found!")
    except IndexError:
        print(R+"[!]Index Out Of Range Supply Arguments")
        sys.argv[1:] = ""
        Config()
#Clear
def cls():
    if os.name != "nt":
        os.system("clear")
    else:
        os.system("cls")

#Help
def Config():
    
    print(G+"\t\t\t\t\t\t"+"*****[Antivirus System]*****"+"\t\t\t\t\t\t\t")
    if len(sys.argv) < 2:
        print(f"\nusage : python {sys.argv[0]} ")
        print("\noptions")
        print("\n--f    \t\t\t\tScan a Single File")
        print("\n--ext \t\t\t\tScan only extension .py .exe .txt [Any]")
        print("\n--ip \t\t\t\t Scan Ip For Security")
        print(f"\nEg:{sys.argv[0]} --ext .py")
        print(f"\nEg:{sys.argv[0]} --f File.txt")
        print(f"\nEg:{sys.argv[0]} --ip <ipaddress>")
    else:
        fig = sys.argv[1].replace("--","")
        fig = fig.strip()
        if fig == "f":
            Filescan()
        elif fig == "ext":
            Ext()
        elif fig == "ip":
            try:
                IpInfo(sys.argv[2])
            except:
                print("[!]Pass Arguments as --ip <ipaddress>")
                print(f"\nusage : python {sys.argv[0]} ")
                print("\noptions")
                print("\n--fs\t\t\t\tScan The Whole System")
                print("\n--f    \t\t\t\tScan a Single File")
                print("\n--ext \t\t\t\tScan only extension .py .exe .txt [Any]")
                print("\n--ip \t\t\t\t Scan Ip For Security")
                print(f"\nEg:{sys.argv[0]} --ext .py")
                print(f"\nEg:{sys.argv[0]} --f File.txt")

#Computer Online Or Offline
def IsComputerOnline():
    host = "www.google.com"
    port = 80
    while True:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            s.connect((host,port))
            return True
        except:
            pass
#Request Hash 
def ApiRequest(hashval,file):
    url = "http://virustotal.com/vtapi/v2/file/report"
    data = {"apikey":ApiKey,"resource":hashval}
    response = requests.get(url,params=data)
    print(Y+"[+]Response Code:",response.status_code)
    time.sleep(.7)
    response.close()
    response = response.json()
    if not response["response_code"]==0:
        print(C+"\n[+]MD5:",response["md5"])
        print(R+"\n[!]Postives Count:",response["positives"],G+"/",response["total"])
        print(G)
        print("\n[+]Time:",response["scan_date"])
        time.sleep(.7)
        v = response["scans"].items()
        counter = 0
        print(Y+"\n [+]",response["verbose_msg"],"!")
        print("\n","="*30,"Report","="*30)
        for i in v:
            
            if not i[1]["detected"] == False or i[0].strip()=="K7AntiVirus" or i[0].strip()=="Kaspersky" or i[0].strip()=="Google":
                counter+=1
                print(W+f"\n[{counter}]Vendor:",i[0])
                if not i[1]["result"] == None:
                    print(R+f"Identification:",i[1]["result"])
                else:
                    print(G+f"Bypassed[!]")
                print("")
        print(Y+"="*60)
        if response["positives"] >=3:
            ack=input(Y+"[Warning]File Looks Suspicious or Malicious ! Do You Want To Delete The File ?:")
            if ack == "y":
                os.remove(file)
                if not os.path.exists(file):
                    print(G+"\n[success]Virus Removed SuccessFully !")
        else:
            print("File Is Not Malicious [!]")
            print(Y+"="*60)
    else:

        #Upload File For Hash
        print("\n[Msg] ",response["verbose_msg"])
        FileUpload(file)
        
        
#Get Response For The Upload
def GetFileReport(Id,file):
    print("\n[!]File Report")
    url = f"https://www.virustotal.com/api/v3/analyses/{Id}"
    header = {
        "accept":"application/json",
        "x-apikey":ApiKey
        }
    response = requests.get(url,headers=header)
    data = response.json()
    data = data["data"]
    print("[*]Process:",data["type"])
    print(R+"[!]Plz wait For 20 Secs  ")
    time.sleep(25)
    #Recursion Of Found Hash
    ApiRequest(sig.hexdigest(),file)

#File Upload 
def FileUpload(file):
    url = "https://www.virustotal.com/api/v3/files"
    ext = FilterExt()
    key = ApiKey
    files = {"file":(file,open(file,"rb"),f"{ext}")}
    headers = {"accept":"application/json","x-apikey":key}
    response = requests.post(url,files=files,headers=headers)
    j = response.json()
    j = j["data"].items()
    for i in j:
        if i[0] == "id":
            Id = i[1]
            break
    response.close()
    print("[+]Id:",Id)
    print(G+"\n[!]File Upload SuccessFull [success]")
    File = file
    GetFileReport(Id,File)
#Ip Info []
def IpInfo(ip):
    cls()
    print(G+"\t\t\t\t\t\t"+"*****[IP Lookup]*****"+"\t\t\t\t\t\t\t")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    key = ApiKey
    headers = {
    "accept": "application/json",
    "x-apikey": key
    }
    print(Y+"[+]Ip:",sys.argv[2])
    response = requests.get(url, headers=headers)
    time.sleep(.7)
    j = response.json()
    I = j["data"].items()
    for key,val in I:
        if key == "attributes":
            for i in val:
                if i == "last_analysis_results":
                    Count = 0
                    k = val["last_analysis_results"].items()
                    print("\n","="*30,"Report","="*30)
                    for l in k:
                        Count+=1
                        print(Y+f"\n[{Count}]",C+f"Vendor:{l[0]}")
                        if not l[1]["category"] == "malicious":
                            print(f"Category:",l[1]["category"])
                            print(f"results:",l[1]["result"])
                        else:
                            print(R+f"[!]Category:",l[1]["category"])
                            print(R+f"[!]results:",l[1]["result"])
                            print(C)
                    print("\n","="*60)
                elif i == "total_votes":
                    H = val["total_votes"]
                    print(R+"\n[+]malicious:",H["malicious"])
                    time.sleep(.7)
                elif i == "network":
                    v = val["network"]
                    print(W+"\n[+]Network:",v)
                    time.sleep(.7)
                elif i == "country":
                    print(W+"\n[+]Conutry :",val["country"])
                    time.sleep(.7)
                elif i == "continent":
                    print(W+"\n[+]Continent:",val["continent"])
                    time.sleep(.7)
cls()
Config()
