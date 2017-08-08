# Twilight

A tool to prepare nmap scans and local user data to Elasticsearch.  
  
  
How to:  
  - Run allinone.sh with administrator privileges from the twilight folder.
```sh
$ sudo ./allinone.sh 
``` 
  - You can run it with " -i 'yourindex in Elasticsearch' " argument.
```sh
$ sudo ./allinone.sh -i etc_log
```
  - After you have selected your options from the menu, nmap executes the scan.  
  - The scan results and system informations are converted into one xml file.  
  - Elasticsearch receives and stores this file.  
  - The results will show up in kibana.  
    
All the network scans and local informations are stored in logstr folder in archives.  
