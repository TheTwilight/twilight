# Twilight

A tool to prepare nmap scans and local user data to Elasticsearch.  
  
  
How to:  
  1, Run allinone.sh with administrator privileges from the twilight folder.      (" sudo ./allinone.sh ")  
     You can run it with " -i 'yourindex in Elasticsearch' " argument.            (" sudo ./allinone.sh -i etc_log ")  
  2, After you have selected your options from the menu, nmap executes the scan.  
  3, The scan results and system informations are converted into one xml file.  
  4, Elasticsearch receives and stores this file.  
  5, The results will show up in kibana.  
    
All the network scans and local informations are stored in logstr folder in archives.  
