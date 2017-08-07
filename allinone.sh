#!/bin/bash

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  


# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
#if [ $# -eq 0 ]
#  then
#    echo "No arguments supplied. -i is necessary!"
#    exit 1
#fi
IDX=
IU="0"
while getopts "i:" opt; do
    case $opt in
    i) IDX=$OPTARG
       IU="1" ;; # Handle -i
    \?) echo "Missing argument. Plase specify an index." 
	exit 1 ;; # Handle error: unknown option or missing required argument.
    esac
done

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

#get the time
echo -n "Date: " > ./hwinfo.txt
TIME=$(date '+%d.%m.%Y')
echo $TIME >> ./hwinfo.txt
 
#get the date
echo -n "Time: " >> ./hwinfo.txt
DATE1=$(date '+%H:%M:%S')
echo $DATE1 >> ./hwinfo.txt
 
#get the actual user
echo -n "User: " >> ./hwinfo.txt
USER=$(who | cut -d' ' -f1)
echo $USER >> ./hwinfo.txt
 
#kernel version for ip
DEBIKER=$(uname -a | grep -i "Debian")
UBUNKER=$(uname -a | grep -i "Ubuntu")
SUSEKER=$(uname -a | grep -i "Suse")
 
#DEBIAN/KALI
if [ -n "$DEBIKER" ]; then
	echo -n "Ip address: " >> ./hwinfo.txt
	IPADDR=$(ip r | grep -o 'src.*' | cut -f2- -d' ' | cut -d' ' -f1)
	echo $IPADDR >> ./hwinfo.txt

	echo -n "HW address: " >> ./hwinfo.txt
	MACADDR=$(ip a | grep -B1 "$IPADDR" | grep -o 'ether.*'  | cut -f2- -d' ' | cut -d' ' -f1)
	echo $MACADDR >> ./hwinfo.txt
	SAVEDKERNEL=$DEBIKER
fi
 
#UBUNTU
if [ -n "$UBUNKER" ]; then
	echo -n "Ip address: " >> ./hwinfo.txt
	IPADDR=$(ifconfig | grep "inet addr:" | grep -v 127.0.0.1 | cut -d':' -f2 | cut -d' ' -f1)
	echo $IPADDR >> ./hwinfo.txt

	echo -n "HW address: " >> ./hwinfo.txt
	MACADDR=$(ifconfig | grep -B1 "inet addr:" | grep -v 127.0.0.1 |  grep -o "HWaddr.* " | cut -d' ' -f2 | cut -d' ' -f1)
	echo $MACADDR >> ./hwinfo.txt
	SAVEDKERNEL=$UBUNKER
fi
 
#SUSE
if [ -n "$SUSEKER" ]; then
	echo -n "Ip address: " >> ./hwinfo.txt
	IPADDR=$(ip r | grep -o 'src.*' | cut -f2- -d' ' | cut -d' ' -f1)
	echo $IPADDR >> ./hwinfo.txt

	echo -n "HW address: " >> ./hwinfo.txt
	MACADDR=$(ip a | grep -B1 "$IPADDR" | grep -o 'ether.*'  | cut -f2- -d' ' | cut -d' ' -f1)
	echo $MACADDR >> ./hwinfo.txt
	SAVEDKERNEL=$SUSEKER
fi
 
#get the public ip
echo -n "Public Ip address: " >> ./hwinfo.txt
PUBIPADDR=$(dig +short myip.opendns.com @resolver1.opendns.com)
if [ -z "$PUBIPADDR" ]; then
	PUBIPADDR=$(dig TXT +short o-o.myaddr.l.google.com @ns1.google.com | awk -F'"' '{ print $2}')
fi

echo $PUBIPADDR >> ./hwinfo.txt

#get the OS informations
echo -n "operating-system: " >> ./hwinfo.txt
uname -o >> ./hwinfo.txt

echo -n "processor: " >> ./hwinfo.txt
uname -p >> ./hwinfo.txt

echo -n "kernel-release: " >> ./hwinfo.txt
uname -r >> ./hwinfo.txt

echo -n "kernel-version: " >> ./hwinfo.txt
echo $SAVEDKERNEL >> ./hwinfo.txt

#get the nmap version
nmap --version | awk '/^Nmap version/ {print $1, $2, $3}' >> ./hwinfo.txt

#get the routing table
printf "\n" >> ./hwinfo.txt
route -n >> ./hwinfo.txt

#netstat infos
printf "\n" >> ./hwinfo.txt
netstat -a >> ./hwinfo.txt

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#  -*- coding: utf-8 -*-
#
#  Copyright 2017 Máté Varga
#Let's see those changes.
#


#Configuration file reading
source ./conf/dconfs.cfg
($DCONF_PARAM1 >&2 ) 2>> /dev/null
($DCONF_PARAM2 >&2 ) 2>> /dev/null
($DCONF_PARAM3 >&2 ) 2>> /dev/null
($DCONF_URL1 >&2 ) 2>> /dev/null
($DCONF_URL2 >&2 ) 2>> /dev/null
($DCONF_URL3 >&2 ) 2>> /dev/null
if test -e "./prev"; then
	source ./prev
	($PREVUSR >&2 ) 2>> /dev/null
	if ! grep -q "PREVUSR=*" ./prev ; then
		echo "PREVUSR=" >> ./prev
	fi
	if ! grep -q "PREVIDX=*" ./prev ; then
		echo "PREVIDX=" >> ./prev
	fi
else
	echo "PREVUSR=" > ./prev
	echo "PREVIDX=" >> ./prev
fi

#Main menu
OPTION=$(whiptail --title "Main Menu" --menu "Choose your option" 15 80 5 \
"1" "Default Config 1: $DCONF_PARAM1" \
"2" "Default Config 2: $DCONF_PARAM2" \
"3" "Default Config 3: $DCONF_PARAM3" \
"4" "Custum Configuration File" \
"5" "Custom Options" 3>&1 1>&2 2>&3)

#Menu points
case $OPTION in
	#Option one: Read the first default configs
        "1")
		CONF_PARAM=$DCONF_PARAM1
		CONF_URL=$DCONF_URL1
            ;;
	#Option two: Read the second default configs
        "2")
		CONF_PARAM=$DCONF_PARAM2
		CONF_URL=$DCONF_URL2
            ;;
	#Option three: Read the third default configs
        "3")
		CONF_PARAM=$DCONF_PARAM3
		CONF_URL=$DCONF_URL3
            ;;
	#Option four: Read the user defined configs, can give custom path
	"4")
		SRC=$(whiptail --title "Path" --inputbox "Path to configuration file?" 10 80 ./conf/conf*.cfg 3>&1 1>&2 2>&3)
		while ! test -f "$SRC"; do
			SRC=$(whiptail --title "Path" --inputbox "Path to configuration file? Invalid Path!" 10 80 $SRC 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi
			done
		source $SRC
		($CCONF_PARAM >&2) 2>> /dev/null
		($CCONF_URL >&2) 2>> /dev/null
		CONF_PARAM=$CCONF_PARAM
		CONF_URL=$CCONF_URL
            ;;
	#Option five: User can define the configs with a GUI containing the most used parameters
	"5")
		#Timing options
		TIMING=$(whiptail --title "Timing - (1/7)" --radiolist \
			"Choose a timing for the scanning" 15 80 6 \
			" -T0" "Paranoid" OFF \
			" -T1" "Sneaky" OFF \
			" -T2" "Polite" OFF \
			" -T3" "Normal" ON \
			" -T4" "Aggressive" OFF \
			" -T5" "Insane" OFF 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi

		#Port options 1
		PORTS1=$(whiptail --title "Ports - 1. - (2/7)" --checklist \
			"Choose what ports to scan - 1st Page" 15 80 6 \
			" -F" "Scan 100 most popular ports" OFF \
			" -r" "Scan linearly (do not randomize ports)" OFF 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi
 
		#Port options 2, only accessible if "-F" parameter wasn't picked 
		if [[ $PORTS1 != *"-F"* ]]; then
		PORTS2=$(whiptail --title "Ports - 2. - (3/7)" --radiolist \
			"Choose what ports to scan - 2nd Page" 15 80 6 \
			" -p<port1>-<port2>" "Port range" OFF \
			" -p<port1>,<port2>,..." "Port List" OFF \
			" --top-ports <n>" "Scan n most popular ports" OFF 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi
		fi
 
		#Inputbox for port 2 ontions, only accessible if a port 2 option was picked
		if [ -n "$PORTS2" ]; then			
			while test -z "$PX"; do
			HELP1=$(echo $PORTS2 | sed 's/--top-ports //g' | sed 's/-p//g')
			PX=$(whiptail --title "Port(s) - (3.1/7)" --inputbox "Write the port(s) what you want to use. $HELP1" 10 80 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi
			done
			PORTS2=$(echo $PORTS2 | sed 's/<port1>-<port2>//g' | sed 's/<port1>,<port2>,...//g' | sed 's/<n>//g')			
			PORTS2=$(echo "$PORTS2$PX")
		fi
		
		#Probing options
		PROB=$(whiptail --title "Probing Options - (4/7)" --checklist \
			"Choose the probing ptions" 15 80 6 \
			" -Pn" "Don't probe (assume all hosts are up)" OFF \
			" -PB" "Default probe (TCP 80, 445 & ICMP)" OFF \
			" -PS" "Check whether targets are up by probing TCP ports" OFF \
			" -PE" "Use ICMP Echo Request" OFF \
			" -PM" "Use ICMP Timestamp Request" OFF \
			" -PP" "Use ICMP Netmask Request" OFF 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi

		#Scan type options
		SCTYP=$(whiptail --title "Scan Types - (5/7)" --checklist \
			"Choose what ports to scan - 2nd Page" 15 80 6 \
			" -sP" "Probe only (host discovery, not port scan)" OFF \
			" -sS" "SYN Scan" OFF \
			" -sT" "TCP Connect Scan" OFF \
			" -sU" "UDP Scan" OFF \
			" -sV" "Version Scan" OFF \
			" -O" "OS Detection" OFF 3>&1 1>&2 2>&3)
			exitstatus=$?
				if [ $exitstatus != 0 ]; then
					echo "You closed the script."; exit
				fi

		#Inputbox for the target URL, IP
		while test -z "$URL"; do
		URL=$(whiptail --title "URL / IP - (6/7)" --inputbox "Enter URL or IP address of target." 10 80 scanme.nmap.org 3>&1 1>&2 2>&3)
		exitstatus=$?
			if [ $exitstatus != 0 ]; then
				echo "You closed the script."; exit
			fi		
		done

		#Merging the parameters
		PARAMS="$TIMING $PORTS1 $PORTS2 $PROB $SCTYP"
		PARAMS=$(echo $PARAMS | sed 's/"//g')

		#Inputbox for the Elasticsearch server URL, IP
		while test -z "$ES_IP"; do
			ES_IP=$(whiptail --title "Elasticsearch IP" --inputbox "Enter the IP address of the Elasticsearch server." 10 80 127.0.0.1 3>&1 1>&2 2>&3)
		done

		#User login data
		while test -z "$USR"; do
			USR=$(whiptail --title "Username - Elasticsearch" --inputbox "Enter your username for Elasticsearch." 10 80 $PREVUSR 3>&1 1>&2 2>&3)
			if [ $exitstatus != 0 ]; then
				echo "You closed the script."; exit
			fi
		done
		while test -z "$PSW"; do
			PSW=$(whiptail --title "Password - Elasticsearch" --passwordbox "Enter your password for Elasticsearch." 10 80 3>&1 1>&2 2>&3)
			exitstatus=$?
			if [ $exitstatus != 0 ]; then
				echo "You closed the script."; exit
			fi
		done
		#Save username & index
		if [ -z "$USR" ] || [ "$USR" != "$PREVUSR" ]; then
			if (whiptail --title "Save Username & Index" --yesno "Do you want to save your username and index?" 10 60) then
				sed -i -e "s/PREVUSR=.*/PREVUSR=$USR/g" ./prev
				sed -i -e "s/PREVIDX=.*/PREVIDX=$IDX/g" ./prev
				( PREVIDX=$IDX ) 2>> /dev/null
				IU=1
			fi
		fi
		if [ "$IDX" != "$PREVIDX" ] && [ "$IU" == "0" ]; then
			if (whiptail --title "Save Index" --yesno "Do you want to save your index?" 10 60) then
				sed -i -e "s/PREVIDX=.*/PREVIDX=$IDX/g" ./prev
			fi
		fi

		#Summary of the parameters and target URL/IP, option to edit them
		if (whiptail --title "Start scanning / Edit - (7/7)" --yes-button "Scan" --no-button "Edit"  --yesno "Start scanning or edit parameters? \n Parameters: $PARAMS $URL" 10 80) then
			nmap $PARAMS -oX ./log.xml $URL
		else  					
			PARAMS=$(whiptail --title "Edit" --inputbox "Editing: \n $PARAMS" 10 80 " $PARAMS" 3>&1 1>&2 2>&3)
			nmap $PARAMS -oX ./log.xml $URL
		fi

		exit
            ;;
esac

#Inputbox for the target URL, IP
if [ -n "$OPTION" ]; then
	CONF_URL=$(whiptail --title "URL / IP Address" --inputbox "Enter the URl or IP address of the target." 10 80 "$CONF_URL" 3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus != 0 ]; then
		echo "You closed the script."; exit
	fi
	#Reenter the address if target was empty
	while test -z "$CONF_URL"; do
	CONF_URL=$(whiptail --title "URL / IP Address" --inputbox "ENTER the URl or IP address of the target!" 10 80 "$CONF_URL" 3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus != 0 ]; then
		echo "You closed the script."; exit
	fi
	done

#Inputbox for the Elasticsearch server URL, IP
while test -z "$ES_IP"; do
	ES_IP=$(whiptail --title "Elasticsearch IP" --inputbox "Please enter the IP address of the Elasticsearch server." 10 80 127.0.0.1 3>&1 1>&2 2>&3)
	if [ $exitstatus != 0 ]; then
		echo "You closed the script."; exit
	fi
done

#User login data & index (if not provided at the beggining)
while test -z "$USR"; do
	USR=$(whiptail --title "Username - Elasticsearch" --inputbox "Enter your username for Elasticsearch." 10 80 $PREVUSR 3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus != 0 ]; then
		echo "You closed the script."; exit
	fi
done
while test -z "$PSW"; do
	PSW=$(whiptail --title "Password - Elasticsearch" --passwordbox "Enter your password for Elasticsearch." 10 80 3>&1 1>&2 2>&3)
	exitstatus=$?
	if [ $exitstatus != 0 ]; then
		echo "You closed the script."; exit
	fi	
done
if [ -z "$IDX" ]; then
	while test -z "$IDX"; do
		IDX=$(whiptail --title "Index - Elasticsearch" --inputbox "Enter the index name for Elasticsearch." 10 80 $PREVIDX 3>&1 1>&2 2>&3)
		exitstatus=$?
		if [ $exitstatus != 0 ]; then
			echo "You closed the script."; exit
		fi
	done
fi 

#Save username & index
if [ -z "$USR" ] || [ "$USR" != "$PREVUSR" ]; then
	if (whiptail --title "Save Username & Index" --yesno "Do you want to save your username and index?" 10 60) then
		sed -i -e "s/PREVUSR=.*/PREVUSR=$USR/g" ./prev
		sed -i -e "s/PREVIDX=.*/PREVIDX=$IDX/g" ./prev
		( PREVIDX=$IDX ) 2>> /dev/null
		IU=1
	fi
fi
if [ "$IDX" != "$PREVIDX" ] && [ "$IU" == "0" ]; then
	if (whiptail --title "Save Index" --yesno "Do you want to save your index?" 10 60) then
		sed -i -e "s/PREVIDX=.*/PREVIDX=$IDX/g" ./prev
	fi
fi

	#Summary of the parameters and target URL/IP, option to edit them
	if (whiptail --title "Start scanning / Edit" --yes-button "Scan" --no-button "Edit"  --yesno "Start scanning or edit parameters? \n Parameters: $CONF_PARAM $CONF_URL" 10 80) then
			nmap $CONF_PARAM -oX ./log.xml $CONF_URL
		else  					
			CONF_PARAM=$(whiptail --title "Edit" --inputbox "Editing: \n $CONF_PARAM" 10 80 " $CONF_PARAM" 3>&1 1>&2 2>&3)
			nmap $CONF_PARAM -oX ./log.xml $CONF_URL
		fi
fi

#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

python txttoxml.py --inputtxt hwinfo.txt --inputxml log.xml --output twilight.xml
now=$(date '+%F_%R:%S')
mkdir -p ./logstr/
zip -q -T ./logstr/log_$now.zip kibana_json.txt hwinfo.txt log.xml twilight.xml
python VulntoES.py -i twilight.xml -e "$ES_IP" -r nmap -I "$IDX" -u "$USR" -p "$PSW"
