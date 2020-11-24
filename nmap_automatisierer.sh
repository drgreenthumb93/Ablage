#!/bin/bash
#by kl4ps3r

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

SECONDS=0

usage(){
echo -e ""
echo -e "${RED}Usage: $0 <Ziel-IP> <TYPE>"
echo -e "${YELLOW}"
echo -e "Scan Types:"
echo -e "\tQuick:	Schnellanzeige aller offenen Ports (~15 Sekunden)"
echo -e "\tBasic:	Erst ein schneller Scan, danach ein gründlicher bei gefundenen, offenen Ports (~5 Minuten)"
echo -e "\tUDP:	Durchläuft \"Basic\"-Scan bei den UDP-Ports (~5 Minuten)"
echo -e "\tFull:	Durchläuft einen kompletten Scan (ganze Range), danach einen gründlichen Scan (~5-10 Minuten)"
echo -e "\tVulns:	Durchläuft einen CVE-Scan und NMap Vulns Scan bei offenen Ports (~5-15 Minuten)"
echo -e "\tRecon:	Schägt RECON-Commands vor, danach werden alle automatisch abgefeuert"
echo -e "\tAll:	Durchläuft alle Scans (~20-30 Minuten)"
echo -e ""
exit 1
}

header(){
echo -e ""

if [ "$2" == "All" ]; then
	echo -e "${YELLOW}Durchlaufe alle Scans auf $1"
else
	echo -e "${YELLOW}Starte einen $2 Scan auf $1"
fi

subnet=$(echo "$1" | cut -d "." -f 1,2,3)".0"

checkPing=$(checkPing "$1")
nmapType="nmap -Pn"

: '
#nmapType=`echo "${checkPing}" | head -n 1`
if [ "$nmapType" != "nmap" ]; then 
	echo -e "${NC}"
	echo -e "${YELLOW}Keinen Ping erkannt.. Durchlaufe mit -Pn Option!"
	echo -e "${NC}"
fi
'

ttl=$(echo "${checkPing}" | tail -n 1)
if [[  $(echo "${ttl}") != "nmap -Pn" ]]; then
	osType="$(checkOS "$ttl")"	
	echo -e "${NC}"
	echo -e "${GREEN}Auf Host läuft wahrscheinlich $osType"
	echo -e "${NC}"
fi

echo -e ""
echo -e ""
}

assignPorts(){
if [ -f nmap/Quick_"$1".nmap ]; then
	basicPorts=$(cat nmap/Quick_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
fi

if [ -f nmap/Full_"$1".nmap ]; then
	if [ -f nmap/Quick_"$1".nmap ]; then
		allPorts=$(cat nmap/Quick_"$1".nmap nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-1)
	else
		allPorts=$(cat nmap/Full_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | head -c-1)
	fi
fi

if [ -f nmap/UDP_"$1".nmap ]; then
	udpPorts=$(cat nmap/UDP_"$1".nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
	if [[ "$udpPorts" == "Al" ]]; then
		udpPorts=""
	fi
fi
}

checkPing(){
pingTest=$(ping -c 1 -W 3 "$1" | grep ttl)
if [[ -z $pingTest ]]; then
	echo "nmap -Pn"
else
	echo "nmap"
	ttl=$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)
	echo "${ttl}"
fi
}

checkOS(){
if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
        echo "OpenBSD/Cisco/Oracle"
elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
        echo "Windows"
elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
        echo "Linux"
else
        echo "Unknown OS!"
fi
}

cmpPorts(){
oldIFS=$IFS
IFS=','
touch nmap/cmpPorts_"$1".txt

for i in $(echo "${allPorts}")
do
	if [[ "$i" =~ ^($(echo "${basicPorts}" | sed 's/,/\|/g'))$ ]]; then
       	       :
       	else
       	        echo -n "$i," >> nmap/cmpPorts_"$1".txt
       	fi
done

extraPorts=$(cat nmap/cmpPorts_"$1".txt | tr "\n" "," | head -c-1)
rm nmap/cmpPorts_"$1".txt
IFS=$oldIFS
}

quickScan(){
echo -e "${GREEN}---------------------Starte schnellen NMap Scan---------------------"
echo -e "${NC}"

$nmapType -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Quick_"$1".nmap "$1"
assignPorts "$1"

echo -e ""
echo -e ""
echo -e ""
}

basicScan(){
echo -e "${GREEN}---------------------Starte normalen NMap-Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${basicPorts}") ]; then
        echo -e "${YELLOW}Keine Ports im schnellen Scan.. Überspringen!"
else
	$nmapType -sCV -p$(echo "${basicPorts}") -oN nmap/Basic_"$1".nmap "$1" 
fi

if [ -f nmap/Basic_"$1".nmap ] && [[ ! -z $(cat nmap/Basic_"$1".nmap | grep -w "Service Info: OS:") ]]; then
	serviceOS=$(cat nmap/Basic_"$1".nmap | grep -w "Service Info: OS:" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1)
	if [[ "$osType" != "$serviceOS"  ]]; then
		osType=$(echo "${serviceOS}")
		echo -e "${NC}"
		echo -e "${NC}"
		echo -e "${GREEN}OS Erkennung modifiziert zu: $osType"
		echo -e "${NC}"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

UDPScan(){
echo -e "${GREEN}----------------------Starte Nmap UDP Scan----------------------"
echo -e "${NC}"

$nmapType -sU --max-retries 1 --open -oN nmap/UDP_"$1".nmap "$1"
assignPorts "$1"

if [ ! -z $(echo "${udpPorts}") ]; then
        echo ""
        echo ""
        echo -e "${YELLOW}ErstelleScript für UDP-Scan: $(echo "${udpPorts}" | sed 's/,/, /g')"
        echo -e "${NC}"
	if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
        	$nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
	else
        	$nmapType -sCVU -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

fullScan(){
echo -e "${GREEN}---------------------Starte kompletten NMap-Scan----------------------"
echo -e "${NC}"

$nmapType -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Full_"$1".nmap "$1"
assignPorts "$1"

if [ -z $(echo "${basicPorts}") ]; then
	echo ""
        echo ""
        echo -e "${YELLOW}Erstelle Script für Scan auf allen Ports"
        echo -e "${NC}"
        $nmapType -sCV -p$(echo "${allPorts}") -oN nmap/Full_"$1".nmap "$1"
	assignPorts "$1"
else
	cmpPorts "$1"
	if [ -z $(echo "${extraPorts}") ]; then
        	echo ""
        	echo ""
		allPorts=""
        	echo -e "${YELLOW}Keine neuen Ports"
		rm nmap/Full_"$1".nmap
        	echo -e "${NC}"
	else
		echo ""
        	echo ""
        	echo -e "${YELLOW}Erstelle Script für Extra-Ports: $(echo "${extraPorts}" | sed 's/,/, /g')"
        	echo -e "${NC}"
        	$nmapType -sCV -p$(echo "${extraPorts}") -oN nmap/Full_"$1".nmap "$1"
		assignPorts "$1"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

vulnsScan(){
echo -e "${GREEN}---------------------Starte Nmap Vulns Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${allPorts}") ]; then
	portType="basic"
	ports=$(echo "${basicPorts}")
else
	portType="all"
	ports=$(echo "${allPorts}")
fi


if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
	echo -e "${RED}Bitte installiere 'vulners.nse' nmap script:"
	echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
        echo -e "${RED}"
        echo -e "${RED}Überspringe CVE Scan!"
	echo -e "${NC}"
else    
	echo -e "${YELLOW}Durchlaufe CVE-Scan auf $portType Ports"
	echo -e "${NC}"
	$nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"
	echo ""
fi

echo ""
echo -e "${YELLOW}Durchlaufe Vuln-Scan auf $portType Ports"
echo -e "${NC}"
$nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"$1".nmap "$1"
echo -e ""
echo -e ""
echo -e ""
}

recon(){

reconRecommend "$1" | tee nmap/Recon_"$1".nmap

availableRecon=$(cat nmap/Recon_"$1".nmap | grep "$1" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)

secs=30
count=0

reconCommand=""

if [ ! -z "$availableRecon"  ]; then
	while [ ! $(echo "${reconCommand}") == "!" ]; do
		echo -e "${YELLOW}"
		echo -e "Welche Kommandos willst du ausführen?${NC}\nAll (Default), $availableRecon, Überspringen <!>\n"
		while [[ ${count} -lt ${secs} ]]; do
			tlimit=$(( $secs - $count ))
			echo -e "\rRunning Default in (${tlimit}) s: \c"
			read -t 1 reconCommand
			[ ! -z "$reconCommand" ] && { break ;  }
			count=$((count+1))
		done
		if [ "$reconCommand" == "Alle" ] || [ -z $(echo "${reconCommand}") ]; then
			runRecon "$1" "Alle"
			reconCommand="!"
		elif [[ "$reconCommand" =~ ^($(echo "${availableRecon}" | tr ", " "|"))$ ]]; then
			runRecon "$1" $reconCommand
			reconCommand="!"
		elif [ "$reconCommand" == "Überspringen" ] || [ "$reconCommand" == "!" ]; then
			reconCommand="!"
			echo -e ""
			echo -e ""
			echo -e ""
		else
			echo -e "${NC}"
			echo -e "${RED}Falsche Auswahl!"
			echo -e "${NC}"
		fi
	done
fi

}

reconRecommend(){
echo -e "${GREEN}---------------------Recon-Vorschläge----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [ -f nmap/Full_"$1".nmap ] && [ -f nmap/Basic_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat nmap/Basic_"$1".nmap nmap/Full_"$1".nmap | grep -w "Offen")
elif [ -f nmap/Full_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat nmap/Quick_"$1".nmap nmap/Full_"$1".nmap | grep -w "Offen")
elif [ -f nmap/Basic_"$1".nmap ]; then
	ports=$(echo "${basicPorts}")
	file=$(cat nmap/Basic_"$1".nmap | grep -w "Offen")
else
	ports=$(echo "${basicPorts}")
	file=$(cat nmap/Quick_"$1".nmap | grep -w "Offen")

fi

if [[ ! -z $(echo "${file}" | grep -i http) ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Web Servers Recon:"
	echo -e "${NC}"
fi

for line in $file; do
	if [[ ! -z $(echo "${line}" | grep -i http) ]]; then
		port=$(echo "${line}" | cut -d "/" -f 1)
		if [[ ! -z $(echo "${line}" | grep -w "IIS") ]]; then
			pages=".html,.asp,.php"
		else
			pages=".html,.php"
		fi
		if [[ ! -z $(echo "${line}" | grep ssl/http) ]]; then
			#echo "sslyze --regular $1 | tee recon/sslyze_$1_$port.txt"
			echo "sslscan $1 | tee recon/sslscan_$1_$port.txt"
			echo "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x $pages -u https://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host https://$1:$port -ssl | tee recon/nikto_$1_$port.txt"
		else
			echo "gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x $pages -u http://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host $1:$port | tee recon/nikto_$1_$port.txt"
		fi
		echo ""
	fi
done

if [ -f nmap/Basic_"$1".nmap ]; then
	cms=$(cat nmap/Basic_"$1".nmap | grep http-generator | cut -d " " -f 2)
	if [ ! -z $(echo "${cms}") ]; then
		for line in $cms; do
			port=$(cat nmap/Basic_"$1".nmap | grep "$line" -B1 | grep -w "open" | cut -d "/" -f 1)
			if [[ "$cms" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
				echo -e "${NC}"
				echo -e "${YELLOW}CMS Recon:"
				echo -e "${NC}"
			fi
			case "$cms" in
				Joomla!) echo "joomscan --url $1:$port | tee recon/joomscan_$1_$port.txt";;
				WordPress) echo "wpscan --url $1:$port --enumerate p | tee recon/wpscan_$1_$port.txt";;
				Drupal) echo "droopescan scan drupal -u $1:$port | tee recon/droopescan_$1_$port.txt";;
			esac
		done
	fi
fi

if [[ ! -z $(echo "${file}" | grep -w "445/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SMB Recon:"
	echo -e "${NC}"
	echo "smbmap -H $1 | tee recon/smbmap_$1.txt"
	echo "smbclient -L \"//$1/\" -U \"guest\"% | tee recon/smbclient_$1.txt"
	if [[ $osType == "Windows" ]]; then
		echo "nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_$1.txt $1"
	fi
	if [[ $osType == "Linux" ]]; then
		echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	fi
	echo ""
elif [[ ! -z $(echo "${file}" | grep -w "139/tcp") ]] && [[ $osType == "Linux" ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SMB Recon:"
	echo -e "${NC}"
	echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	echo ""
fi


if [ -f nmap/UDP_"$1".nmap ] && [[ ! -z $(cat nmap/UDP_"$1".nmap | grep open | grep -w "161/udp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}SNMP Recon:"
	echo -e "${NC}"
	echo "snmp-check $1 -c public | tee recon/snmpcheck_$1.txt"
	echo "snmpwalk -Os -c public -v $1 | tee recon/snmpwalk_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "53/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}DNS Recon:"
	echo -e "${NC}"
	echo "host -l $1 $1 | tee recon/hostname_$1.txt"
	echo "dnsrecon -r $subnet/24 -n $1 | tee recon/dnsrecon_$1.txt"
	echo "dnsrecon -r 127.0.0.0/24 -n $1 | tee recon/dnsrecon-local_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "1521/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${YELLOW}Oracle Recon \"Exc. from Default\":"
	echo -e "${NC}"
	echo "cd /opt/odat/;#$1;"
	echo "./odat.py sidguesser -s $1 -p 1521"
	echo "./odat.py passwordguesser -s $1 -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
	echo "cd -;#$1;"
	echo ""
fi

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

runRecon(){
echo -e ""
echo -e ""
echo -e ""
echo -e "${GREEN}---------------------Durchlaufe Recon Kommandos----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [[ ! -d recon/ ]]; then
        mkdir recon/
fi

if [ "$2" == "All" ]; then
	reconCommands=$(cat nmap/Recon_"$1".nmap | grep "$1" | grep -v odat)
else
	reconCommands=$(cat nmap/Recon_"$1".nmap | grep "$1" | grep "$2")
fi

for line in $(echo "${reconCommands}"); do
	currentScan=$(echo "$line" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)
	fileName=$(echo "${line}" | awk -F "recon/" '{print $2}' | head -c-1)
	if [ ! -z recon/$(echo "${fileName}") ] && [ ! -f recon/$(echo "${fileName}") ]; then
		echo -e "${NC}"
		echo -e "${YELLOW}Starte $currentScan Scan"
		echo -e "${NC}"
		echo "$line" | /bin/bash
		echo -e "${NC}"
		echo -e "${YELLOW}Scan $currentScan wurde beendet"
		echo -e "${NC}"
		echo -e "${YELLOW}========================="
	fi
done

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

footer(){

echo -e "${GREEN}---------------------Alle NMap Scans beendet---------------------"
echo -e "${NC}"
echo -e ""

if (( $SECONDS > 3600 )) ; then
    let "hours=SECONDS/3600"
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${YELLOW}Fertiggestellt in $hours Stunde(n), $minutes Minute(n) und $seconds Sekunde(n)" 
elif (( $SECONDS > 60 )) ; then
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${YELLOW}Fertiggestellt in $minutes Minute(n) und $seconds Sekunde(n)"
else
    echo -e "${YELLOW}Fertiggestellt in $SECONDS Sekunden"
fi
echo -e ""
}

if (( " $# " != 2 )); then
	usage
fi

if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	:
else
	echo -e "${RED}"
	echo -e "${RED}Ungültige IP!"
	echo -e "${RED}"
	usage
fi

if [[ "$2" =~ ^(Quick|Basic|UDP|Full|Vulns|Recon|All|quick|basic|udp|full|vulns|recon|all)$ ]]; then
	if [[ ! -d $1 ]]; then
	        mkdir "$1"
	fi

	cd "$1" || exit
	
	if [[ ! -d nmap/ ]]; then
	        mkdir nmap/
	fi
	
	assignPorts "$1"

	header "$1" "$2"
	
	case "$2" in
		Quick | quick) 	quickScan "$1";;
		Basic | basic)	if [ ! -f nmap/Quick_"$1".nmap ]; then quickScan "$1"; fi
				basicScan "$1";;
		UDP | udp) 	UDPScan "$1";;
		Full | full) 	fullScan "$1";;
		Vulns | vulns) 	if [ ! -f nmap/Quick_"$1".nmap ]; then quickScan "$1"; fi
				vulnsScan "$1";;
		Recon | recon) 	if [ ! -f nmap/Quick_"$1".nmap ]; then quickScan "$1"; fi
				if [ ! -f nmap/Basic_"$1".nmap ]; then basicScan "$1"; fi
				recon "$1";;
		All | all)	quickScan "$1"
				basicScan "$1"
				UDPScan "$1"
				fullScan "$1"
				vulnsScan "$1"
				recon "$1";;
	esac
	
	footer
else
	echo -e "${RED}"
	echo -e "${RED}Ungültiger Typ!"
	echo -e "${RED}"
	usage
fi
