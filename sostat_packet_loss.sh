#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019 Security Onion Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Written by:
# Doug Burks
# Fixes contributed by:
# Stephane Chazelas
# Shane Castle
# Wes Lambert
# Freq_server and Domain_stats components written by:
# Justin Henderson

# Import settings file
if [ -f /etc/nsm/securityonion.conf ]; then
	source /etc/nsm/securityonion.conf
else
	echo "Missing /etc/nsm/securityonion.conf file!" && exit 1
fi

# make sure if statements using wildcards for filenames don't equal true when no files exist
shopt -s nullglob

# Define a banner to separate sections
banner="========================================================================="

# Check for root
[ "$(id -u)" -ne 0 ] && echo "This script must be run using sudo!" && exit 1

header() {
	printf '%s\n' "$banner" "$*" "$banner"
}

remove_ansi_escapes() {
	sed $'s/\e[^mk]*[mk]//g;s/[\e\r]//g'
}

# Options
usage()
{
	cat <<EOF

Security Onion Statistics

Options:

-h              This message
-a              Show all installed Security Onion packages

Usage: $0
EOF
}

# Check flags
ALL_PKGS=0
while getopts ":ha" OPTION
do
	case $OPTION in
		h)
		usage
		exit 0
		;;
		a)
		ALL_PKGS=1
		;;
	esac
done

# Determine sensor interfaces for packet loss stats
INTERFACES=""
NUM_INTERFACES=0
SENSORTAB="/etc/nsm/sensortab"
if [ -s $SENSORTAB ]; then
	INTERFACES=$(grep -v "#" $SENSORTAB | awk '{print $4}')
	NUM_INTERFACES=$(grep -v "#" $SENSORTAB | wc -l)
fi

# Text formatting
if [ -t 1 ];then
	underline=`tput smul`
	normal=`tput sgr0`
else
	:
fi

# Begin output
PROCS=`nproc --all`
header "CPU Usage"
echo "Load average for the last 1, 5, and 15 minutes:"
cat /proc/loadavg | awk '{print $1,$2,$3}'
echo "Processing units: $PROCS"
echo "If load average is higher than processing units,"
echo "then tune until load average is lower than processing units."
if [ -d /nsm/sensor_data ] && [ $NUM_INTERFACES -gt 0 ]; then
	echo
	FREQUENCY=`grep -A1 packets_received /var/ossec/etc/ossec.conf | tail -1 | cut -d\> -f2 | cut -d\< -f1`
	header "Packets received during last monitoring interval ($FREQUENCY seconds)"
	/usr/sbin/sostat-interface-delta
	echo
	header "Packet Loss Stats"
	echo
	echo "${underline}NIC${normal}:"
	echo
	for IFACE in $INTERFACES;do
		echo "$IFACE:" && echo && echo `ifconfig $IFACE |awk '/dropped:/ {print $1,$2,$4}'` && echo ""
	done
	echo "-------------------------------------------------------------------------"
	echo
	if [ -f /proc/net/pf_ring/info ]; then
		echo "${underline}pf_ring${normal}:"
		echo
		for i in /proc/net/pf_ring/*-* ; do
			APP_NAME=`grep "Appl. Name" $i | awk '{print $4}'`
			PF_TOT_IN=`grep "Tot Packets" $i | awk '{print $4}'`
			PF_TOT_LOST=`grep "Tot Pkt Lost" $i | awk '{print $5}'`
			if [[ -n $PF_TOT_LOST ]] && [[ $PF_TOT_LOST -gt 0 ]] ; then
				PF_PERCENT_LOST=$(echo "scale=2 ; $PF_TOT_LOST * 10 / $PF_TOT_IN" | bc)
			else
				PF_PERCENT_LOST=0
			fi
			echo "Appl. Name: $APP_NAME"
			echo "Tot Packets: $PF_TOT_IN"
			echo "Tot Pkt Lost: $PF_TOT_LOST"
			echo "Loss as a percentage: $PF_PERCENT_LOST"
			echo
		done
	fi
	echo "-------------------------------------------------------------------------"
	echo
	echo "${underline}IDS Engine ($ENGINE) packet drops${normal}:"
	echo
	if [ "$ENGINE" = "suricata" ]; then
		for i in /nsm/sensor_data/*/stats.log; do
			echo "$i"
			if [ $( tail -n1000 $i | grep -c "capture.kernel_packets" ) -ne 0 ]; then
				echo
				SURI_TOTAL=`tail -n1000 $i | grep "capture.kernel_packets" | tail -n1 | tee /dev/tty | awk '{print $5}'`
				SURI_DROP=`tail -n1000 $i | grep "capture.kernel_drops" | tail -n1 | tee /dev/tty | awk '{print $5}'`
				if [[ -n $SURI_DROP ]] ; then
					SURI_PERCENT_DROP=$(echo "scale=2 ; $SURI_DROP * 100 / $SURI_TOTAL" | bc)
				else
					SURI_PERCENT_DROP=0
				fi
				echo
				echo "Drop as a percentage: $SURI_PERCENT_DROP"
				echo
			else
				echo
				echo "No packet drops reported."
				echo
			fi
		done
	else
		for i in /nsm/sensor_data/*/snort-*.stats; do
			if grep -q '^[^#]' "$i"; then
				echo -n "$i last reported pkt_drop_percent as "
				grep -v '^#' "$i" |tail -n 1 |cut -d\, -f2
			else
				echo "ERROR: No stats found in $i"
			fi
		done
	fi
	echo "-------------------------------------------------------------------------"
	echo
	TMP=`mktemp`
	su sguil -c '/opt/bro/bin/broctl netstats' > $TMP
	if [ -s $TMP ]; then
		echo "${underline}Bro${normal}:"
		echo
		echo -n "Average packet loss as percent across all Bro workers: "
		cat $TMP | \
		sed 's/[a-z]*=//g' | \
		awk '{ drop += $4 ; link += $5 } \
		END { if ( link >=1 ) printf("%f\n", ((drop/NR) / (link/NR)) * 100); else print("No packets seen."); }'
		echo
		cat $TMP
		echo
		if [ -f /nsm/bro/logs/current/capture_loss.log ]; then
			echo "Capture Loss:"
			echo
			# If Bro is writing logs in json format, then parse with jq
			if grep -q '^@load json-logs' /opt/bro/share/bro/site/local.bro; then
				CL_LOG="/nsm/bro/logs/current/capture_loss.log"
				PERCENT_LOST=$(cat $CL_LOG | jq .percent_lost | sort -u)
				for i in $(cat $CL_LOG | jq .peer | sort -u); do
					PEER=$(echo $i | sed s'/"//g')
					echo "$PEER: $PERCENT_LOST"
				done
				# If Bro is writing logs in tsv format, then parse with bro-cut
			else
				echo "`/opt/bro/bin/bro-cut peer percent_lost < /nsm/bro/logs/current/capture_loss.log | sort -u`"
			fi
			echo
			echo "If you are seeing capture loss without dropped packets, this"
			echo "may indicate that an upstream device is dropping packets (tap or SPAN port)."
		else
			echo "No capture loss reported."
		fi
		rm $TMP
	fi
	echo
	echo "-------------------------------------------------------------------------"
	if ls /var/log/nsm/*/netsniff-ng.log > /dev/null 2>&1; then
		echo
		echo "${underline}Netsniff-NG${normal}:"
		for i in /var/log/nsm/*/netsniff-ng.log;
		do
			if grep -q -e "-[1-9]*)" "$i"; then
				echo
				echo "This may take a second..."
				echo
				RCVD=()
				DRPD=()
				IFS=".(+"
				for line in `cat "$i"`;
				do
					#echo $line
					for word in "${line[@]}";
					do
						if [[ $word =~ ')' ]]; then
							RCVD+=(`echo "$word" | cut -d '/' -f1`);
						fi
					done;
				done < "$i"

				IFS='+' rcvd_sum=$(echo "scale=1;${RCVD[*]}"|bc)
				TOT_RCVD=`echo $rcvd_sum`

				IFS="-"
				for line in `cat "$i"`
				do
					for word in "${line[@]}";
					do
						if [[ $word =~ ')' ]]; then
							DRPD+=(`echo "$word" | cut -d ')' -f1`);
						fi
					done;
				done < "$i"

				IFS='+' drpd_sum=$(echo "scale=1;${DRPD[*]}"|bc)
				TOT_DRPD=`echo $drpd_sum`
				TOT_PKTS=`echo 'scale=2; '$TOT_DRPD'+'$TOT_RCVD''|bc`
				DRPD_PCT=`echo 'scale=2; '$TOT_DRPD'*100/'$TOT_PKTS''|bc`
				echo
				echo Percentage of packets dropped:
				echo
				echo $i " -- " $DRPD_PCT
				echo
			else
				echo
				echo "0 Loss"
			fi
		done
	fi
fi
echo