#!/bin/bash



		# check if tshark is installed and installs it if not.
		if ! command -v tshark &>/dev/null; 
		then
			echo -e "\033[1;31m tshark is not installed, starting installation\033[0m"
			sudo apt-get -qqy install foremost
			echo -e "\033[1;32m tshark has been installed.\e[0m"
		else
			echo -e "\033[1;32m tshark is installed\e[0m."
			
		fi
		
		
		# check if jq is installed and installs it if not.
		if ! command -v jq &>/dev/null; 
		then
			echo -e "\033[1;31m jq is not installed, starting installation\033[0m"
			sudo apt-get -qqy install jq
			echo -e "\033[1;32m jq has been installed.\e[0m"
		else
			echo -e "\033[1;32m jq is installed\e[0m."
		fi
			
			
			
		function cleanup() {
			# Function to clean up resources
			echo "Cleaning up..."
			# Terminate tshark process
			pkill -TERM -P $$  # Terminate child processes of the script
			}
		
			trap cleanup EXIT  # Execute cleanup function when the script exits
		
		
		
			# Directory containing pcap files
			pcap_dir="pcaps"
			# Ensure the pcaps directory exists
			mkdir -p "$pcap_dir" >/dev/null 2>&1
			
			# File containing wanted URLs and IPs to alert
			url="configuration/IOC_URL.conf"
			ips="configuration/IOC_IP.conf"
			
			# Read configuration parameters from hunter.conf
			source "configuration/hunter.conf"
			
			# Declare an associative array to store seen lines
			declare -A seen_lines
			
		function TRAFFIC_CAPTURE() {
			# A function to capture network traffic.
			# Adjust the "FILE_SIZE" as needed in the "configuration/hunter.conf" configuration file
			while true; do
				tshark -i eth0 -t ad -w "$pcap_dir"/traffic.pcap -b filesize:"$FILE_SIZE" 2>/dev/null
			done
		}
		
		function PROCESS_PCAP() {
			last_file=""
			while true; do
				# Check if any pcap files are present in the directory
				if ls "$pcap_dir"/*.pcap 1> /dev/null 2>&1; then
					# Check for the newest file in the directory
					current_file=$(ls -t "$pcap_dir"/*.pcap | head -n1)
					
					if [[ "$current_file" != "$last_file" ]]; then
						if [[ -n "$last_file" ]]; then
							echo "New file detected, switching to $current_file"
						fi
						last_file="$current_file"
						
						# Process the new pcap file for DNS queries and responses endlessly
						while [[ "$current_file" == "$last_file" ]]; do
							process_pcap_file "$last_file"
							
							# Pass the latest pcap file to the extract_files function
							extract_files "$last_file"
							
							# Check again for the newest file
							current_file=$(ls -t "$pcap_dir"/*.pcap | head -n1)
							
							# Sleep for a short while before reprocessing the current file
							sleep 3  # Adjust the sleep time as needed
						done
					fi
				fi
				
				# Sleep for a while before checking for new pcap files again
				sleep 3  # Adjust the sleep time as needed
			done
		}
		
		function process_pcap_file() {
			pcap_file="$1"
			seen_file="seen_lines.dat"  # File to store seen lines persistently
		
			# Ensure seen file exists
			touch "$seen_file"
		
			# Load seen lines from file into the array
			while IFS= read -r line; do
				seen_lines["$line"]=1
			done < "$seen_file"
		
			# Process DNS queries based on IP addresses
			while IFS= read -r ioc_ip; do
				if [[ -n "$ioc_ip" ]]; then
					tshark -r "$pcap_file" -t ad -Y "dns.a == $ioc_ip" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a | \
					while IFS= read -r line; do
						if [[ -z "${seen_lines["$line"]}" ]]; then
							echo "$line"
							seen_lines["$line"]=1
							echo "$line" >> "$seen_file"  # Append new seen line to file
						fi
					done
				fi
			done < "$ips" 2>/dev/null
		
			# Process DNS responses based on URLs
			while IFS= read -r ioc_url; do
				if [[ -n "$ioc_url" ]]; then
					tshark -r "$pcap_file" -t ad -Y "dns.resp.name == $ioc_url" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.resp.name | \
					while IFS= read -r line; do
						if [[ -z "${seen_lines["$line"]}" ]]; then
							echo "$line"
							seen_lines["$line"]=1
							echo "$line" >> "$seen_file"  # Append new seen line to file
						fi
					done
				fi
			done < "$url" 2>/dev/null 
		}
		
		function extract_files() { 
			local pcap_file="$1"  # Latest PCAP file passed as argument
			# Create log directory and necessary files if they do not exist
			mkdir -p logs
			touch logs/details.log
			touch logs/hash.log
			touch logs/processed_files.log
			touch logs/downloaded_files.log  # Log file to track downloaded files
		
			# Step 1: Extract files if not already extracted
			if [ ! -s logs/downloaded_files.log ]; then
				tshark -r "$pcap_file" --export-objects http,extracted_files > /dev/null 2>&1
				# Record the downloaded files
				ls extracted_files > logs/downloaded_files.log
			fi
		
			# Step 2: Extract the necessary details from the pcap file
			tshark -r "$pcap_file" -Y 'http.request.method==GET' -T fields -e frame.time -e frame.number -e ip.src -e http.request.uri > new_details.txt  
		
			# Step 3: Process the details and compute the sha256 hash
			while IFS=$'\t' read -r time frame_num ip uri; do
				# Remove "IDT" from the time
				time_clean=$(echo "$time" | sed 's/ IDT//')
		
				# Extract the actual file name from the URI
				file_name=$(basename "$uri")
		
				# Check if the file has already been processed
				if grep -q "$file_name" logs/processed_files.log; then
					continue
				fi
		
				# Calculate the sha256 hash of the file and log it
				if [ -f "extracted_files/$file_name" ]; then
					hash=$(sha256sum "extracted_files/$file_name" | awk '{print $1}' | tee -a logs/hash.log | cut -d' ' -f1)
				else
					hash="File not found"
				fi
		
				# Log the details
				echo -e "$time_clean\t$ip\t$file_name\tpcaps/http.pcap\t$hash" >> logs/details.log
				echo "$file_name" >> logs/processed_files.log
			done < new_details.txt
		
			
			# Sleep for a while before the next iteration
			sleep 1
		
		}
		
		function virus_total() {
			api_key='INSERT YOUR API KEY'  # Replace with your actual VirusTotal API key
			hash_file="logs/hash.log"  # Replace with the path to your hash list file
		
			# ANSI escape codes for bold red text
			bold_red="\033[1;31m"
			reset="\033[0m"
		
			process_hashes() {
				# Read hash values from the file
				tail -n0 -F "$hash_file" | while IFS= read -r hash_value; do
					# Skip empty lines
					if [[ -z "$hash_value" ]]; then
						continue
					fi
		
					url="https://www.virustotal.com/api/v3/files/$hash_value"
					echo "Querying $url"
					response=$(curl -sS -H "x-apikey: $api_key" "$url")
		
					if echo "$response" | jq -e .error > /dev/null; then
						error_message=$(echo "$response" | jq -r .error.message)
						echo "Error occurred while querying $hash_value"
						echo "Response: $error_message"
					else
						# Extract the malicious count using jq
						malicious_count=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')
		
						if [[ "$malicious_count" -gt 0 ]]; then
							echo -e "${bold_red}hash '$hash_value' is found malicious${reset}"
						fi
					fi
				done
			}
		
			# Run the process_hashes function in the background
			process_hashes &
		}
		
		# Start capturing network traffic in background
		TRAFFIC_CAPTURE &
		
		# Start processing pcap files
		PROCESS_PCAP &
		
		# Check hashes against VirusTotal
		virus_total &
		
		echo "Monitoring $hash_file for new entries. Press Ctrl+C to stop."
		wait
