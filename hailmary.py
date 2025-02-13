import sys
from sys import argv
import re
import os
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter


def get_logfile_path(arg_num):
    if len(argv) < 2:
            print("Error: Please provide the path to the log file as a command line argument")
            sys.exit()
    elif not os.path.isfile(argv[arg_num]):
            print("Error: The specified file does not exist.")
            sys.exit()
    else:
        return argv[arg_num]

        
def filter_log_messages(log_path, regex):
    with open(log_path, 'r') as f:
        log_messages = f.readlines()
        
    pattern = re.compile(regex)
    matching_messages = [msg for msg in log_messages if pattern.match(msg)]
        
    return matching_messages
        
def get_source_ip_addresses(log_records):
    ip_pattern = re.compile(r'SRC=(\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3})')
    source_ips = Counter()
        
    for msg in log_records:
        match = ip_pattern.search(msg)
        if match:
            source_ip = match.group(1)
            source_ips[source_ip] += 1
                
    return source_ips
        
def generate_report_csv(log_records, output_path):
    df = pd.DataFrame(log_records, columns=['Message'])
    df.to_csv(output_path)
        
def generate_plaintext_report(source_ip, log_records, output_path):
    pattern = re.compile(f'SRC={source_ip}')
    matching_messages = [msg for msg in log_records if pattern.search(msg)]
    with open(output_path, 'w') as f:
        f.writelines(matching_messages)
            
def main():
        # Get the log file path from command line argument
    log_file = get_logfile_path(1)
        
        # Filter records that contain "DROP" and save them to a list
    dropped_records = filter_log_messages(log_file, r'.*DROP.*')
        
        # Generate CSV report for all dropped messages
    generate_report_csv(dropped_records, 'dropped.csv')
        
        # Get the top 5 source IP addresses and their counts
    ip_counts = get_source_ip_addresses(dropped_records)
    top_ips = ip_counts.most_common(5)
        
for ip, count in top_ips:
        # Generate a plain text report for each of the top 5 source IP addresses
        source_log_path = f'source_ip_{ip.replace(".", "_")}.log'
        generate_plaintext_report(ip, dropped_records, source_log_path)
        one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_records = filter_log_messages(log_file, r'.*' + re.escape(str(one_hour_ago)) + '.*')
    generate_report_csv(recent_records, 'last_hour.csv')


if __name__ == '__main__':
        main()