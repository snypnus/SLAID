import os
import pandas as pd
import numpy as np

np.set_printoptions(threshold=np.inf)

# list_dir function presents a directory of folders inside the mentioned path
def list_dir(path):
    arr = os.listdir(path)
    for num in arr:
        print(num)

# Paths for the log and csv files
original_path = r"/home/user/Downloads/c/"
new_path = r"/home/user/Documents/e/"

# Counters for query results
count_Unknown_host = 0
count_mozilla_request = 0
count_opera_request = 0
count_unique_IP_pair = 0
count_amazon_visits = 0
count_google_visits = 0
count_alert_1 = 0
count_alert_alert_2 = 0
port_not_http = []

# Folders contains the list of folders inside the original lof files path
folders = os.listdir(original_path)


for sub_folders in folders:

# Use shutil.copy2(original_path,new_path) to copy file to a new path with new name and extension
# Define both the log path and csv path
    log_file_path = original_path + sub_folders + r"/http.log"
    csv_file_path = new_path + sub_folders + r"_http.csv"
    file = open(log_file_path, 'r+')
    skip_lines = file.readlines()

# Skip first 6 lines and the last line if necessary (Optional)
    skip_array = skip_lines[6:-1]
    del (skip_array[1])
    new_array = skip_array
    a = np.array(new_array)

# Read content from first file and append content to second file
    with open(csv_file_path, 'w') as secondfile:
        for line in skip_array:
            secondfile.write(line)

# Path file of each http.log file is printed inside the folder loop
    http_csv = csv_file_path
    print('\nPath of File: ', http_csv)

# Convert the csv file (Optional: shift the column by one to right)
    csv_file = open(csv_file_path, 'r+')
    df = pd.read_csv(csv_file, sep='\t')
    shifted_df = df.shift(+1, axis="columns")


# Change the column name of source and destination ports
    port_df = shifted_df.rename(columns={"id.orig_p": "source_port", "id.resp_p": "destn_port"})
    unique_port = port_df.destn_port.unique()
    port_not_http.append(unique_port)
    unique_df = port_df[['id.orig_h', 'id.resp_h', 'host']]

# Unique IP pairs and the number of occurances
    print("Below are the pairs of unique source IP and unique destination IP in the log file:")
    print(unique_df.groupby(["id.orig_h", "id.resp_h"]).size().reset_index().rename(columns={0: 'count'}))

# Number of occurances for amazon.com in logs per folder
    amazon_df = unique_df[unique_df['host'].str.contains('amazon.com')]
    count_amazon_visits = amazon_df.host.count() + count_amazon_visits
    print("Amazon visits:", amazon_df.host.count())

# Number of visits to google.com
    google_df = shifted_df[shifted_df['host'].str.contains('google.com')]
    count_google_visits = google_df.host.count() + count_google_visits

# Requests done using Mozilla/4.0
    mozilla_df = shifted_df[shifted_df['user_agent'].str.contains('Mozilla/4.0')]
    count_mozilla_request = mozilla_df.user_agent.count() + count_mozilla_request

# Requests done using Opera/9.0
    opera_df = shifted_df[shifted_df['user_agent'].str.contains('Opera/9')]
    count_opera_request = opera_df.user_agent.count() + count_opera_request

# Alert message 1 on malicious host name
    alert_1_df = shifted_df[shifted_df['host'].str.contains('alert_1.com')]
    count_alert_1 = alert_1_df.host.count() + count_alert_1
    for alert1 in alert_1_df.index:
        print("\nAlert! Malicious host/URL: 'alert_1.com' detected at Log_event: ", alert1)

# Alert message 2 on malicious host name
    alert_2_df = shifted_df[shifted_df['host'].str.contains('alert_2.de')]
    count_alert_alert_2 = alert_2_df.host.count() + count_alert_alert_2
    for alert2 in alert_2_df.index:
        print("\nAlert! Malicious host/URL: 'alert_2.de' detected at Log_event: ", alert2)

# Events where hostname is not available
    unknown_host = shifted_df['host']
    shifted_df['unknown_host'] = np.where((shifted_df['id.resp_h'] == unknown_host), 'True', 'False')
    unknown_host_df = shifted_df[shifted_df['unknown_host'].str.contains('True')]
    count_Unknown_host = unknown_host_df.unknown_host.count() + count_Unknown_host
    print(unknown_host_df[['id.resp_h', 'host', 'unknown_host']])


# Print all the results in values 
print("Number of requests from Unknown hosts: ", count_Unknown_host)
print("Total number of times amazon is visited: ", count_amazon_visits)
print("Number of times google is visited: ", count_google_visits)
print("Number of Mozilla requests: ", count_mozilla_request)
print("Number of Opera requests: ", count_opera_request)
print("Number of alert_1.com alerts: ", count_alert_1)
print("Number of alert_2.de alerts: ", count_alert_alert_2)
ports = list(set(i for j in port_not_http for i in j))
print("Number of destination ports are: ", len(ports), str(ports))
