"""
Python script for SLAID tool
"""
import os
import pandas as pd
import numpy as np

np.set_printoptions(threshold=np.inf)

# list_dir function presents a directory of folders inside the mentioned path
def list_dir(path):
    """
    List the files and folders in the path
    """
    arr = os.listdir(path)
    for num in arr:
        print(num)


# Paths for the log and csv files
ORIGNAL_PATH = r"/home/user/Downloads/c/"
NEW_PATH = r"/home/user/Documents/e/"

# Counters for query results
COUNT_UNKNOWN_HOST = 0
COUNT_MOZILLA_REQUEST = 0
COUNT_OPERA_REQUEST = 0
COUNT_UNIQUE_IP_PAIR = 0
COUNT_AMAZON_VISITS = 0
COUNT_GOOGLE_VISITS = 0
COUNT_ALERT_1 = 0
COUNT_ALERT_ALERT_2 = 0
port_not_http = []

# Folders contains the list of folders inside the original lof files path
folders = os.listdir(ORIGNAL_PATH)


for sub_folders in folders:

    # Define both the log path and csv path
    log_file_path = ORIGNAL_PATH + sub_folders + r"/http.log"
    csv_file_path = NEW_PATH + sub_folders + r"_http.csv"
    file = open(log_file_path, mode="r+", encoding="utf-8")
    skip_lines = file.readlines()

    # Skip first 6 lines and the last line if necessary (Optional)
    skip_array = skip_lines[6:-1]
    del skip_array[1]
    new_array = skip_array
    a = np.array(new_array)

    # Read content from first file and append content to second file
    with open(csv_file_path, mode="w", encoding="utf-8") as secondfile:
        for line in skip_array:
            secondfile.write(line)

    # Path file of each http.log file is printed inside the folder loop
    http_csv = csv_file_path
    print("\nPath of File: ", http_csv)

    # Convert the csv file (Optional: shift the column by one to right)
    csv_file = open(csv_file_path, mode="r+", encoding="utf-8")
    df = pd.read_csv(csv_file, sep="\t")
    shifted_df = df.shift(+1, axis="columns")

    # Change the column name of source and destination ports
    port_df = shifted_df.rename(
        columns={"id.orig_p": "source_port", "id.resp_p": "destn_port"}
    )
    unique_port = port_df.destn_port.unique()
    port_not_http.append(unique_port)
    unique_df = port_df[["id.orig_h", "id.resp_h", "host"]]

    # Unique IP pairs and the number of occurances
    print(
        "Below are the pairs of unique source IP and unique destination IP in the log file:"
    )
    print(
        unique_df.groupby(["id.orig_h", "id.resp_h"])
        .size()
        .reset_index()
        .rename(columns={0: "count"})
    )

    # Number of occurances for amazon.com in logs per folder
    amazon_df = unique_df[unique_df["host"].str.contains("amazon.com")]
    COUNT_AMAZON_VISITS = amazon_df.host.count() + COUNT_AMAZON_VISITS
    print("Amazon visits:", amazon_df.host.count())

    # Number of visits to google.com
    google_df = shifted_df[shifted_df["host"].str.contains("google.com")]
    COUNT_GOOGLE_VISITS = google_df.host.count() + COUNT_GOOGLE_VISITS

    # Requests done using Mozilla/4.0
    mozilla_df = shifted_df[shifted_df["user_agent"].str.contains("Mozilla/4.0")]
    COUNT_MOZILLA_REQUEST = mozilla_df.user_agent.count() + COUNT_MOZILLA_REQUEST

    # Requests done using Opera/9.0
    opera_df = shifted_df[shifted_df["user_agent"].str.contains("Opera/9")]
    COUNT_OPERA_REQUEST = opera_df.user_agent.count() + COUNT_OPERA_REQUEST

    # Alert message 1 on malicious host name
    alert_1_df = shifted_df[shifted_df["host"].str.contains("alert_1.com")]
    COUNT_ALERT_1 = alert_1_df.host.count() + COUNT_ALERT_1
    for alert1 in alert_1_df.index:
        print(
            "\nAlert! Malicious host/URL: 'alert_1.com' detected at Log_event: ", alert1
        )

    # Alert message 2 on malicious host name
    alert_2_df = shifted_df[shifted_df["host"].str.contains("alert_2.de")]
    COUNT_ALERT_ALERT_2 = alert_2_df.host.count() + COUNT_ALERT_ALERT_2
    for alert2 in alert_2_df.index:
        print(
            "\nAlert! Malicious host/URL: 'alert_2.de' detected at Log_event: ", alert2
        )

    # Events where hostname is not available
    unknown_host = shifted_df["host"]
    shifted_df["unknown_host"] = np.where(
        (shifted_df["id.resp_h"] == unknown_host), "True", "False"
    )
    unknown_host_df = shifted_df[shifted_df["unknown_host"].str.contains("True")]
    COUNT_UNKNOWN_HOST = unknown_host_df.unknown_host.count() + COUNT_UNKNOWN_HOST
    print(unknown_host_df[["id.resp_h", "host", "unknown_host"]])


# Print all the results in values
print("Number of requests from Unknown hosts: ", COUNT_UNKNOWN_HOST)
print("Total number of times amazon is visited: ", COUNT_AMAZON_VISITS)
print("Number of times google is visited: ", COUNT_GOOGLE_VISITS)
print("Number of Mozilla requests: ", COUNT_MOZILLA_REQUEST)
print("Number of Opera requests: ", COUNT_OPERA_REQUEST)
print("Number of alert_1.com alerts: ", COUNT_ALERT_1)
print("Number of alert_2.de alerts: ", COUNT_ALERT_ALERT_2)
ports = list(set(i for j in port_not_http for i in j))
print("Number of destination ports are: ", len(ports), str(ports))
