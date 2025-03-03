import csv
import pprint
from datetime import datetime
import re

# Initialize dictionaries and lists to store failed attempts, brute force attacks, and succeeded logins
failed_attempts = {}
brute_force_att = {}
secceded_login = []

# Open the CSV file in read mode
with open('server_log - server_log.csv', 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:

        ip = row['IP']
        stasusCode = row['Status Code']
        request = row['Request']
        time_str = row['Time']

        # Convert the time string to a datetime object using the specified format
        time_obj = datetime.strptime(time_str, '%d/%m/%Y %H:%M')

        # Check if the Status Code is '401' (Unauthorized) and the Request contains the word 'login'
        if stasusCode == '401' and re.search(r"login", request):
            # If the IP is not already in the failed_attempts dictionary, add it with an empty list
            if ip not in failed_attempts:
                failed_attempts[ip] = []
            # Append the current time to the list of failed attempts for this IP
            failed_attempts[ip].append(time_obj)

        # Check if the Status Code is '200' (OK) and the Request contains the word 'login'
        if (stasusCode == '200' or stasusCode == '201') and re.search(r"login", request):
            # If the IP is not already in the succeeded_login list, add it
            if ip not in secceded_login:
                secceded_login.append(ip)

# count number off 401 attempts for each ip
for j in failed_attempts:
    times = failed_attempts[j]

    for i in range(len(times)-2):
        window = times[i:i + 3]
        if (window[-1] - window[0]).total_seconds() / 60 <= 5:
            brute_force_att[j] = []

            brute_force_att[j].append(len(times)) # Append the number of failed attempts

            brute_force_att[j].append(times[0].strftime('%d/%m/%Y %H:%M')) # Append the time of the first failed attempt in the window

            brute_force_att[j].append(times[-1].strftime('%d/%m/%Y %H:%M')) # Append the time of the last failed attempt in the window

            # Check if the IP is in the succeeded_login list and append "yes" or "no" accordingly
            if j in secceded_login:
                brute_force_att[j].append("yes")
            else:
                brute_force_att[j].append("no")

            break # Exit the loop after detecting a brute force attack for this IP
        # Brute force detected!

# print in nice format
pprint.pprint(brute_force_att)