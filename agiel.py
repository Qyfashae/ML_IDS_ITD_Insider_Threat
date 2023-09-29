# Coded by: Qyfashae
'''
Feat-Eng for IDS-Insider_Threat_Detection
'''

import numpy as np 
import pandas as pd

path_to_dataset = "./your_dataset/" # Path to your own dataset data

#Specify the .csv files and wich columns to read
log_types = [
			 "device", 
			 "email",
			 "file", 
			 "logon",  
			 "http",
			 ]

log_fields_list = [
				   ["date", "employee", "activity"],
				   ["date", "employee", "to", "cc", "bcc"],
				   ["date", "employee", "filename"], 
				   ["date", "employee", "activity"], 
				   ["date", "employee", "url"],				
				   ]

# We create features & encode them thats why we create a dict to track these(We will add features/functions)
features = 0
features_map = {}

# Exp
def funcstruct():
	print('''
		Engine for Insider Threat Detection.
		So for this IDS i will use no specified file but i will print here what columns for random usage.
		Columns inside csv: 
			device, email, file, logon, http
		Columns fields in csv:
			activity, [to, cc, bcc], filename, activity, url
		''')

# Here we hand-engineer the features
def add_feature(name):
	if name not in feature_map:
		global features
		feature_map[name] = features
		features += 1

		# Features to add to the dict
		add_feature("Weekday_Logon_Normal")
		add_feature("Weekday_Logon_After")
		add_feature("Weekend_Logon")
		add_feature("Logoff")
		add_feature("Connect_Normal")
		add_feature("Connect_After")
		add_feature("Connect_Weekend")
		add_feature("Disconnect")
		add_feature("Email_In")
		add_feature("Email_Out")
		add_feature("File_exe")
		add_feature("File_jpg")
		add_feature("File_zip")
		add_feature("File_txt")
		add_feature("File_doc")
		add_feature("File_pdf")
		add_feature("File_other")
		add_feature("url")


# Define a function to note the filetype if its copied to a removable devies | recording file_ext of the file used
def file_feat(row):
	if row["filename"].endswith(".exe"):
		return feature_map["File_exe"]
	if row["filename"].endswith(".jpg"):
		return feature_map["File_jpg"]
	if row["filename"].endswith(".zip"):
		return feature_map["File_zip"]
	if row["filename"].endswith(".txt"):
		return feature_map["File_txt"]
	if row["filename"].endswith(".doc"):
		return feature_map["File_doc"]
	if row["filename"].endswith(".pdf"):
		return feature_map["File_pdf"]
	else:
		return feature_map["File_other"]

# Define a function to identify whether an employee has sent and email to a non-company email
def email_feat(row):
	outsider = False 
	if not pd.isnull(row["to"]):
		for address in row["to"].split(";"):
			if not address.endswith("company.com") # company.com --> your company @company.com email ext|url
				outsider = True

	if not pd.isnull(row["cc"]):
		for address in row["cc"].split(";"):
			if not address.endswith("company.com") # company.com --> your company @company.com email ext|url
				outsider = True

	if not pd.isnull(row["bcc"]):
		for address in row["bcc"].split(";"):
			if not address.endswith("company.com") # company.com --> your company @company.com email ext|url
				outsider = True

	if outsider:
		return feature_map["Email_Out"]
	else:
		return feature_map["Email_In"]

# Define a function to note whether the employee used removable device outside of business hours
def device_features(row):
	if row["activity"] == "Connect":
		if row["date"].weekday() < 5:
			if row["date"].hour >= 8 and row["date"].hour < 17:
				return feature_map["Connect_Normal"]
			else:
				return feature_map["Connect_After"]
		else:
			return features_map["Connect_Weekend"]
	else:
		return feature_map["Disconnect"]

# Define a function to note whether an employee logged into a machine outside of working hours
def logon_feature(row):
	if row["activity"] == "Logon"
		if row["date"].weekday() < 5:
			if row["date"].hour >= 8 and row["date"].hour < 17:
				return feature_map["Weekday_Logon_Normal"]
			else:
				return features_map["Weekday_Logon_After"]
		else:
			return feature_map["Weekend_Logon"]
	else:
		return feature_map["Logoff"]

# Will not collect information contained in the requests or url visited by employee for privacy reasons
def http_feature(row):
	return feature_map["url"]

'''
# Will collect information contained in the requests or url visited by employee if employee == suspicious
def urlcollect_feature(row):
	if ***
'''

# To not override we only collect the day an event occured and not full timestamp for memory reasons
def date_to_day(row):
	day_only = row["date"].date()
	return day_only

# We will loop the .csv files having logs and then read them into pandas data frames
log_feature_functions = [
	device_features,
	email_features,
	file_features,
	logon_features,
	http_features
]
dfs = []
for i in range(len(log_types)):
	log_type = log_types[i]
	log_fields = log_fields_list[i]
	log_feature_function = log_feature_functions[i]
	df = pd.read_csv(
		path_to_dataset + log_type + ".csv", usecols=log_fields, index_col=None
		)
date_format = "%m/%d/%Y %H:%M:%S"
df["date"] = pd.to_datetime(df["date"], format=date_format)
new_feature = df.apply(log_feature_function, axis=1)
df["feature"] = new_feature
cols_to_keep = ["date", "user", "feature"]
df = df["cols_to_keep"]
df["date"] = df.apply(date_to_day, axis=1)
dfs.append(df)
	joint = pd.concat(dfs)
	joint = joint.sort_values(by="date")

