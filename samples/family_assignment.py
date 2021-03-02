__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"

# Import libraries
import csv
import os
import hashlib
import glob
import shutil

''' Utility function to extract the hash codes and ransomware
family information from VirusTotal and AVClass reprot '''
def retrieve_VT_and_AVClass_Report():
	try:
		master_info = {}
		with open('master_datasets_information_734_samples.csv') as csvfile:
			reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
			i = 1	# Counter
			for row in reader:
				if i == 1: # Ignore the column names of the CSV file
					i += 1
					continue

				# Minor modification for clear value extractions
				row = str(row)
				row = row.replace('[','')
				row = row.replace('\'','')
				row = row.replace(']','')

				# Adding the information to the dictionary
				master_info[i] = {}
				master_info[i]['sha1'] = row.split(',')[0]
				master_info[i]['md5'] = row.split(',')[1]
				master_info[i]['family'] = row.split(',')[2]
				i += 1

		return master_info

	except:
		print("Something went wrong parsing the CSV file...")
		exit(1)
		return {}

# Driver program
if __name__ == '__main__':

	# Get the report data in a dictionary
	master_info = retrieve_VT_and_AVClass_Report()

	# Change the directory to where the samples are for family assignment
	os.chdir("./samples")
	all_filenames = [i for i in glob.glob('*')]
	all_filenames = sorted(all_filenames)

	# Access each sample file to assign to its family folder
	for fName in all_filenames:
		h_md5 = hashlib.md5()
		h_sha1 = hashlib.sha1()
		with open(fName, 'rb') as aFile:
			buf = aFile.read()
			h_md5.update(buf)
			h_sha1.update(buf)
		
		# Derived the hash codes of the file to match the dictionary
		fName_md5 = h_md5.hexdigest()
		fName_sha1 = h_sha1.hexdigest()

		# Search the family from the dictionary to move the sample to its respective family folder
		for item in master_info:
			try:
				if master_info[item]['md5'] == fName_md5:
					shutil.move(fName, '../' + master_info[item]['family'] + '/' + fName_md5)
					break
			except:
				print(fName)
				print(master_info[item]['family'])
				break
