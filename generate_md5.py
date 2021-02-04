__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@students.tntech.edu"
__status__ = "Prototype"

# ---- File type -----
def fileType(fName):
	try:
		f = magic.Magic(mime=True, uncompress=True)
		#print "File Type:\t", f.from_file(fName)
		return f.from_file(fName)
	except:
		return ""

# ---- Fingerprint -----
def fingerprint(fName):
	data = {'md5': '', 'sha1': '', 'sha256': ''}
	try:
		h1 = hashlib.md5()
		h2 = hashlib.sha1()
		h3 = hashlib.sha256()
		with open(fName, 'rb') as aFile:
			buf = aFile.read()
			h1.update(buf)
			h2.update(buf)
			h3.update(buf)
		data['md5'] = h1.hexdigest()
		data['sha1'] = h2.hexdigest()
		data['sha256'] = h3.hexdigest()
		#print(data)
		return data
	except:
		return data

# ---- Parse values through PEFile library ----
def peInfo(fName):
	data = {
		'e_magic_value' : '',
		'signature_value': '',
		'imp_hash': '',
		'data_directory': [],
		'imports': {},
		'exports': [],
		'sections': {}
	}

	try:
		pe = pefile.PE(fName)
	except OSError as e:
		print(e)
		return {}
	except pefile.PEFormatError as e:
		print(e.value)
		return {}

	try:
		data['e_magic_value'] = hex(pe.DOS_HEADER.e_magic)
	except:
		print "DOS Header is NOT found: ", fName
	try:
		data['signature_value'] = hex(pe.NT_HEADERS.Signature)
	except:
		print "Signature value is NOT found: ", fName
	try:
		data['imp_hash'] = pe.get_imphash()
	except:
		print "IMP Hash is not found"

	try:
		temp = []
		for dirValue in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
			temp.append(str(dirValue.name))
		data['data_directory'] = temp
		del temp
	except:
		print "Data Directory is not found"

	if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
		tempDic = {}
		tempList = []
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			#print "%s" % entry.dll
			for imp in entry.imports:
				if imp.name != None:
					#print "\t%s" % (imp.name)
					tempList.append(str(imp.name))
				else:
					#print "\tord(%s)" % (str(imp.ordinal))
					tempList.append(str(imp.ordinal))
			tempDic[str(entry.dll)] = tempList
		data['imports'] = tempDic
		del tempDic
		del tempList

	if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
		temp = []
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			temp.append(str(exp.name))
		data['exports'] =  temp
		del temp

	# ---- PE Resource -----
	tempDic = {}
	for section in pe.sections:
		tempDic[str(section.Name)] = [section.Misc_VirtualSize, section.SizeOfRawData]
	data['sections'] = tempDic
	del tempDic

	#print data
	return data

# import libraries
import magic
import pefile
import hashlib
import json
import socket
import requests
import os
import glob

api_key = "f429b594917f733ec948e2966b6203fe57a5484e1d4a8a961e2c6b1b323294e5"

os.chdir("./static_ransomware_analysis_samples")
all_filenames = [i for i in glob.glob('*')]
all_filenames = sorted(all_filenames)

json_data = {}
for fName in all_filenames:
	data = {}
	try:
		data['fingerprint'] = fingerprint(fName)
		json_data[fName] = data
	except:
		print fName

print "Writing to file..."

with open('knowledge_extractor_train_set_dump.json', 'w') as json_file:#, encoding="ISO-8859-1") as json_file:
	json.dump(json_data, json_file)