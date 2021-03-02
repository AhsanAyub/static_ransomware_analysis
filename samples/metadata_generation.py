__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


# Import libraries
import magic
import pefile
import hashlib
import json
import requests
import os
import glob


# Driver program
if __name__ == '__main__':
	fName = "00b79b9b29e5514f292cf0ec81a7e24d5fd6acf9caa4acae20b47822e4ee7104"

	# Access each sample file to assign to its family folder
	h_md5 = hashlib.md5()
	h_sha1 = hashlib.sha1()
	with open(fName, 'rb') as aFile:
		buf = aFile.read()
		h_md5.update(buf)
		h_sha1.update(buf)

	print(h_md5.hexdigest())
	print(h_sha1.hexdigest())

	pe = pefile.PE(fName)
	print(pe.dump_info())