__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


# Import libraries
import os
import glob
import hashlib
import magic
import pefile

class basicSampleInfo(object):
	''' A class to hold a few basic pieces of information of the
	ransomware sample privided. '''

	def __init__(self, file_name, family_name):
		''' Initialize the contianer with a couple of information '''
		self._ransomware_sample_file_name = file_name
		self._ransomware_family_name = family_name
		self._file_size = 0		# in bytes
		self._file_type = ""
		self._md5_hash = hashlib.md5()
		self._sha1_hash = hashlib.sha1()
		self._sha256_hash = hashlib.sha256()

	def collect_information(self):
		''' Extract important pieces of information about the PE file '''

		# Collect the hashes of the file
		with open(self._ransomware_sample_file_name, 'rb') as f:
			buf = f.read()
			self._md5_hash.update(buf)
			self._sha1_hash.update(buf)
			self._sha256_hash.update(buf)
			
		# Update the hashes to private members
		self._md5_hash = self._md5_hash.hexdigest()
		self._sha1_hash = self._sha1_hash.hexdigest()
		self._sha256_hash = self._sha256_hash.hexdigest()

		# Collect the file size in bytes
		self._file_size = os.stat(self._ransomware_sample_file_name).st_size
		# Collect the file type
		self._file_type = magic.from_file(self._ransomware_sample_file_name, mime=True)

	def get_file_name(self):
		''' Get the sample's file name '''
		return self._ransomware_sample_file_name

	def get_family_name(self) :
		''' Get the sample's family name '''
		return self._ransomware_family_name

	def get_md5_hash(self):
		''' Get the md5 hash of the sample '''
		return self._md5_hash

	def get_sha1_hash(self):
		''' Get the sha1 hash of the sample '''
		return self._sha1_hash

	def get_sha256_hash(self):
		''' Get the sha256 hash of the sample '''
		return self._sha256_hash

	def get_file_type(self):
		''' Get the type of the sample file '''
		return self._file_type

	def get_file_size(self):
		''' Get the size of the sample file '''
		return self._file_size	


class peFileExtractor(object):
	''' This class is responsible to extract all the useful pieces
	of information of the ransomware samples using different libraries. '''
	def __init__(self, file_name):
		self._ransomware_sample_file_name = file_name
		self._pe_file_extracted_data = {}	# Dictnionary to store all the data

	def get_pe_file_extracted_data(self):
		''' Get all the extracted data in dictionary format '''
		return self._pe_file_extracted_data

	def set_pe_file_extracted_data(self):
		''' Extract all the PE file meta-data '''
		try:
			pe = pefile.PE(self._ransomware_sample_file_name)
		except OSError as e:
			print(e)
		except pefile.PEFormatError as e:
			print(e.value)

		''' Feature from the DOS Header '''
		# Could be MZ, stands for Mark Zbikowski, or ZM on an (non-PE) EXE
		self._pe_file_extracted_data['e_magic_value'] = hex(pe.DOS_HEADER.e_magic)[2:].decode("hex")
		# This is a relative address to the NT header (can't be null)
		self._pe_file_extracted_data['e_lfanew'] = hex(pe.DOS_HEADER.e_lfanew)

		''' Features from the File Header '''
		# Number identifying the type of the target (x14C - 32 bit ni+nary; x8664 - 64 bit binary)
		self._pe_file_extracted_data['target_machine'] = hex(pe.FILE_HEADER.Machine)
		# Indicates the size of the section table (Can be null)
		self._pe_file_extracted_data['number_of_section'] = int(hex(pe.FILE_HEADER.NumberOfSections), 16)
		# Time and date the file was created (used for bound import checks)
		self._pe_file_extracted_data['time_date_stamp'] = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
		# Flags indicating the attributes of the file
		self._pe_file_extracted_data['characteristics'] = hex(pe.FILE_HEADER.Characteristics)

		''' Features from the Optional Header '''
		# Magic specifies the exact format of the PE file (x10b - 32bit; x20b - 64bit)
		self._pe_file_extracted_data['magic'] = hex(pe.OPTIONAL_HEADER.Magic)
		# Size of the code (text) section, or the sum of all code sections if there are multiple sections
		self._pe_file_extracted_data['size_of_code'] = int(hex(pe.OPTIONAL_HEADER.SizeOfCode), 16)
		# Size of the initialized data section, or the sum of all code sections if there are multiple data sections
		self._pe_file_extracted_data['size_of_initialized_data'] = int(hex(pe.OPTIONAL_HEADER.SizeOfInitializedData), 16)
		# Relative to the image base, when executable file is loaded into memory
		self._pe_file_extracted_data['entry_point_address'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		# Amount of contiguous memory that must be reserved to load the binary into memory
		self._pe_file_extracted_data['size_of_image'] = int(hex(pe.OPTIONAL_HEADER.SizeOfImage), 16)
		# Specifies the preferred virtual memory locaiton where the beginning of the binary should be placed
		self._pe_file_extracted_data['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
		# Specifies that sections must be aligned on boundaries which are multples of this value.
		self._pe_file_extracted_data['section_alignment'] = hex(pe.OPTIONAL_HEADER.SectionAlignment)
		# Specifies that the data written to the binary in chunks no smaller than this value
		self._pe_file_extracted_data['file_alignment'] = hex(pe.OPTIONAL_HEADER.FileAlignment)
		# Subsystem required to run this image file
		self._pe_file_extracted_data['subsystem'] = int(hex(pe.OPTIONAL_HEADER.Subsystem), 16)
		# Specifies some of the security characteristics for the PE file
		self._pe_file_extracted_data['dll_characteristics'] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
		# An array of data entries
		self._pe_file_extracted_data['number_of_data_directory'] = 0
		self._pe_file_extracted_data['data_directory'] = []
		for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
			self._pe_file_extracted_data['data_directory'].append(entry.name)
			self._pe_file_extracted_data['number_of_data_directory'] += 1

if __name__ == '__main__':
	''' Driver program '''

	# Store the current directory to dump the samples later
	current_directory = os.getcwd()
	
	# Change the directory to go where the samples are
	os.chdir("../samples/family_wise_samples/")

	# get all the ransomware familiy names
	all_ransomware_families = [i for i in glob.glob("*")]
	all_ransomware_families = sorted(all_ransomware_families)

	# Go to the family folder to scan each of its sample
	os.chdir("./" + all_ransomware_families[0] + "/")
	sample_names = [i for i in glob.glob("*")]
	sample_names = sorted(sample_names)

	# Extract the basic pieces of information regarding the PE file
	sample_info = basicSampleInfo(sample_names[0], all_ransomware_families[0])
	sample_info.collect_information()

	# Extract the information based on the PE module
	sample_pe_info = peFileExtractor(sample_names[0])
	sample_pe_info.set_pe_file_extracted_data()
	print(sample_pe_info.get_pe_file_extracted_data())

	'''print(sample_info.get_file_name())
	print(sample_info.get_family_name())
	print(sample_info.get_file_size())
	print(sample_info.get_file_type())
	print(sample_info.get_md5_hash())
	print(sample_info.get_sha1_hash())
	print(sample_info.get_sha256_hash())'''