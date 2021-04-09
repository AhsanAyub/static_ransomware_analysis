#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"

# Import libraries
import pandas as pd
import numpy as np

from exploratory_analysis.pe_file_metadata import (DosHeader, FileHeader,
OptionalHeader, SectionHeader, ImportTables, PackerInfo, CryptoInfo)


class ProcessSampleFrequencyFeatureSet(object):
    '''
    This class will store a sample's PE meta data information by utilizing
    all the container classes written in pe_file_metadata.py file.
    '''
    
    def __init__(self, sample_name: str, family_name: str, file_size: int,
                 file_type: str):
        ''' Initialize the object with some of the basic pieces of sample's
        information, along with empty object container from other class '''
        
        self._sample_name = sample_name
        self._family_name = family_name
        self._file_size = file_size
        self._file_type = file_type
        
        # Initialize public object containers for classes
        # The object of the class can easily access the containers from outside
        self.dos_header = None
        self.file_header = None
        self.optional_header = None
        self.section_header = None
        self.import_tables = None
        self.packer_info = None
        self.crypto_info = None
        
    # Get methods to retrieve the basic sample's details
    def get_sample_name(self) -> str:
        return self._sample_name

    def get_family_name(self) -> str:
        return self._family_name
    
    def get_file_size(self) -> int:
        return self._file_size
    
    def get_file_type(self) -> str:
        return self._file_type
    

def process_pe_dos_header(dataset) -> DosHeader:
    ''' This method will parse through the dataset and store the required pieces
    of information to the object of DosHeader class.
    It will return the created object '''
    try:
        dos_header = DosHeader(dataset["e_magic_value"])
    except:
        dos_header = DosHeader("")
        print("e_magic_value field is not found")
    return dos_header


def process_pe_file_header(dataset) -> FileHeader:
    ''' This method will parse through the dataset of a particular sample and
    store the required pieces of information to the object of FileHeader class.
    It will return the created object '''
    
    # target machine to identify either 32 bit or 64 bit
    target_machine = np.nan
    try:
        if dataset["target_machine"] == "0x14c":
            target_machine = 32
        if dataset["target_machine"] == "0x8664":
            target_machine = 64            
    except:
        print("target machine field is not found")
        pass
    
    # Indicates the size of the section table (can be null) 
    number_of_section = np.nan
    try:
        number_of_section = dataset["number_of_section"]
    except:
        print("number of section field is not found")
        pass
     
    # Flags indicating the attributes of the file
    characteristics = np.nan
    try:
        characteristics = dataset["characteristics"]
    except:
        print("characteristics field is not found")
        pass
    
    file_header = FileHeader(target_machine, number_of_section, characteristics)
    return file_header


def process_pe_optional_header(dataset) -> OptionalHeader:
    ''' This method will parse through the dataset of a particular sample and
    store the required pieces of information to the object of OptionalHeader class.
    It will return the created object '''

    optional_header = OptionalHeader()
    
    try:
        if dataset["magic"] == "0x10b":
            optional_header.set_pe_file_format(32)
        elif dataset["magic"] == "0x20b":
            optional_header.set_pe_file_format(64)
        else:
            optional_header.set_pe_file_format(np.nan)
    except:
        optional_header.set_pe_file_format(np.nan)
        print("magic field is not found")
        
    try:
        optional_header.set_size_of_code(dataset["size_of_code"])
    except:
        optional_header.set_size_of_code(np.nan)
        print("size of code field is not found")
    
    try:    
        optional_header.set_size_of_initialized_data(dataset["size_of_initialized_data"])
    except:
        optional_header.set_size_of_initialized_data(np.nan)
        print("size of initialized data field is not found")
        
    try:
        optional_header.set_size_of_image(dataset["size_of_image"])
    except:
        optional_header.set_size_of_image(np.nan)
        print("size of image field is not found")
    
    try:
        optional_header.set_subsystem(dataset["subsystem"])
    except:
        optional_header.set_subsystem(np.nan)
        print("subsystem field is not found")
    
    try:
        optional_header.set_dll_characteristics(dataset["dll_characteristics"])
    except:
        optional_header.set_dll_characteristics(np.nan)
        print("dll characteristics field is not found")
    
    try:
        if len(dataset["data_directory"]):
            optional_header.data_directory(dataset["data_directory"])
        else:
            optional_header.data_directory([])
    except:
        print("data directory field is not found")
        optional_header.data_directory([])

    return optional_header


def process_pe_packer_info(dataset) -> PackerInfo:
    ''' This method will parse through the dataset of a particular sample and
    store the required pieces of information to the object of PackerInfo class.
    It will return the created object '''
    
    packer_libraries = []
    if (len(dataset["packer_info"]["packer_list"]) > 2):
        packer_libraries = dataset["packer_info"]["packer_list"]
        packer_libraries = packer_libraries[1:-1]
        packer_libraries = list(packer_libraries.split(', '))
    
    packer_info = PackerInfo(packer_libraries)
    return packer_info


def process_pe_crypto_info(dataset) -> CryptoInfo:
    ''' This method will parse through the dataset of a particular sample and
    store the required pieces of information to the object of CryptoInfo class.
    It will return the created object '''
    
    crypto_libraries = []
    if (len(dataset["crypto_info"]["crypto_list"]) > 2):
        crypto_libraries = dataset["crypto_info"]["crypto_list"]
        crypto_libraries = crypto_libraries[1:-1]
        crypto_libraries = list(crypto_libraries.split(', '))
    crypto_info = CryptoInfo(crypto_libraries)
    return crypto_info


if __name__ == '__main__':
    ''' Driver program '''
    
    dataset = pd.read_pickle('data/pe_vt_info_dataset.pkl')
    
    sample_info_objects = []
    for sample_name in dataset:
        sample_info_object = ProcessSampleFrequencyFeatureSet(sample_name,
                          # Family name of the sample
                          dataset[sample_name]["sample_info"]["family_name"],
                          # Size of the sample file
                          dataset[sample_name]["sample_info"]["file_size"],
                          # Type of the sample file
                          dataset[sample_name]["sample_info"]["file_type"])
        
        
        sample_info_object.dos_header = process_pe_dos_header(
                dataset[sample_name]["pe_static_analyzer"])
        
        sample_info_object.file_header = process_pe_file_header(
                dataset[sample_name]["pe_static_analyzer"])
        
        sample_info_object.optional_header = process_pe_optional_header(
                dataset[sample_name]["pe_static_analyzer"])
            
        try:
            sample_info_object.section_header = SectionHeader(
                    dataset[sample_name]["pe_static_analyzer"]["sections_info"])
        except:
            sample_info_object.section_header = SectionHeader({})
            print("section info field is not found")
        
        try:
            sample_info_object.import_tables = ImportTables(
                dataset[sample_name]["pe_static_analyzer"]["imports_list"],
                dataset[sample_name]["pe_static_analyzer"]["libraries_list"],
                dataset[sample_name]["pe_static_analyzer"]["libraries_import_counts"])
        except:
            sample_info_object.import_tables = ImportTables([], [], {})
            print("Import Tables field is not found")
        
        sample_info_object.packer_info = process_pe_packer_info(
                dataset[sample_name]["pe_static_analyzer"])
        
        sample_info_object.crypto_info = process_pe_crypto_info(
                dataset[sample_name]["pe_static_analyzer"])
        
        sample_info_objects.append(sample_info_object)
        
    del dataset
    
    # Column names to initilize a dataframe
    cols = ["number_of_sections", "characteristics", "size_of_code",
            "size_of_initialized_data", "size_of_image", "subsystem",
            "dll_characteristics", "number_of_data_directory", "data_directory",
            "number_of_section_names", "section_names", "number_of_imports",
            "number_of_libraries", "libraries", "libraries_import_counts",
            "number_of_packer_libraries", "packer_libraries",
            "number_of_crypto_libraries", "crypto_libraries", "file_size",
            "file_type", "family_name"]
    
    data = []
    for sample_info_object in sample_info_objects:
        temp = []
        
        temp.append(sample_info_object.file_header.get_number_of_sections())
        temp.append(sample_info_object.file_header.get_characteristics())
        
        temp.append(sample_info_object.optional_header.get_size_of_code())
        temp.append(sample_info_object.optional_header.get_size_of_initialized_data())
        temp.append(sample_info_object.optional_header.get_size_of_image())
        temp.append(sample_info_object.optional_header.get_subsystem())
        temp.append(sample_info_object.optional_header.get_dll_characteristics())
        temp.append(sample_info_object.optional_header.get_number_of_data_directory())
        temp.append(sample_info_object.optional_header.get_data_directory())
        
        temp.append(sample_info_object.section_header.get_number_of_pe_section())
        temp.append(sample_info_object.section_header.get_section_names())
        
        temp.append(sample_info_object.import_tables.get_imports_length())
        temp.append(sample_info_object.import_tables.get_libraries_length())
        temp.append(sample_info_object.import_tables.get_libraries())
        temp.append(sample_info_object.import_tables.get_libraries_import_counts())
        
        temp.append(sample_info_object.packer_info.get_packer_libraries_length())
        temp.append(sample_info_object.packer_info.get_packer_libraries())
        
        temp.append(sample_info_object.crypto_info.get_crypto_libraries_length())
        temp.append(sample_info_object.crypto_info.get_crypto_libraries())
        
        temp.append(sample_info_object.get_file_size())
        temp.append(sample_info_object.get_file_type())
        temp.append(sample_info_object.get_family_name())
        
        data.append(temp)
        
    dataset = pd.DataFrame(data, columns = cols)