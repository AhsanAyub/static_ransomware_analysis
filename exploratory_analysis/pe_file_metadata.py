#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


class DosHeader(object):
    '''
    This class will store one important detail from the PE file.
    1. Magic Value: value is going to be either MZ or MZ (an EXE file)
    '''
    
    def __init__(self, magic_value: str):
        ''' Store the required information during creation of the object '''
        self._magic_value = str(bytes.fromhex(magic_value[2:]).decode())
        
    def get_magic_value(self) -> str:
        ''' Return the magic value '''
        return self._magic_value

    def __str__(self) -> str:
        ''' Return the object's status '''
        if (self._magic_value == "MZ"):
            return "The PE file is a Non-EXE"
        elif (self._magic_value == "ZM"):
            return "The PE file is an EXE"
        else:
            # Hihgly unlikely to occur
            return "The PE file is neither Non-EXE nor EXE"
        

class FileHeader(object):
    '''
    This class is responsible to store features from the File Header section.
    The features are assigned at the time of object creation and
    accessed with get methods.
    '''
    
    def __init__(self, target_machine: int, number_of_sections: int = 0,
                 characteristics: str = ""):
        ''' Initialize the container with variables '''
        
        # Either 32 bit or 64 bit monstly
        self._target_machine = target_machine
        # Indicates the size of the section table (can be null)
        self._number_of_sections = number_of_sections
        # Flags indicating the attributes of the file
        self._characteristics = characteristics
        
    
    def get_target_machine(self) -> int:
        ''' Return the type of the machine targetting '''
        return self._target_machine
    
    def get_number_of_sections(self) -> int:
        ''' Return the number of sections in the PE file '''
        return self._number_of_sections
    
    def get_characteristics(self) -> str:
        ''' Return the string based (Hex) characteristics flags '''
        return self._characteristics
    
    
class OptionalHeader(object):
    '''
    This class is responsible to store essential details on the PE optional
    headers. The details need to be assigned to variables in the set methods
    and retrieved using the get methods.
    '''
        
    def __init__(self):
        ''' Initialize the container with variables '''
        
        # Specifies the exact format of the PE file (x10b - 32bit; x20b - 64bit)
        self._pe_file_format = 0
        # Size of the code (text) section, or the sum of all code sections
        # if there are multiple sections
        self._size_of_code = 0
        # Size of the initialized data section, or the sum of all code
        # sections if there are multiple data sections
        self._size_of_initialized_data = 0
        # Amount of contiguous memory that must be reserved to load the binary
        # into memory
        self._size_of_image = 0
        # Subsystem required to run this image file
        self._subsystem = 0
        # Specifies some of the security characteristics for the PE file
        self._dll_characteristics = ""
        # The list of data entries
        self._data_directory = []
       
    # Set and get methods for PE file format
    def set_pe_file_format(self, pe_file_format: int):
        self._pe_file_format = pe_file_format
        
    def get_pe_file_format(self) -> int:
        return self._pe_file_format
    
    # Set and get methods for the size of code
    def set_size_of_code(self, size_of_code: int):
        self._size_of_code = size_of_code
        
    def get_size_of_code(self) -> int:
        return self._size_of_code
    
    # Set and get methods for the size of initialized data
    def set_size_of_initialized_data(self, size_of_initialized_data: int):
        self._size_of_initialized_data = size_of_initialized_data
        
    def get_size_of_initialized_data(self) -> int:
        return self._size_of_initialized_data
    
    # Set and get methods for the size of image
    def set_size_of_image(self, size_of_image: int):
        self._size_of_image = size_of_image
        
    def get_size_of_image(self) -> int:
        return self._size_of_image
    
    # Set and get methods for the subsystem
    def set_subsystem(self, subsystem: int):
        self._subsystem = subsystem
        
    def get_subsystem(self) -> int:
        return self._subsystem
    
    # Set and get methods for the DLL characteristics
    def set_dll_characteristics(self, dll_characteristics: str):
        self._dll_characteristics = dll_characteristics
        
    def get_dll_characteristics(self) -> str:
        return self._dll_characteristics
    
    # Set and get methods for the DLL characteristics
    def data_directory(self, data_directory: list):
        self._data_directory = data_directory
        
    def get_number_of_data_directory(self) -> int:
        ''' This method should be called after the previous method named
        data_directory to initialize a list of data directory '''
        return len(self._data_directory)
    
    def get_data_directory(self) -> list:
        ''' This method should be called after the previous method named
        data_directory to initialize a list of data directory '''
        return self._data_directory
    
    
class SectionHeader(object):
    '''
    This class will store all the pieces of PE section header information.
    It will additionally store the list of section names as a list.
    '''
    
    def __init__(self, sectios_info: dict):
        ''' Initialize the container with variables '''
        self._section_info = sectios_info
        self._section_names = []
        
    # Retrieve the seciton info information from the dictionary
    def get_section_info(self) -> dict:
        return self._section_info
    
    def get_section_names(self) -> list:
        for item in self._section_info:
            self._section_names.append(self._section_info[item]["section_name"])
        return self._section_names
    
    def get_number_of_pe_section(self) -> int:
        return len(self._section_names)
    
    
class ImportTables(object):
    '''
    This class will store the import tables information of the PE file.
    '''
    
    def __init__(self, imports: list, libraries: list,
                 libraries_import_counts: dict):
        ''' Initialize the container with variables '''
        self._imports = imports
        self._libraries = libraries
        self._libraries_import_counts = libraries_import_counts
       
    # Get methods for the initialized variables
    def get_imports(self) -> list:
        return self._imports
    
    def get_imports_length(self) -> int:
        return len(self._imports)
    
    def get_libraries(self) -> list:
        return self._libraries
    
    def get_libraries_length(self) -> list:
        return len(self._libraries)
    
    def get_libraries_import_counts(self) -> dict:
        return self._libraries_import_counts


class PackerInfo(object):
    '''
    This class will only store the list of packer libraries of the PE file.
    '''
    
    def __init__(self, packer_libraries: list):
        ''' Initialize the container with variables '''
        self._packer_libraries = packer_libraries
        
    # Return the list of packer librairs
    def get_packer_libraries(self) -> list:
        return self._packer_libraries
    
    # Return the number of packer librareis used
    def get_packer_libraries_length(self) -> int:
        return len(self._packer_libraries)
    
    # Check if any packer libraries were found
    def is_packed(self) -> int:
        if self.get_packer_libraries_length():
            return 1
        else:
            return 0
    

class CryptoInfo(object):
    '''
    This class will only store the list of crypto libraries of the PE file.
    '''
    
    def __init__(self, crypto_libraries: list):
        ''' Initialize the container with variables '''
        self._crypto_libraries = crypto_libraries
        
    # Return the list of packer librairs
    def get_crypto_libraries(self) -> list:
        return self._crypto_libraries
    
    # Return the number of packer librareis used
    def get_crypto_libraries_length(self) -> int:
        return len(self._crypto_libraries)
    
    # Check if any packer libraries were found
    def is_crypto_used(self) -> int:
        if self.get_crypto_libraries_length():
            return 1
        else:
            return 0