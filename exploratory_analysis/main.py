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


def sample_structure(dataset):
    ''' Explore the structure of the samples 
    - EXE and NON-EXE file? [e_magic_header]
    - Format of the PE file (32-bit or 64-bit) '''
    
    number_of_exe_files = 0
    number_of_non_exe_files = 0
    number_of_32_bit_target_machines = 0
    number_of_64_bit_target_machines = 0
    
    for sample in dataset:
        try:
            e_magic_value = str(bytes.fromhex(dataset[sample]['pe_static_analyzer']['e_magic_value'][2:]).decode())
            if e_magic_value == 'MZ':
                number_of_exe_files += 1
            elif e_magic_value == 'ZM':
                number_of_non_exe_files += 1
            else:
                pass
        except:
            print('e_magic_value does not exist')
        
        try:
            target_machine = dataset[sample]['pe_static_analyzer']['target_machine']
            if target_machine == "0x14c":
                number_of_32_bit_target_machines += 1
            elif target_machine == "0x8664":
                number_of_64_bit_target_machines += 1
            else:
                pass
        except:
            print('e_magic_value does not exist')
        
    return number_of_exe_files, number_of_non_exe_files, number_of_32_bit_target_machines, number_of_64_bit_target_machines


def crypto_libraries_used(dataset):
    ''' Explore how many samples have used crypto libraries
    along with what types of libraries are used. '''
    
    number_of_samples_crypto_lib_used = 0
    number_of_lib_used_by_sampples = []
    crypto_lib_used_list = []
    
    for sample in dataset:
        if (len(dataset[sample]['pe_static_analyzer']['crypto_info']['crypto_list']) > 2):
            number_of_samples_crypto_lib_used += 1
            string_list = dataset[sample]['pe_static_analyzer']['crypto_info']['crypto_list']
            string_list = string_list[1:-1]
            string_list = list(string_list.split(', '))
            
            number_of_lib_used_by_sampples.append(len(string_list))
                
            for item in string_list:
                if item not in crypto_lib_used_list:
                    crypto_lib_used_list.append(item)
                else:
                    pass
        else:
            pass
        
    return number_of_samples_crypto_lib_used, crypto_lib_used_list, number_of_lib_used_by_sampples


def packer_libraries_used(dataset):
    ''' Explore how many samples have used packer libraries
    along with what types of libraries are used. '''
    
    number_of_samples_packer_lib_used = 0
    number_of_lib_used_by_sampples = []
    packer_lib_used_list = []
    
    for sample in dataset:
        if (len(dataset[sample]['pe_static_analyzer']['packer_info']['packer_list']) > 2):
            number_of_samples_packer_lib_used += 1
            string_list = dataset[sample]['pe_static_analyzer']['packer_info']['packer_list']
            string_list = string_list[1:-1]
            string_list = list(string_list.split(', '))
            
            number_of_lib_used_by_sampples.append(len(string_list))
                
            for item in string_list:
                if item not in packer_lib_used_list:
                    packer_lib_used_list.append(item)
                else:
                    pass
        else:
            pass
        
    return number_of_samples_packer_lib_used, packer_lib_used_list, number_of_lib_used_by_sampples


def virus_total_report_assessment(dataset):
    ''' Explore the percentage of VT engines that label the ransomware samples as safe '''
    
    labeled_safe_percentage = []
    for sample in dataset:
        labeled_safe_percentage.append(dataset[sample]['vt_analyzer_report']['number_of_engines_detected_safe'] / dataset[sample]['vt_analyzer_report']['total_number_of_engines'] * 100)
        
    return labeled_safe_percentage


def compilation_time_stamp(dataset):
    ''' Explore the year each ransomware sample was created '''
    year_list = []
    
    # "time_date_stamp":"Mon May 27 16:35:27 2013 UTC"
    try:
        for sample in dataset:
            time_str = dataset[sample]['pe_static_analyzer']['time_date_stamp']
            time_str = time_str.split(' ')[-2]
            year_list.append(int(time_str))
    except:
        pass
    
    return year_list


def code_and_data_info(dataset):
    ''' Explore the Optional header section to find out the following distribution:
        - Size of the code (text) section [size_of_code]
        - Amount of contiguous memory that must be reserved to load the binary into memory [OPTIONAL_HEADER.SizeOfImage]
        - Size of the initialized data section [SizeOfInitializedData] '''
    
    size_of_code_list = []
    size_of_image_list = []
    size_of_inialized_data = []
    
    
    for sample in dataset:
        try:
           size_of_code_list.append(dataset[sample]['pe_static_analyzer']['size_of_code'])
        except:
            print("Size of the code (text) section is not found")
        
        try:
            size_of_image_list.append(dataset[sample]['pe_static_analyzer']['size_of_image'])
        except:
            print("Size of the image is not found")
        
        try:
            size_of_inialized_data.append(dataset[sample]['pe_static_analyzer']['size_of_initialized_data'])
        except:
            print("Size of the initialized data is not found")

    return size_of_code_list, size_of_image_list, size_of_inialized_data


def pe_sections_info(dataset):
    ''' Explore the information provided in the pe sections' names and one important detail, which
    is if the virtual size more than the size of the raw data. '''
    
    section_names_list = []
    virtual_size_gt_raw_data_frequency = 0
    virtual_size_gt_raw_data_frequency_samples = 0
    virtual_size_gt_raw_data_flag = 0
    
    for sample in dataset:
        try:
            for pe_sections in dataset[sample]['pe_static_analyzer']['sections_info']:
                if(dataset[sample]['pe_static_analyzer']['sections_info'][pe_sections]['section_name'] not in section_names_list):
                    section_names_list.append(dataset[sample]['pe_static_analyzer']['sections_info'][pe_sections]['section_name'])
                
                virtual_size = dataset[sample]['pe_static_analyzer']['sections_info'][pe_sections]['virtual_size']
                size_of_raw_data = dataset[sample]['pe_static_analyzer']['sections_info'][pe_sections]['size_of_raw_data']
                if virtual_size > size_of_raw_data:
                    virtual_size_gt_raw_data_frequency += 1
                    virtual_size_gt_raw_data_flag = 1
            if virtual_size_gt_raw_data_flag:
                virtual_size_gt_raw_data_frequency_samples += 1
            virtual_size_gt_raw_data_flag = 0
            
        except:
            print("sections info is not found")
            pass

    # Reference: https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
    popular_section_names = ['.00cfg', '.AAWEBS', '.apiset', '.arch', '.autoload_text',
    '.bindat', '.bootdat', '.bss', '.BSS', '.buildid', '.CLR_UEF', '.code',
    '.cormeta', '.complua', '.CRT', '.cygwin_dll_common', '.data', '.DATA',
    '.data1', '.data2', '.data3', '.debug', '.debug$F', '.debug$P', '.debug$S',
    '.debug$T', '.drectve', '.didat', '.didata', '.edata', '.eh_fram',
    '.export', '.fasm', '.flat', '.gfids', '.giats', '.gljmp', '.glue_7t', '.glue_7',
    '.idata', '.idlsym', '.impdata', '.import', '.itext', '.ndata', '.orpc',
    '.pdata', '.rdata', '.reloc', '.rodata', '.rsrc', '.sbss', '.script',
    '.shared', '.sdata', '.srdata', '.stab', '.stabstr', '.sxdata',
    '.text', '.text0', '.text1', '.text2', '.text3', '.textbss', '.tls',
    '.tls$', '.udata', '.vsdata', '.xdata', '.wixburn', '.wpp_sf',
    'BSS', 'CODE', 'DATA', 'DGROUP', 'edata', 'idata', 'INIT', 'minATL',
    'PAGE', 'rdata', 'sdata', 'shared', 'Shared', 'testdata', 'text']

    for section_names in section_names_list:
        if section_names.strip() in popular_section_names:
            section_names_list.remove(section_names)

    return section_names_list, virtual_size_gt_raw_data_frequency, virtual_size_gt_raw_data_frequency_samples


def import_address_tables_info(dataset):
    ''' Explore the distribution of the import table tables in terms of the unique number
    of libraries and imports used '''
    
    unique_libraries_used = []
    unique_imports_used = []
    
    for sample in dataset:
        try:
            for libraries_used in dataset[sample]['pe_static_analyzer']['libraries_list']:
                if (libraries_used in unique_libraries_used):
                    continue
                unique_libraries_used.append(libraries_used) 
        except:
            pass
        
        try:
            for imports_used in dataset[sample]['pe_static_analyzer']['imports_list']:
                if (imports_used in unique_imports_used):
                    continue
                unique_imports_used.append(imports_used)
        except:
            pass
            
    return unique_libraries_used, unique_imports_used


if __name__ == '__main__':
    ''' Driver program '''
    dataset = pd.read_pickle('data/pe_vt_info_dataset.pkl')
    
    print(sample_structure(dataset))
    
    number_of_samples_crypto_lib_used, crypto_lib_used_list, number_of_lib_used_by_sampples = crypto_libraries_used(dataset)
    print(np.median(number_of_lib_used_by_sampples))
    print(np.mean(number_of_lib_used_by_sampples))
    print(np.min(number_of_lib_used_by_sampples))
    print(np.max(number_of_lib_used_by_sampples))
        
    number_of_samples_packer_lib_used, packer_lib_used_list, number_of_lib_used_by_sampples = packer_libraries_used(dataset)
    print(np.median(number_of_lib_used_by_sampples))
    print(np.mean(number_of_lib_used_by_sampples))
    print(np.min(number_of_lib_used_by_sampples))
    print(np.max(number_of_lib_used_by_sampples))
    
    labeled_safe_percentage = virus_total_report_assessment(dataset)
    print(np.median(labeled_safe_percentage))
    print(np.mean(labeled_safe_percentage))
    print(np.min(labeled_safe_percentage))
    print(np.max(labeled_safe_percentage))
    
    try:
        for sample in dataset:
            print(len(dataset[sample]['pe_static_analyzer']['exports_list']))
    except:
        pass
    
    file_compilation_year_list = compilation_time_stamp(dataset)
    print(np.median(file_compilation_year_list))
    print(np.mean(file_compilation_year_list))
    print(np.min(file_compilation_year_list))
    print(np.max(file_compilation_year_list))
    
    size_of_code_list, size_of_image_list, size_of_inialized_data = code_and_data_info(dataset)
    print(np.median(size_of_code_list))
    print(np.mean(size_of_code_list))
    print(np.min(size_of_code_list))
    print(np.max(size_of_code_list))
    
    print(np.median(size_of_image_list))
    print(np.mean(size_of_image_list))
    print(np.min(size_of_image_list))
    print(np.max(size_of_image_list))
    
    print(np.median(size_of_inialized_data))
    print(np.mean(size_of_inialized_data))
    print(np.min(size_of_inialized_data))
    print(np.max(size_of_inialized_data))
    
    section_names_list, virtual_size_gt_raw_data_frequency, virtual_size_gt_raw_data_frequency_samples = pe_sections_info(dataset)
    
    unique_libraries_used, unique_imports_used = import_address_tables_info(dataset)