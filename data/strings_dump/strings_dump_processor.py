#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


# Import libraries
import pandas as pd
import glob
import os

if __name__ == '__main__':
    ''' Driver program '''
    
    strings_dataset = []
    
    current_directory = os.getcwd()
    ransomware_families = [i for i in glob.glob('*')]
    
    for ransomware_family in ransomware_families:
    
        try:
            os.chdir(ransomware_family)
            samples = [i for i in glob.glob('*')]
            
            for sample in samples:
                dataset = pd.read_json(sample)
                temp = []
                # Name of the sample
                temp.append(sample)
                # Static Strings
                temp.append(dataset["strings"]["static_strings"])
                # Decoded Strings
                temp.append(dataset["strings"]["decoded_strings"])
                # Stack strings
                temp.append(dataset["strings"]["stack_strings"])
                # family name
                temp.append(ransomware_family)
                strings_dataset.append(temp)
            os.chdir(current_directory)
        except:
            pass
        
    strings_dataset_df = pd.DataFrame(strings_dataset, columns=["sample",
                                    "static_strings", "decoded_strings",
                                    "stack_strings", "family_name"])
    strings_dataset_df.to_pickle("strings_dump.pkl")
    strings_dataset_df.to_csv("strings_dump.csv")