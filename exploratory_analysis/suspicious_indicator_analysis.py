#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


# Import libraries
import pandas as pd
from nltk.corpus import words
import re
from knowledge_base.suspicious_imports import SuspiciousImports


def compute_item_counts(data) -> dict:
    ''' The purpose of this method is to iterate through the nested list type
    of data and scan each item in the record to count the frequency of each
    item appeared through the given data.
    
    The method will return a dictionary where the keys will be the name
    of the items and the values will be its counts respectively. '''
    
    # This dictionary will hold the details
    items_count = {}
    # Iterate through all the records in the given list
    for i in range(len(data)):
        # Convert the string into lower case to not include the reappeared item
        verbose = data[i]  # verbose is a list of entries
        for item in verbose:
            item = str(item).lower()
            if (item in items_count):   # Check if it already exists
                items_count[item] += 1
            else:                       # New entry
                items_count[item] = 1
            
    return items_count


def derive_suspicious_unique_import_list(dataset) -> list:
    ''' This utility method will iterate throgh all the unique items in all the
    appeared samples' import list. Then, based on the knowledge base given to
    it from the SuspiciousImports class, it will return the unique list. '''
    
    # Compute the unique imports in the appeared dataset records
    items_count = compute_item_counts(dataset["imports"].tolist())
    
    # Get the Suspicious Imports from the knowledge base
    suspicious_imports = SuspiciousImports().get_suspicious_imports()
    
    # Retrieve the unique appeared imports
    verbose = []
    for keys in items_count:
        verbose.append(keys)
    
    # This list will store the suspicious unique imports
    suspicious_verbose = []
    # Scan each item in the unique imports to match it with the knowledge
    # base obtained list as singnature
    for item in verbose:
        for suspicious_import in suspicious_imports:
            if(suspicious_import in item):
                # Matched, add it to the list and break from further iterations
                suspicious_verbose.append(item)
                break
            else:
                # Not matched, scan next suspicious signature
                pass
    
    return suspicious_verbose


def find_english_words(corpus):
    
    temp = set()
    from nltk.tokenize import WordPunctTokenizer
    for item in corpus:
        flag = 0
        tokenizer = WordPunctTokenizer()
        tokens = tokenizer.tokenize(item)
        for token in tokens:
            if(flag):
                break
            #Split when camel case item is found
            split_tokens = re.sub('([A-Z][a-z]+)', r' \1', re.sub('([A-Z]+)', r' \1', token)).split()
            for split_token in split_tokens:
                split_token = split_token.lower()
                if len(split_token) > 2:
                    if split_token in words.words():
                        temp.add(item)
                        flag = 1
                        break
    return temp


if __name__ == '__main__':
    ''' Driver program '''
    
    dataset = pd.read_pickle('./data/strings_dump.pkl')
    
    uniques_strings = []
    strings_dump = []
    for i in range(len(dataset)):
        unique_string_items = []
        unique_string_items += list(find_english_words(dataset["static_strings"][i]))
        unique_string_items += list(find_english_words(dataset["decoded_strings"][i]))
        unique_string_items += list(find_english_words(dataset["stack_strings"][i]))
        uniques_strings.append(unique_string_items)
        strings_dump += unique_string_items
        del unique_string_items
        
        
    length = 0
    for i in range(len(dataset)):
        length += len(dataset["static_strings"][i])
        
    
    dataset = pd.read_pickle('./data/feature_dataset_dump.pkl')
    suspicious_imports = derive_suspicious_unique_import_list(dataset)
    
    
    for imports in suspicious_imports:
        if "region" in imports:
            suspicious_imports.remove(imports)
    
    
    suspicious_imports_counts = []
    for i in range(len(dataset)):
        verbose = " ".join(dataset["imports"][i]).lower()
        temp = []
        for suspicious_import in suspicious_imports:
            if(suspicious_import in verbose):
                temp.append(1)
            else:
                temp.append(0)
        
        suspicious_imports_counts.append(temp)
    
    
    suspicious_imports_df = pd.DataFrame(suspicious_imports_counts,
                                         columns = suspicious_imports)
    
    suspicious_imports_df['family_name'] = dataset['family_name']
    suspicious_imports_df.to_pickle('./data/suspicious_imports_sparse.pkl')
    suspicious_imports_df.to_csv('./data/suspicious_imports_sparse.csv')
    
    
    suspicious_imports_signature = SuspiciousImports().get_suspicious_imports()
    suspicious_imports_signature_counts = []
    for i in range(len(dataset)):
        verbose = " ".join(dataset["imports"][i]).lower()
        temp = []
        for imports in suspicious_imports_signature:
            temp.append(len(re.findall(imports, verbose)))
        suspicious_imports_signature_counts.append(temp)
        
    suspicious_imports_signature_df = pd.DataFrame(
                                        suspicious_imports_signature_counts,
                                        columns=suspicious_imports_signature)
    suspicious_imports_signature_df['family_name'] = dataset['family_name']
    suspicious_imports_signature_df.to_csv('./data/suspicious_imports_counts.csv')
    
    
    suspicious_libraries_signature = ["wininet.dll", "wtsapi32.dll",
                                      "psapi.dll", "crypt32.dll", "msi.dll"]
    suspicious_libraries_signature_counts = []
    for i in range(len(dataset)):
        verbose = " ".join(dataset["libraries"][i]).lower()
        temp = []
        for libraries in suspicious_libraries_signature:
            temp.append(len(re.findall(libraries, verbose)))
        suspicious_libraries_signature_counts.append(temp)
        
    suspicious_libraries_signature_df = pd.DataFrame(
                                        suspicious_libraries_signature_counts,
                                        columns=suspicious_libraries_signature)
    suspicious_libraries_signature_df['family_name'] = dataset['family_name']