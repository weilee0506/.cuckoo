from lib.cuckoo.common.abstracts import Signature
import logging
import pandas as pd

class HashMatch(Signature):
    name = "hash_match"
    description = "the target's hash value matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    families = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    # read ioc_hash.csv
    ioc_hash_file = "/home/cuckoo/.cuckoo/ioc_file/ioc_hash.csv"
    ioc_hash_data = pd.read_csv(ioc_hash_file, low_memory = False)
    ioc_hash_df = pd.DataFrame(ioc_hash_data)

    # add test hash in ioc_hash_df
    test_hash_df = pd.DataFrame({
        "IoCType":["Hash"],
        "InfoSource":["F-ISAC"],
        "IoCCategory":["C2C"],
        "MD5":["5e3a80524bb7d23222a489aee2b8c340"],
        "SHA1":["eac6a6586c3d731c364454d8234039fef78901dc"],
        "SHA256":["69f3ad423309e22491adbb317a7b12ccebe03f3d233a0ff1e45147199ceffc3f"]
        })
    ioc_hash_df = pd.concat([ioc_hash_df,test_hash_df], ignore_index = True, axis = 0)

    # grab specific column
    ioc_hash_df_final = ioc_hash_df[["IoCType","InfoSource","IoCCategory","MD5","SHA1","SHA256"]]

    # replace nan with "null"
    ioc_hash_df_final = ioc_hash_df_final.fillna("null")

    # turn ioc_hash_df into list
    ioc_hash_list = ioc_hash_df_final.values.tolist()

    # logging.warning(ioc_hash_list) 
    # logging.warning("show after init")

    def on_complete(self):    
        # logging.warning(self.ioc_hash_list)        
        for row in self.ioc_hash_list:
            # logging.warning(row[3])
            if self.check_hash(pattern=row[3]):
                # logging.warning("esunioc")
                self.mark_esunioc(category = row[2], infoSource = row[1], ioc = row[3])

        return self.has_marks()
        