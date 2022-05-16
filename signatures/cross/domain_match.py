from lib.cuckoo.common.abstracts import Signature
import logging
import pandas as pd

class DomainMatch(Signature):
    name = "domain_match"
    description = "the target's related domain matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    # read ioc_domain.csv
    ioc_domain_file = "/home/cuckoo/.cuckoo/ioc_file/ioc_domain.csv"
    ioc_domain_data = pd.read_csv(ioc_domain_file, low_memory = False)
    ioc_domain_df = pd.DataFrame(ioc_domain_data)

    # add test domain in ioc_domain_df
    test_domain_df = pd.DataFrame({"IoCType":["Domain"],"InfoSource":["F-ISAC"],"IoCCategory":["C2C"],"IoCValue":["www.facebook.com"]})
    ioc_domain_df = pd.concat([ioc_domain_df,test_domain_df], ignore_index = True, axis = 0)

    # turn ioc_domain_df into list
    ioc_domain_list = ioc_domain_df.values.tolist()

    

    def on_complete(self):    
        logging.warning(self.ioc_domain_list)        
        for row in self.ioc_domain_list:
            if self.check_domain(pattern=row[3]):
                logging.warning("esunioc")
                self.mark_esunioc(category = row[1], infoSource = row[0], ioc = row[3])

        return self.has_marks()