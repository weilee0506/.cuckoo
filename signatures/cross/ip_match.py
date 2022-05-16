from lib.cuckoo.common.abstracts import Signature
import logging
import pandas as pd

class IPMatch(Signature):
    name = "ip_match"
    description = "the target's related ip matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    # read ioc_ip.csv
    ioc_ip_file = "/home/cuckoo/.cuckoo/ioc_file/ioc_ip.csv"
    ioc_ip_data = pd.read_csv(ioc_ip_file, low_memory = False)
    ioc_ip_df = pd.DataFrame(ioc_ip_data)

    # add test ip in ioc_ip_df
    test_ip_df = pd.DataFrame({"IoCType":["IP"],"InfoSource":["F-ISAC"],"IoCCategory":["Malware"],"IoCValue":["8.8.8.8"]})
    ioc_ip_df = pd.concat([ioc_ip_df,test_ip_df], ignore_index = True, axis = 0)

    # turn ioc_ip_df into list
    ioc_ip_list = ioc_ip_df.values.tolist()

    # ioc_ip_list_test = ioc_ip_list

    

    # add ioc_ip into ioc_ip_list
    # ioc_ip_list = []
    # for i in range(len(ioc_ip_df)):
    #     ioc_ip_list.append(ioc_ip_df.loc[i,"IoCValue"])

    
    def on_complete(self):    
        # logging.warning(self.ioc_ip_list)        
        for row in self.ioc_ip_list:
            if self.check_ip(pattern=row[3]):
                logging.warning("esunioc")
                self.mark_esunioc(category = row[1], infoSource = row[0], ioc = row[3])

        return self.has_marks()


    # def on_complete(self):            
    #     for ipaddr in self.ioc_ip_list:
    #         if self.check_ip(pattern=ipaddr):
    #             self.mark_ioc("ioc_ip", ipaddr)

    #     return self.has_marks()
        