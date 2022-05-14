from lib.cuckoo.common.abstracts import Signature

class HashMatch(Signature):
    name = "domain_match"
    description = "the targets domain matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    def on_complete(self):
        return True