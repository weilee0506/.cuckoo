from lib.cuckoo.common.abstracts import Signature

class HashMatch(Signature):
    name = "ip_match"
    description = "the targets ip matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    def on_complete(self):
        return True