from lib.cuckoo.common.abstracts import Signature

class IPMatch(Signature):
    name = "ip_match"
    description = "the target's related ip matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    def on_complete(self):
        return True