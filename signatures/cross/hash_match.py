from lib.cuckoo.common.abstracts import Signature

class HashMatch(Signature):
    name = "hash_match"
    description = "the target's hash value matches the IoC "
    severity = 10
    categories = ["esun_ioc"]
    authors = ["22326"]
    minium = "2.0"

    def on_complete(self):
        return True