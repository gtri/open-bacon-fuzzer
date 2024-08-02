from flask import Flask

from baconfuzzer.fuzzer.fuzzer import Fuzzer


class BaconfuzzerApp(Flask):
    def __init__(self, name):
        super().__init__(import_name=name)
        self.fuzzer = Fuzzer()
        self.job_data = {}


app = BaconfuzzerApp(__name__)
