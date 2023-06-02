class extractor:
    '''extract zipped firmware'''
    def __init__(self, filename):
        self.filename = filename
        self.extractor = None
        print("extractor init")
        # self.extractor = self.get_extractor()
        # self.extractor.extractall()