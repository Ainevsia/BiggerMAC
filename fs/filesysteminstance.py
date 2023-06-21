from android.init import AndroidInit
from se.sepolicygraph import PolicyGraph


class FileSystemInstance:
    def __init__(self, sepol: PolicyGraph, init: AndroidInit):
        self.sepol = sepol
        self.init = init


        self.file_mapping = {}

        # Mixed instantiation
        self.subjects = {}
        self.subject_groups = {}
        self.domain_attributes = []
        self.objects = {}

        # Fully instantiated graph
        self.processes = {}

    def instantiate(self):
        """
        Recreate a running system's state from a combination of MAC and DAC policies.
            * Inflate objects into subjects (processes) if they can be executed
            * Instantiate files, IPC primitives,
            * Link subjects together through objects

        Namespaces:
         - subject
         - process
         - object
            * file
            * ipc
            * socket
        """
        




        pass


