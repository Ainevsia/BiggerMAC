from typing import Dict, List, Set, Union
import setools
from setools.policyrep import TERule, AVRuleXperm, AVRule, FileNameTERule

from utils.logger import Logger

class SELinuxPolicyGraph(setools.SELinuxPolicy):
    pass
    # 不知道为什么，这里不能写构造函数，否则会报错
    #     super().__init__(policy_file)
    # TypeError: object.__init__() takes exactly one argument (the instance to initialize

    def find_useless_type(self):
        """Find useless types and attributes"""
        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        # base identifiers
        classes: Dict[str, Dict[str, Union[List[str], str]]] = {}
        attributes: Dict[str, List[str]] = {}   # key: attribute name, value: list of types
        commons: Dict[str, List[str]] = {}
        types: Dict[str, List[str]] = {}  
        aliases: Dict[str, bool] = {}
        ta_used: Set[str] = set()

        # define type attributes
        Logger.debug(f'typeattributes len: {len(self.typeattributes())}')
        for attribute_ in cond_sort(self.typeattributes()):
            attributes[str(attribute_)] = []    # empty list
        
        # access vectors
        Logger.debug(f'commons len: {len(self.commons())}')
        for common_ in cond_sort(self.commons()):
            commons[str(common_)] = [str(x) for x in common_.perms]
        
        # security object classes
        Logger.debug(f'classes len: {len(self.classes())}')
        for class_ in cond_sort(self.classes()):
            try:
                parent: str = str(class_.common)
                commons[parent] # just ensure it exists
            except:
                parent = None

            perms: List[str] = [str(x) for x in class_.perms]
            classes[str(class_)] = { "perms" : perms, "parent" : parent }
            # print(classes[str(class_)])
        
        # define types, aliases and attributes
        Logger.debug(f'types len: {len(self.types())}')
        for type_ in cond_sort(self.types()):
            name: str = str(type_)
            # print(type_)
            for attr in type_.attributes():
                # print(attr)
                attributes[str(attr)] += [name]
            # print('1111')
            for alias in type_.aliases():
                # print(alias)
                types[str(alias)] = name
                aliases[str(alias)] = True

            types[name] = [str(x) for x in type_.attributes()]
            # exit(1)
        # exit(1)
        # define type enforcement rules
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))

            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))
            # type_* type enforcement rules
            elif isinstance(terule_, TERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))
                ta_used.add(str(terule_.default))
            elif isinstance(terule_, FileNameTERule):
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))
                ta_used.add(str(terule_.default))

            else:
                print(terule_)
                print(type(terule_))

                from IPython import embed; embed()
                raise RuntimeError("Unhandled TE rule")

        print("--= Useless attributes list =--")
        for k in attributes.keys():
            if k not in ta_used:
                print(k)

        print("--= Useless types list =--")
        for k in types.keys():
            if k not in ta_used:
                is_used_in_attr = False
                for a in types[k]:
                    if a in ta_used:
                        is_used_in_attr = True
                        break
                if is_used_in_attr == False:
                    print(k)

        print("--= done =--")
        return
