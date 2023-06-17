from typing import List
from android.property import AndroidPropertyList
from fs.filesystempolicy import FileSystemPolicy


class AndroidSecurityPolicy:
    def __init__(self, combined_fs: FileSystemPolicy, properties: AndroidPropertyList):
        self.combined_fs = combined_fs
        self.properties = properties
    
    def get_android_version(self) -> List[int]:
        android_version: List[int] = list(map(int, self.get_properties()['properties']['android_version'].split('.')))

        if len(android_version) < 1 or len(android_version) > 3:
            raise ValueError("Android version %s is malformed" % str(android_version))

        # pad out the version tokens if they dont exist
        android_version = android_version + [0]*(3-len(android_version))
        return android_version


    def get_properties(self):
        '''获取一个综合的信息'''
        props = self.properties
        android_version = props['ro.build.version.release']
        build_id = props['ro.build.id']
        try:
            brand = props['ro.product.brand']
        except:
            brand = "unknown"

        # Some samsung/lineage prop files don't have a model listed...
        model = props.get_multi_default(
                ['ro.product.model', 'ro.product.base_model'], default="UNKNOWN")

        product_name = props.get_multi_default(['ro.product.name'], default="UNKNOWN")
        product_device = props.get_multi_default(['ro.product.device'],
                                                 default="UNKNOWN")

        interesting_properties = {
            "brand": brand,
            "model": model,
            "build_id": build_id,
            "android_version": android_version,
            "product_name": product_name,
            "product_device": product_device
        }

        summary_string = "%s - %s (BUILD_ID %s, Android %s)" % \
            (brand, model, build_id, android_version)

        image_data = {
            "summary": summary_string,
            "properties": interesting_properties,
        }

        return image_data