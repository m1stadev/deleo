from importlib.metadata import version

__version__ = version(__package__)
print(f'pyfuturerestore version: {__version__}')
pymobiledevice3_version = version('pymobiledevice3')
print(f'pymobiledevice3 version: {pymobiledevice3_version}')