from setuptools import setup


setup(
    name='nfagent',
    version='0.0.1',
    packages=['.'],
    install_requires=[r.strip() for r in open("requirements.txt").readlines()],
    url='',
    license='',
    author='shu1r0',
    author_email='',
    description='SRv6 PTF gRPC Lib and Netfilter queue agent'
)
