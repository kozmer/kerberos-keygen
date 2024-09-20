from setuptools import setup

setup(
    name="kerberos-keygen",
    version="1.0",
    description="A tool to calculate Kerberos keys for AD accounts",
    py_modules=["kerberos_keygen"],
    install_requires=[
        "impacket",
        "pycryptodome",
    ],
    entry_points={
        'console_scripts': [
            'kerberos-keygen=kerberos_keygen:main',
        ],
    },
    python_requires='>=3.10',
)
