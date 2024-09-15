from setuptools import setup

setup(
    name="kerberos-keygen",
    version="0.1",
    author="kozmer",
    author_email="kozmer@protonmail.com",
    description="A tool to calculate Kerberos keys for AD accounts",
    py_modules=["kerberos_keygen"],  # This refers to kerberos_keygen.py
    install_requires=[
        "impacket",
        "pycryptodome",
    ],
    entry_points={
        'console_scripts': [
            'kerberos-keygen=kerberos_keygen:main',  # Point to kerberos_keygen.py's main() function
        ],
    },
    python_requires='>=3.10',
)

