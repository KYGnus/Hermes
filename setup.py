from setuptools import setup, find_packages

# Read requirements.txt
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

setup(
    name='Hermes',
    version='1.0',
    packages=find_packages(where='app'),
    package_dir={'': 'app'},
    include_package_data=True,
    install_requires=requirements,  # Load all packages
    entry_points={
        'console_scripts': [
            'hermes = main_linux:main',
        ],
    },
)

