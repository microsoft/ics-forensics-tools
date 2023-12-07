import os
import setuptools


with open('requirements.txt') as f:
    requirements = f.read().splitlines()


class CleanCommand(setuptools.Command):
    """Custom clean command to tidy up the project root."""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


setuptools.setup(
    name="forensic",
    version="0.0.6",
    author_email="yshitrit@microsoft.com",
    description="ICS forensics tools",
    long_description="",
    long_description_content_type="text/markdown",
    python_requires=">=3.9.0",
    cmdclass={
        'clean': CleanCommand,
    },
    package_dir={'': 'src'},
    include_package_data=True,
    package_data={'': ['*.json', '**/*.csv', '**/*.json']},
    packages=setuptools.find_packages(where="src"),
    install_requires=requirements,
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        'Topic :: Software Development :: Libraries'
    ],
)
