from setuptools import setup, find_packages

setup(
    name='frida-utils',
    version='0.1.0',
    packages=find_packages(),
    description='Utils for Frida.',
    package_data={'frida_enumerate': ['hooks/*']},
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Topic :: Software Development :: Automation Tools",
        "Programming Language :: Python :: 3.8"
    ],
    python_requires='>=3.7',
    install_requires=[
        "colorama >= 0.4.4",
        "colorlog >= 5.0.1",
        "frida >= 14.2.18 "
    ],
    entry_points={
            "console_scripts": [
                "frida-enumerate=frida_enumerate:start_cmd"
            ],
        }
)