from setuptools import setup, find_packages

setup(
    name="xss-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "beautifulsoup4",
        "colorama",
        "tqdm",
        "urllib3",
        "html5lib",  # Added for better HTML parsing
        "lxml",      # Added for better HTML parsing
    ],
    entry_points={
        "console_scripts": [
            "xss-scanner=src.main:main",
        ],
    },
    author="LIMBO-2018",
    author_email="kaungsettwin999@gmail.com",
    description="A professional XSS scanning tool for web security testing",
    keywords="security, xss, scanner, web, hacking",
    python_requires=">=3.7",
)

