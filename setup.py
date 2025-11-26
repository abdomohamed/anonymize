"""Setup configuration for PII Anonymization Tool."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pii-anonymize",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool for detecting and anonymizing PII in text files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pii-anonymize",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        "spacy>=3.5.0",
        "faker>=18.0.0",
        "pyyaml>=6.0",
        "regex>=2023.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pii-anonymize=cli:main",
        ],
    },
)
