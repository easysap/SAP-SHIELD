from setuptools import setup, find_packages

setup(
    name="sap-shield",
    version="0.1.0",
    description="Open-source insider threat detection for SAP systems",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="SAP Shield Contributors",
    license="Apache-2.0",
    url="https://github.com/YOUR_USERNAME/sap-shield",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "pydantic>=2.5.0",
        "pyyaml>=6.0.1",
        "numpy>=1.24.0",
        "pandas>=2.1.0",
        "scikit-learn>=1.3.0",
        "scipy>=1.11.0",
        "sqlalchemy>=2.0.0",
        "aiosqlite>=0.19.0",
        "httpx>=0.25.0",
        "python-dateutil>=2.8.0",
        "loguru>=0.7.0",
        "rich>=13.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.23.0",
            "black>=23.12.0",
            "ruff>=0.1.0",
        ],
        "sap": [
            "pyrfc>=3.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "sapshield=api.app:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
