# setup.py — setuptools config
# Run: pip install -e .
# Then use: shield setup / shield login

from setuptools import setup, find_packages

setup(
    name="shield-vault",
    version="1.0.0",
    description="A CLI password manager",
    py_modules=["shield", "engine", "authservice", "entity", "db"],
    entry_points={
        "console_scripts": [
            "shield=shield:main",
        ],
    },
    python_requires=">=3.10",
)
