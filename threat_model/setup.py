from setuptools import setup, find_packages

setup(
    name="threat_summarizer",
    version="1.0.0",
    description="AI-powered Threat Summary Generator using local LLMs via Ollama",
    author="Your Name",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests"
    ],
    entry_points={
        "console_scripts": [
            "threat-summarize=threat_summarizer.main:cli_entry",
        ],
    },
)
