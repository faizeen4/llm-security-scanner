from setuptools import find_packages, setup

setup(
    name="llm-security-scanner",
    version="0.1.0",
    description="Automated red-teaming CLI for OpenAI-compatible chat models.",
    packages=find_packages(),
    install_requires=["openai>=1.30.0"],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "llm-scan=llm_security_scanner.cli:main",
        ],
    },
)
