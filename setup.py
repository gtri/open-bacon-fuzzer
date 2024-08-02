from setuptools import setup

setup(
    name="baconfuzzer",
    version="0.1",
    packages=["baconfuzzer"],
    install_requires=["flask", "fluent-validator", "scapy", "pyserial", "requests"],
    python_requires=">=3.7",
    entry_points="""
    [console_scripts]
    baconfuzz=baconfuzzer.bacon_fuzzer_webapp:main
    """,
)
