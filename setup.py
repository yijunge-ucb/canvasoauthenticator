from setuptools import setup, find_packages

setup(
    name='jupyterhub-canvasoauthenticator',
    version='0.1',
    python_requires='>=3.5',
    packages=find_packages(),
    install_requires=[
        'oauthenticator==17.1.0',
        'aiohttp'
    ]
)
