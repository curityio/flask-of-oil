from distutils.core import setup

setup(
    name='Flask-of-Oil',
    packages=['flask_of_oil'],
    version='0.0.1',
    license='Apache license 2.0',
    description='Flask OAuth Filter - an OAuth Interceptor Logic',
    author='Curity AB',
    author_email='info@curity.io',
    url='https://github.com/curity/flask-of-oil',
    keywords=['oauth', 'flask', 'introspection', 'access token', 'jwt', 'opaque'],
    install_requires=[
        'requests',
        'cachelib',
        'Flask',
        'pyjwkest'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache license 2.0',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
)
