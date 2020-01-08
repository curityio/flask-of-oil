from distutils.core import setup

setup(
    name='Flask-of-Oil',
    packages=['flask_of_oil'],
    version='1.0.0',
    license='Apache Software License',
    description='Flask OAuth Filter - an OAuth Interceptor Logic',
    long_description=open('README.rst').read(),
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
        'Development Status :: 5 - Production/Stable',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Topic :: Security'
    ],
)
