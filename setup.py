from setuptools import setup

setup(
    name='Flask-Gallery-API',
    version='1.0.0',
    packages=['database'],
    include_package_data=True,
    zip_safe=False,
    install_requires=['Flask',
                      'requests'
                      'werkzeug',
                      'Pillow',
                      'flask',
                      'flask-login',
                      'flask-sqlalchemy',
                      'flask-jwt-extended',
                      'flask-cors',
                      'mysqlclient',
                      ],
    url='https://github.com/JakeStanger/Flask-Gallery-API',
    license='MIT',
    author='Jake Stanger',
    author_email='mail@jstanger.dev',
    description='Flask Gallery API'
)
