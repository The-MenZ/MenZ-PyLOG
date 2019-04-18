# MenZ-PyLOG

test create(You do not run)
'''
$ sls create -t aws-python3 -p MenZ-PyLOG
'''

first
'''
$ sls plugin install -n serverless-python-requirements
$ sls plugin install -n serverless-wsgi
'''

test
'''
$ sls invoke -f hello
'''

deploy
'''
$ sls deploy
'''
