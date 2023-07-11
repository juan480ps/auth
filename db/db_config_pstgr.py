postgresql = {  'host': 'localhost',
                'user': 'postgres',
                'passwd': 'postgres',
                'db': 'jdewsring01'}

postgresqlConfig = "postgresql://{}:{}@{}/{}".format(postgresql['user'], postgresql['passwd'], postgresql['host'], postgresql['db'])