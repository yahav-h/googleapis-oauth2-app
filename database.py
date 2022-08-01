from sqlalchemy import create_engine, Column, Text, BLOB, Integer
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from helpers import getdatatbaseinfo
from contextlib import contextmanager
from os.path import dirname, abspath, join
import sys

db_session = None
if '--debug' in sys.argv and bool(int(sys.argv[sys.argv.index('--debug')+1])):
    debug_db_path = join(dirname(abspath(__file__)), "debug.db")
    engine = create_engine(f"sqlite:///{debug_db_path}", convert_unicode=True)
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
    Base = declarative_base()
    Base.query = db_session.query_property()
else:
    dbinfo = getdatatbaseinfo()
    engine = create_engine(
        f"mysql+pymysql://{dbinfo['user']}:{dbinfo['passwd']}@{dbinfo['host']}:{dbinfo['port']}/{dbinfo['dbname']}",
        pool_pre_ping=True
    )
    db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
    Base = declarative_base()
    Base.query = db_session.query_property()


def init_debug_db():
    Base.metadata.create_all(bind=engine)

@contextmanager
def get_session():
    global db_session
    try:
        yield db_session
    except:
        db_session.rollback()
        raise
    else:
        db_session.commit()
