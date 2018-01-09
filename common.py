
from   models import Object
from   init    import db
import time,datetime

class STATUS:
    
    OK            = 0 # all ok
    ERR           = 1 # generic err 
    ERR_AUTH      = 2 # auth err
    ERR_INPUT     = 3 # wrong input 
    UNKNOWN_USER  = 4
    

class USER_STATE:
    
    NOT_INIT   = 0 # registerred but not confirmed
    ACTIVE     = 1 # active user
    INACTIVE   = 2 # fraud detected 

class USER_ROLES:
    
    USER            = 1 # normal user
    ADMIN           = 2 # admin 
    GROUP_MANAGER   = 3 # group manager


# Class for constants & data types ..
class COMMON:

    # mirror with jScript -> app.js
    SECTION_SETTINGS = 'SECTION_SETTINGS'
    OPER_UPDATE_NAME = 'UPDATE_NAME'
    OPER_UPDATE_USERNAME = 'UPDATE_USERNAME'
    OPER_UPDATE_COMPANY = 'UPDATE_COMPANY'
    OPER_UPDATE_EMAIL = 'UPDATE_EMAIL'
    OPER_UPDATE_PASS = 'UPDATE_PASS'
    
    SECTION_DASHBOARD = 'SECTION_DASHBOARD'
    OPER_DASHBOARD_PLANT_OPERATIONS = 'DASHBOARD_PLANT_OPERATIONS'

    # data types maped over object table
    TYPE_ASSET = 'ASSET'
    TYPE_USER_ASSET = 'USER_ASSET'


class Asset(Object):

    def copy(self, src):

        # init from base class or another assignment
        if isinstance(src, Object) or isinstance(src, Asset):

            # copy id
            self.id   = src.id

            # copy indexes 
            self.idx1  = src.idx1 # integer
            self.idx2  = src.idx2 # integer
            self.idx3  = src.idx3 # integer
            self.idx4  = src.idx4 # integer
            self.idx5  = src.idx5 # integer

            self.idx6  = src.idx6 # float
            self.idx7  = src.idx7 # float
            self.idx8  = src.idx8 # float
            
            # copy keys 
            self.key1  = src.key1
            self.key2  = src.key2
            self.key3  = src.key3
            self.key4  = src.key4
            self.key5  = src.key5
            self.key6  = src.key6
            self.key7  = src.key7
            self.key8  = src.key8
            self.key9  = src.key9
            self.key10 = src.key10

            # copy data 
            self.data1  = src.data1
            self.data2  = src.data2
            self.data3  = src.data3
            self.data4  = src.data4
            self.data5  = src.data5
            self.data6  = src.data6
            self.data7  = src.data7
            self.data8  = src.data8
            self.data9  = src.data9
            self.data10 = src.data10

            # copy rawdata 
            self.rawdata = src.rawdata

            # copy context info 
            self.counter    = src.counter
            self.expiry     = src.expiry
            self.lastupdate = src.lastupdate
            
            return self 

        else:
            return None

    def __init__(self):

        self.id         = None

        self.idx1       = 0 # gcode    (integer)
        self.idx2       = 0 # ocode    (integer)
        self.idx3       = 0 # untyronl (integer) 
        self.idx4       = 0 # not used
        self.idx5       = 0 # not used

        self.idx6       = 0 # npc (float)
        self.idx7       = 0 # not used
        self.idx8       = 0 # not used

        self.key1       = COMMON.TYPE_ASSET
        self.key2       = '' # state 
        self.key3       = '' # not used
        self.key4       = '' # not used
    
        self.data1      = '' # pname
        self.data2      = '' # uid
        self.data3      = '' # prmvr
        self.data4      = '' # fuel
        self.data5      = '' # not used
        self.rawdata    = ''

        self.counter    = 0

    #####################################################
    #
    # KEYS .. used to select information
    #
    #####################################################
    
    # check the type / kind 
    def kind(self):
        return self.key1

    # gcode getter     
    def gcode(self):
        return self.idx1
    
    # gcode setter     
    def set_gcode(self, input ):
        self.idx1 = input

    # ocode getter     
    def ocode(self):
        return self.idx2
    
    # ocode setter     
    def set_ocode(self, input ):
        self.idx3 = input

    # untyronl getter     
    def untyronl(self):
        return self.idx2
    
    # untyronl setter     
    def set_untyronl(self, input ):
        self.idx3 = input

    # state getter     
    def state(self):
        return self.key2
    
    # state setter     
    def set_state(self, input ):
        self.key2 = input

    # npc getter     
    def npc(self):
        return self.idx6
    
    # npc setter     
    def set_npc(self, input ):
        self.idx6 = input

    #####################################################
    #
    # DATA .. used to store information
    #
    #####################################################

    # pname getter
    def pname(self):
        return self.data1

    # pname setter
    def set_pname(self, input ):
        self.data1 = input
    
    # uid getter
    def uid(self):
        return self.data2

    # uid setter
    def set_uid(self, input ):
        self.data2 = input    

    # prmv getter
    def prmv(self):
        return self.data3

    # prmv setter
    def set_prmv(self, input ):
        self.data3 = input    

    # fuel getter
    def fuel(self):
        return self.data4

    # fuel setter
    def set_fuel(self, input ):
        self.data4 = input    

    #####################################################
    #
    # Context helpers .. updated automatically 
    #
    #####################################################

    def get_created(self):
        return self.lastupdate

    def set_created(self):
        self.lastupdate = int(time.time())

    def reset_counter(self):
        self.counter = 0

    #####################################################
    #
    # Context helpers .. updated automatically 
    #
    #####################################################

    def save(self):

        # if object has no id, means it was created by Asset() constructor
        if not self.id:

            # Assign the first free one 
            self.id = Object.query.order_by('id desc').limit(1)[0].id + 1

            # Inject self into db session    
            db.session.add ( self )                    

        try:
            # commit change and save the object
            db.session.commit( )            

            return True

        except:

            return False
