#!/usr/bin/env python

import os

# from app import app
# from app import db

from app import *

# ----------------------------------------
#  launch
# ----------------------------------------

if __name__ == "__main__":
    db.create_all()
    app.run(host='0.0.0.0', port=8000, debug=True)



