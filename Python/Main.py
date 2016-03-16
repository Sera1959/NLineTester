#!/usr/bin/env python
# -*- coding: utf-8 -*- 
#Created by Dagger -- https://github.com/DaggerES
   
if __name__ == "__main__":
    import NlineTester
    
    nline = "N: my.server.com 999 username password"
    configKey = "01 02 03 04 05 06 07 08 09 10 11 12 13 14"

    NlineTester.TestNline(nline, configKey)
