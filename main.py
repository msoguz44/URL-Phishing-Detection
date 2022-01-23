from tkinter import *
from tkinter import ttk
import tkinter.filedialog
from PIL import ImageTk
from PIL import Image
from tkinter import messagebox
from io import BytesIO
import  os
import string
from random import *
import pandas as pd
from datetime import datetime
import whois as who
import OpenSSL
import ssl, socket
import datetime, smtplib
import argparse
from selenium import webdriver
import requests
import sys
from bs4 import BeautifulSoup
import re
import validators
import pandas as pd
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from detection import *
from rulers import *

class UrlDetection:

    art ='''¯\_(ツ)_/¯'''
    art2 = '''
#     # ######  #          ######                                                   
#     # #     # #          #     # ###### ##### ######  ####  ##### #  ####  #    # 
#     # #     # #          #     # #        #   #      #    #   #   # #    # ##   # 
#     # ######  #          #     # #####    #   #####  #        #   # #    # # #  # 
#     # #   #   #          #     # #        #   #      #        #   # #    # #  # # 
#     # #    #  #          #     # #        #   #      #    #   #   # #    # #   ## 
 #####  #     # #######    ######  ######   #   ######  ####    #   #  ####  #    # '''
    output_image_size = 0


    def home(self,frame):
            frame.destroy()
            self.main(root)

    def save(url):
        frame2 = Frame(root)
        l1 = Label(frame2, text='That URL {} is phising attack, do you want add to the black list?'.format(url))
        l1.config(font=('courier',18))
        l1.grid()
        bws_button = Button(d_f2, text='Evet', command=lambda :self.Yes(self,url))
        bws_button.config(font=('courier',18))
        bws_button.grid()
        back_button = Button(d_f2, text='Hayır', command=lambda : UrlDetection.home(self,frame2))
        back_button.config(font=('courier',18))
        back_button.grid(pady=15)
        back_button.grid()
        d_f2.grid()
        
    def yes(self,url):
        url_list=open("/Users/msoguz/Desktop/bitirme/urllist.txt","w")
        url_list.write(url)
        UrlDetection.home(self,frame2)
    

    def search(url):
        url="http://panel.dirilisenerji.com/login"
        newurl=FindDomainName(url)
        list_detect=[ControlIp(newurl),
                ControlNumberCharacters(newurl),
                ControlShortDomain(newurl),
                ControlAtSign(url),
                ControlDoubleSlash(url),
                ControlHyphen(newurl),
                ControlSubDomain(url),
                ControlCertificate(url),
                ControlCertificate(url),
                ControlRegistrationAge(url),
                Favicon(url),
                PortControl(url),
                Httptoken(url),
                Media(url),
                Aherf(url),
                Tags(url),
                Mail(url),
                Controlhostname(url),
                redirect(url),
                onmouseover(url),
                0,0,0,
                ControlDomainAge(url),
                Alexa(url),0,0,
                Ireport(newurl)
                ]
        result=detect(list_detect)
        url_list=open("/Users/msoguz/Desktop/bitirme/urllist.txt","w")
        urll=url_list.read()
        if result<1:
            if url not in urll:
                save(url)
        print(result)
        return result       
    
    def main(self,root):
        root.title('URL DETECTION')
        root.geometry('800x600')
        root.config(bg="BLACK")
        root.resizable(width =False, height=False)
        f = Frame(root, bg="BLACK")

        title = Label(f,text='Url Phishing Detection', fg="BLUE", bg="BLACK")
        title.config(font=('courier',33))
        title.grid(pady=10)

        ascii_art = Label(f,text=self.art, fg="BLUE", bg="BLACK")
        # ascii_art.config(font=('MingLiU-ExtB',50))
        ascii_art.config(font=('courier',60))

        ascii_art2 = Label(f,text=self.art2, fg="BLUE", bg="BLACK")
        # ascii_art.config(font=('MingLiU-ExtB',50))
        ascii_art2.config(font=('courier',12,'bold'))
        title1 = Label(f,text='Please input url adress for Url Phishing Detection', fg="BLUE", bg="BLACK")
        title1.config(font=('courier',20))
        title1.grid(pady=10)
        text_area = Text(f, width=90, height=5, fg="BLUE", bg="BLACK")
        text_area.grid()
        url=text_area.get("1.0","end-1c")
        b_search = Button(f,text="Search",command=lambda: search(url), padx=14)
        b_search.config(font=('courier',14))
        
        try:
            if search(url)>0:
                result_="Pshising !!!"
            elif search(url)<0:
                result_="Clean"
        except :
            result_=" "
        
        result=Label(f,text=result_)
        
        root.grid_rowconfigure(1, weight=1)
        root.grid_columnconfigure(0, weight=1)
        
        f.grid()
        title.grid(row=1)
        ascii_art.grid(row=2,pady=10)
        ascii_art2.grid(row=3,pady=5)
        title1.grid(row=4)
        text_area.grid(row=5)
        b_search.grid(row=6)
        result.grid(row=7)
        
 
root = Tk()

o = UrlDetection()
o.main(root)

root.mainloop()
