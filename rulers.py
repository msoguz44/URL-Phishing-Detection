#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Dec  8 11:58:33 2021

@author: msoguz
"""
import pandas as pd
from datetime import *
import whois as who
import OpenSSL
import ssl, socket
import datetime, smtplib
import argparse
from selenium import webdriver
import os
import requests
import sys
from bs4 import BeautifulSoup
import re
import validators
import pandas as pd
import os

def Whois(url):
        return who.whois(url)
    
def FindDomainName(url):
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/domain.csv')
    domain=data["Domain"]
    for x in domain:
        if x in url:
            a=url.split(x)
            b=a[0].split("//")
            if "www" in b[1]:
                c=b[1].split("www.")
                return c[1]
            else: return b[1]
def HtmlSource(url):
    browser=webdriver.Safari()
    # get source code
    browser.get(url)
    html = browser.page_source
    # close web browser
    browser.close()
    if os.path.isfile("/Users/msoguz/Desktop/bitirme/html.txt"):
        os.remove("/Users/msoguz/Desktop/bitirme/html.txt")
        with open("/Users/msoguz/Desktop/bitirme/html.txt","w") as file:
            file.write(html)
    else:
        with open("/Users/msoguz/Desktop/bitirme/html.txt","w") as file:
            file.write(html)
    return html

def ControlIp(url):
    if url.count(".")>=4:
        return 1
    else: return -1
    
    
def ControlNumberCharacters(url):
    if len(url)>75:
        return 1
    elif len(url)<75 and len(url)>=54:
        return 0
    else: return -1
    
def ControlShortDomain(url):
    datashort=pd.read_csv('/Users/msoguz/Desktop/bitirme/shortdomain.csv')
    if url in datashort:
        return 1
    else: return -1

def ControlAtSign(url):
    if "@" in url:
        return 1
    else: return -1

def ControlDoubleSlash(url):
    if url.count("//")>1:
            return 1
    elif "http" in url:
        if url.index("//")>7:
            return 1
    elif "https" in url:
        if url.index("//")>7:
            return 1
    elif "http" not in url:
        if url.count("//")>=1:
            return 1
    else:
         return -1

def ControlHyphen(url):
    if "-" in url:
        return 1
    else: return -1

def ControlSubDomain(url):
    if url.count(".")>2:
        return 1
    else: return -1

def ControlCertificate(url):
    try:
        port = '443'
        context = ssl.create_default_context()
        with socket.create_connection((url, port)) as sock:
            with context.wrap_socket(sock, server_hostname = url) as ssock:
                certificate = ssock.getpeercert()
        certExpires = datetime.datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
        certExpires2 = datetime.datetime.strptime(certificate['notBefore'], '%b %d %H:%M:%S %Y %Z')
        daysToExpiration = (certExpires - certExpires2).days
        if daysToExpiration>730:
            return -1
        else: return 1
    except:
        return 1


def ControlRegistrationAge(url):
    info=Whois(url)
    CreateDate=info["creation_date"]
    ExpiratDate=info["expiration_date"]
    date=ExpiratDate-CreateDate
    month=date.days/30
    if month<6:
        return 1
    else: return -1
    
    
def ControlDomainAge(url):
    info=Whois(url)
    CreateDate=info["creation_date"]
    now= datetime.now()
    date=now-CreateDate
    age=date.days/365
    if age<1:
        return 1
    else: return -1
    
def ControlCountHttp(url):
    if url.count("http")>1:
        return 1
    else: return -1
    
def Favicon(url):
    html=open("html.txt","r")
    html=html.read()
    x=html.index("favicon")
    a=""
    i=""
    for i in range(x+8,x+90):
        x=html[i]
        if x=='"':
            break
        a+=x
    if FindDomainName(url) in a:
        return -1
    else: return 1
    
def PortControl(url):
    remoteServerIP  = socket.gethostbyname(url)
    port_list=[21,22,23,80,443,445,1433,1521,3306,3389]
    status=[]
    for port in port_list:  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            status.append("Open")
        else:
            status.append("Close")
        sock.close()
    if status[0]=="Close" and status[1]=="Close" and status[2]=="Close" and status[3]=="Open" and status[4]=="Open" and status[5]=="Close" and status[6]=="Close" and status[7]=="Close" and status[8]=="Close" and status[9]=="Close" :
        return -1
    else: return 1
    
def Httptoken(url):
    a=url.split("http")
    b=a[1]
    if b[0]=="-":
        return 1
    else:return -1
    
def https(url):
    if "http" in url or "https" in url:
        return 1
    else: return -1

def Media(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    count=0
    countimg=html.count('img src="')
    counts=html.count('bgsound src="')
    countv=html.count('embed src="')
    srcimg=html.split('img src="')
    srcs=html.split('bgsound src="')
    srcv=html.split('embed src="')
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/domain.csv')
    domain=data["Domain"]
    for i in srcimg:
        if i in domain:
            if url not in i:
                count+=1
    for i in srcs:
        if i in domain:
            if url not in i:
                count+=1
    for i in srcv:
        if i in domain:
            if url not in i:
                count+=1
    total=countimg+counts+countv
    if count>(total*0.6):
        return 1
    elif (total*0.22)<=count<(total*0.61):
        return 0
    elif count<(total*0.22):
        return -1

def Aherf(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    count=0
    counta=html.count('<a href=')
    aherf=html.split('<a href=')
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/domain.csv')
    domain=data["Domain"]
    for i in aherf:
        if i in domain:
            if url not in i:
                count+=1
    if count>(counta*0.6):
        return 1
    elif (counta*0.22)<=count<(counta*0.61):
        return 0
    elif count<(counta*0.22):
        return -1

def Tags(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    count=0
    countmeta=html.count("meta")
    countscript=html.count("script")
    countlink=html.count("link")
    meta=html.split('<meta')
    script=html.split('<script')
    link=html.split('<link')
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/domain.csv')
    domain=data["Domain"]
    for i in meta:
        if i in domain:
            if url not in i:
                count+=1
    for i in script:
        if i in domain:
            if url not in i:
                count+=1
    for i in link:
        if i in domain:
            if url not in i:
                count+=1
    total=countmeta+countscript+countlink
    if count>(total*0.67):
        return 1
    elif (total*0.30)<=count<(total*0.61):
        return 0
    elif count<(total*0.22):
        return -1
    elif count==0:
        return -1

def Mail(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    count=0
    countm=html.count("mail()")
    countmt=html.count("mailto()")
    mail=html.split('mail()')
    mailto=html.split('mailto()')
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/domain.csv')
    domain=data["Domain"]
    for i in mail:
        if i in domain:
            if url not in i:
                count+=1
    for i in mailto:
        if i in domain:
            if url not in i:
                count+=1
    total=countm+countmt
    if count>(total*0.67):
        return 1
    elif (total*0.30)<=count<(total*0.61):
        return 0
    elif count<(total*0.22):
        return -1
    elif count==0:
        return -1
    
def Controlhostname(url):
    info=who.whois(url)
    if FindDomainName(url) in info["name"]:
        return -1
    else: return 1

def redirect(url):
    return 1


def onmouseover(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    countm=0
    countm=html.count("onmouseover")
    if countm>0:
        return 1
    else:return -1

def Rightclick(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    countm=0
    countm=html.count("event.button==2")
    if countm>0:
        return 1
    else:return -1
    
def Iframe(url):
    html=open("/Users/msoguz/Desktop/bitirme/html.txt","r")
    html=html.read()
    countm=0
    countm=html.count("<iframe>")
    if countm>0:
        return 1
    else:return -1
    
def Alexa(url):
    result=Alexa_rank(url)
    if result<100000:
        return -1
    elif 100000<result<110000:
        return 0
    else: return 1
    
def Alexa_rank(url):
    alexa_base_url = 'https://alexa.com/siteinfo/'
    url=url.split("www.")
    site=url[1].split("/")
    site_name=site[0]
    
    url_for_rank = alexa_base_url + site_name
    
    # Request formatted url for rank(s)
    page = requests.get(url_for_rank)
    soup = BeautifulSoup(page.content, 'html.parser')
    
    # get ranks text in a list
    country_ranks = soup.find_all('div', id='CountryRank')
    
    # select the data with class='rank-global' and the class='data'
    global_rank = soup.select('.rank-global .data')
    
    # Display Global rank safely
    try:
        match = re.search(r'[\d,]+', global_rank[0].text.strip())
        print("Global Rank: ", match.group())
    except:
        print("No global rank found for ", site_name)
    
    # Display country rank(s)
    try:
        ranks_list = country_ranks[0].text.strip().split("\n")
        print("Country Rank: ")
        for rank in ranks_list:
            if re.search(r'#\d+', rank):
                print("\t",rank)
    except:
        print("No country rank was found for ", site_name)
        
    if match.group()>rank:
        return match.group()
    else: return rank
    
def PageRank(url):
    rank = 0.19
    if rank<0.2:
        return 1
    else: return -1

def Ireport(url):
    data=pd.read_csv('/Users/msoguz/Desktop/bitirme/verified_online.csv')
    if url in data:
        return 1
    else: return -1