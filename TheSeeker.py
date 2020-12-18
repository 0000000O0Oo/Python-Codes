import urllib.request
import urllib.parse
import urllib.error
import optparse
from urllib.parse import urlsplit
import os
from PIL import Image
from PIL.ExifTags import TAGS
from bs4 import BeautifulSoup
from os.path import basename

def pBanner():
    os.system("clear")
    print("""
        ⣼⡟⠋⣀⣼⣾⣶⣶⣦⣤⣤⣴⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡘⢹⠄
        ⡟⠄⢰⣿⣿⣿⣿⣿⣿⣿⠈⠈⣿⣿⣿⣿⡋⠉⣻⣿⣿⣿⣿⣿⣿⣿⡄⠘⣇
        ⠁⠄⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⢵⣽⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠄⢹
        ⠄⢀⣾⣿⣿⣿⣿⣿⣿⣿⡿⠋⣿⣿⣿⣿⣿⠉⠻⠿⣿⣿⣿⣿⣿⣿⣿⣇⠄
        ⠄⢰⣿⣿⡿⠿⠟⠋⠉⠄⠄⠈⣿⣿⣿⣿⡏⢀⣤⣤⣄⣀⣀⣀⡈⠉⢻⣿⠄
        ⡄⢸⣯⣥⡴⠒⢊⡁ ⭕ ⢸⣿⣿⣿⣿⣦⠈⠁ ⭕ ⣆⠈⣁⣈⣿⣿⡴
        ⣿⢸⣿⣿⣿⣿⣶⣶⣿⣶⣡⣼⣿⣿⣿⣿⣿⢿⣆⣤⣾⣬⣭⣵⣶⣿⣿⣿⣿
        ⠄⢻⡟⣩⣾⣿⣿⣿⠏⠿⡿⢿⡿⠿⠯⠎⠉⠙⠻⣿⣿⣿⡿⢖⣀⣀⠄⣼⠄
        ⢀⠘⣷⣿⢿⣿⣿⣿⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⠿⠟⠋⠁⣴⣿⠏⠄
        ⠄⠄⠘⣿⣷⣌⠙⠻⢿⣷⣶⣤⣤⣤⣀⣠⡤⠞⡋⡍⠄⠂⠄⠄⣼⣿⠃⠄⠄
        ⠄⠄⠄⠄⢸⣿⣦⠄⠘⣿⡁⣾⣹⡍⣁⠐⡆⡇⠁⡌⠄⠄⠄⣰⣿⠇⠄⠄⠄
        ⠄⠄⠄⠄⠄⢹⣿⣷⡘⢻⣧⣇⡟⢿⢿⠄⢷⢸⡧⠁⠄⠄⢰⣿⣿⠏⠄⠄⠄
        ⠄⠄⠄⠄⠄⠈⣿⣿⣷⡹⢹⠸⢣⢈⠘⡇⠘⠈⠄⠁⠄⠄⣼⣿⣿⠃⣰⠄⠄
        ⠄⠄⠄⠄⠄⣷⠘⣿⣿⣷⡀⠄⠸⢿⣿⡏⣾⠓⠃⠄⠄⢀⡟⣿⠏⣰⣿⣷⠄
        ⠄⠄⣠⣿⣿⣿⣷⠙⣿⣿⣷⡀⠄⠈⠄⠄⠄⠄⠄⠄⣠⡞⣼⡿⢀⣿⣿⣿⣷
        ⠄⣼⣿⣿⣿⣿⣿⣷⠈⠿⣝⣿⣿⣦⣤⣭⣥⣤⣤⣶⣾⠿⠋⢀⣼⣿⣿ TheSeeker
        """)

def downloadImage(url,tag):
    try:
        print("[+] Downloading images...")
        imgSrc = tag['src']
        imgContent = urllib.request.urlopen(imgSrc).read()
        imgFileName = basename(urlsplit(imgSrc)[2])
        with open(imgFileName, 'wb') as file:
            imgFile.write(imgContent)
        return imgFileName
    except OSError:
        return ''

def getURL():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", type="string", help="Enter the url of the website you wish to download and parse image data")
    (options, args) = parser.parse_args()
    if not options.url:
        parser.error("Please enter an url using -u or --url !")
        exit(0)
    else:
        return options.url

def findImages(url):
    print("[+] Finding images on : " + url)
    urlContent = urllib.request.urlopen(url).read()
    soup = BeautifulSoup(urlContent, features="html.parser")
    imgTags = soup.findAll('img')
    return imgTags

def testForExif(imgFileName):
    try:
        exifData = {}
        imgFile = Image.open(imgFileName)
        print("GetExif()")
        info = imgFile._getexif()
        if info:
            for(tag, value) in info.items():
                decoded = TAGS.get(tag, tag)
                exifData[decoded] = value
            exifGPS = exifData['GPSInfo']
            if exifGPS:
                print("[*] " + imgFileName + ' contains GPS MetaData')
            else:
                print("[-] No MetaData found for these images")
    except:
        pass

pBanner()
url = getURL()
print("[+] URL Obtained")
imgTags = findImages(url)
print("[+] Images Obtained")
for imgTag in imgTags:
    imgFileName = downloadImage(url,imgTag)
    testForExif(imgFileName)
