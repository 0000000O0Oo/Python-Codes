import urllib2
import optparse
from PIL import Image
from PIL.ExifTags import TAGS
from bs4 import BeautifulSoup
from urlparse import urlsplit
from os.path import basename

def downloadImage(imgTag):
    try:
        print("[+] Downloading images...")
        imgSrc = imgTag['src']
        imgContent = urllib2.urlopen(imgSrc).read()
        imgFileName = basename(urlsplit(imgSrc)[2])
        imgFile = open(imgFileNamem 'wb')
        imgFile.write(imgContent)
        imgFile.close()
        return imgFileName
    except:
        return ''

def getURL():
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Enter the url of the website you wish to download and parse image data")
    (options, args) = parser.parse_args()
    if not options.url:
        parser.error("Please enter an url using -u or --url !")
        exit(0)
    else:
        return options.url

def findImages(url):
    print("[+] Finding images on : " + url)
    urlContent = urllib2.urlopen(url).read()
    soup = BeautifulSoup(urlContent)
    imgTags = soup.findAll('img')
    return imgTags

def textForExif(imgFileName):
    try:
        exifData = {}
        imgFile = Image.open(imgFileName)
        info = imgFile._getexif()
        if info:
            for(tag, value) in info.items():
                decoded = TAGS.get(tag, tag)
                exifData[decoded] = value
            exifGPS = exifData['GPSInfo']
            if exifGPS:
                print("[*] " + imgFileName + ' contains GPS MetaData')
    except:
        pass

url = getURL()
imgTags = findImages(url)
for imgTag in imgTags:
    imgFileName = downloadImage(imgTag)
    testForExif(imageFileName)
