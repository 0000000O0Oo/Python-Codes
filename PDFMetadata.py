import pyPdf
import optparse
from PyPdf import PdfFileReader as readr

def getFileName():
    parser = optparse.OptionParser()
    parser.add_option("-f", "--file", dest="filename", help="Enter the name of your PDF File.")
    (options, argument) = parser.parse_args()
    if not filename:
        parser.error("Please provide a PDF file using -> -f or --file !")
    else:
        return options.filename

def printMeta(filename):
    pdfFile = readr(file(filename, 'rb'))
    docInfo = pdfFile.getDocumentInfo()
    print("[*] PDF MetaData For : " + str(filename))
    for metaItem in docInfo:
        print('[+] ' + metaItem + ": " + docInfo[metaItem])

pdf = getFileName()
printMeta(pdf)
