#!/usr/bin/python
# -*- coding: utf-8 -*-


#sistemde aktif olan python sürümünü bulur ve onun üzerinde projeyi çalıştırır
# kodlama dilini utf-8 formatına çevirir 


#------------ MODÜLLER BAŞLANGIÇ -----------------------------

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint
from PyQt4 import QtGui, QtCore

#------------ MODÜLLER BİTİŞ -----------------------------





#------------- TÜRKÇE KARAKTER BAŞLANGIÇ ----------------------

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

#------------- TÜRKÇE KARAKTER BİTİŞ ----------------------



class FileDialog(QtGui.QWidget):
    def __init__(self):
        QtGui.QWidget.__init__(self)
        self.setFixedSize(700,600)						#form boyutları ayarlanıyor
        self.setWindowTitle(_fromUtf8("Online Zararlı Yazılım Tespit Sistemi")) #pencere ismi ayarlanıyor
        
        
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("/home/plox/Masaüstü/1.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off) # Projemize icon ekliyoruz.
        self.setWindowIcon(icon)
       
        
        self.lineEdit = QtGui.QLineEdit(self)
        self.lineEdit.setGeometry(QtCore.QRect(150, 20, 501, 31))	  #Dosya seç butonu oluşturuyor
        self.lineEdit.setObjectName("dosyaSec")
            
        self.button = QtGui.QPushButton(_fromUtf8("Dosya Seç"),self)	  #Buton yerleştiriliyor
        self.button.move(25,25)
        self.button.clicked.connect(self.openFileDialog)
        
        self.listWidget = QtGui.QListWidget(self)
        self.listWidget.setGeometry(QtCore.QRect(20, 90, 630, 500))	  #Liste oluşturuluyor	
        self.listWidget.setObjectName(_fromUtf8("listWidget"))
        
        for i in range(60):
            item = QtGui.QListWidgetItem()
            self.listWidget.addItem(item)
           
        
                
    def openFileDialog(self):
        filter = "All Files(*.*)"											#Dosya seçim ekranında filtreleme yapıyor
        filename1 = QtGui.QFileDialog.getOpenFileNameAndFilter(self, "Open File", "/home/plox/Masaustu/" ,filter)	#Dosya seç için başlangıç dizini belirleniyor
        self.lineEdit.setText(filename1[0])
        print(filename1[0])
        md5 = hashlib.md5(open(filename1[0],'rb').read())		#seçilen dosyanın md5 ini alıyor
        binary_md5 = md5.hexdigest()					#dosyanın hexini alıyor				
        vt=vtAPI()							#vtAPI fonksiyonunu çalıştırıyor
        verbose=True
        self.parse(vt.getReport(binary_md5), binary_md5 ,verbose)	#parçalama fonksiyonu çağırılıyor.
        
    def parse(self, it, md5, verbose):
        if it['response_code'] == 0:
            for i in range(60):
                item = self.listWidget.item(i)
                item.setText("")
            item = self.listWidget.item(0)
            item.setText("MD5: "+ md5 + _fromUtf8(" -- Zararlı yazılım bulunamadı.!"))
            print md5 + " -- Zararlı yazılım bulunamadı.!"
            return 0
        item = self.listWidget.item(0)
        item.setText("MD5: " + str(it['md5']) + " \n\n\tTespit Edilen: " + str(it['positives']) + '/' + str(it['total']) + '\n')
        if 'Sophos' in it['scans']:
            item = self.listWidget.item(1)
            item.setText("\tSophos Tespiti: " + str(it['scans']['Sophos']['result']) + "\n")
            if 'Kaspersky' in it['scans']:
                item = self.listWidget.item(2)
                item.setText("\tKaspersky Tespiti: " + str(it['scans']['Kaspersky']['result']) + "\n")
                if 'ESET-NOD32' in it['scans']:
                    item = self.listWidget.item(3)
                    item.setText("\tESET Tespiti: " + str(it['scans']['ESET-NOD32']['result']) + "\n")
                    item = self.listWidget.item(4)
                    item.setText("\tTarama Tarihi: " + str(it['scan_date']) + "\n")
                    
                    item = self.listWidget.item(6)
                    item.setText("\n\tDetayli Tarama Ciktilari:\n")
                    item = self.listWidget.item(7)
                    item.setText(_fromUtf8("\n\tAntivirüs\t\tSonuç\tVirüs Tipi\n"))
                    item = self.listWidget.item(8)
                    item.setText(" ")
   
   

        if verbose == True:
            c=8
            for x in it['scans']:
                c=c+1
                item.setText("\t" + x + "\t\t" +  str(it['scans'][x]['detected']) + "\t" + str(it['scans'][x]['result']))
                item = self.listWidget.item(c)
             
            

class vtAPI():
    def __init__(self):
        self.api = '42c7f344f593dc57473fc2f7a94ab7604b9c2d75d9b9241d94bc6df4254bf246'
        self.base = 'http://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata
    
    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Tekrar Tarama Basliyor. -- " + md5 + " (10 Dakika icinde tekrar sorgulayiniz.)"


# Md5 Fonksiyonu

    def checkMD5(self, checkval):
        if re.match(r"([a-fA-F\d]{32})", checkval) == None:
            md5 = self.md5sum(checkval)
            return md5.upper()
        else: 
            return checkval.upper()

    def md5sum(self,filename):
        fh = open(filename, 'rb')
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
            return m.hexdigest() 
          


if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    fd = FileDialog()
    fd.show()
    sys.exit(app.exec_())

