#!/usr/bin/python
# -*- coding: utf-8 -*-


#sistemde aktif olan python sürümünü bulur ve onun üzerinde projeyi çalıştırır
# kodlama dilini utf-8 formatına çevirir 

#------------ MODÜLLER BAŞLANGIÇ -----------------------------

import urllib, urllib2  		#url işlemleri için kullanılan modül
import re				#string işlemleri için kullanılan modül
import os				#işletim sistemi üzerinde işlemler için kullanılan modül
import sys				#Python sürümü ile ilgili bilgi edinmenizi ve kullandığınız Python sürümü ile çeşitli işlemler yapabilmenizi sağlar.
import time				#zaman modülü
import hashlib				#hash alma için modül
from PyQt4 import QtGui, QtCore		#görsel arayüz için modül  qt kullanılmıştır.

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
        self.setFixedSize(470,220)						   #form boyutları ayarlanıyor
        self.setWindowTitle(_fromUtf8("Offline Zararlı Yazılım Tespit Sistemi"))   #pencere ismi ayarlanıyor

        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8("/home/plox/Masaüstü/1.ico")), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)
        # Projemize icon ekliyoruz.
        
        self.lineEdit = QtGui.QLineEdit(self)
        self.lineEdit.setGeometry(QtCore.QRect(150, 20, 301, 41))		  #Dosya seç butonu oluşturuyor
        self.lineEdit.setObjectName("dosyaSec")
            
        self.button = QtGui.QPushButton(_fromUtf8("Dosya Seç"),self)
        self.button.move(25,25)							  #Buton yerleştiriliyor
        self.button.clicked.connect(self.openFileDialog)
        
        self.listWidget = QtGui.QListWidget(self)				  #Liste oluşturuluyor	
        self.listWidget.setGeometry(QtCore.QRect(20, 90, 430, 120))
        self.listWidget.setObjectName(_fromUtf8("listWidget"))
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtGui.QListWidgetItem()
        self.listWidget.addItem(item)
                
        
    def openFileDialog(self):
        filter = "All Files(*.*)"											#Dosya seçim ekranında filtreleme yapıyor
        filename1 = QtGui.QFileDialog.getOpenFileNameAndFilter(self, "Open File", "/home/plox/Masaustu/" ,filter)	#Dosya seç için başlangıç dizini belirleniyor
        self.lineEdit.setText(filename1[0])
        print(filename1[0])
        self.filename = "hash.txt"    
        self.binary_md5 = ""
        self.number = ""
        self.md5 = ""
        self.virustype = ""
        self.severity = ""
        self.virusname = ""
        self.date = ""
        self.parcalanmis =[]
        self.filename = "hash.txt"
        
        md5 = hashlib.md5(open(filename1[0],'rb').read())	#seçilen dosyanın md5 ini alıyor
        self.binary_md5 = md5.hexdigest()			#dosyanın hexini alıyor
        print self.binary_md5					
        

	#Hash.txt dosyasının okunup okunmadığını kontrol ediyor.
        try:
            FILE  = open (self.filename,"r" )   
            self.entries = FILE.readlines()
            
            FILE.close()
        except IOError:
            print "[+] hashset.txt dosyasi bulunamadi.!\n"
            sys.exit(1)
            


        print "[+] Zararli yazilim bulunamadi.!"
        item = self.listWidget.item(0)
        item.setText("[+] Zararli yazilim bulunamadi.!")    
        for i in range(1,4):
                item = self.listWidget.item(i)
                item.setText("")
        for entry in self.entries:
            if (entry.find(self.binary_md5) > 0):
                parcalanmis= entry.split("|")
                print "[+] Zararli Yazilim Tespit Edildi!"
                print "\t[*] Virus Ismi:", parcalanmis[2]
                print "\t[*] Tipi:", parcalanmis[3]
                print "\t[*] Tarih:", parcalanmis[4] 
                item = self.listWidget.item(0)
                item.setText("")
                item = self.listWidget.item(0)
                item.setText("[+] Zararli Yazilim Tespit Edildi!")
                item = self.listWidget.item(1)
                item.setText("\t[*] Virus Ismi: " + parcalanmis[2])
                item = self.listWidget.item(2)
                item.setText("\t[*] Tipi: " + parcalanmis[3])     
                item = self.listWidget.item(3)
                item.setText("\t[*] Tarih: " + parcalanmis[4])     
             
 
        

if __name__ == "__main__":
    app = QtGui.QApplication(sys.argv)
    fd = FileDialog()  	#fd nesnesi oluşturuluyor.
    fd.show()	      	#nesneyi ekrana getiriyor.
    sys.exit(app.exec_())

