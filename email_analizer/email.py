class email(object):
    """docstring"""

    def __init__(self):
        """Constructor"""
    
    def _process_eml(self, eml_file:str):
        """
        """

        import hashlib
        from email.parser import Parser
        
        self._eml_file = eml_file

        parser = Parser()

        self._attachment_name = hashlib.sha256(open(self._eml_file, 'rb').read()).hexdigest()
        self._email = parser.parsestr(open(self._eml_file, 'r').read())

        # Process headers
        self.process_headers(self._email)
        
        # Process body and attachments
        self.process_body(self._email)
 

    def process_headers(self, email):
        """
        """

        import re
        import base64

        self._email_metadata = {}
        self._email = email

        # Email sender
        if  len(re.findall('<.*>', self._email['From'])) > 0:
            self._email_sender_name = re.findall('<.*>', self._email['From'])
            self._email_sender_name = self._email_sender_name[0][1:-1].encode('utf-8')

        elif (self._email['From'].find("\r\n\t") > 0):
            self._mail_sender_name = self._email['From'].replace("\r\n\t", " ")
            self._email_sender_name = self._email_sender_name.split(' ')[0].encode('utf-8')
        elif len(re.findall('.*<', self._email['From'])) > 0:
            # email sender in user <user email> format
            self._email_sender_name = self._email_sender_name[0][0:-1].encode('utf-8')  # Remove the " <"
        else:
            self._email_sender_name = self._email['From']
        self._email_metadata.update({'E-mail Sender': self._email_sender_name})
        
        # Email recipient
        if self._email['To']:  # No email recipient (Weird)
            self._email_recipient = re.findall('<.*>', self._email['To'])
            if len(self._email_recipient) > 0:
                self._email_recipient = self._email_recipient[0][1:-1].encode('utf-8')
            else:
                self._email_recipient = self._email['To']
        else:
            self._email_recipient = ''
        self._email_metadata.update({'E-mail Recipient': self._email_recipient})
        
        # Email subject
        self._email_subject = self._email['Subject']
        if (self._email_subject.find('utf-8') > 0):
            self._email_subject = base64.b64decode(self._email_subject.split('?')[3])

        self._email_metadata.update({'E-mail Subject': self._email_subject})

        # Email date
        self._email_date = self._email['date'].encode('utf-8')
        self._email_metadata.update({'E-mail date': self._email_date})

        print(self._email_metadata)
    

    def process_body(self, email):
        """
        """
        self._email = email

        if self._email.is_multipart():
            self._MIME_parts = self._email.get_payload()

            # Process each MIME part of the e-mail
            for self._MIME_part in self._MIME_parts:
                self._MIME_type = self._MIME_part.get_content_type()
                self.MIME_type_processor(self._MIME_type, self._MIME_part)

        if not self._email.is_multipart():
            self._MIME_type = self._email.get_content_type()
        self.MIME_type_processor(self._MIME_type, self._email)


    def MIME_type_processor(self, MIME_type, email):
        """
        """
        self._MIME_type = MIME_type
        self._MIME_part = email

        self._MIME_types = ['application/octet-stream', 'application/pdf', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/msword', 'application/vnd.ms-xpsdocument', 'application/zip', 'image/png', 'image/gif', 'image/bmp', 'image/jpeg', 'image/jpg', 'image/webp']
        
        if self._MIME_type == 'text/plain':
            if (self._MIME_part['Content-Transfer-Encoding'] == 'quoted-printable' or self._MIME_part['Content-Transfer-Encoding'] == '7bit' or self._MIME_part['Content-Transfer-Encoding'] == None):
                self._body = self._MIME_part.get_payload()
                self._filename = '{0}_email_body.txt' .format(self._attachment_name)
            if self._MIME_part['Content-Transfer-Encoding'] == 'base64':
                self._body = self._MIME_part.get_payload(decode=True)
                self._filename = '{0}_email_body.txt.base64_decoded' .format(self._attachment_name)
            file = open(self._filename, 'w')
            file.write(self._body)
            file.close()

        elif self._MIME_type == 'text/html':
            if (self._MIME_part['Content-Transfer-Encoding'] == 'quoted-printable' or self._MIME_part['Content-Transfer-Encoding'] == None):
                self._body = self._MIME_part.get_payload()
                self._filename = '{0}_email_body.html' .format(self._attachment_name)
            if self._MIME_part['Content-Transfer-Encoding'] == 'base64':
                self._body = self.MIME_part.get_payload(decode=True)
                self._filename = '{0}email_body.html.decoded' .format(self._attachment_name)
            file = open(self._filename, 'w')
            file.write(self._body)
            file.close()

        elif (self._MIME_type == 'multipart/alternative') or (self._MIME_type == 'multipart/related'):
            # This is usually the body of the email
            # Process email body
            self._multipart = self._MIME_part.get_payload()
            for self._part2 in self._multipart:
                self._MIME_type = self._part2.get_content_type()
                self.MIME_type_processor(self._MIME_type, self._part2)

        elif self._MIME_type == 'multgsart/mixed':
            # multgsart/mixed
            # This code is shit and needs to be reviewed
            # Cannot process the new email as an email 'cause its an string
            # have to figure out how to convert it into an email for parsing
            self._temp_new_email = self._MIME_part.get_payload()
            self._filename = "new_email.base64"
            self._new_email = open(self._filename, 'w')
            self._new_email.write(self._temp_new_email)
            self._new_email.close()
        
        elif self._MIME_type in self._MIME_types:
            self._attachment = self._MIME_part.get_payload(decode=True)

            if self._attachment:
                self.process_attachment(self._attachment)

        else:
            print('[E-mail analizer] professor Falken, New MIME type found -> {0}' .format(self._MIME_type))


    def process_attachment(self,attachment):
        """
        """
        
        self._attachment = attachment

        import hashlib
        import subprocess
        import os
        import py7zr

        if not(os.path.isdir('attachments')):
            os.mkdir('attachments')
        else:
            pass

        # Extract and save attachment
        self._attachment_sha256 = hashlib.sha256(self._attachment).hexdigest()
        #self._attachment_md5 = hashlib.md5(self._attachment.decode('utf-8')).hexdigest()
        #self._attachment_sha1 = hashlib.sha1(self._attachment.decode('utf-8')).hexdigest()

        # Get attachment type using yara rule
        self._yara_rule = str(self.check_yara(self._attachment)[0])

        if self._yara_rule == 'zip_file':
            self._filename = './attachments/'+self._attachment_sha256+'.zip.vir'
            self._file_type = 'ZIP'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'doc_file':
            self._filename = './attachments/'+self._attachment_sha256+'.doc.vir'
            self._file_type = 'DOC'
            self._analyze = True
            self._tools = "<UL><LI>oledump</LI></UL>"
            self._url = ""
        elif self._yara_rule == 'xls_file':
            self._filename = './attachments/'+self._attachment_sha256+'.xls.vir'
            self._file_type = 'XLS'
            self._analyze = True
            self._tools = "<UL><LI>oledump</LI></UL>"
            self._url = ""
        elif self._yara_rule == 'pdf_file':
            self._filename = './attachments/'+self._attachment_sha256+'.pdf.vir'
            self._file_type = 'PDF'
            self._analyze = True
            self._tools = "<UL><LI>pdfid</LI><LI>pdf-parser</LI></UL>"
            self._url = ""
        elif self._yara_rule == 'png_file':
            self._filename = './attachments/'+self._attachment_sha256+'.png'
            self._file_type = 'PNG'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'gif_file':
            self._filename = './attachments/'+self._attachment_sha256+'.gif'
            self._file_type = 'GIF'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'bmp_file':
            self._filename = './attachments/'+self._attachment_sha256+'.bmp'
            self._file_type = 'BMP'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'jpg_file':
            self._filename = './attachments/'+self._attachment_sha256+'.jpg'
            self._file_type = 'JPG'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'executable_file':
            self._filename = './attachments/'+self._attachment_sha256+'.exe.vir'
            self._file_type = 'EXE'
            self._analyze = True
            self._tools = ""
            self._url = ""
        elif self._yara_rule == 'webp_file':
            self._filename = './attachments/'+self._attachment_sha256+'.webp'
            self._file_type = 'WEBP'
            self._analyze = False
            self._tools = ""
            self._url = ""

        self._attachment_file = open(self._filename, 'wb')
        self._attachment_file.write(self._attachment)
        self._attachment_file.close()

        if self._analyze:
            # Zip and password protect file - Password: infected
            self._zip_filename = self._attachment_sha256+'.7z'
            self._zipfilter = [{"id": py7zr.FILTER_LZMA2 , "preset": 7}]
            with py7zr.SevenZipFile('./attachments/'+self._zip_filename,'w', filters=self._zipfilter, password='infected') as archive:
                archive.write(self._filename)

            # Remove original file
            os.remove(self._filename)
            #self._filename = self._zip_filename
      


    def check_yara(self, attachment):
        """TODO DOCSTRING."""

        self._attachment = attachment

        import yara
        import os
    
        self._yara_rules = yara.compile('yara_rules/file_type.yar')
        self._filename = 'temp.file'
        self._attachment_file = open(self._filename, 'wb')
        self._attachment_file.write(self._attachment)
        self._attachment_file.close()

        self._matches = self._yara_rules.match(self._filename)
        os.remove(self._filename)

        return self._matches

