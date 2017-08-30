import os
import ssl
import datetime
from socket import setdefaulttimeout
import OpenSSL
import base64


class SSLParser(object):
    def __init__(self):
        pass

    def get_cert_info_by_cert(self, x509):
        if type(x509) in [str, unicode]:
            try:
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
            except Exception as err:
                print err
                return dict()
        if x509:
            subject_items, common_name = self.__get_subject(x509)
            issuer = self.__get_issuer(x509)
            expire_date, expired, renewable = self.__get_expiration_date(x509)
            issue_date = self.__get_issue_date(x509)
            algorithm = self.__get_algorithm(x509)
            bits = x509.get_pubkey().bits()
            serial_number = self.__get_serial_number(x509)
            fingerprint = self.__get_fingerprint(x509)
            valid = self.__check_cert_valid(expired, algorithm)
            san_domain_list = self.get_san_domain_list(x509)
            cert_text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, x509) if x509 else None
            result = dict(
                subject_items=subject_items,
                issuer=issuer,
                bits=bits,
                issue_date=issue_date,
                expire_date=expire_date,
                expired=expired,
                renewable=renewable,
                serial_number=serial_number,
                fingerprint=fingerprint,
                algorithm=algorithm,
                common_name=common_name,
                valid=valid,
                san_domain_list=san_domain_list,
                san_str=", ".join(san_domain_list),
                cert_text=base64.b64encode(cert_text)
            )
        else:
            result = dict()
        return result

    def get_san_domain_list(self, x509):
        ext_count = x509.get_extension_count()
        san_domain_list = []
        for i in range(ext_count):
            extension = x509.get_extension(i)
            try:
                ext_str = extension.__str__()
                if 'DNS:' in ext_str:
                    for item in ext_str.split(','):
                        item = item.replace('DNS', '')
                        item = item.replace(':', '')
                        item = item.replace('\n', '')
                        item = item.strip()
                        if item and item not in san_domain_list:
                            san_domain_list.append(item)
            except Exception as err:
                print err
        return san_domain_list

    def __get_subject(self, x509):
        comps = x509.get_subject().get_components()
        items = []
        common_name = None
        for comp in comps:
            key = comp[0]
            value = comp[1]
            if key == 'CN':
                common_name = value
            items.append(dict(
                key=key,
                value=value
            ))
        return items, common_name

    def __get_issuer(self, x509):
        comps = x509.get_issuer().get_components()
        for comp in comps:
            if comp[0] == 'CN':
                return comp[1]
        return None

    def __get_serial_number(self, x509):
        global temp_str
        serial_number = '%x' % x509.get_serial_number()
        temp_list = []
        for i in range(len(serial_number)):
            if i % 2 == 0:
                temp_str = serial_number[i]
            else:
                temp_str = "{0}{1}".format(temp_str, serial_number[i])
                temp_list.append(temp_str)
        serial_number_formatted = ":".join(temp_list)
        return serial_number

    def __get_fingerprint(self, x509):
        fingerprint_sha1 = x509.digest('sha1')
        fingerprint_md5 = x509.digest('md5')
        result = dict(
            sha1=fingerprint_sha1,
            md5=fingerprint_md5
        )
        return result

    def __get_algorithm(self, x509):
        result = x509.get_signature_algorithm()
        return result

    def __get_expiration_date(self, x509):
        date_str = x509.get_notAfter()
        date_obj = datetime.datetime.strptime(date_str, '%Y%m%d%H%M%SZ')
        result = date_obj.strftime('%m/%d/%Y')
        date_now = datetime.datetime.now()
        expired = date_now > date_obj
        renewable = (date_now + datetime.timedelta(days=45)) > date_obj
        return result, expired, renewable

    def __get_issue_date(self, x509):
        date_str = x509.get_notBefore()
        date_obj = datetime.datetime.strptime(date_str, '%Y%m%d%H%M%SZ')
        result = date_obj.strftime('%m/%d/%Y')
        return result

    def __check_cert_valid(self, expired, algorithm):
        if not expired and 'sha2' in algorithm.lower():
            return True
        else:
            return False