#!/usr/bin/python
# coding: utf-8
import hmac, hashlib, base64
import random
import datetime, time, pytz
import urllib
import re
import requests

class NotOwnDomainException(Exception):
    def __init__(self, domain):
        Exception.__init__(self, '你的阿里云账号下面并不拥有此域名：' + domain)
class RecordNotFoundException(Exception):
    def __init__(self, record):
        Exception.__init__(self, 'Record不存在：' + record)
        
class AliyunRequest:
    __url_prefix = 'http://alidns.aliyuncs.com/?'
    def __init__(self, key_id, key_secret):
        self.key_id = key_id
        self.key_secret = key_secret
        
    def __signature(self, msg):
        h =hmac.new(self.key_secret + '&', msg, hashlib.sha1)
        return base64.b64encode(h.digest())

    def __urlencode_for_sig(self, query):
        str_q = urllib.urlencode(query)
        str_q = str_q.replace('+', '%20')
        str_q = str_q.replace('*', '%2A')
        str_q = str_q.replace('=', '%3D')
        str_q = str_q.replace('&', '%26')
        str_q = str_q.replace('%7E', '~')
        return str_q
    
    def send_request(self, action, map_arg):
        map_common_args = {
            'AccessKeyId':self.key_id,
            'Action':action,
            'Format':'json',
            'Version':'2015-01-09',
            'SignatureMethod': 'HMAC-SHA1',
            'SignatureVersion':'1.0',
            'SignatureNonce':str(random.randint(100000000,1000000000)),
            'Timestamp': datetime.datetime.fromtimestamp(time.time(), pytz.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        map_arg.update(map_common_args)
        url_items = sorted(map_arg.items(), key=lambda e : e[0])
        url_items = [(item[0], urllib.quote_plus(item[1])) for item in url_items]
        sig_items = 'GET&%%2F&%s' % self.__urlencode_for_sig(url_items)
        str_sig = self.__signature(sig_items)
        str_sig = urllib.quote_plus(str_sig)
        url_items.append(('Signature',str_sig))
        url_params = ['='.join(item) for item in url_items]
        url = AliyunRequest.__url_prefix + '&'.join(url_params)
        r = requests.get(url)
        if r.status_code <200 or r.status_code>299:
            raise Exception(r.status_code)
        return r.json()   

class AliyunDomainRequest(AliyunRequest):
    def __init__(self, key_id, key_secret, domain):
        offset = domain.rfind('.', 0, domain.rfind('.'))
        self.domain_base = domain[offset+1:]
        self.domain_name = domain[0:offset]
        AliyunRequest.__init__(self, key_id, key_secret)
        
    def query_record(self):
        action = 'DescribeSubDomainRecords'
        args = {
            'SubDomain':self.domain_name + '.' + self.domain_base,
        }
        try:        
            ret = self.send_request(action, args)
            ret = ret['DomainRecords']['Record']
            return ret
        except Exception as e:
            #print 'error: response code is' + str(e)
            pass
        
    def get_record(self):
        ret = self.query_record()
        if ret is None:
            raise NotOwnDomainException(self.domain_base)
        elif isinstance(ret, list):
            if len(ret)>0:
                #成功找到record id
                ret = ret[0]
            else:
                #拥有域名但没有记录
                raise RecordNotFoundException(self.domain_name + '.' + self.domain_base)
        else:
            raise Exception('未知错误')
        
        return ret
    
    def add_record(self, ip):
        action = 'AddDomainRecord'
        args = {
            'DomainName':self.domain_base,
            'RR':self.domain_name,
            'Type':'A',
            'Value':ip,
            'TTL':'600',
        }
        return self.send_request(action, args)
    
    def update_record(self,record_id, ip):
        action = 'UpdateDomainRecord'
        args = {
            'RR':self.domain_name,
            'RecordId':record_id,
            'Type':'A',
            'TTL':'600',
            'Value':ip,
        }
        return self.send_request(action, args)

class AliyunDDns:
    def __init__(self, key_id, key_secret, domain):
        self.domain_request = AliyunDomainRequest(key_id, key_secret, domain)
    
    @staticmethod
    def __get_ip():
        r = requests.get('http://whatismyip.akamai.com')       
        if r.status_code == 200:
            return r.content
        return None
    def update(self, add_if_no_record=False):
        try:
            record = self.domain_request.get_record()
            ip = self.__get_ip()
            if ip != record['Value']:
                # 更新ip
                self.domain_request.update_record(record['RecordId'], ip)
        except NotOwnDomainException as e:
            print e
        except RecordNotFoundException as e:
            print e
            if add_if_no_record:
                print '添加一条record'
                ip = self.__get_ip()
                if ip is not None:
                    self.domain_request.add_record(ip)
        except Exception as e:
            print '未知异常' + e

if __name__ == "__main__":
    wz1 = AliyunDDns('LTALAP92s8dnLGnF', 'x1xq5Do8dveqz8Xo8dvacvacjitN6D', 'wz.luxi.me')
    wz2 = AliyunDDns('LTALAP92s8dnLGnF', 'x1xq5Do8dveqz8Xo8dvacvacjitN6D', 'wuzhou.luxi.me')
    wz1.update(True)
    wz2.update(True)
