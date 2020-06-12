import re
import rsa
import json
import time
import base64
import binascii
import requests
from collections import Counter


class WeiboLogin:

    def __init__(self, username, password):
        """
        登录微博获取微博信任
        :param username:
        :param password:
        """
        self.session = requests.Session()
        self.headers = {   # 伪装请求
            'Referer': 'https://weibo.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36'
        }
        self.username = username
        self.password = password

    def get_username(self):
        """
        通过base64编码获取su的值
        """
        username_base64 = base64.b64encode(self.username.encode())
        return username_base64.decode()

    def get_json_data(self, su):
        """
        通过su参数发起第一次请求，获取pubkey和nonce的值
        """
        url = 'https://login.sina.com.cn/sso/prelogin.php'
        timestamp = int(time.time() * 1000)
        params = {
            'entry': 'weibo',
            'callback': 'sinaSSOController.preloginCallBack',
            'su': su,
            'rsakt': 'mod',
            'checkpin': '1',
            'client': 'ssologin.js(v1.4.19)',
            '_': timestamp
        }
        data = self.session.get(url=url, headers=self.headers, params=params).text
        json_data = json.loads(re.findall(r'\((.*?)\)', data, re.S)[0])
        return json_data

    def get_password(self, servertime, nonce, pubkey):
        """
        对密码进行rsa加密
        """

        stri = (str(servertime)+'\t'+str(nonce)+'\n'+self.password).encode()
        public_key = rsa.PublicKey(int(pubkey, 16), int('10001', 16))
        password = rsa.encrypt(stri, public_key)
        password = binascii.b2a_hex(password)
        return password.decode()

    def login_first(self):
        """
        发起第一次登录请求，获取登录请求跳转页redirect_login_url
        """
        su = self.get_username()
        json_data = self.get_json_data(su)
        sp = self.get_password(json_data['servertime'], json_data['nonce'], json_data['pubkey'])
        # sp = sp	c43c74bb875e23e63bdd45da3b64ebc4222fd3b48c461df0c7bad43d6a64e37d14e53161d978f26178fd7b46f9c5e003c60cadc7832759f40a6d736c2287a36e744c6b1db5c4c23cf07ddbcdbb04fa0d7d73d55bbc573c1f962c24e6097521f20a1a288d55c0d9e0b4e2267e7d8982cdc105ffa7a712edcf0574c378bfd053d9
        data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer': '',
            'vsnf': '1',
            'su': su,
            'service': 'miniblog',
            'servertime': json_data['servertime'],
            'nonce': json_data['nonce'],
            'pwencode': 'rsa2',
            'rsakv': json_data['rsakv'],
            'sp': sp,
            'sr': '1920*1080',
            'encoding': 'UTF-8',
            'prelt': '5109',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        # 首次登录请求地址
        login_url = 'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)'
        response = self.session.post(url=login_url, data=data, headers=self.headers)
        response.encoding = response.apparent_encoding
        try:
            redirect_login_url = re.findall(r'replace\("(.*?)"\)', response.text, re.S)[0]
            return redirect_login_url
        except:
            return '获取首次登录请求跳转页失败'

    def login_second(self):
        """
        发起第二次登录请求，再次获取登录请求跳转页arrURL
        """
        # 第二次登录请求地址
        url = self.login_first()
        response = self.session.get(url, headers=self.headers)
        response.encoding = response.apparent_encoding
        try:
            arr_url = json.loads(re.findall(r'setCrossDomainUrlList\((.*?)\)', response.text, re.S)[0])['arrURL'][0]
            return arr_url
        except:
            return '获取第二次登录请求跳转页失败'

    def login_finally(self):
        """
        发起最终登录请求，实现登录并跳转到用户微博首页
        """
        # 最终登录请求地址
        url = self.login_second()
        try:
            res = self.session.get(url, headers=self.headers)
            res.encoding = res.apparent_encoding
        except:
            return '登录失败，或为用户名或密码错误'
        try:
            # 获取用户id
            uid = json.loads(res.text[1:-4])['userinfo']['uniqueid']
            # 拼接用户微博首页
            user_home_url = 'https://www.weibo.com/u/{}/home'.format(uid)
            # 访问用户微博首页
            response = self.session.get(url=user_home_url, headers=self.headers)
            response.encoding = response.apparent_encoding
            result = response.content.decode('utf8')
            title = re.findall(r'<title>(.*?)</title>', result, re.S)[0]
            if '我的首页' in title:
                print('登录成功')
                return self.session
            else:
                return '登录失败'
        except:
            return '获取最终登录请求跳转页失败'


class Wb_Spider():
    def __init__(self, sessions):
        """
        抓取热门微博分类的音乐分类中出现过的音乐名
        并按照音乐名称出现的次数进行排序
        :param sessions:
        """
        self.session = sessions
        self.headers = {  # 伪装请求
            'Host': 'd.weibo.com',
            'Referer': 'https://d.weibo.com/102803_ctg1_5288_-_ctg1_5288?from=faxian_hot&mod=fenlei',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36'
        }

    def spider(self):
        """
        抓取微博数据
        :return:
        """
        music_name_list = []
        for i in range(2, 1000):
            url = f'https://d.weibo.com/p/aj/v6/mblog/mbloglist?ajwvr=6&domain=102803_ctg1_5288_-_ctg1_5288&from=faxian_hot&mod=fenlei&pagebar={i-1}&tab=home&current_page={i}&pre_page=1&page=1&pl_name=Pl_Core_NewMixFeed__3&id=102803_ctg1_5288_-_ctg1_5288&script_uri=/102803_ctg1_5288_-_ctg1_5288&feed_type=1&domain_op=102803_ctg1_5288_-_ctg1_5288'
            response = self.session.get(url, headers=self.headers)
            music_names = re.findall(r'《(.*?)》', response.json()['data'])
            music_name_list += [music_name for music_name in music_names]
        music_name_list = [j for j in music_name_list if '<' not in j]
        music_dict = dict(Counter(music_name_list).most_common())
        with open('music_names.js', 'w', encoding='utf-8') as file:
            json.dump(music_dict, file, ensure_ascii=False)
        print('程序运行完成')

if __name__ == '__main__':
    # 此处输入用户名和密码
    username = '****'
    password = '****'
    weibo = WeiboLogin(str(username), str(password))
    # 发起模拟登录
    sessionss = weibo.login_finally()
    # 爬取微博音乐栏音乐名称
    Wb_Spider(sessionss).spider()
